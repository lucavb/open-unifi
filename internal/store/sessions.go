// Per-device client session store: the controller-owned record rows the
// inform path derives from decoded station data (internal/inform
// StationMACs → this package). A session row records one client's
// presence across consecutive FULL informs: a client present in one full
// inform and absent in the next has DISCONNECTED (a connect/disconnect
// event); rows persist after disconnect (connected=false) so the admin
// API can list a device's clients with their state.
//
// Trust policy (CONTEXT.md): session rows and the disconnect-event flag
// are CONTROLLER-OWNED keys — a device can neither overwrite nor
// introduce them via an inform body. The adapter's prev-wins preservation
// list carries them across informs (adoption.ControllerOwnedKeys), and
// the only writer is the session refresh computed adapter-side from
// decoded station data, never a passthrough. The §6.6 setdefault
// demotion sweeps the controller-owned keys with it: a factory-reset
// device re-adoption starts with fresh session state.
//
// Rows are deliberately never pruned for age or count: no recovered
// retention rule exists in this worktree's docs, and an invented TTL
// would be uncited behavior (the lane report records this as a noted
// bound — row growth is bounded by the client population each device
// ever serves).
package store

import "sort"

// Extra keys of the session store (controller-owned class).
const (
	// SessionsExtraKey holds the session rows: a JSON object keyed by
	// canonical 12-hex client MAC, each row {"last_seen": <unix float>,
	// "connected": <bool>}. The map key gives identity + dedup; the row
	// never repeats the MAC.
	SessionsExtraKey = "client_sessions"

	// SessionDisconnectEventExtraKey is the one-shot pending-outcome flag
	// the session refresh arms when a previously-connected client
	// disconnects (armedLifecycle pattern, adoption.FlagSetdefaultArmed
	// shape): the adoption engine consumes it on the device's next decoded
	// inform — firing the §6.2(e) blocked_sta reconnect push (or having it
	// satisfied by any blocked_sta-carrying emission) — and clears it in
	// the same decision. Truthy read; plain `true` write.
	SessionDisconnectEventExtraKey = "client_disconnect_pending"
)

// ClientSession is one client session row read out of the record.
type ClientSession struct {
	// MAC is the canonical 12-hex client MAC (the row's map key).
	MAC string
	// Connected reports whether the client was present in the device's
	// most recent station table.
	Connected bool
	// LastSeen is the unix-seconds timestamp of the last full inform whose
	// station table proved the client present. It is NOT advanced on
	// disconnects (the row keeps the last proof) and stays put across
	// sparse heartbeats.
	LastSeen int64
}

// sessionRow is the JSON row shape (write side; reads tolerate only what
// the JSON round trip and this writer produce).
type sessionRow struct {
	connected bool
	lastSeen  int64
}

// ClientSessions returns the device's session rows sorted by MAC.
// Absent/odd-shaped Extra values read as no rows; malformed rows are
// skipped, never fatal (a read must never fail over stored noise).
func ClientSessions(d Device) []ClientSession {
	rows := readSessionRows(d.Extra)
	out := make([]ClientSession, 0, len(rows))
	for mac, row := range rows {
		out = append(out, ClientSession{MAC: mac, Connected: row.connected, LastSeen: row.lastSeen})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// RefreshSessions applies one full inform's station table to the session
// rows and returns the connect/disconnect events observed, as canonical
// client MACs in sorted order. stationMACs carries the decoded rows in any
// spelling (canonicalized here); unparseable entries are skipped
// defensively. nowUnix is the inform's timestamp.
//
// The caller invokes this ONLY when the inform carried a station table
// (inform.StationMACs present=true): a sparse heartbeat refreshes nothing
// and wipes nothing (device-refreshable caps semantics — rows survive).
//
// Transition rules:
//   - a station absent from the rows → NEW session, connect event;
//   - a stored disconnected row seen again → reconnect, connect event;
//   - a stored connected row absent from the table → disconnect event,
//     row flips to connected=false (lastSeen keeps the last proof);
//   - a disconnect arms Extra[SessionDisconnectEventExtraKey] — the
//     one-shot flag the adoption engine consumes (§6.2(e) trigger).
//
// Repeated disconnects keep the flag armed (idempotent true write) until
// the engine consumes it.
func RefreshSessions(d *Device, stationMACs []string, nowUnix int64) (connects, disconnects []string) {
	rows := readSessionRows(d.Extra)
	present := make(map[string]bool, len(stationMACs))
	for _, m := range stationMACs {
		c, err := CanonicalMAC(m)
		if err != nil {
			continue // tolerate odd rows; never fail an inform over noise
		}
		present[c] = true
		row, known := rows[c]
		if !known || !row.connected {
			connects = append(connects, c)
		}
		rows[c] = sessionRow{connected: true, lastSeen: nowUnix}
	}
	for mac, row := range rows {
		if row.connected && !present[mac] {
			row.connected = false
			rows[mac] = row
			disconnects = append(disconnects, mac)
		}
	}
	sort.Strings(connects)
	sort.Strings(disconnects)
	writeSessionRows(d, rows)
	if len(disconnects) > 0 {
		if d.Extra == nil {
			d.Extra = JSONMap{}
		}
		d.Extra[SessionDisconnectEventExtraKey] = true
	}
	return connects, disconnects
}

// readSessionRows loads the rows from Extra, tolerating absent/odd shapes
// and odd row values (the JSON round trip yields float64 timestamps and
// bools from this package's own writes).
func readSessionRows(extra JSONMap) map[string]sessionRow {
	out := map[string]sessionRow{}
	raw, ok := extra[SessionsExtraKey].(map[string]any)
	if !ok {
		return out
	}
	for mac, v := range raw {
		row, ok := v.(map[string]any)
		if !ok {
			continue
		}
		sr := sessionRow{}
		if c, ok := row["connected"].(bool); ok {
			sr.connected = c
		}
		if ls, ok := row["last_seen"].(float64); ok {
			sr.lastSeen = int64(ls)
		}
		out[mac] = sr
	}
	return out
}

// writeSessionRows stores the rows back into Extra. An empty row set
// deletes the key (no zero-value object lingers in the persisted bytes);
// rows are written as plain map[string]any so the store file's JSON
// round trip and this reader agree on the shape.
func writeSessionRows(d *Device, rows map[string]sessionRow) {
	if d.Extra == nil {
		d.Extra = JSONMap{}
	}
	if len(rows) == 0 {
		delete(d.Extra, SessionsExtraKey)
		return
	}
	out := make(map[string]any, len(rows))
	for mac, row := range rows {
		out[mac] = map[string]any{
			"last_seen": float64(row.lastSeen),
			"connected": row.connected,
		}
	}
	d.Extra[SessionsExtraKey] = out
}

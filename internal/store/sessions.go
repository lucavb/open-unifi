// Per-device client session store: the controller-owned record rows the
// inform path derives from decoded station data (internal/inform
// StationMACs → this package). A session row records one client's
// presence across consecutive FULL informs: a client present in one full
// inform and absent in the next has DISCONNECTED (a connect/disconnect
// event); rows persist after disconnect (connected=false) so the admin
// API can list a device's clients with their state.
//
// Trust policy (CONTEXT.md): session rows and the disconnect-event flag
// are CONTROLLER-OWNED keys — a device can neither overwrite the rows nor
// introduce them once the record holds them; on a record that never held
// them (fresh or just-swept) a body copy stands and is thereafter
// prev-wins-protected (pinned by
// TestAbsorbControllerOwnedRestoresOnlyFromTheRecord). Record absorption
// carries them across informs (the controllerOwnedKeys registry in this
// package), and the only writer is the session refresh computed
// adapter-side from decoded station data, never a passthrough. The §6.6
// setdefault demotion sweeps the controller-owned keys with it: a
// factory-reset device re-adoption starts with fresh session state.
//
// Rows are bounded by sessionRowCap per device. When a refresh exceeds the
// cap, the oldest last_seen rows are evicted, with canonical MAC as the
// deterministic tie-break.
package store

import "sort"

// sessionRowCap is the per-device session-row retention cap (see the
// package comment): RefreshSessions evicts the rows with the oldest
// last_seen once a device's row count would exceed it.
const sessionRowCap = 2048

// Extra keys of the session store (controller-owned class).
const (
	// SessionsExtraKey holds the session rows: a JSON object keyed by
	// canonical 12-hex client MAC, each row {"last_seen": <unix float>,
	// "connected": <bool>} plus the optional context keys "since",
	// "hostname", "ip", "essid", "radio", "channel" and "bytes" (written
	// only when known). The map key gives identity + dedup; the row never
	// repeats the MAC.
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

	// The fields below are best-effort context captured from the station
	// table (zero = unknown; rows written before they existed read as
	// zero). They let the client event log report a connection duration,
	// the SSID/radio/channel the client sat on, and byte totals.

	// Since is the unix-seconds time the current (or, once disconnected,
	// the last) association was first observed.
	Since    int64
	Hostname string
	IP       string
	ESSID    string
	Radio    string
	Channel  int
	// Bytes is the last observed tx+rx byte total of the association.
	Bytes int64
}

// StationInfo is one decoded station-table row as the store consumes it
// (the server adapter converts inform.Station; this package stays free of
// the inform codec). Every field but MAC is optional.
type StationInfo struct {
	MAC      string
	Hostname string
	IP       string
	ESSID    string
	Radio    string
	Channel  int
	Bytes    int64
}

// TransitionKind classifies one observed session-row change.
type TransitionKind string

const (
	// TransitionConnect: a new session, or a stored disconnected row seen
	// again.
	TransitionConnect TransitionKind = "connect"
	// TransitionDisconnect: a connected row absent from the table.
	TransitionDisconnect TransitionKind = "disconnect"
	// TransitionRadioChange: a still-connected row whose radio or channel
	// changed on the same device (the same-AP half of a roam).
	TransitionRadioChange TransitionKind = "radio_change"
)

// Transition is one observed change of a client's session row on a device.
type Transition struct {
	// MAC is the canonical 12-hex client MAC.
	MAC  string
	Kind TransitionKind
	// At is the inform timestamp (unix seconds) that observed the change.
	At int64
	// Session is the row after the change; Prev the row before it (zero
	// value for a client never seen on this device).
	Session ClientSession
	Prev    ClientSession
}

// sessionRow is the JSON row shape (write side; reads tolerate only what
// the JSON round trip and this writer produce).
type sessionRow struct {
	connected bool
	lastSeen  int64
	since     int64
	hostname  string
	ip        string
	essid     string
	radio     string
	channel   int
	bytes     int64
}

func (r sessionRow) session(mac string) ClientSession {
	return ClientSession{
		MAC: mac, Connected: r.connected, LastSeen: r.lastSeen, Since: r.since,
		Hostname: r.hostname, IP: r.ip, ESSID: r.essid, Radio: r.radio, Channel: r.channel, Bytes: r.bytes,
	}
}

// ClientSessions returns the device's session rows sorted by MAC.
// Absent/odd-shaped Extra values read as no rows; malformed rows are
// skipped, never fatal (a read must never fail over stored noise).
func ClientSessions(d Device) []ClientSession {
	rows := readSessionRows(d.Extra)
	out := make([]ClientSession, 0, len(rows))
	for mac, row := range rows {
		out = append(out, row.session(mac))
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
	stations := make([]StationInfo, 0, len(stationMACs))
	for _, m := range stationMACs {
		stations = append(stations, StationInfo{MAC: m})
	}
	for _, t := range RefreshSessionStations(d, stations, nowUnix) {
		switch t.Kind {
		case TransitionConnect:
			connects = append(connects, t.MAC)
		case TransitionDisconnect:
			disconnects = append(disconnects, t.MAC)
		}
	}
	return connects, disconnects
}

// RefreshSessionStations is RefreshSessions with station context: the same
// transition rules (and the same disconnect arming), but the rows keep the
// per-association context and every observed change is returned as a typed
// Transition, ordered by client MAC (connect, then disconnect, then
// radio_change for a MAC). A still-connected row whose radio or channel
// changed (both values known) additionally yields TransitionRadioChange.
//
// Context merge: a reconnect/new row takes only what this table reports;
// a surviving row keeps its earlier values for fields the table omits.
func RefreshSessionStations(d *Device, stations []StationInfo, nowUnix int64) []Transition {
	rows := readSessionRows(d.Extra)
	prev := make(map[string]sessionRow, len(rows))
	for mac, row := range rows {
		prev[mac] = row
	}
	var out []Transition
	present := make(map[string]bool, len(stations))
	for _, st := range stations {
		c, err := CanonicalMAC(st.MAC)
		if err != nil {
			continue // tolerate odd rows; never fail an inform over noise
		}
		if present[c] {
			continue // duplicate row for the same client in one table
		}
		present[c] = true
		old, known := prev[c]
		fresh := !known || !old.connected
		next := sessionRow{connected: true, lastSeen: nowUnix}
		if fresh {
			next.since = nowUnix
		} else {
			next = old
			next.lastSeen = nowUnix
		}
		if st.Hostname != "" {
			next.hostname = st.Hostname
		}
		if st.IP != "" {
			next.ip = st.IP
		}
		if st.ESSID != "" {
			next.essid = st.ESSID
		}
		if st.Radio != "" {
			next.radio = st.Radio
		}
		if st.Channel != 0 {
			next.channel = st.Channel
		}
		if st.Bytes != 0 {
			next.bytes = st.Bytes
		}
		rows[c] = next
		switch {
		case fresh:
			out = append(out, Transition{MAC: c, Kind: TransitionConnect, At: nowUnix, Session: next.session(c), Prev: old.session(c)})
		case (old.radio != "" && next.radio != "" && old.radio != next.radio) ||
			(old.channel != 0 && next.channel != 0 && old.channel != next.channel):
			out = append(out, Transition{MAC: c, Kind: TransitionRadioChange, At: nowUnix, Session: next.session(c), Prev: old.session(c)})
		}
	}
	armed := false
	for mac, row := range prev {
		if row.connected && !present[mac] {
			gone := row
			gone.connected = false
			rows[mac] = gone
			armed = true
			out = append(out, Transition{MAC: mac, Kind: TransitionDisconnect, At: nowUnix, Session: gone.session(mac), Prev: row.session(mac)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].MAC != out[j].MAC {
			return out[i].MAC < out[j].MAC
		}
		return transitionOrder(out[i].Kind) < transitionOrder(out[j].Kind)
	})
	enforceSessionRowCap(rows)
	writeSessionRows(d, rows)
	if armed {
		if d.Extra == nil {
			d.Extra = JSONMap{}
		}
		d.Extra[SessionDisconnectEventExtraKey] = true
	}
	return out
}

func transitionOrder(k TransitionKind) int {
	switch k {
	case TransitionConnect:
		return 0
	case TransitionDisconnect:
		return 1
	default:
		return 2
	}
}

// enforceSessionRowCap evicts rows with the oldest last_seen (MAC as
// the deterministic tie-break) until the row count sits at
// sessionRowCap. Eviction is silent: the rows it retires produce no
// connect/disconnect events; a later inform sighting of an evicted
// client is simply a fresh connect.
func enforceSessionRowCap(rows map[string]sessionRow) {
	over := len(rows) - sessionRowCap
	if over <= 0 {
		return
	}
	macs := make([]string, 0, len(rows))
	for mac := range rows {
		macs = append(macs, mac)
	}
	sort.Slice(macs, func(i, j int) bool {
		ri, rj := rows[macs[i]], rows[macs[j]]
		if ri.lastSeen != rj.lastSeen {
			return ri.lastSeen < rj.lastSeen
		}
		return macs[i] < macs[j]
	})
	for _, mac := range macs[:over] {
		delete(rows, mac)
	}
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
		if v, ok := row["since"].(float64); ok {
			sr.since = int64(v)
		}
		if v, ok := row["hostname"].(string); ok {
			sr.hostname = v
		}
		if v, ok := row["ip"].(string); ok {
			sr.ip = v
		}
		if v, ok := row["essid"].(string); ok {
			sr.essid = v
		}
		if v, ok := row["radio"].(string); ok {
			sr.radio = v
		}
		if v, ok := row["channel"].(float64); ok {
			sr.channel = int(v)
		}
		if v, ok := row["bytes"].(float64); ok {
			sr.bytes = int64(v)
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
		m := map[string]any{
			"last_seen": float64(row.lastSeen),
			"connected": row.connected,
		}
		// Context keys are written only when known, so rows without
		// station context keep their original two-key shape.
		if row.since != 0 {
			m["since"] = float64(row.since)
		}
		if row.hostname != "" {
			m["hostname"] = row.hostname
		}
		if row.ip != "" {
			m["ip"] = row.ip
		}
		if row.essid != "" {
			m["essid"] = row.essid
		}
		if row.radio != "" {
			m["radio"] = row.radio
		}
		if row.channel != 0 {
			m["channel"] = float64(row.channel)
		}
		if row.bytes != 0 {
			m["bytes"] = float64(row.bytes)
		}
		out[mac] = m
	}
	d.Extra[SessionsExtraKey] = out
}

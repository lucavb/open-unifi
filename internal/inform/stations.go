// Station-table decode: the per-client rows a full inform carries. The
// inform codec owns body shape knowledge (CONTEXT.md: decision modules —
// this is the decode lane, framing/crypto aside), so the one payload field
// the session store needs is read here — defensively, because inform
// payloads are DEVICE-supplied bytes and a decode must never fail an
// inform over odd rows.
//
// The observed wire shape nests station rows under
// body["vap_table"][]["sta_table"][]; each row identifies a client by its
// "mac" field. The top-level "sta_table" form is retained as a fallback for
// firmware variants that use it.
//
// Row identity is the "mac" field, the same identity spelling the §103
// top-level body uses. Odd values are skipped, never fatal; an ABSENT
// table in BOTH shapes is reported as absent (present=false) so the
// caller can tell a sparse heartbeat (no table — session rows must
// survive) from a genuine empty table (zero clients — every
// previously-connected client disconnected). A vap_table whose rows
// carry no sta_table keys at all also reports absent: an uncertain shape
// must never read as "zero clients". That distinction is the
// device-refreshable caps semantics applied to session data
// (CONTEXT.md: a sparse heartbeat must not wipe controller-side rows).
package inform

import "encoding/json"

// StationMACs reads the per-client station table out of a decoded inform
// body. It returns the row MAC strings verbatim (any spelling — the store
// lane canonicalizes via store.CanonicalMAC; this package is a leaf and
// must not import it) and a present flag:
//
//   - present=false: the body carries no station table in any shape (a
//     sparse heartbeat or odd-shaped values). Callers must NOT touch
//     session state on such informs.
//   - present=true: at least one station-table array was found (top-level
//     or nested in a vap row), possibly empty — the device reports zero
//     associated clients. macs carries the rows whose "mac" field was a
//     string; odd rows are skipped, never fatal. The same MAC reached
//     through both shapes is reported once.
//
// The MAC order is the wire order: top-level rows first (the fallback
// shape), then vap rows in table order, stations within each vap in row
// order.
func StationMACs(body map[string]any) (macs []string, present bool) {
	stations, present := Stations(body)
	for _, st := range stations {
		macs = append(macs, st.MAC)
	}
	return macs, present
}

// Station is one decoded station-table row plus the context of the vap row
// it was nested in. Every field except MAC is optional: a zero value means
// "the device did not report it" (or reported something undecodable). The
// decode is defensive — inform payloads are DEVICE-supplied bytes.
//
// Row field names (hostname, ip, rssi/signal, tx_bytes, rx_bytes, uptime)
// and the vap context fields (essid, bssid, radio, channel) follow the
// classic controller's published stat/device shape; the 2026-09-20 bench
// capture pinned only the nesting and "mac", so these remain best-effort
// until a capture of a populated row confirms them.
type Station struct {
	// MAC is the row's "mac" field verbatim (any spelling).
	MAC      string
	Hostname string
	IP       string
	// Signal is the reported RSSI/signal in dBm (0 = unreported).
	Signal int
	// TxBytes/RxBytes are the cumulative per-association byte counters.
	TxBytes int64
	RxBytes int64
	// Uptime is the association age in seconds the device reports.
	Uptime int64

	// Vap context (copied from the parent vap row).
	ESSID   string
	BSSID   string
	Radio   string
	Channel int
}

// Stations reads the station table like StationMACs (same present
// semantics, same order, same dedupe — the first row for a MAC wins) but
// keeps the per-row and parent-vap context the client event log needs.
func Stations(body map[string]any) (stations []Station, present bool) {
	seen := map[string]bool{}
	add := func(rows []any, vap map[string]any) {
		for _, row := range rows {
			m, ok := row.(map[string]any)
			if !ok {
				continue // tolerate odd rows; never fail an inform over noise
			}
			mac, ok := m["mac"].(string)
			if !ok || mac == "" || seen[mac] {
				continue
			}
			seen[mac] = true
			st := Station{
				MAC:      mac,
				Hostname: strField(m, "hostname"),
				IP:       strField(m, "ip"),
				Signal:   int(numField(m, "signal", "rssi")),
				TxBytes:  numField(m, "tx_bytes"),
				RxBytes:  numField(m, "rx_bytes"),
				Uptime:   numField(m, "uptime"),
			}
			// Vap context wins; a top-level row may carry its own.
			ctx := vap
			if ctx == nil {
				ctx = m
			}
			st.ESSID = strField(ctx, "essid")
			st.BSSID = strField(ctx, "bssid")
			st.Radio = strField(ctx, "radio")
			st.Channel = int(numField(ctx, "channel"))
			stations = append(stations, st)
		}
	}
	if raw, ok := body["sta_table"].([]any); ok {
		add(raw, nil)
		present = true
	}
	if vaps, ok := body["vap_table"].([]any); ok {
		for _, v := range vaps {
			vm, ok := v.(map[string]any)
			if !ok {
				continue
			}
			if rows, ok := vm["sta_table"].([]any); ok {
				add(rows, vm)
				present = true
			}
		}
	}
	return stations, present
}

func strField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// numField returns the first present numeric key as an int64 (JSON numbers
// decode as float64 or json.Number; anything else reads as 0).
func numField(m map[string]any, keys ...string) int64 {
	for _, k := range keys {
		switch n := m[k].(type) {
		case float64:
			return int64(n)
		case int:
			return int64(n)
		case int64:
			return n
		case json.Number:
			if i, err := n.Int64(); err == nil {
				return i
			}
			if f, err := n.Float64(); err == nil {
				return int64(f)
			}
		}
	}
	return 0
}

// Station-table decode: the per-client rows a full inform carries. The
// inform codec owns body shape knowledge (CONTEXT.md: decision modules —
// this is the decode lane, framing/crypto aside), so the one payload field
// the session store needs is read here — defensively, because inform
// payloads are DEVICE-supplied bytes and a decode must never fail an
// inform over odd rows.
//
// Wire shape, LIVE-PINNED (2026-09-20 bench capture, UAP-AC-Pro-Gen2
// U7PG2, fw 6.8.2.15592, phone associated): the station table is nested
// inside the vap rows — body["vap_table"][]["sta_table"][] — with each
// station row identified by its "mac" field (colon-hex spelling, e.g.
// "aa:bb:cc:dd:ee:01"). Every observed vap row carries a sta_table array,
// empty when that vap has no associated clients. The earlier BLOCKED
// verdict's top-level "sta_table" key was never observed on the wire; it
// stays readable as a fallback union for firmware variants this worktree
// has not captured.
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
	seen := map[string]bool{}
	add := func(rows []any) {
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
			macs = append(macs, mac)
		}
	}
	// Fallback shape: a top-level sta_table array (never observed on the
	// wire; kept from the pre-pin reader for uncaptured firmware variants).
	if raw, ok := body["sta_table"].([]any); ok {
		add(raw)
		present = true
	}
	// Live-pinned shape: stations nested in the vap rows.
	if vaps, ok := body["vap_table"].([]any); ok {
		for _, v := range vaps {
			vm, ok := v.(map[string]any)
			if !ok {
				continue // tolerate odd rows; never fail an inform over noise
			}
			if rows, ok := vm["sta_table"].([]any); ok {
				add(rows)
				present = true
			}
		}
	}
	return macs, present
}

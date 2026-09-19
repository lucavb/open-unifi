// Station-table decode: the per-client rows a full inform carries. The
// inform codec owns body shape knowledge (CONTEXT.md: decision modules —
// this is the decode lane, framing/crypto aside), so the one payload field
// the session store needs is read here — defensively, because inform
// payloads are DEVICE-supplied bytes and a decode must never fail an
// inform over odd rows.
//
// Field naming (live-proof obligation, docs/PROTOCOL-mgmt.md §6.2): no
// capture in this worktree pins the per-client table's exact wire key or
// row shape — the BLOCKED verdict is recorded in the lane report. The
// reader keys on "sta_table", following the two naming rules this
// worktree's docs already establish for device-sent payload fields:
//
//   - the *_table family for device-sent tables: radio_table, vap_table,
//     vwire_table, if_table, ethernet_table (docs/PROTOCOL.md §100-131);
//   - "sta" as the controller's abbreviation for stations/clients:
//     stat.user-num_sta (docs/PROTOCOL.md §129), blocked_sta
//     (docs/PROTOCOL-mgmt.md §4).
//
// Row identity is the "mac" field, the same identity spelling the §103
// top-level body uses. Odd values are skipped, never fatal; an ABSENT
// table is reported as absent (present=false) so the caller can tell a
// sparse heartbeat (no table — session rows must survive) from a genuine
// empty table (zero clients — every previously-connected client
// disconnected). That distinction is the device-refreshable caps
// semantics applied to session data (CONTEXT.md: a sparse heartbeat must
// not wipe controller-side rows).
package inform

// StationMACs reads the per-client station table out of a decoded inform
// body. It returns the row MAC strings verbatim (any spelling — the store
// lane canonicalizes via store.CanonicalMAC; this package is a leaf and
// must not import it) and a present flag:
//
//   - present=false: the body carries no station table (a sparse
//     heartbeat or an odd-shaped value). Callers must NOT touch session
//     state on such informs.
//   - present=true: the table was a JSON array (possibly empty — the
//     device reports zero associated clients). macs carries the rows whose
//     "mac" field was a string; odd rows are skipped, never fatal.
func StationMACs(body map[string]any) (macs []string, present bool) {
	raw, ok := body["sta_table"].([]any)
	if !ok {
		return nil, false
	}
	for _, row := range raw {
		m, ok := row.(map[string]any)
		if !ok {
			continue // tolerate odd rows; never fail an inform over noise
		}
		mac, ok := m["mac"].(string)
		if !ok || mac == "" {
			continue
		}
		macs = append(macs, mac)
	}
	return macs, true
}

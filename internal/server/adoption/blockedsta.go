// blocked_sta: the per-device blocked-client list delivered inside full
// provisioning. Wire shape is normative from docs/PROTOCOL-mgmt.md §4: the
// real controller's O00O writer emits users.map(mac).collect(joining("\n"))
// over blocked clients — newline-joined colon-hex MACs, the EMPTY STRING when
// none are blocked — and the §6.2(d) catalog example shows the spelling
// ("aa:bb:cc:dd:ee:ff\n11:22:33:44:55:66"). The content lives in the
// admin-owned Extra row (internal/store.BlockedClients), so this file is a
// pure projection: render, hash, and a drift decision against the
// delivery baseline. No bookkeeping, no mutation of the WLAN delivery state.
package adoption

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/lucavb/open-unifi/internal/store"
)

// Extra keys for the blocked_sta projection. The set itself is stored by
// internal/store under the wire-named key; only the delivery baseline lives
// here. extraBlockedStaSha holds sha256(blockedStaWire) of the wire string
// last EMITTED by assignedKeyFlow — the same offer-then-confirm shape as
// the wlan_cfg_sha baseline, except capture happens at emission (blocked
// content has no observable on-device confirmation beyond the cfgversion
// echo the equality path already tracks).
const (
	extraBlockedSta    = "blocked_sta"
	extraBlockedStaSha = "blocked_sta_sha"
)

// blockedStaWire renders the §4 wire string for the device's blocked-client
// set: newline-joined colon-hex MACs in the set's canonical (sorted) order,
// "" when the set is empty. Deterministic by construction — the stored set
// is sorted and deduplicated — so identical sets always render identical
// bytes.
func blockedStaWire(d store.Device) string {
	clients := store.BlockedClients(d)
	if len(clients) == 0 {
		return ""
	}
	parts := make([]string, len(clients))
	for i, c := range clients {
		parts[i] = store.ColonMAC(c)
	}
	return strings.Join(parts, "\n")
}

// blockedStaHash is the delivery-baseline hash of a rendered wire string.
func blockedStaHash(wire string) string {
	sum := sha256.Sum256([]byte(wire))
	return hex.EncodeToString(sum[:])
}

// blockedStaDrift decides whether the blocked-client set differs from the
// last delivered content. A KNOWN baseline drifts when the current wire no
// longer hashes to it; an ABSENT baseline drifts only when there is
// content to deliver — absent + empty must NOT drift, or every
// never-touched device would re-enter provisioning after its baseline is
// (re)introduced, breaking the post-adoption connected noop the
// 2026-09-16 live round captured (docs/PROTOCOL-mgmt.md §6.2 equal path).
func blockedStaDrift(d store.Device) (wire string, drift bool) {
	wire = blockedStaWire(d)
	baseline, known := d.Extra[extraBlockedStaSha].(string)
	if !known {
		return wire, wire != ""
	}
	return wire, blockedStaHash(wire) != baseline
}

// stampBlockedSta records the delivery baseline: assignedKeyFlow calls this
// with the wire string it just emitted, so the next inform whose set hashes
// equal is confirmed content, not drift. Like every full-provisioning
// write, it lands in the record Extra the adapter persists atomically with
// the outcome.
func stampBlockedSta(d *store.Device, wire string) {
	if d.Extra == nil {
		d.Extra = store.JSONMap{}
	}
	d.Extra[extraBlockedStaSha] = blockedStaHash(wire)
}

// Per-device blocked-client set: the ADMIN-OWNED record row behind the
// blocked_sta wire field (docs/PROTOCOL-mgmt.md §4 + §6.2(d)). Storage is
// Extra[blockedStaKey] — a sorted, deduplicated []any of canonical lowercase
// 12-hex client MACs (the same canonical form every other MAC in a record
// uses; store.CanonicalMAC is the single normalizer). Only the admin API
// writes it (internal/app block/unblock); the inform path preserves it
// verbatim against device-supplied bodies (internal/server extraAdminOwned —
// a device can neither write nor introduce the key, CONTEXT.md trust
// policy), and the adoption engine renders the §4 wire string from it.
package store

import (
	"fmt"
	"sort"
)

// blockedStaKey is the Extra key of the admin-owned blocked-client set. The
// name matches the wire field the real controller's O00O writer produces
// (docs/PROTOCOL-mgmt.md §4).
const blockedStaKey = "blocked_sta"

// BlockedClients returns the device's blocked-client set from the record
// Extra: canonical lowercase 12-hex MACs, sorted, deduplicated. An absent,
// empty, or odd-shaped value reads as the empty set. The returned slice is
// freshly allocated; callers may keep or mutate it.
func BlockedClients(d Device) []string {
	raw, _ := d.Extra[blockedStaKey].([]any)
	seen := map[string]bool{}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue // tolerate odd entries; never fail a read over stored noise
		}
		c, err := CanonicalMAC(s)
		if err != nil || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// AddBlockedClient adds one client MAC to the device's blocked-client set.
// client may carry any common MAC spelling (the record's single normalizer
// applies); unparseable input is an error and aborts the caller's store
// cycle. added reports whether the set changed. The stored form is always
// sorted and deduplicated, so identical sets render identical wire bytes.
func AddBlockedClient(d *Device, client string) (bool, error) {
	c, err := CanonicalMAC(client)
	if err != nil {
		return false, fmt.Errorf("blocked client mac: %w", err)
	}
	set := BlockedClients(*d)
	for _, existing := range set {
		if existing == c {
			return false, nil // idempotent: already blocked
		}
	}
	set = append(set, c)
	sort.Strings(set)
	writeBlockedClients(d, set)
	return true, nil
}

// RemoveBlockedClient removes one client MAC from the device's blocked-client
// set. removed reports whether the MAC was actually blocked. Unparseable
// input is an error (the admin API already 400'd it at its boundary; this is
// the adapter-side backstop).
func RemoveBlockedClient(d *Device, client string) (bool, error) {
	c, err := CanonicalMAC(client)
	if err != nil {
		return false, fmt.Errorf("blocked client mac: %w", err)
	}
	set := BlockedClients(*d)
	out := make([]string, 0, len(set))
	found := false
	for _, existing := range set {
		if existing == c {
			found = true
			continue
		}
		out = append(out, existing)
	}
	if !found {
		return false, nil
	}
	writeBlockedClients(d, out)
	return true, nil
}

// writeBlockedClients stores the canonical set back into Extra,
// materializing the map when the record predates the inform channel
// (UpdateExisting seeds Device{MAC: …} with a nil Extra).
func writeBlockedClients(d *Device, set []string) {
	if d.Extra == nil {
		d.Extra = JSONMap{}
	}
	if len(set) == 0 {
		delete(d.Extra, blockedStaKey)
		return
	}
	raw := make([]any, len(set))
	for i, c := range set {
		raw[i] = c
	}
	d.Extra[blockedStaKey] = raw
}

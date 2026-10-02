// Package wireless owns the WLAN type shared by the admin API (its JSON
// tags are the admin wire), the stored device record (device_wlans and the
// wlan_cfg_*_wlans snapshots, in their own untagged format: see
// EncodeStoredWlans), the Provisioning plan and the system_cfg renderer.
// adminapi.Wlan is an alias of it: one type, no cross-package converters.
//
// The system_cfg emission contract is docs/PROTOCOL-systemcfg-wireless.md
// (§1 header block, §2 indexing, §3 radio rows, §4 aaa rows, §5 wireless
// rows, §6 VLAN wiring, §7 worked example, §8 admin-API mapping).
package wireless

// Wlan is one WLAN of a device's wireless envelope. The JSON tags are the
// admin API wire only (strict decoding there rejects unknown keys). Stored
// blobs never go through these tags: EncodeStoredWlans writes the untagged
// Go-field-name format and DecodeStoredWlans reads it.
type Wlan struct {
	Name       string `json:"name,omitempty"`       // human label; also the on-wire ssid source (see SSIDOf)
	SSID       string `json:"ssid"`                 // broadcast SSID (preferred over Name when set)
	Security   string `json:"security"`             // "open" | "wpa-p" | "wpa-eap" (the admin API also accepts wpa3-p, wpa2-wpa3)
	Passphrase string `json:"passphrase,omitempty"` // plaintext (psk writer never hashes)
	VLAN       int    `json:"vlan"`                 // 0 = untagged (mgmt br0); 2..4094 tagged br0.<vid>
	Enabled    bool   `json:"enabled"`              // false ⇒ ENTIRE WLAN omitted (doc §2)
	ID         string `json:"id,omitempty"`         // stable WlanConf._id; see WlanID for the empty-ID fallback
	Band       string `json:"band,omitempty"`       // 2g, 5g, both; empty is legacy both

	// Inline RADIUS profile (wpa-eap only; the classic controller's
	// radiusprofile auth_servers/x_secret copied onto the wlanConf via
	// copyAttrsIfPresent, int §1401-1405). Zero on non-EAP WLANs; the
	// admin API enforces that invariant.
	RadiusServers  []RadiusServer `json:"radius_servers,omitempty"`   // auth rows, 1..4 usable entries
	RadiusSecret   string         `json:"radius_secret,omitempty"`    // profile-level x_secret, one value for every auth row
	RadiusVLANMode string         `json:"radius_vlan_mode,omitempty"` // vlan_wlan_mode: ""/"disabled"→dynamic_vlan=0, "optional"→1, "required"→2

	// Inline RADIUS profile accounting fields (wpa-eap only; §12 rows
	// 1013-1014, docs/PROTOCOL-systemcfg-wireless.md §4.3). Zero on
	// non-EAP WLANs and on EAP WLANs that do no accounting — with
	// AccountingEnabled false the render is byte-identical to a WLAN
	// with no accounting fields at all (pinned by the renderer goldens).
	AccountingEnabled    bool               `json:"accounting_enabled,omitempty"`     // radiusprofile accounting_enabled: gates the acct rows AND the interim_update rows
	AcctServers          []RadiusAcctServer `json:"acct_servers,omitempty"`           // acct rows, 0..4 entries; inert while AccountingEnabled is false (profile-shaped: the radiusprofile stores servers independent of the toggle)
	InterimUpdateEnabled bool               `json:"interim_update_enabled,omitempty"` // radiusprofile interim_update_enabled: needs AccountingEnabled (the jar's own gate, §12 row 1014 rationale)
	RadiusDASEnabled     bool               `json:"radius_das_enabled,omitempty"`     // radiusprofile radius_das_enabled: the das/dad rows under accounting_enabled && hasCapability(0x100000) (§12 row 1014 implemented; the admin API requires accounting_enabled for it)
}

// RadiusAcctServer is one accounting server of a WLAN's inline RADIUS
// profile (§12 row 1013: "emitted per radiusprofile accounting server
// (port 1813) when accounting_enabled"). Row shape and slot semantics
// mirror the auth server family: row index = ARRAY POSITION (slots
// 1..4, empty-ip slot skipped with no backfill, a 5th server has no
// slot), port 0 means "unset" and renders as the jar's 1813 default,
// and the secret is the PROFILE-LEVEL RadiusSecret on every row — the
// doc's `<x_secret>` symbol is the same profile-level secret the auth
// rows use (docs/PROTOCOL-systemcfg-wireless.md §4.3, line 416), so the
// accounting server carries no secret of its own.
type RadiusAcctServer struct {
	IP   string `json:"ip"`             // emitted verbatim into aaa.<n>.radius.acct.<i>.ip
	Port int    `json:"port,omitempty"` // 0 ⇒ 1813 at emission
}

// RadiusServer is one auth server of a WLAN's inline RADIUS profile. Port 0
// means "unset" and renders as the jar's 1812 default (radius profile int
// §791-840); an empty IP renders no rows (the jar skips empty ip entries —
// the admin API rejects them, so that skip is renderer defense only).
type RadiusServer struct {
	IP   string `json:"ip"`             // emitted verbatim into aaa.<n>.radius.auth.<i>.ip
	Port int    `json:"port,omitempty"` // 0 ⇒ 1812 at emission
}

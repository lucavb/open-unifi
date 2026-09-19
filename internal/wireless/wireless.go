// Package wireless owns the shared WLAN type: the server-local WLAN
// envelope item fed by Config.WirelessSource (mirrors adminapi.Wlan —
// deliberately re-declared so the inform lane stays decoupled from the
// admin API lane).
//
// The system_cfg emission contract is docs/PROTOCOL-systemcfg-wireless.md
// (§1 header block, §2 indexing, §3 radio rows, §4 aaa rows, §5 wireless
// rows, §6 VLAN wiring, §7 worked example, §8 admin-API mapping).
package wireless

// Wlan is the server-local WLAN envelope item fed by Config.WirelessSource
// (mirrors adminapi.Wlan — deliberately re-declared here so the inform lane
// stays decoupled from the admin API lane).
type Wlan struct {
	Name       string // human label; also the on-wire ssid source (see SSIDOf)
	SSID       string // broadcast SSID (preferred over Name when set)
	Security   string // "open" | "wpa-p" | "wpa-eap"
	Passphrase string // plaintext (psk writer never hashes)
	VLAN       int    // 0 = untagged (mgmt br0); 2..4094 tagged br0.<vid>
	Enabled    bool   // false ⇒ ENTIRE WLAN omitted (doc §2)
	ID         string // stable WlanConf._id; empty ⇒ sha256(nameSSID)[:24]
	Band       string // 2g, 5g, both; empty is legacy both

	// Inline RADIUS profile (wpa-eap only; the classic controller's
	// radiusprofile auth_servers/x_secret copied onto the wlanConf via
	// copyAttrsIfPresent, int §1401-1405). Zero on non-EAP WLANs; the
	// admin API enforces that invariant.
	RadiusServers  []RadiusServer // auth rows, 1..4 usable entries
	RadiusSecret   string         // profile-level x_secret, one value for every auth row
	RadiusVLANMode string         // vlan_wlan_mode: ""/"disabled"→dynamic_vlan=0, "optional"→1, "required"→2
}

// RadiusServer is one auth server of a WLAN's inline RADIUS profile. Port 0
// means "unset" and renders as the jar's 1812 default (radius profile int
// §791-840); an empty IP renders no rows (the jar skips empty ip entries —
// the admin API rejects them, so that skip is renderer defense only).
type RadiusServer struct {
	IP   string // emitted verbatim into aaa.<n>.radius.auth.<i>.ip
	Port int    // 0 ⇒ 1812 at emission
}

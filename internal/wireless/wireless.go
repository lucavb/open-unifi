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
}

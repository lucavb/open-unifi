package server

// Wireless system_cfg emission — byte-verified schema, THE contract is
// docs/PROTOCOL-systemcfg-wireless.md (§1 header block, §2 indexing,
// §3 radio rows, §4 aaa rows, §5 wireless rows, §6 VLAN wiring, §7 worked
// example, §8 admin-API mapping).
//
// Structural facts baked in here:
//   - disabled WLANs are dropped with no trace (F.super line 44) — absence
//     is the disabled signal, no `status=disabled` row ever exists;
//   - `radio.<n4>` is 1-based per radio sorted by `name`;
//   - `aaa.<n>`/`wireless.<n>` share one 1-based counter across all vaps in
//     radio-sorted order; the madwifi devname is `ath<N>` with a GLOBAL
//     0-based counter that keeps counting across radios/wlans;
//   - `wireless.<n>.security` is LITERAL "none" even for WPA — the actual
//     security lives in `aaa.<n>.wpa.*` rows only;
//   - the `# vlan`/`# bridge`/`# netconf`/`# dhcpc` blocks have their own
//     counters, independent of the vap counters.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lucabecker/open-unifi/internal/store"
)

// Wlan is the server-local WLAN envelope item fed by Config.WirelessSource
// (mirrors adminapi.Wlan — deliberately re-declared here so the inform lane
// stays decoupled from the admin API lane).
type Wlan struct {
	Name       string // human label; also the on-wire ssid source (see ssidOf)
	SSID       string // broadcast SSID (preferred over Name when set)
	Security   string // "open" | "wpa-p" | "wpa-eap"
	Passphrase string // plaintext (psk writer never hashes)
	VLAN       int    // 0 = untagged (mgmt br0); 2..4094 tagged br0.<vid>
	Enabled    bool   // false ⇒ ENTIRE WLAN omitted (doc §2)
	ID         string // stable WlanConf._id; empty ⇒ sha256(nameSSID)[:24]
}

// wlanEnvelopeShape is a work-in-progress marker for the band model.
const (
	// wlanBandDefault is the band value our admin API cannot express today.
	// It maps to WlanConf "both": ONE vap per device radio (doc §8).
	wlanBandDefault = "both"

	// wepFallbackPsk is the classic getWpaPreSharedKey() fallback
	// (WlanConf.java §308-311), mirrored "in shape" per the contract; it is
	// unreachable for wpa-p because the admin API enforces >= 8 chars.
	fallbackPsk = "letmeinnow"

	// defaultEthIface is the one uplink iface in `# vlan` rows. The device's
	// eth inventory lives in informs we do not persist separately yet.
	defaultEthIface = "eth0"
)

func ssidOf(w Wlan) string {
	if w.SSID != "" {
		return w.SSID
	}
	return w.Name
}

func wlanId(d store.Device, w Wlan) string {
	if w.ID != "" {
		return w.ID
	}
	src := w.Name
	if src == "" {
		src = w.SSID
	}
	if src == "" {
		src = "vlan" + strconv.Itoa(w.VLAN)
	}
	sum := sha256.Sum256([]byte(src))
	return hex.EncodeToString(sum[:])[:24]
}

// ---- stored radio data ----------------------------------------------------

// radioRow is one device radio from the stored inform passthrough
// (the per-radio map under rec.Extra["radio_table"]).
type radioRow struct {
	name string // radio_table "name" → phyname + parent + sort key
	band string // "radio" field: "ng" | "na" (default ng)
	raw  map[string]any
}

// storedRadios extracts and sorts radios by name (sort key = `name`,
// config_int §141) from the device record's stored inform data. No radios →
// empty slice → the "no radio found" variant of the block (doc §1).
func storedRadios(d store.Device) []radioRow {
	rawList, ok := d.Extra["radio_table"].([]any)
	if !ok {
		return nil
	}
	var out []radioRow
	for _, item := range rawList {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := jsonStr(m, "name", "")
		if name == "" {
			continue
		}
		band := jsonStr(m, "radio", "ng")
		if band == "" || band != "na" && band != "ng" {
			band = "ng"
		}
		out = append(out, radioRow{name: name, band: band, raw: m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// jsonStr fetches a string field, formatting JSON scalars (float64 from
// decode) as their number form — "0", "42", "auto", …
func jsonStr(m map[string]any, key, def string) string {
	v, ok := m[key]
	if !ok {
		return def
	}
	switch t := v.(type) {
	case string:
		if t != "" {
			return t
		}
		return def
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return def
	}
}

// jsonBool fetches a boolean field (defaults false when absent).
func jsonBool(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

// ---- vap plan -------------------------------------------------------------

// vapPlan is one provisioned vap: an (enabled) WLAN instantiated on
// radio i, holding its bridge binding and devname.
type vapPlan struct {
	wlan    Wlan
	id      string
	radioN  int // 1-based index into the sorted radio list
	phyname string
	athN    int // global 0-based counter → devname "ath<N>"
	vid     int // 0 = untagged mgmt br0; 2..4094 tagged br0.<vid>
}

// planVaps builds the vap list in radio-sorted order (global wireless/aaa
// counter = list order; doc §2). Band default "both": one vap per radio.
func planVaps(d store.Device, wls []Wlan) ([]vapPlan, []radioRow) {
	radios := storedRadios(d)
	var vaps []vapPlan
	ath := 0
	for i, r := range radios {
		for _, w := range wls {
			if !w.Enabled {
				continue // dropped with no trace (F.super line 44)
			}
			_ = wlanBandDefault // one vap per radio: band fixed at "both"
			vaps = append(vaps, vapPlan{
				wlan:    w,
				id:      wlanId(d, w),
				radioN:  i + 1,
				phyname: r.name,
				athN:    ath,
				vid:     wrapVID(w.VLAN),
			})
			ath++
		}
	}
	return vaps, radios
}

// wrapVID applies the doc §6 VLAN guard: vids ≤ 1 (0/absent, or the classic
// 1) join the mgmt bridge untagged, never br-trunk (documented deviation).
func wrapVID(vid int) int {
	if vid < 2 || vid > 4094 {
		return 0
	}
	return vid
}

// ---- emission -------------------------------------------------------------

// emitWirelessCfg appends the whole wireless/VLAN compound to b: the
// `# wlans (radio)` block (header + radio.<n4> rows + virtual rows), all
// per-vap `aaa.<n>`/`wireless.<n>` rows, then `# vlan`, `# bridge`,
// `# netconf` (br0.<vid> rows only) and `# dhcpc`.
func (s *Server) emitWirelessCfg(b *strings.Builder, d store.Device, wls []Wlan) {
	vaps, radios := planVaps(d, wls)
	if len(radios) == 0 {
		// doc §1 int §489-493 variant.
		b.WriteString("# no wlan provisioned as no radio found\n")
		b.WriteString("radio.status=disabled\n")
		return
	}

	line := func(k, v string) { b.WriteString(k); b.WriteString("="); b.WriteString(v); b.WriteString("\n") }

	// Header block (int §488-497 / doc §1) — country default 840, outdoor
	// override from site settings we do not carry yet → "disabled".
	b.WriteString("# wlans (radio)\n")
	line("radio.status", "enabled")
	line("radio.countrycode", "840")
	line("aaa.status", "enabled")
	line("wireless.status", "enabled")
	line("radio.outdoor", "disabled")

	// radio.<n4> rows (doc §3, worked-example row order), then the per-vap
	// virtual companion rows for vapIdxOnRadio > 0 (doc §536-542).
	perRadioCount := map[int]int{}
	for _, v := range vaps {
		perRadioCount[v.radioN]++
	}
	for i, r := range radios {
		n := i + 1
		prefix := fmt.Sprintf("radio.%d.", n)
		line(prefix+"phyname", r.name)
		line(prefix+"ack.auto", "disabled")
		line(prefix+"acktimeout", "64")
		line(prefix+"ampdu.status", "enabled")
		line(prefix+"clksel", "1")
		line(prefix+"countrycode", "840")
		line(prefix+"cwm.enable", "0")
		line(prefix+"cwm.mode", "0")
		line(prefix+"forbiasauto", "0")
		line(prefix+"channel", jsonStr(r.raw, "channel", "0"))
		line(prefix+"backup_channel", jsonStr(r.raw, "backup_channel", "0"))
		// TODO(wireless): ht-width for ieee_mode is UNRESOLVED (doc §9,
		// devmgr chanWidth resolver class never decompiled) — emitting the
		// commonly-seen "20" default pending a live cfg dump.
		if r.band == "na" {
			line(prefix+"ieee_mode", "11naht20")
		} else {
			line(prefix+"ieee_mode", "11nght20")
		}
		line(prefix+"mode", "master")
		line(prefix+"rate.auto", "enabled")
		line(prefix+"rate.mcs", "auto")
		line(prefix+"rfscan", boolStr(jsonBool(r.raw, "spectrum_enabled")))
		line(prefix+"bcmc_l2_filter.status", "enabled")
		line(prefix+"bgscan.status", "disabled")
		line(prefix+"antenna.gain", antennaGain(r.raw))
		line(prefix+"antenna", jsonStr(r.raw, "antenna_id", "-1"))
		line(prefix+"txpower_mode", jsonStr(r.raw, "tx_power_mode", "auto"))
		line(prefix+"txpower", jsonStr(r.raw, "tx_power", "auto"))
		line(prefix+"hard_noisefloor.status", "disabled")
		// virtual companion rows: vap index on this radio (>0 only when the
		// radio hosts a second+ vap).
		vIdx := 0
		for _, v := range vaps {
			if v.radioN != n {
				continue
			}
			if vIdx > 0 { // vapIdxOnRadio > 0 → companion row pair
				line(fmt.Sprintf("%svirtual.%d.devname", prefix, vIdx), "ath"+strconv.Itoa(v.athN))
				line(fmt.Sprintf("%svirtual.%d.status", prefix, vIdx), "enabled")
			}
			vIdx++
		}
	}

	// Per-vap aaa.<n> + wireless.<n> rows, radio-sorted order (doc §4/§5).
	// open-hostapd capability (wifi_caps bit 0x2000) gates
	// aaa.<n>.status for open WLANs; records without fw_caps default to
	// supported (modern U7PG2 firmware).
	fwCapsKnown, fwCaps := numFromExtra(d.Extra, "fw_caps")
	openHostapd := !fwCapsKnown || fwCaps&0x2000 != 0
	for n, v := range vaps { // 0-based over emissions → row index n+1
		s.emitAaaRows(b, n+1, v, openHostapd)
		s.emitWirelessRows(b, n+1, v)
	}

	// VLAN wiring (doc §6): tag table, bridges, netconf, dhcpc — each with
	// its own counter.
	s.emitVlanBlocks(b, vaps)
}

func boolStr(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

// antennaGain: builtin_antenna → builtin_ant_gain (default 0), else
// antenna_gain (default 6 when absent, doc §3).
func antennaGain(raw map[string]any) string {
	if jsonBool(raw, "builtin_antenna") {
		return jsonStr(raw, "builtin_ant_gain", "0")
	}
	return jsonStr(raw, "antenna_gain", "6")
}

func numFromExtra(extra store.JSONMap, key string) (bool, int64) {
	v, ok := extra[key].(float64)
	if !ok {
		return false, 0
	}
	return true, int64(v)
}

// emitAaaRows writes the aaa.<n> block for one vap per doc §4:
// always-first block, then the security branch (§4.2 open, §4.3 WPA),
// then the common tail.
func (s *Server) emitAaaRows(b *strings.Builder, n int, v vapPlan, openHostapd bool) {
	p := fmt.Sprintf("aaa.%d.", n)
	line := func(k, vv string) {
		b.WriteString(p)
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(vv)
		b.WriteString("\n")
	}
	name := ssidOf(v.wlan)

	// §4.1 always-first block (int §566-578; no log_level row: record field
	// absent ⇒ default never >= 0).
	line("pmf.status", "disabled")
	line("pmf.mode", "0")
	line("ft.status", "disabled")
	line("country_beacon", "disabled")
	line("11k.status", "disabled")

	br := aaaBridge(v)
	line("br.devname", br)
	line("devname", "ath"+strconv.Itoa(v.athN))
	line("driver", "madwifi") // atheros bean naming branch (doc §0)
	line("ssid", name)

	switch v.wlan.Security {
	case "open":
		// §4.2: status = enabled iff supportOpenHostapd (wifi_caps 0x2000).
		if openHostapd {
			line("status", "enabled")
		} else {
			line("status", "disabled")
		}
		line("id", v.id)
		// no wpa.* rows in the open branch (§4.2).
	default:
		if v.wlan.Security == "wpa-eap" {
			// Our admin API carries no RADIUS servers/profile yet; the real
			// controller would append radius.auth.<i>.* rows from the
			// RADIUS profile (int §791-840) after the psk writer.
			// TODO(wireless): radius rows once the API has RADIUS fields.
			s.lg.Warn("provisioning WPA-EAP wlan without RADIUS servers; " +
				"emitting mgmt=WPA-EAP with auth_cache enabled, no radius.* rows")
		}
		line("status", "enabled") // only is_wds_uplink → disabled; we have none

		// NOTE for wpa-eap: still the fixed §4.3 block; psk uses the same
		// getWpaPreSharedKey() fallback shape.
		line("verbose", "2")
		line("wpa", "2") // wpa_mode auto → WPA2 (WpaMode.getMode javap)
		line("eapol_version", "2")
		line("wpa.group_rekey", "3600")
		line("p2p", "disabled")
		line("p2p_cross_connect", "disabled")
		line("proxy_arp", "disabled")
		line("is_guest", "false")
		line("tdls_prohibit", "disabled")
		line("bss_transition", "enabled")
		line("id", v.id)

		psk := v.wlan.Passphrase
		if psk == "" {
			psk = fallbackPsk // getWpaPreSharedKey() fallback shape (§8)
		}
		mgmt := "WPA-PSK"
		if v.wlan.Security == "wpa-eap" {
			mgmt = "WPA-EAP"
			line("auth_cache", "enabled") // default per WlanConf (§8)
		}
		line("wpa.key.1.mgmt", mgmt)
		line("wpa.psk", psk)           // psk writer: NEVER hashed/obfuscated (§8)
		line("wpa.1.pairwise", "CCMP") // wpa_enc auto → CCMP (§8)
		line("pmf.cipher", "AES-128-CMAC")
		if v.wlan.Security == "wpa-eap" {
			// vlan_wlan_mode disabled → dynamic_vlan=0 (default §8); the
			// RADIUS-driven 1|2 variants need the missing RADIUS fields.
			line("dynamic_vlan", "0")
		}
	}

	// §4.3/§613-624 common tail (macacl off, not hidden).
	line("radius.macacl.status", "disabled")
	line("hide_ssid", "false")
}

// aaaBridge resolves the bridge hosting this vap's athdev (doc §6/§555-561).
func aaaBridge(v vapPlan) string {
	if v.vid == 0 {
		return "br0"
	}
	return "br0." + strconv.Itoa(v.vid)
}

// emitWirelessRows writes the wireless.<n> block per doc §5 (worked-example
// key order; security is LITERAL none, authmode 0 only for open).
func (s *Server) emitWirelessRows(b *strings.Builder, n int, v vapPlan) {
	p := fmt.Sprintf("wireless.%d.", n)
	line := func(k, vv string) {
		b.WriteString(p)
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(vv)
		b.WriteString("\n")
	}

	line("mode", "master")
	line("devname", "ath"+strconv.Itoa(v.athN))
	line("id", v.id)
	line("status", "enabled") // literal — disabled wlans never reach here
	if v.wlan.Security == "open" {
		line("authmode", "0")
	} else {
		line("authmode", "1")
	}
	line("l2_isolation", "disabled")
	line("is_guest", "false")
	line("security", "none") // ⚠ literal, even for WPA (doc §5 line 250)
	line("addmtikie", "disabled")
	line("ssid", ssidOf(v.wlan))
	line("hide_ssid", "false")
	line("mac_acl.status", "enabled") // literal
	line("mac_acl.policy", "deny")    // literal
	line("wmm", "enabled")
	line("uapsd", "disabled")
	line("parent", v.phyname) // radio TABLE device name (§1399)
	line("puren", "0")
	line("pureg", "1") // b_supported default false ⇒ jour pure-g (§8)
	line("usage", "user")
	line("wds", "disabled")
	line("mcast.enhance", "0")
	line("autowds", "disabled")
	line("vport", "disabled")
	line("vwire", "disabled")
	line("schedule_enabled", "disabled")
	line("no2ghz_oui", "disabled")
	// condition-gated follow-ups that always fire at defaults (§7 example):
	line("element_adopt", "disabled")
	line("mcastrate", "auto")
	line("dtim_period", "3")
}

// emitVlanBlocks writes `# vlan`, `# bridge`, `# netconf` and `# dhcpc`
// from the vap wiring (doc §6 + §7 excerpt).
func (s *Server) emitVlanBlocks(b *strings.Builder, vaps []vapPlan) {
	line := func(k, v string) { b.WriteString(k); b.WriteString("="); b.WriteString(v); b.WriteString("\n") }

	// collect tagged vids (sorted) and bridge memberships
	vidAths := map[int][]string{}
	var vids []int
	for _, v := range vaps {
		if v.vid != 0 {
			if _, seen := vidAths[v.vid]; !seen {
				vids = append(vids, v.vid)
			}
			vidAths[v.vid] = append(vidAths[v.vid], "ath"+strconv.Itoa(v.athN))
		}
	}
	sort.Ints(vids)

	if len(vids) > 0 {
		b.WriteString("# vlan\n")
		for i, vid := range vids {
			// TODO(wireless): eth0 is the literal uplink; read the device's
			// actual eth port inventory from persistd inform data instead.
			line(fmt.Sprintf("vlan.%d.devname", i+1), defaultEthIface)
			line(fmt.Sprintf("vlan.%d.id", i+1), strconv.Itoa(vid))
		}
	}

	// bridge section: mgmt br0 (untagged ports: eth0 + untagged aths), then
	// one br0.<vid> per sorted vid with its ath ports.
	b.WriteString("# bridge\n")
	j := 0
	writeBridge := func(name string, ports ...string) {
		j++
		line(fmt.Sprintf("bridge.%d.devname", j), name)
		line(fmt.Sprintf("bridge.%d.fd", j), "1")
		line(fmt.Sprintf("bridge.%d.stp.status", j), "disabled")
		for k, port := range ports {
			line(fmt.Sprintf("bridge.%d.port.%d.devname", j, k+1), port)
		}
	}
	untagged := []string{defaultEthIface}
	for _, v := range vaps {
		if v.vid == 0 {
			untagged = append(untagged, "ath"+strconv.Itoa(v.athN))
		}
	}
	writeBridge("br0", untagged...)
	for _, vid := range vids {
		writeBridge("br0."+strconv.Itoa(vid), vidAths[vid]...)
	}

	// netconf: ONLY for the tagged bridges. No rows for br0/eth0: emitting
	// them would re-assert the device's mgmt interface addressing we must
	// not override during provisioning (doc §6 table; deliberate omission).
	if len(vids) > 0 {
		b.WriteString("# netconf\n")
		for k, vid := range vids {
			m := fmt.Sprintf("netconf.%d.", k+1)
			line(m+"devname", "br0."+strconv.Itoa(vid))
			line(m+"ip", "0.0.0.0")
			line(m+"autoip.status", "disabled")
			line(m+"promisc", "enabled")
			line(m+"up", "enabled")
		}
	}

	// dhcpc: status row only in our build — guest-WLAN tagged-bridge rows
	// need an is_guest flag the admin API does not have yet.
	b.WriteString("# dhcpc\n")
	line("dhcpc.status", "enabled")
}

// ---- envelope hash (FSM drift input) ---------------------------------------

// wlanListHash serializes the wireless envelope stably (sorted-key JSON per
// item) and hashes it with sha256; the value is only compared against
// itself, so any stable canonicalization works.
func wlanListHash(wls []Wlan) string {
	m := make([]map[string]any, 0, len(wls))
	for _, w := range wls {
		m = append(m, map[string]any{
			"name":       w.Name,
			"ssid":       w.SSID,
			"security":   w.Security,
			"passphrase": w.Passphrase,
			"vlan":       w.VLAN,
			"enabled":    w.Enabled,
			"id":         w.ID,
		})
	}
	blob, err := json.Marshal(m) // map keys marshal in sorted order
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(blob)
	return hex.EncodeToString(sum[:])
}

// currentWireless resolves the configured source; nil source ⇒ empty list.
func (s *Server) currentWireless() []Wlan {
	if s.cfg.WirelessSource == nil {
		return nil
	}
	return s.cfg.WirelessSource()
}

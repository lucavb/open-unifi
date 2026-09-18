package systemcfg

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
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

// wlanEnvelopeShape is a work-in-progress marker for the band model.
const (
	// fallbackPsk is the classic getWpaPreSharedKey() fallback
	// (WlanConf.java §308-311), mirrored "in shape" per the contract; it is
	// unreachable for wpa-p because the admin API enforces >= 8 chars.
	fallbackPsk = "letmeinnow"

	// defaultEthIface is the last-resort fallback uplink iface for `# vlan`
	// rows when the record carries NO eth inventory at all (ethPortNames);
	// with an inventory the emitted names come from ethernet_table, else from
	// the ethN names in if_table, else from the learned uplink (6.8.2 U7PG2
	// sends no ethernet_table — live acceptance 2026-09-16).
	defaultEthIface = "eth0"
)

// mgmtDevOf resolves the device's mgmt interface name for system_cfg rows
// (admin escape hatch Extra["mgmt_dev"], else the classic br0 — same shape
// as the sshd.1.ifname resolver in server.go).
func mgmtDevOf(d store.Device) string {
	if v, ok := d.Extra["mgmt_dev"].(string); ok && v != "" {
		return v
	}
	return "br0"
}

// ---- emission -------------------------------------------------------------

// emitWirelessCfg appends the whole wireless/VLAN compound to b: the
// `# wlans (radio)` block (header + radio.<n4> rows + virtual rows), all
// per-vap `aaa.<n>`/`wireless.<n>` rows, then `# vlan`, `# bridge`,
// `# netconf` (mgmt netconf.1 + br0.<vid> instances) and `# dhcpc`.
func (rd *render) emitWirelessCfg(b *strings.Builder, d store.Device, wls []wireless.Wlan) {
	if skipped := wireless.UnknownBandRadios(d); skipped > 0 {
		// Diagnosability (fix 4): skipping unknown band tokens (real token
		// set na/ng/6e/scan) is correct behavior, but a table of all-unknown
		// tokens silently drops every WLAN — say so once per planning pass.
		rd.warnings = append(rd.warnings, fmt.Sprintf("wireless provision: skipped %d radio(s) with unrecognized band token "+
			"(known provisioning bands: na, ng; real tokens also include 6e/scan)", skipped))
	}
	vaps, radios := wireless.PlanVaps(d, wls)
	if len(radios) == 0 {
		// doc §1 int §489-493 variant.
		b.WriteString("# no wlan provisioned as no radio found\n")
		b.WriteString("radio.status=disabled\n")
		// The mcad validator requires netconf.1.status unconditionally
		// (emitNetconfSection doc), even on the no-radio variant — the
		// vlan/bridge/dhcpc sections stay absent here by design.
		rd.emitNetconfSection(b, d, []int{})
		return
	}

	line := rd.lineWriter(b, "wireless-radio")

	// Header block (int §488-497 / doc §1) — country is explicitly configured,
	// with the compatibility default applied by ValidateConfig.
	// override from site settings we do not carry yet → "disabled".
	b.WriteString("# wlans (radio)\n")
	line("radio.status", "enabled")
	line("radio.countrycode", strconv.Itoa(rd.facts.CountryCode))
	line("aaa.status", "enabled")
	line("wireless.status", "enabled")
	line("radio.outdoor", "disabled")

	// radio.<n4> rows (doc §3, worked-example row order), then the per-vap
	// virtual companion rows for vapIdxOnRadio > 0 (doc §536-542).
	for i, r := range radios {
		n := i + 1
		prefix := fmt.Sprintf("radio.%d.", n)
		line(prefix+"phyname", r.Name)
		line(prefix+"ack.auto", "disabled")
		line(prefix+"acktimeout", "64")
		line(prefix+"ampdu.status", "enabled")
		line(prefix+"clksel", "1")
		line(prefix+"countrycode", strconv.Itoa(rd.facts.CountryCode))
		line(prefix+"cwm.enable", "0")
		line(prefix+"cwm.mode", "0")
		line(prefix+"forbiasauto", "0")
		line(prefix+"channel", wireless.JSONStr(r.Raw, "channel", "0"))
		line(prefix+"backup_channel", wireless.JSONStr(r.Raw, "backup_channel", "0"))
		// chanWidth resolver (devmgr c javap 1242-1298): width =
		// min(countryLimit, ht cap (ng→20 / na→40), device caps). All three
		// floors resolve to 20 on ng and 40 on na for U7PG2 defaults, so
		// the emitted ieee_mode is the static "11nght20"/"11naht40" pair
		// (FID-3; supersedes the doc §9 UNRESOLVED note).
		if r.Band == "na" {
			line(prefix+"ieee_mode", "11naht40")
		} else {
			line(prefix+"ieee_mode", "11nght20")
		}
		line(prefix+"mode", "master")
		line(prefix+"rate.auto", "enabled")
		line(prefix+"rate.mcs", "auto")
		line(prefix+"rfscan", boolStr(wireless.JSONBool(r.Raw, "spectrum_enabled")))
		line(prefix+"bcmc_l2_filter.status", "enabled")
		line(prefix+"bgscan.status", "disabled")
		line(prefix+"antenna.gain", antennaGain(r.Raw))
		line(prefix+"antenna", wireless.JSONStr(r.Raw, "antenna_id", "-1"))
		line(prefix+"txpower_mode", wireless.JSONStr(r.Raw, "tx_power_mode", "auto"))
		line(prefix+"txpower", wireless.JSONStr(r.Raw, "tx_power", "auto"))
		line(prefix+"hard_noisefloor.status", "disabled")
		// per-vap devname/status rows (int offsets 1141-1432): emitted for
		// EVERY vap walking this radio — plain `radio.<n>` prefix for
		// vapIdxOnRadio 0, `radio.<n>.virtual.<vapIdxOnRadio>` for the
		// radio's second+ member (FID-5).
		vIdx := 0
		for _, v := range vaps {
			if v.RadioN != n {
				continue
			}
			p := prefix
			if vIdx > 0 { // vapIdxOnRadio > 0 → virtual companion prefix
				p += "virtual." + strconv.Itoa(vIdx) + "."
			}
			line(p+"devname", "ath"+strconv.Itoa(v.AthN))
			line(p+"status", "enabled")
			vIdx++
		}
	}

	// Per-vap aaa.<n> + wireless.<n> rows, radio-sorted order (doc §4/§5).
	// Device capability bits come from the RECORD's `wifi_caps` field
	// (Device.hasWifiCapability(int) javap: (wifi_caps & mask) == mask —
	// NOT fw_caps; X.getInt default 0 when the field is absent, so an
	// unreported wifi_caps means every capability is_UNSUPPORTED). FID-15.
	wifiCapsKnown, wifiCaps := wireless.NumFromExtra(d.Extra, "wifi_caps")
	openHostapd := wifiCapsKnown && wifiCaps&0x2000 != 0 // supportOpenHostapd() = bit 0x2000 (Device §7696-7704)
	bgaFilterCap := wifiCapsKnown && wifiCaps&0x40 != 0  // hasWifiCapability(64) (FID-51)
	for n, v := range vaps {                             // 0-based over emissions → row index n+1
		rd.emitAaaRows(b, n+1, v, openHostapd)
		rd.emitWirelessRows(b, n+1, v, bgaFilterCap)
	}

	// VLAN wiring (doc §6): tag table, bridges, netconf, dhcpc — each with
	// its own counter.
	rd.emitVlanBlocks(b, d, vaps)
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
	if wireless.JSONBool(raw, "builtin_antenna") {
		return wireless.JSONStr(raw, "builtin_ant_gain", "0")
	}
	return wireless.JSONStr(raw, "antenna_gain", "6")
}

// emitAaaRows writes the aaa.<n> block for one vap per doc §4:
// always-first block, then the security branch (§4.2 open, §4.3 WPA),
// then the common tail.
func (rd *render) emitAaaRows(b *strings.Builder, n int, v wireless.VapPlan, openHostapd bool) {
	p := fmt.Sprintf("aaa.%d.", n)
	prefix := rd.lineWriter(b, "aaa-rows")
	line := func(k, vv string) { prefix(p+k, vv) }
	name := wireless.SSIDOf(v.Wlan)

	// §4.1 always-first block (int §566-578; no log_level row: record field
	// absent ⇒ default never >= 0).
	line("pmf.status", "disabled")
	line("pmf.mode", "0")
	line("ft.status", "disabled")
	line("country_beacon", "disabled")
	line("11k.status", "disabled")

	br := aaaBridge(v)
	line("br.devname", br)
	line("devname", "ath"+strconv.Itoa(v.AthN))
	line("driver", "madwifi") // atheros bean naming branch (doc §0)
	line("ssid", name)

	switch v.Wlan.Security {
	case "open":
		// §4.2: status = enabled iff supportOpenHostapd (wifi_caps 0x2000,
		// Device.hasWifiCapability — absence of the reported field means
		// DISABLED, not enabled: X.getInt default 0, FID-15).
		if openHostapd {
			line("status", "enabled")
		} else {
			line("status", "disabled")
		}
		line("id", v.ID)
		// no wpa.* rows in the open branch (§4.2).
	default:
		if v.Wlan.Security == "wpa-eap" {
			// Our admin API carries no RADIUS servers/profile yet; the real
			// controller would append radius.auth.<i>.* rows from the
			// RADIUS profile (int §791-840) right after the auth_cache row,
			// before dynamic_vlan.
			// TODO(wireless): radius rows once the API has RADIUS fields.
			rd.alerts = append(rd.alerts, Alert{
				Msg: "provisioning WPA-EAP wlan without RADIUS servers; " +
					"emitting mgmt=WPA-EAP with auth_cache enabled, no radius.* rows",
			})
		}
		line("status", "enabled") // only is_wds_uplink → disabled; we have none

		// NOTE for wpa-eap: still the fixed §4.3 block; psk uses the same
		// getWpaPreSharedKey() fallback shape.
		line("verbose", "2")
		// wpa_mode default = WpaMode.AUTO → getMode() = 3 (enum javap
		// static{}: AUTO=3, WPA1=1, WPA2=2; FID-4 — NOT wpa2's 2).
		line("wpa", "3")
		line("eapol_version", "2")
		line("wpa.group_rekey", "3600")
		line("p2p", "disabled")
		line("p2p_cross_connect", "disabled")
		line("proxy_arp", "disabled")
		line("is_guest", "false")
		line("tdls_prohibit", "disabled")
		line("bss_transition", "enabled")
		line("id", v.ID)

		psk := v.Wlan.Passphrase
		if psk == "" {
			psk = fallbackPsk // getWpaPreSharedKey() fallback shape (§8)
		}
		// Row order below the fixed block per the AAA writer (int offsets
		// 2357-3031 + EAP sub-writer at 8616-8920): mgmt → psk → auth_cache
		// → [radius.*] → dynamic_vlan → wpa.1.pairwise → pmf.cipher
		// (FID-25).
		mgmt := "WPA-PSK"
		if v.Wlan.Security == "wpa-eap" {
			mgmt = "WPA-EAP"
		}
		line("wpa.key.1.mgmt", mgmt)
		line("wpa.psk", psk) // psk writer: NEVER hashed/obfuscated (§8)
		if v.Wlan.Security == "wpa-eap" {
			// always "enabled" at WlanConf's auth_cache is(..., true) default
			line("auth_cache", "enabled")
			// vlan_wlan_mode disabled → dynamic_vlan=0 (default §8); the
			// RADIUS-driven 1|2 variants need the missing RADIUS fields.
			line("dynamic_vlan", "0")
		}
		line("wpa.1.pairwise", "CCMP") // wpa_enc auto → CCMP (§8)
		line("pmf.cipher", "AES-128-CMAC")
	}

	// §4.3/§613-624 common tail (macacl off, not hidden).
	line("radius.macacl.status", "disabled")
	line("hide_ssid", "false")
}

// aaaBridge resolves the bridge hosting this vap's athdev (doc §6/§555-561).
func aaaBridge(v wireless.VapPlan) string {
	if v.Vid == 0 {
		return "br0"
	}
	return "br0." + strconv.Itoa(v.Vid)
}

// emitWirelessRows writes the wireless.<n> block per doc §5 (worked-example
// key order; security is LITERAL none, authmode 0 only for open).
func (rd *render) emitWirelessRows(b *strings.Builder, n int, v wireless.VapPlan, bgaFilterCap bool) {
	p := fmt.Sprintf("wireless.%d.", n)
	prefix := rd.lineWriter(b, "wireless-rows")
	line := func(k, vv string) { prefix(p+k, vv) }

	line("mode", "master")
	line("devname", "ath"+strconv.Itoa(v.AthN))
	line("id", v.ID)
	line("status", "enabled") // literal — disabled wlans never reach here
	if v.Wlan.Security == "open" {
		line("authmode", "0")
	} else {
		line("authmode", "1")
	}
	// l2_isolation = enabled iff (this wlan's l2_isolation flag || is_guest)
	// (int offsets 3468-3502); both false in our admin API, and FID-51 notes
	// the polarity stays ambiguous until those fields exist — the defaultValue
	// is "disabled" either way (is_guest=false ⇒ same).
	line("l2_isolation", "disabled")
	line("is_guest", "false")
	line("security", "none") // ⚠ literal, even for WPA (doc §5 line 250)
	line("addmtikie", "disabled")
	line("ssid", wireless.SSIDOf(v.Wlan))
	line("hide_ssid", "false")
	line("mac_acl.status", "enabled") // literal
	line("mac_acl.policy", "deny")    // literal
	line("wmm", "enabled")
	line("uapsd", "disabled")
	line("parent", v.Phyname) // radio TABLE device name (§1399)
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
	// bga_filter: emitted only when the device reports wifi_caps bit 64
	// (hasWifiCapability(64), int offsets 4433-4546); absent capability →
	// the ROW IS SKIPPED entirely, not "disabled" (FID-51). At our defaults
	// (no wds vaps; forward_bpdu absent ⇒ bga bridge-flooded ON) the value
	// is enabled. forward_bpdu tie-in unrepresentable in the admin API — flagged.
	if bgaFilterCap {
		line("bga_filter", "enabled")
	}
	line("dtim_period", "3")
}

// emitVlanBlocks writes `# vlan`, `# bridge`, `# netconf` and `# dhcpc`
// from the vap wiring (doc §6 + §7 excerpt).
//
// Merge model (FID-2, int/String bytecode): a vlan-table row keyed
// ("vlan", <vid>) accumulates a PORT SET from both wlan sides — the
// per-vap ath members (`br0.<vid>` ath ports, int offsets 2733-2830) AND
// the eth-port×vid sub-interfaces `<eth>.<vid>` (int offsets 3662-3730,
// ports×vids) — and the bridge writer (String offsets 3886-4052) drains
// each row as `bridge.<j>.port.<k>.devname`. The `# vlan` block itself
// prints eth-ports×vids pairs (String offsets ~3862-3970: vids outer,
// ports inner). Status rows: vlan.status/bridge.status exist even when
// their table is empty (disabled), netconf.status/dhcpc.status are
// written unconditionally (FID-14).
// The netconf section itself is emitted by emitNetconfSection (see its
// doc for the mgmt-instance + validator rationale).
func (rd *render) emitVlanBlocks(b *strings.Builder, d store.Device, vaps []wireless.VapPlan) {
	line := rd.lineWriter(b, "vlan-blocks")

	// eth inventory from the device record's inform passthrough
	// (ethernet_table num_port sum; Device.getPortNum fallback,
	// Device.java §6941-6957), else from the ethN interfaces in if_table,
	// else from the learned uplink (6.8.2 U7PG2 sends no ethernet_table —
	// live acceptance 2026-09-16). port_table is deliberately NOT used: its
	// names are labels ("Main", "Secondary"), not ifaces, and the same record
	// reports has_eth1=false with a lone eth0 in if_table. An absent/partial
	// inventory is flagged: we then fall back to a single inferred uplink
	// instead of inventing ports (partial-eth-inventory flag, FID-2).
	ethIfaces, ethKnown := ethPortNames(d)
	if !ethKnown {
		rd.alerts = append(rd.alerts, Alert{
			Msg: "wireless provision: no ethernet_table/if_table inventory in the device record; " +
				"falling back to a single inferred uplink (partial eth inventory)",
		})
	}

	// collect tagged vids (sorted) and bridge memberships
	vidAths := map[int][]string{}
	var vids []int
	for _, v := range vaps {
		if v.Vid != 0 {
			if _, seen := vidAths[v.Vid]; !seen {
				vids = append(vids, v.Vid)
			}
			vidAths[v.Vid] = append(vidAths[v.Vid], "ath"+strconv.Itoa(v.AthN))
		}
	}
	sort.Ints(vids)

	// `# vlan`: status row exists always; rows are eth-port×vid pairs.
	b.WriteString("# vlan\n")
	if len(vids) > 0 {
		line("vlan.status", "enabled")
		i := 0
		for _, vid := range vids {
			for _, p := range ethIfaces {
				i++
				line(fmt.Sprintf("vlan.%d.devname", i), p)
				line(fmt.Sprintf("vlan.%d.id", i), strconv.Itoa(vid))
			}
		}
	} else {
		line("vlan.status", "disabled")
	}

	// bridge section: status row first, then mgmt br0 (infra eth ports +
	// untagged aths), then one br0.<vid> per sorted vid carrying BOTH the
	// `<eth>.<vid>` sub-interface ports and the vap ath ports (FID-2).
	b.WriteString("# bridge\n")
	line("bridge.status", "enabled")
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
	untagged := append([]string{}, ethIfaces...)
	for _, v := range vaps {
		if v.Vid == 0 {
			untagged = append(untagged, "ath"+strconv.Itoa(v.AthN))
		}
	}
	writeBridge("br0", untagged...)
	for _, vid := range vids {
		tagged := make([]string, 0, len(ethIfaces)+len(vidAths[vid]))
		for _, p := range ethIfaces {
			tagged = append(tagged, p+"."+strconv.Itoa(vid))
		}
		tagged = append(tagged, vidAths[vid]...)
		writeBridge("br0."+strconv.Itoa(vid), tagged...)
	}

	// netconf: always the management instance (netconf.1) first, then the
	// tagged instances numbered contiguously from 2. See emitNetconfSection.
	rd.emitNetconfSection(b, d, vids)

	// dhcpc: status row always; then the mgmt dhcp-client row for the
	// mgmt dev — the classic writer emits dhcpc.<n>.status + .devname
	// whenever config_network.type != "static" (B__P javap offsets
	// 38-115; the site default type is "dhcp", so this is the default
	// shape), FID-13. The guest-vlan branch (.ip_only=true) needs an
	// is_guest flag the admin API does not have yet. (FID-14)
	b.WriteString("# dhcpc\n")
	line("dhcpc.status", "enabled")
	line("dhcpc.1.status", "enabled")
	line("dhcpc.1.devname", mgmtDevOf(d))
}

// factoryMgmtIP / factoryMgmtNetmask are the factory-baseline management
// netconf values for this firmware lane (U7PG2 / 6.8.2.15592): the
// firmware's fallback STATIC address, as carried by /tmp/system.cfg on the
// factory-reset AP (/tmp/harness/ap-forensics/tmp/system.cfg:58-60, fetched
// 2026-09-17). Runtime addressing is owned by udhcpc — the dhcpc.1=br0
// section we push stays byte-identical to the factory one, so DHCP keeps
// running and these rows never take effect while adopted.
const (
	factoryMgmtIP      = "192.168.1.20"
	factoryMgmtNetmask = "255.255.255.0"
)

// emitNetconfSection writes the `# netconf` block as a FACTORY ECHO of the
// running baseline inventory plus the tagged-vid bridge instances appended
// after the base inventory.
//
// WHY an echo and not the real builder's render: the real controller
// renders netconf from its site-networks model (intsuper javap offsets
// 627-676: the mgmt instance is patched with the config_network ip/netmask —
// type "dhcp" → ip 0.0.0.0, no netmask row), which on a factory-reset AP
// CHANGES netconf.1.ip (192.168.1.20 → 0.0.0.0) and restarts the `net`
// plugin (/etc/sysinit/net.conf, fetched 2026-09-17: plugin_stop =
// `ifconfig br0/eth0/ath0/ath1 down` + `killall dropbear`; plugin_start =
// HARDCODED factory bootstrap br0=192.168.1.20/24). Real APs survive that
// restart via the udhcpc inittab respawn; OUR two live first-pushes
// (2026-09-16 09:43 both-band sha 11fddde5…, 13:54 2g-only sha f77521e8…)
// did NOT recover — the pushed system_cfg is a FULL-CONFIG REPLACEMENT and
// ours also deleted the eth0/ath0/ath1 instances the running config
// carried. The recovery path is not yet understood (fast-apply diff
// granularity; Ghidra u7pg2-ubntconf project available), so the first push
// MUST NOT restart `net` at all: /tmp/harness/minimal-diff-spec.md. Every
// base instance below therefore echoes the RUNNING factory values
// row-for-row, keeping the parsed netconf tree IDENTICAL to the running
// one → no `net` plugin restart → br0/eth0/ath* are never bounced.
//
// Base inventory + row order (factory file order per instance):
//
//	netconf.1  = mgmt bridge (mgmtDevOf; autoip.status, devname, ip,
//	            netmask, status, up — the factory carries NO promisc row
//	            for the mgmt instance). RECORDED DEVIATION from the real
//	            builder's DHCP shape (ip 0.0.0.0, no netmask): deliberate
//	            minimal-diff first-push policy
//	            (docs/PROTOCOL-systemcfg-wireless.md §12 tracks it).
//	netconf.2+ = one per eth port (ethPortNames — the same inventory the
//	            bridge writer uses): ip 0.0.0.0, promisc=enabled,
//	            up=enabled, no netmask row.
//	then       = one ath<n> slot per radio_table entry (ath0, ath1, …):
//	            ip 0.0.0.0, promisc=enabled, up=disabled — the factory
//	            carries ath slots disabled even with vaps running (the
//	            wireless plugin, not the net plugin, raises active vaps;
//	            live-observed: factory vap_table RUN on ath0 while
//	            netconf.3.up=disabled).
//	then       = one br0.<vid> per tagged vid (additive rows for VLAN
//	            WLANs, real-builder shape: status first).
//
// For the U7PG2 baseline this reproduces the factory numbering exactly
// (1=br0, 2=eth0, 3=ath0, 4=ath1); tagged instances start at 5.
//
// mcad gate: the firmware's system_cfg validator (fw 6.8.2.15592,
// reverse-engineered FUN_0040a924 "mcad_validate_system_cfg") requires
// netconf.1.status in the parsed tree (together with users.1.status and
// sshd.status), otherwise the config is REJECTED ("[apply-config] Unable
// to write system.cfg or its contents are invalid.") and apply-config
// never runs (live-observed 2026-09-16). The echo keeps the row, so the
// gate stays green.
//
// An earlier `preserveMgmt` branch that asserted a recorded mgmt IP
// (Extra["mgmt_ip"]) was deleted as dead code — mgmt_ip has no writer
// anywhere in the repo. mgmt_dev may still steer netconf.1.devname via
// mgmtDevOf (documented admin escape hatch, has its own test).
func (rd *render) emitNetconfSection(b *strings.Builder, d store.Device, vids []int) {
	line := rd.lineWriter(b, "netconf")

	b.WriteString("# netconf\n")
	line("netconf.status", "enabled")

	n := 0
	next := func() string {
		n++
		return fmt.Sprintf("netconf.%d.", n)
	}

	// netconf.1: management instance (factory echo, factory row order).
	m := next()
	line(m+"autoip.status", "disabled")
	line(m+"devname", mgmtDevOf(d))
	line(m+"ip", factoryMgmtIP)
	line(m+"netmask", factoryMgmtNetmask)
	line(m+"status", "enabled")
	line(m+"up", "enabled")

	// eth port instances (factory echo; ethPortNames falls back to the
	// inferred uplink, never invents ports).
	ports, _ := ethPortNames(d)
	for _, p := range ports {
		m := next()
		line(m+"autoip.status", "disabled")
		line(m+"devname", p)
		line(m+"ip", "0.0.0.0")
		line(m+"promisc", "enabled")
		line(m+"status", "enabled")
		line(m+"up", "enabled")
	}

	// radio slot instances ath0..ath<n> (factory echo).
	for i := range wireless.StoredRadios(d) {
		m := next()
		line(m+"autoip.status", "disabled")
		line(m+"devname", "ath"+strconv.Itoa(i))
		line(m+"ip", "0.0.0.0")
		line(m+"promisc", "enabled")
		line(m+"status", "enabled")
		line(m+"up", "disabled")
	}

	// tagged-vid bridge instances (additive; real-builder shape).
	for _, vid := range vids {
		m := next()
		line(m+"status", "enabled")
		line(m+"devname", "br0."+strconv.Itoa(vid))
		line(m+"ip", "0.0.0.0")
		line(m+"autoip.status", "disabled")
		line(m+"promisc", "enabled")
		line(m+"up", "enabled")
	}
}

// ethPortNames derives the physical eth port names from the record's inform
// passthrough: sum of ethernet_table num_port values (per the vlan writer's
// port count), entries without num_port count as one each. When ethernet_table
// is absent (6.8.2 U7PG2 never sends one — live acceptance 2026-09-16) the
// ethN names in if_table are used, else the learned uplink. Returns known=false
// when the record carries no usable inventory (caller flags partial inventory,
// FID-2).
func ethPortNames(d store.Device) (ports []string, known bool) {
	if names, ok := ethPortNamesFromEthernetTable(d); ok {
		return names, true
	}
	if names, ok := ethPortNamesFromIfTable(d); ok {
		return names, true
	}
	if up, ok := d.Extra["uplink"].(string); ok && isEthIfaceName(up) {
		return []string{up}, false
	}
	return []string{defaultEthIface}, false
}

// ethPortNamesFromEthernetTable expands ethernet_table entries into ethN names
// (an entry without num_port counts as one port).
func ethPortNamesFromEthernetTable(d store.Device) ([]string, bool) {
	rawList, ok := d.Extra["ethernet_table"].([]any)
	if !ok {
		return nil, false
	}
	total := 0
	sawEntries := false
	for _, item := range rawList {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		sawEntries = true
		if n := wireless.JSONInt(m, "num_port"); n > 0 {
			total += n
		} else {
			total++
		}
	}
	if !sawEntries || total <= 0 {
		return nil, false
	}
	out := make([]string, 0, total)
	for i := 0; i < total; i++ {
		out = append(out, "eth"+strconv.Itoa(i))
	}
	return out, true
}

// ethPortNamesFromIfTable collects the distinct ethN interface names the
// device reports in if_table (its interface inventory). This is the fallback
// the 6.8.2 U7PG2 needs: it sends no ethernet_table (live acceptance
// 2026-09-16, where if_table was [{name: "eth0", up: true}]). port_table is
// deliberately not consulted — its entries are labels ("Main", "Secondary"),
// not ifaces — and the same record reports has_eth1=false, so deriving a port
// count from it would invent an eth1 the device does not have.
func ethPortNamesFromIfTable(d store.Device) ([]string, bool) {
	rawList, ok := d.Extra["if_table"].([]any)
	if !ok {
		return nil, false
	}
	seen := map[string]bool{}
	for _, item := range rawList {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if !isEthIfaceName(name) {
			continue
		}
		seen[name] = true
	}
	if len(seen) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, true
}

// isEthIfaceName reports whether name is of the form "ethN" (N ≥ 0 digits).
func isEthIfaceName(name string) bool {
	if !strings.HasPrefix(name, "eth") || len(name) == len("eth") {
		return false
	}
	for _, r := range name[len("eth"):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

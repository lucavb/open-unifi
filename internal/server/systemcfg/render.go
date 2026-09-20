// Package systemcfg is the system_cfg RENDERER (CONTEXT.md: decision
// modules): the pure producer of config text from a device, the WLANs, and
// site facts. It reads nothing else and mutates nothing — credential-cache
// writes come back as Result.CredentialDeltas values the adapter applies,
// and diagnostics come back as Result.Warnings/Alerts values the adapter
// logs; the renderer itself never logs and never takes a logger.
//
// The byte-verified emission contract is docs/PROTOCOL-mgmt.md §3 and
// docs/PROTOCOL-systemcfg-wireless.md (§1 header block, §2 indexing,
// §3 radio rows, §4 aaa rows, §5 wireless rows, §6 VLAN wiring, §7 worked
// example, §8 admin-API mapping); the factory-echo policy is
// /tmp/harness/minimal-diff-spec.md.
package systemcfg

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lucavb/open-unifi/internal/configtext"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

// SiteFacts are the controller-level inputs a render needs (CONTEXT.md:
// site facts): controller URL, regulatory country code, AP SSH password,
// the provisioned SSH public keys, the SSH password-login disable knob, and
// the current WLANs.
type SiteFacts struct {
	// ControllerURL is the configured controller base URL. Empty means
	// "not overridden" (nothing in system_cfg derives from it today; it is
	// carried for symmetry with the site-facts definition and future rows).
	ControllerURL string

	// CountryCode is the regulatory country code used for the radio rows,
	// already resolved by the caller (zero is not defaulted here — the
	// caller maps its configured zero to the compatibility default before
	// building the facts).
	CountryCode int

	// SSHPassword overrides the default SSH password ("ubnt") hashed into
	// system_cfg users.1. SECURITY NOTE: this string lives in server memory
	// and, by protocol design, travels VERBATIM (hashed) inside the
	// provisioned config; the passphrase itself never appears in mgmt_cfg.
	// Treat records/config containing the hash as credentials.
	SSHPassword string

	// SSHPublicKeys are the site's authorized public keys, rendered as the
	// sshd.auth.key.<n>.* rows (1-based, slice order, no dedup). Zero keys
	// emit zero rows. The firmware rebuilds /etc/dropbear/authorized_keys
	// from these rows on every boot/apply, so keys pushed here survive
	// where a manually written file is wiped (see sshkey.go for the
	// firmware evidence). NOT yet live-bench-validated — a live-validated
	// apply is owed before the rows are treated as trusted
	// (docs/PROTOCOL-systemcfg-wireless.md §13).
	SSHPublicKeys []PublicKey

	// SSHDisablePassword sets sshd.auth.passwd=disabled: the firmware
	// respawn builder then appends the dropbear "-s" flag (disable remote
	// password logins) to "null::respawn:%s -F %s%s%s%s". Default false
	// (password auth enabled) is byte-identical to the pre-feature render.
	SSHDisablePassword bool

	// WLANs is the current WLAN envelope (the engine's per-decision
	// snapshot, so the drift hash and the rendered config always agree).
	WLANs []wireless.Wlan
}

// Result is one completed render.
type Result struct {
	// Text is the rendered system_cfg blob (byte-identical to the
	// pre-extraction builder's output for identical inputs).
	Text string

	// Warnings are the renderer's debug-level diagnostics; the adapter logs
	// them at debug with the same wording.
	Warnings []string

	// Alerts are the renderer's warn-level diagnostics (newline-injected
	// rows skipped, partial eth inventory, WPA-EAP without RADIUS); the
	// adapter logs them at warn with the same wording. Msg carries the
	// wording; Where/Key carry the structured slog attrs of the newline
	// skip (the only attributed diagnostic — the pre-extraction lineWriter
	// logged Warn(msg, "where", where, "key", key)); message-only alerts
	// leave both empty and are logged without attrs, matching the
	// pre-extraction call shapes exactly.
	Alerts []Alert

	// CredentialDeltas carries the ssh password-cache writes the render
	// produced — exactly the keys/values the former in-place mutation wrote
	// (ssh_md5passwd / ssh_sha512passwd). The renderer never mutates the
	// device record: the adapter applies these inside the store's
	// read-modify-write cycle at the same point the mutation used to land.
	// Absent entries mean the cached hash matched and nothing was written.
	CredentialDeltas map[string]string
}

// Alert is one warn-level renderer diagnostic, carrying the exact wording
// the adapter logs. Where/Key carry the structured slog attrs of the
// newline-injection skip (the only attributed diagnostic — the
// pre-extraction lineWriter logged Warn(msg, "where", where, "key", key));
// message-only alerts leave both empty and are logged without attrs,
// matching the pre-extraction call shapes exactly.
type Alert struct {
	Msg   string
	Where string
	Key   string
}

// defaultSSHPassword is the site's default SSH password (docs §7:
// x_ssh_password default "ubnt").
const defaultSSHPassword = "ubnt"

// render carries one render's accumulated outputs (warnings-as-values and
// credential-cache deltas) plus the resolved site facts.
type render struct {
	facts    SiteFacts
	warnings []string // debug-level diagnostics (Result.Warnings)
	alerts   []Alert  // warn-level diagnostics (Result.Alerts)
	deltas   map[string]string
	// dasDadStatusDone is the jar's cross-wlan once-flag for the
	// radius.dad.status/dad.port block: initialized once per device render
	// (zero value), advancing only when the dad block emits (jar local 19,
	// int offsets 1435-1439 / 231-232 / 2901).
	dasDadStatusDone bool
}

// lineWriter returns the injection-guarded writer; newline-injected rows are
// collected as structured warn-level alerts (the renderer never logs).
func (rd *render) lineWriter(b *strings.Builder, where string) func(k, v string) {
	return configtext.LineWriter(func(where, key string) {
		rd.alerts = append(rd.alerts, Alert{
			Msg:   "config blob: row skipped, newline in value",
			Where: where,
			Key:   key,
		})
	}, b, where)
}

// sshPassword is the effective SSH password ("ubnt" default, facts override).
func (rd *render) sshPassword() string {
	if rd.facts.SSHPassword != "" {
		return rd.facts.SSHPassword
	}
	return defaultSSHPassword
}

// Render produces the system_cfg text for the device record from the site
// facts alone: it computes the provisioning plan from (d, facts.WLANs) —
// the same one constructor every other consumer uses — and renders from it.
// An error aborts the whole provisioning push (FID-23) — the caller must
// answer the inform with the noop path instead of persisting/shipping
// partial config.
//
// TODO(wireless): see docs/PROTOCOL-systemcfg-wireless.md when it lands —
// the wireless/aaa.<n>, vlan/bridge/netconf, qos/bandsteering, syslog, snmp
// and cron/ntp sections from the real int builder are pending
// reverse-engineering and must NOT be invented here.
func Render(d store.Device, facts SiteFacts) (Result, error) {
	return RenderWithPlan(d, facts, wireless.PlanProvisioning(d, facts.WLANs))
}

// RenderWithPlan is the engine-threaded render entry: instead of computing
// the provisioning plan from (d, facts.WLANs) itself, it emits from the plan
// the adoption engine computed for the same record and envelope snapshot, so
// the renderer's rows and the drift hash the decision compared share ONE
// computation. Inside THIS entry the plan is the sole wireless input:
// facts.WLANs is not read for the wireless sections at all (Render's own
// door above is the only site that passes facts.WLANs into a plan), so a
// mismatched facts.WLANs cannot leak second-half rows into a
// plan-consistent render — pinned in-package by
// TestRenderWithPlanIgnoresFactsWLAN.
// See the wireless section's emission notes in wireless.go.
func RenderWithPlan(d store.Device, facts SiteFacts, plan wireless.ProvisioningPlan) (Result, error) {
	rd := &render{facts: facts}
	var b strings.Builder
	line := rd.lineWriter(&b, "system_cfg")
	raw := func(l string) {
		if l != "" {
			b.WriteString(l)
			if !strings.HasSuffix(l, "\n") {
				b.WriteString("\n")
			}
		}
	}

	// 1/unifi-zone. Section head order (bytecode int.txt:17208-17216, the
	// AP top-level else-branch): the real controller emits `# unifi` FIRST
	// (int.Ó00000(sb,Device,Setting) = String's unifi writer + cfgcap_info
	// appended), THEN `# system` (int.Ø00000 semantics), THEN `# users`.
	// config_String unifi pair array — String.txt:1851-1897 — fixes the
	// unifi row order below.
	b.WriteString("# unifi\n")
	line("unifi.version", "0.1.0-dev")
	// Anonymous ids turn on only when present in the record; reporterid
	// mirrors the controller anonymous id (same source in the jar); siteid
	// carries the device's site name (getSiteId always set there; our
	// fallback is the "default" site) — FID-17. Row order per the pair
	// array: version, anonymous_controller_id, anonymous_site_id,
	// reporterid, siteid (String.txt:1851-1897).
	if v, ok := d.Extra[store.AnonymousControllerIDKey].(string); ok && v != "" {
		line("unifi.anonymous_controller_id", v)
	}
	if v, ok := d.Extra[store.AnonymousSiteIDKey].(string); ok && v != "" {
		line("unifi.anonymous_site_id", v)
	}
	if v, ok := d.Extra[store.AnonymousControllerIDKey].(string); ok && v != "" {
		// reporterid = the very same controller anonymous id.
		line("unifi.reporterid", v)
	}
	line("unifi.siteid", configtext.SiteRef(d))
	// unifi.idp — tail of String's unifi writer (String.txt:1898+,
	// com__ubnt__service__config__String.txt:1899-1902): the bytecode pushes
	// iconst_1, i.e. Setting.is("unifi_idp_enabled", true) — the JAR DEFAULT
	// is ENABLED (which also emits the unifi.mcip/unifi.key rows that we do
	// not carry). We deliberately emit `disabled` anyway: we have no IDP
	// feature, and the AP validator ignores the row. This is a RECORDED
	// DEVIATION from the real builder (docs agent tracks it in the §12
	// deviation table); do not "fix" it back to enabled silently.
	line("unifi.idp", "disabled")
	// unifi.cfgcap_info — the `int` override appends it right after calling
	// the base unifi writer (int.txt:16600-16630: "0x" +
	// Integer.toHexString(Ô00000())). The capability int (int.Ô00000()I,
	// int.txt:5332-5387) splits the CONTROLLER version: major ≤ 2 → 0x0,
	// v3.0–3.2 → 0x3, v3.3+/v4+ → 0x7. Our advertised version is the
	// placeholder "0.1.0-dev", which would compute 0x0 — deliberately NOT
	// derived from it: we emit the literal 0x7 matching every modern real
	// controller (v3.3+, the only value this firmware has ever been paired
	// with). ubntconf reads it on the AP via
	// get_uint32(cfg, 0, "unifi.cfgcap_info") — absent/0 can zero the
	// plugin layer's capability gating
	// (docs/AP-FIRMWARE-APPLY-PATH.md §6).
	line("unifi.cfgcap_info", "0x7")

	// 2. # system — deliberately OMITTED. The real builder skips the
	//    timezone rows when the site locale is absent (PROTOCOL-mgmt.md
	//    §3 step 2) and our site carries no locale; the factory baseline
	//    (/tmp/harness/ap-forensics/tmp/system.cfg) has no system rows
	//    either. The system_cfg apply is a full-config replacement, so
	//    emitting rows here would DELETE-or-CHANGE a section the running
	//    config does not carry and restart the system plugin for nothing.
	//    Minimal-diff policy: /tmp/harness/minimal-diff-spec.md.

	// 3. # users — config_String.java §197-206 / PROTOCOL-systemcfg-Config.
	//    Real AP order (int.txt:17208-17216): unifi → system → users.
	users1pw, uerr := rd.usersPasswordHash(d)
	if uerr != nil {
		return Result{}, uerr
	}
	b.WriteString("# users\n")
	line("users.status", "enabled")
	line("users.1.name", "ubnt")
	line("users.1.password", users1pw)
	line("users.1.status", "enabled")
	line("users.2.name", "nobody")
	line("users.2.password", "x")
	line("users.2.shell", "/bin/false")
	line("users.2.status", "enabled")

	// 3b. `# mgmt` ledbar block — HEADERLESS, between `# users` and the
	//     wireless compound, exactly where the real builder emits it
	//     (int.txt:17221 calls config_String.Ò00000 right after the users
	//     writer; the block itself is String.txt:2566-2745). Rows, order,
	//     and conditions live in ledbar.go — every row cites the packet
	//     there; the block is absent for models without the ledbar
	//     hardware-capability bit (String.txt:2571-2574).
	rd.emitLedBar(line, d)

	// 4. Wireless/VLAN compound (docs/PROTOCOL-systemcfg-wireless.md):
	// `# wlans (radio)` + radio.<n>/virtual + aaa.<n>/wireless.<n> vaps +
	// `# vlan`/`# bridge`/`# netconf`/`# dhcpc` wiring. Real section order
	// per PROTOCOL-mgmt.md §3 puts this before the sshd/syslog ones.
	rd.emitWirelessCfg(&b, plan, d)

	// 4b. Factory-baseline echo sections. The system_cfg apply is a
	// FULL-CONFIG REPLACEMENT (mcad renames the staged file over
	// /tmp/system.cfg; docs/AP-FIRMWARE-APPLY-PATH.md), and ubntconf's
	// fast-apply restarts the on-device plugin for every section whose
	// parsed tree CHANGES — including changes caused by ROW DELETION
	// when the controller's render omits a section the running config
	// carries. The two fatal live pushes (2026-09-16 09:43/13:54) proved
	// the mechanism (net plugin restart → ifconfig br0/eth0 down → AP
	// dark; /etc/sysinit/net.conf fetched 2026-09-17). The rows below
	// therefore ECHO the running factory baseline
	// (/tmp/harness/ap-forensics/tmp/system.cfg, fetched from the
	// factory-reset AP 2026-09-17) so those parsed sections stay
	// IDENTICAL and no plugin restarts fire. Section order follows the
	// real builder where it emits these (PROTOCOL-mgmt.md §3 steps
	// 7-9). These are device-class baseline constants, NOT controller
	// state: do not "clean them up" without a live-validated apply.
	// Full policy: /tmp/harness/minimal-diff-spec.md.

	// # connectivity (§3 step 7 — mac/connectivity overrides). The
	// plugin restarts the uplink-monitor inittab entry when this section
	// changes; the echo keeps it quiet. uplink_eth follows the same eth
	// inventory as the bridge writer; uplink_wds is the last radio slot
	// (the 5g vap used for wireless uplink; factory ath1).
	b.WriteString("# connectivity\n")
	line("connectivity.status", "enabled")
	line("connectivity.uplink_bridge", mgmtDevOf(d))
	ethIfaces, _ := ethPortNames(d)
	line("connectivity.uplink_eth", ethIfaces[0])
	line("connectivity.uplink_wds", fmt.Sprintf("ath%d", len(wireless.StoredRadios(d))-1))

	// # syslog (§3 step 8) — factory echo.
	b.WriteString("# syslog\n")
	line("syslog.status", "enabled")
	line("syslog.file", "/var/log/messages")
	line("syslog.level", "8")
	line("syslog.remote.status", "disabled")
	line("syslog.remote.ip", "192.168.1.1")
	line("syslog.remote.port", "514")
	line("syslog.rotate", "1")
	line("syslog.size", "200")

	// sshd rows — config_String.java §309-337 defaults: SSH on, password
	// auth on, wildcard bind off, no injected keys, mgmt interface bound.
	// FID-20: these rows carry NO "# sshd" section header in the classic
	// builder (no such literal exists in int/String). hooksite: real mgmt
	// dev is model-specific (record pass-through Extra["mgmt_dev"] allowed
	// as the admin escape hatch).
	line("sshd.status", "enabled")
	if rd.facts.SSHDisablePassword {
		// sshd.auth.passwd=disabled → the firmware respawn builder appends
		// dropbear's "-s" flag (disable remote password logins) to
		// "null::respawn:%s -F %s%s%s%s" (port from sshd.%d.port, host
		// keys -r /var/run/dropbear_rsa_host_key and
		// -r /var/run/dropbear_ed25519_host_key). Password auth must be
		// disabled only with an authorized key provisioned — the caller
		// (cmd/openunifi) enforces that fail-closed at startup.
		line("sshd.auth.passwd", "disabled")
	} else {
		line("sshd.auth.passwd", "enabled")
	}
	line("sshd.1.status", "enabled")
	line("sshd.1.ifname", mgmtDevOf(d))
	// sshd.auth.key.<n>.* — the authorized-key row family (firmware:
	// string cluster 0x0063bd40-0x0063be80; line format "%s %s %s\n"
	// written to /etc/dropbear/authorized_keys @0x0063f19c). Row order per
	// the jar's format strings (com.ubnt.service.config.String,
	// String.txt:2849-2911): status, value, type, comment — matched
	// byte-exactly even though the device sorts rows at boot. 1-based, in
	// slice order, NO dedup. Without keys nothing is emitted (zero rows =
	// byte-identical to the pre-feature render, pinned in render_test);
	// the comment row is only emitted when non-empty, matching the
	// firmware's three-field line writer. NOT yet live-bench-validated —
	// a live-validated apply is owed before these rows are treated as
	// trusted (render.go minimal-diff policy; docs §13).
	for i, k := range rd.facts.SSHPublicKeys {
		n := i + 1
		line(fmt.Sprintf("sshd.auth.key.%d.status", n), "enabled")
		line(fmt.Sprintf("sshd.auth.key.%d.value", n), k.Value)
		line(fmt.Sprintf("sshd.auth.key.%d.type", n), k.Type)
		if k.Comment != "" {
			line(fmt.Sprintf("sshd.auth.key.%d.comment", n), k.Comment)
		}
	}

	// # route + # ntpclient (real builder: §3 step 9) — factory echo.
	b.WriteString("# route\n")
	line("route.status", "enabled")
	line("route.1.status", "enabled")
	line("route.1.devname", mgmtDevOf(d))
	line("route.1.ip", "224.0.0.0")
	line("route.1.netmask", "3")

	b.WriteString("# ntpclient\n")
	line("ntpclient.status", "enabled")
	line("ntpclient.1.status", "enabled")
	line("ntpclient.1.server", "0.ubnt.pool.ntp.org")

	// Sections the real builder NEVER emits (PROTOCOL-mgmt.md §3 has no
	// mgmt/dhcpd/httpd/ebtables writers) but the factory baseline
	// carries: omitting them would DELETE the rows from the running
	// config (full-config replacement) with unknown effects — e.g.
	// mgmt.discovery.status gates the discovery announces, and the
	// ebtables row is the EAPOL broute rule on the first vap slot.
	// Factory echo = zero parsed diff = zero plugin restarts.
	//
	// EXCEPT mgmt.is_default: never echo it in any value. The AP boot
	// path (/lib/preinit/99_21_ubnt_ubntconf do_ubntconf, fw 6.8.2)
	// restores the MTD blob text via `cfgmtd -r`, then greps it for
	// `mgmt.is_default=true` — a hit replaces the restored text with the
	// factory template before /tmp/system.cfg is sorted into place, so
	// echoing the factory's is_default=true makes every reboot drop the
	// provisioned WLANs while the tar part still restores mgmt/authkey
	// (retained-key echo + watchdog re-provision ≈49 s). The real
	// controller emits no mgmt.is_default row at all (no writer in
	// config_String/int), so absence is the byte-exact form. AP boot
	// evidence 2026-09-18: /tmp/system.cfg line 258 carried
	// mgmt.is_default=true from this echo; WLAN-ACCEPTANCE A2.
	b.WriteString("# ebtables\n")
	line("ebtables.status", "enabled")
	line("ebtables.1.cmd", "-t broute -A BROUTING -p 0x888e -i ath0 -j DROP")
	line("mgmt.discovery.status", "enabled")
	line("mgmt.flavor", "ace")
	line("dhcpd.status", "disabled")
	line("dhcpd.1.status", "disabled")
	line("httpd.status", "disabled")

	// What is still deliberately missing here (bandsteering, airtime,
	// stamgr, qos, mesh, snmp, resolv, iptables, cron — config_String/
	// int): the factory baseline carries none of those rows either, so
	// omitting them keeps the parsed diff empty under the full-config
	// replacement semantics. Adding any row requires a live-validated
	// apply first (two AP resets already consumed 2026-09-16). The ONE
	// deliberate addition since that policy: the site-fact
	// sshd.auth.key.<n>.* rows (when keys are configured) — firmware-
	// derived but still OWED a live-validated apply (docs §13).

	// 5. The admin "config.system_cfg.<idx>" passthrough lines
	//    (config_String.java §appendix: raw pre-formatted lines). FID-62:
	//    emitted without any "# misc" section header row.
	if extra, ok := d.Extra[store.SystemCfgExtraLinesKey].([]any); ok {
		for _, v := range extra {
			if l, ok := v.(string); ok {
				raw(l)
			}
		}
	}
	return Result{
		Text:             b.String(),
		Warnings:         rd.warnings,
		Alerts:           rd.alerts,
		CredentialDeltas: rd.deltas,
	}, nil
}

// usersPasswordHash selects and derives the users.1.password value for the
// record (config_String §nine-branch: String.txt §1985-2006):
//
//	supportsSsh() && supportsSha512Password() → $6$ SHA-512 crypt (L.ÔO0000)
//	supportsSsh() && !supportsSha512Password() → $1$ MD5 crypt (L.õ00000)
//	!supportsSsh() → DES crypt — unreachable for our inform-driven model set
//	(fw_caps-bearing APs/switches), deliberately not implemented.
//
// supportsSha512Password() = hasCapability(1024) — `(fw_caps & n) == n`
// with a 0 default when the record doesn't report fw_caps (Device.java) —
// or the UDM/firewall device type, which we don't model (flagged: no
// device-type table in this MVP). A freshly generated hash is returned as a
// CREDENTIAL DELTA (the jar writes x_ssh_sha512passwd/x_ssh_md5passwd into
// the site mgmt setting so repeated pushes are byte-identical); the renderer
// never mutates the record — the adapter applies the delta inside its
// read-modify-write cycle.
// FID-23: generation failure or an empty value fails the whole call — the
// classic Crypt.crypt exceptions propagate out of the config build, and a
// degraded/empty row must never ship silently.
func (rd *render) usersPasswordHash(d store.Device) (string, error) {
	pw := rd.sshPassword()
	if !supportsSha512Password(d) {
		cached, _ := d.Extra["ssh_md5passwd"].(string)
		if cached != "" && md5CryptMatches(pw, cached) {
			return cached, nil
		}
		fresh, err := md5Crypt(pw)
		if err != nil {
			return "", fmt.Errorf("users.1 md5 password: %w", err)
		}
		if fresh == "" {
			return "", errors.New("users.1 md5 password generated empty")
		}
		if rd.deltas == nil {
			rd.deltas = map[string]string{}
		}
		rd.deltas["ssh_md5passwd"] = fresh
		return fresh, nil
	}
	cached, _ := d.Extra[store.SSHSha512PasswdKey].(string)
	if cached != "" && sha512CryptMatches(pw, cached) {
		return cached, nil
	}
	fresh, err := sha512Crypt(pw)
	if err != nil {
		return "", fmt.Errorf("users.1 sha512 password: %w", err)
	}
	if fresh == "" {
		return "", errors.New("users.1 sha512 password generated empty")
	}
	if rd.deltas == nil {
		rd.deltas = map[string]string{}
	}
	rd.deltas[store.SSHSha512PasswdKey] = fresh
	return fresh, nil
}

// supportsSha512Password mirrors Device.supportsSha512Password(): the
// fw_caps SHA-512 bit (0x0400); a record that does not report the field
// evaluates to capability 0 (jar X.getInt default) → the $1$ branch.
func supportsSha512Password(d store.Device) bool {
	ok, caps := wireless.NumFromExtra(d.Extra, "fw_caps")
	return ok && caps&0x400 == 0x400
}

// supportsDasDad mirrors the DAS/DAD gate's device capability arm:
// hasCapability(1048576) — the fw_caps 0x100000 bit (main-writer
// offsets 1500-1539; accessor semantics per supportsSha512Password
// above). A record that does not report fw_caps evaluates to
// capability 0: the jar then skips every das/dad row, silently.
func supportsDasDad(d store.Device) bool {
	ok, caps := wireless.NumFromExtra(d.Extra, "fw_caps")
	return ok && caps&0x100000 == 0x100000
}

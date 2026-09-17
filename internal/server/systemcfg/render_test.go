package systemcfg

// Renderer unit tests (checkpoint 3): content rows (moved from package
// server — it was a builder-direct test), the credential-deltas contract
// (the renderer returns the former in-place ssh password-cache writes as
// values and mutates nothing), the warnings contract (debug → Warnings,
// warn → Alerts, renderer never logs), and a golden-style full render for a
// canonical evidence-derived input.

import (
	"errors"
	"strings"
	"testing"

	"github.com/lucabecker/open-unifi/internal/store"
	"github.com/lucabecker/open-unifi/internal/wireless"
)

// renderRecord mirrors the server test fixture: a U7PG2 record whose Extra
// carries the radio table exactly as the server persists it from informs
// (float64 channel for the na radio to exercise numeric normalization) and
// the fw_caps SHA-512 password capability bit.
func renderRecord() store.Device {
	return store.Device{
		MAC: "aabbccddeeff", Model: "U7PG2", State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
		Extra: store.JSONMap{"fw_caps": 1024.0, "radio_table": []any{
			map[string]any{"name": "ra0", "radio": "ng", "channel": "0",
				"tx_power_mode": "auto", "tx_power": "auto",
				"builtin_antenna": true, "builtin_ant_gain": 0.0},
			map[string]any{"name": "rai0", "radio": "na", "channel": 0.0,
				"tx_power_mode": "auto", "tx_power": "auto",
				"builtin_antenna": true, "builtin_ant_gain": 0.0},
		}},
	}
}

// workedEnvelope mirrors the doc §7 worked example: corp (wpa-p /
// correcthorse / VLAN 42) + guest (open, DISABLED — omitted with no trace).
func workedEnvelope() []wireless.Wlan {
	return []wireless.Wlan{
		{Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correcthorse",
			VLAN: 42, Enabled: true, ID: "5629b670e3f80a139930d113"},
		{Name: "guest", SSID: "guest", Security: "open", Enabled: false},
	}
}

// renderUsers1Password extracts the users.1.password value.
func renderUsers1Password(t *testing.T, sys string) string {
	t.Helper()
	for _, l := range strings.Split(sys, "\n") {
		if after, ok := strings.CutPrefix(l, "users.1.password="); ok {
			return after
		}
	}
	t.Fatal("users.1.password row missing")
	return ""
}

// users.1/users.2 row shape + per-device cache stability across renders
// (moved from package server; the cache now rides as CredentialDeltas that
// the CALLER applies — here the test, as the adapter stand-in).
func TestUsers1CacheStability(t *testing.T) {
	rec := renderRecord()
	res1, err := Render(rec, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	pw1 := renderUsers1Password(t, res1.Text)
	if !sha512BodyRx.MatchString(pw1) {
		t.Fatalf("users.1.password shape not $6$salt$hash: %q", pw1)
	}
	// The first render produced exactly one delta: the sha512 cache write.
	if len(res1.CredentialDeltas) != 1 || res1.CredentialDeltas["ssh_sha512passwd"] != pw1 {
		t.Fatalf("deltas = %v, want exactly {ssh_sha512passwd: %q}", res1.CredentialDeltas, pw1)
	}
	// Adapter contract: the caller applies the deltas; the next render then
	// reuses the cache (byte-identical hash, NO new delta).
	for k, v := range res1.CredentialDeltas {
		rec.Extra[k] = v
	}
	res2, err := Render(rec, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	pw2 := renderUsers1Password(t, res2.Text)
	if pw1 != pw2 {
		t.Fatalf("users.1.password not stable across pushes: %q vs %q", pw1, pw2)
	}
	if len(res2.CredentialDeltas) != 0 {
		t.Fatalf("cached render must produce no deltas, got %v", res2.CredentialDeltas)
	}
	if !sha512CryptMatches(defaultSSHPassword, pw1) {
		t.Fatal("cached hash does not self-check against default password ubnt")
	}
	// shape: no users.1.shell row; users.2 has its rows.
	if strings.Contains(res1.Text, "users.1.shell") {
		t.Fatal("users.1 must not carry a shell row (doc §10.1)")
	}
	for _, want := range []string{"users.2.name=nobody\n", "users.2.password=x\n",
		"users.2.shell=/bin/false\n", "users.2.status=enabled\n"} {
		if !strings.Contains(res1.Text, want) {
			t.Fatalf("users.2 missing %q", want)
		}
	}
}

// FID-23: an unrenderable SSH password fails the whole render (moved from
// package server; the injectable salt seam lives here now).
func TestUsers1PasswordGenerationFailureFailsBuild(t *testing.T) {
	rec := renderRecord()
	rec.Extra["fw_caps"] = 0.0 // md5 branch so the injectable salt seam applies
	rec.Extra["ssh_md5passwd"] = ""
	prev := randAlphaSalt
	randAlphaSalt = func(int) (string, error) { return "", errors.New("rand unavailable") }
	defer func() { randAlphaSalt = prev }()

	if _, err := Render(rec, SiteFacts{}); err == nil {
		t.Fatal("failed salt generation must fail the system_cfg build, not emit an empty users.1.password")
	}
}

// Content rows of the full-provisioning system_cfg path (moved from package
// server). Rows already covered elsewhere are deliberately NOT duplicated
// here: unifi.siteid (TestSystemCfgIdentityRows — stays in server),
// users.2.* (TestUsers1CacheStability), section head order
// (TestSystemCfgSectionHeadOrder — stays in server), and the mcad gate rows
// users.1.status/sshd.status/netconf.1.status
// (TestSystemCfgMcadValidatorGateKeysPresent — stays in server).
func TestSystemCfgProvisioningContentRows(t *testing.T) {
	rec := renderRecord()
	delete(rec.Extra, "radio_table") // the drift path's inform carries no radio_table
	res, err := Render(rec, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	sys := res.Text
	for _, want := range []string{
		"unifi.version=0.1.0-dev\n",
		"unifi.idp=disabled\n",
		"unifi.cfgcap_info=0x7\n",
		"users.status=enabled\n",
		"users.1.name=ubnt\n",
		"sshd.1.status=enabled\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("system_cfg missing %q:\n%s", want, sys)
		}
	}
	// FID-20/FID-62: no invented "# sshd"/"# misc" section headers.
	for _, wrong := range []string{"# sshd\n", "# misc\n"} {
		if strings.Contains(sys, wrong) {
			t.Fatalf("system_cfg must not carry the invented header %q:\n%s", wrong, sys)
		}
	}
	if strings.Contains(sys, "wireless.") || strings.Contains(sys, "aaa.") {
		t.Fatalf("system_cfg invented unpublished wireless lines:\n%s", sys)
	}
}

// Credential-deltas contract: a cached hash matching the password produces
// NO delta; a fresh hash produces exactly the one key; the md5 branch uses
// ssh_md5passwd; the renderer never touches the input record's Extra.
func TestRenderCredentialDeltas(t *testing.T) {
	// sha512 branch: fresh delta, applied by the caller, then absent.
	rec := renderRecord()
	if got := len(rec.Extra); got != 2 {
		t.Fatalf("input record mutated by a render is tested below; fixture has %d keys", got)
	}
	res, err := Render(rec, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.CredentialDeltas) != 1 || res.CredentialDeltas["ssh_sha512passwd"] == "" {
		t.Fatalf("fresh sha512 render deltas = %v, want exactly ssh_sha512passwd", res.CredentialDeltas)
	}
	if _, mutated := rec.Extra["ssh_sha512passwd"]; mutated {
		t.Fatal("the pure renderer mutated the input record")
	}
	for k, v := range res.CredentialDeltas {
		rec.Extra[k] = v
	}
	res2, err := Render(rec, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.CredentialDeltas) != 0 {
		t.Fatalf("cached render deltas = %v, want none", res2.CredentialDeltas)
	}

	// md5 branch (fw_caps 0): fresh ssh_md5passwd delta; a seeded matching
	// cache suppresses it.
	recMD5 := renderRecord()
	recMD5.Extra["fw_caps"] = 0.0
	resMD5, err := Render(recMD5, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resMD5.CredentialDeltas) != 1 || resMD5.CredentialDeltas["ssh_md5passwd"] == "" {
		t.Fatalf("fresh md5 render deltas = %v, want exactly ssh_md5passwd", resMD5.CredentialDeltas)
	}
	pwMD5 := renderUsers1Password(t, resMD5.Text)
	recMD5.Extra["ssh_md5passwd"] = pwMD5
	resMD5b, err := Render(recMD5, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resMD5b.CredentialDeltas) != 0 {
		t.Fatalf("cached md5 render deltas = %v, want none", resMD5b.CredentialDeltas)
	}
	if got := renderUsers1Password(t, resMD5b.Text); got != pwMD5 {
		t.Fatalf("cached md5 render changed the password: %q vs %q", got, pwMD5)
	}
}

// Warnings contract: debug-level diagnostics land in Result.Warnings
// (skipped unknown-band radios), warn-level ones in Result.Alerts (partial
// eth inventory, WPA-EAP without RADIUS, newline-injected rows skipped) —
// with the exact wording the adapter logs.
func TestRenderWarnings(t *testing.T) {
	// Debug: two unknown-band radios (real token set is na/ng/6e/scan).
	rec := renderRecord()
	rec.Extra["radio_table"] = []any{
		map[string]any{"name": "rx0", "radio": "weird"},
		map[string]any{"name": "rx1", "radio": "weird2"},
	}
	rec.Extra["ethernet_table"] = []any{map[string]any{"num_port": 2.0}}
	res, err := Render(rec, SiteFacts{WLANs: workedEnvelope()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0],
		"wireless provision: skipped 2 radio(s) with unrecognized band token") {
		t.Fatalf("warnings = %v, want the skipped-radios debug wording", res.Warnings)
	}
	if len(res.Alerts) != 0 {
		t.Fatalf("alerts = %v, want none", res.Alerts)
	}

	// Warn: partial eth inventory (no ethernet_table/if_table) and WPA-EAP
	// without RADIUS — both in one render, message-only (no attrs, matching
	// the pre-extraction slog call shapes).
	rec2 := renderRecord()
	rec2.Extra["radio_table"] = []any{
		map[string]any{"name": "ra0", "radio": "ng", "channel": "0",
			"tx_power_mode": "auto", "tx_power": "auto",
			"builtin_antenna": true, "builtin_ant_gain": 0.0},
	}
	res2, err := Render(rec2, SiteFacts{WLANs: []wireless.Wlan{
		{Name: "ent", SSID: "ent", Security: "wpa-eap", Enabled: true, ID: "eapident"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Alerts) != 2 {
		t.Fatalf("alerts = %+v, want the partial-eth + RADIUS warns", res2.Alerts)
	}
	var partialEth, radius *Alert
	for i := range res2.Alerts {
		switch {
		case strings.Contains(res2.Alerts[i].Msg, "partial eth inventory"):
			partialEth = &res2.Alerts[i]
		case strings.Contains(res2.Alerts[i].Msg, "RADIUS"):
			radius = &res2.Alerts[i]
		}
	}
	if partialEth == nil || partialEth.Where != "" || partialEth.Key != "" {
		t.Fatalf("partial-eth alert = %+v, want message-only", partialEth)
	}
	if radius == nil || radius.Where != "" || radius.Key != "" {
		t.Fatalf("RADIUS alert = %+v, want message-only", radius)
	}
	if len(res2.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", res2.Warnings)
	}

	// Warn: a newline smuggled into a value skips the row (fail loud, never
	// emit) and is reported as a STRUCTURED alert — the pre-extraction
	// lineWriter logged Warn(msg, "where", where, "key", key).
	rec3 := renderRecord()
	rec3.Extra["radio_table"] = []any{
		map[string]any{"name": "ra0", "radio": "ng", "channel": "5\nevil=1",
			"tx_power_mode": "auto", "tx_power": "auto",
			"builtin_antenna": true, "builtin_ant_gain": 0.0},
	}
	res3, err := Render(rec3, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res3.Alerts) != 2 {
		t.Fatalf("alerts = %+v, want the newline-skip + partial-eth warns", res3.Alerts)
	}
	var skip *Alert
	for i := range res3.Alerts {
		if res3.Alerts[i].Msg == "config blob: row skipped, newline in value" {
			skip = &res3.Alerts[i]
		}
	}
	if skip == nil || skip.Where != "wireless-radio" || skip.Key != "radio.1.channel" {
		t.Fatalf("newline-skip alert = %+v, want structured where/key", skip)
	}
	// R4(a): the actual injected token is "evil=1"; it must never leak.
	if strings.Contains(res3.Text, "evil=1") {
		t.Fatalf("injected newline value leaked into system_cfg:\n%s", res3.Text)
	}
}

// R4(c): SiteFacts.SSHPassword overrides the hashed password — the users.1
// row self-checks against the override and NOT the default ("ubnt"); the
// sshd rows are untouched by the password choice.
func TestRenderSSHPasswordOverride(t *testing.T) {
	res, err := Render(renderRecord(), SiteFacts{SSHPassword: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}
	pw := renderUsers1Password(t, res.Text)
	if !sha512CryptMatches("hunter2", pw) {
		t.Fatalf("users.1.password must self-check against the override: %q", pw)
	}
	if sha512CryptMatches("ubnt", pw) {
		t.Fatalf("users.1.password must not verify against the default: %q", pw)
	}
	for _, want := range []string{"sshd.status=enabled\n", "sshd.auth.passwd=enabled\n",
		"sshd.1.status=enabled\n", "sshd.1.ifname=br0\n"} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("ssh rows changed by the password override, missing %q:\n%s", want, res.Text)
		}
	}
}

// R4(d): the FID-23 path on the sha512 branch — a failing salt generation
// fails the whole render, and an empty generated hash is likewise rejected.
func TestSha512SaltGenerationFailureFailsRender(t *testing.T) {
	rec := renderRecord() // fw_caps 0x400 → the sha512 branch
	prev := randSalt
	randSalt = func(int) (string, error) { return "", errors.New("rand unavailable") }
	defer func() { randSalt = prev }()

	if _, err := Render(rec, SiteFacts{}); err == nil || !strings.Contains(err.Error(), "sha512 password") {
		t.Fatalf("failing salt generation must fail the render, got %v", err)
	}
}

func TestSha512EmptyHashGuardFailsRender(t *testing.T) {
	rec := renderRecord()
	prev := randSalt
	randSalt = func(int) (string, error) { return "", nil }
	defer func() { randSalt = prev }()

	if _, err := Render(rec, SiteFacts{}); err == nil || !strings.Contains(err.Error(), "generated empty") {
		t.Fatalf("empty sha512 hash must fail the render, got %v", err)
	}
}

// R4(e): a stale ssh_md5passwd cache (valid for "ubnt") is IGNORED on the
// sha512 branch — the output is $6$ and the deltas carry ONLY
// ssh_sha512passwd (the md5 cache is not the sha512 one).
func TestRenderStaleMD5CacheIgnored(t *testing.T) {
	rec := renderRecord() // fw_caps 1024 → sha512 branch
	stale, err := md5Crypt("ubnt")
	if err != nil {
		t.Fatal(err)
	}
	rec.Extra["ssh_md5passwd"] = stale
	res, err := Render(rec, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	pw := renderUsers1Password(t, res.Text)
	if !strings.HasPrefix(pw, "$6$") {
		t.Fatalf("stale md5 cache must not pin the output, got %q", pw)
	}
	if len(res.CredentialDeltas) != 1 || res.CredentialDeltas["ssh_sha512passwd"] != pw {
		t.Fatalf("deltas = %v, want exactly ssh_sha512passwd (md5 cache ignored)", res.CredentialDeltas)
	}
}

// Golden-style full render: the canonical evidence-derived input (the
// worked-example device, no WLANs) pins the twelve section heads in STRICT
// FIRST-OCCURRENCE ORDER (the only full-order pin in the repo), the exact
// unifi block, the country rows, and the factory-echo blocks byte-for-byte
// (the wireless compound itself is pinned by the live-evidence
// worked-example test through the handler).
func TestRenderGolden(t *testing.T) {
	rec := renderRecord()
	res, err := Render(rec, SiteFacts{CountryCode: 840})
	if err != nil {
		t.Fatal(err)
	}
	sys := res.Text
	// R4(b): the twelve section heads in STRICT first-occurrence order —
	// the only full-order pin in the repo.
	prev := -1
	for _, head := range []string{
		"# unifi\n", "# users\n", "# wlans (radio)\n", "# vlan\n", "# bridge\n",
		"# netconf\n", "# dhcpc\n", "# connectivity\n", "# syslog\n",
		"# route\n", "# ntpclient\n", "# ebtables\n",
	} {
		i := strings.Index(sys, head)
		if i < 0 {
			t.Fatalf("golden render missing section %q:\n%s", head, sys)
		}
		if i <= prev {
			t.Fatalf("section order broken: %q at offset %d follows offset %d", head, i, prev)
		}
		prev = i
	}
	// No invented "# system"/"# sshd"/"# misc" headers.
	for _, wrong := range []string{"# system\n", "# sshd\n", "# misc\n"} {
		if strings.Contains(sys, wrong) {
			t.Fatalf("golden render carries the invented header %q:\n%s", wrong, sys)
		}
	}
	// Exact unifi block (canonical input: no anonymous ids, default site).
	unifiBlock := "# unifi\n" +
		"unifi.version=0.1.0-dev\n" +
		"unifi.siteid=default\n" +
		"unifi.idp=disabled\n" +
		"unifi.cfgcap_info=0x7\n"
	if !strings.Contains(sys, unifiBlock) {
		t.Fatalf("golden unifi block mismatch:\n%s", sys)
	}
	// Country rows carry the resolved code.
	if strings.Count(sys, "radio.countrycode=840\n") != 1 ||
		strings.Count(sys, "radio.1.countrycode=840\n") != 1 ||
		strings.Count(sys, "radio.2.countrycode=840\n") != 1 {
		t.Fatalf("country rows wrong:\n%s", sys)
	}
	// An explicit 840 renders the same rows (same record + applied
	// credential cache, so the random hash cannot differ).
	recZero := renderRecord()
	for k, v := range res.CredentialDeltas {
		recZero.Extra[k] = v
	}
	res0, err := Render(recZero, SiteFacts{CountryCode: 840})
	if err != nil {
		t.Fatal(err)
	}
	if res0.Text != sys {
		t.Fatal("explicit CountryCode 840 must match the default-resolved render")
	}
	// Factory echo: connectivity/syslog/route/ntp/ebtails blocks.
	echoBlock := "# connectivity\n" +
		"connectivity.status=enabled\n" +
		"connectivity.uplink_bridge=br0\n" +
		"connectivity.uplink_eth=eth0\n" +
		"connectivity.uplink_wds=ath1\n" +
		"# syslog\n" +
		"syslog.status=enabled\n" +
		"syslog.file=/var/log/messages\n" +
		"syslog.level=8\n" +
		"syslog.remote.status=disabled\n" +
		"syslog.remote.ip=192.168.1.1\n" +
		"syslog.remote.port=514\n" +
		"syslog.rotate=1\n" +
		"syslog.size=200\n" +
		"sshd.status=enabled\n" +
		"sshd.auth.passwd=enabled\n" +
		"sshd.1.status=enabled\n" +
		"sshd.1.ifname=br0\n" +
		"# route\n" +
		"route.status=enabled\n" +
		"route.1.status=enabled\n" +
		"route.1.devname=br0\n" +
		"route.1.ip=224.0.0.0\n" +
		"route.1.netmask=3\n" +
		"# ntpclient\n" +
		"ntpclient.status=enabled\n" +
		"ntpclient.1.status=enabled\n" +
		"ntpclient.1.server=0.ubnt.pool.ntp.org\n" +
		"# ebtables\n" +
		"ebtables.status=enabled\n" +
		"ebtables.1.cmd=-t broute -A BROUTING -p 0x888e -i ath0 -j DROP\n" +
		"mgmt.discovery.status=enabled\n" +
		"mgmt.flavor=ace\n" +
		"mgmt.is_default=true\n" +
		"dhcpd.status=disabled\n" +
		"dhcpd.1.status=disabled\n" +
		"httpd.status=disabled\n"
	if !strings.Contains(sys, echoBlock) {
		t.Fatalf("golden factory-echo block mismatch:\n--- got tail ---\n%s", sys[strings.Index(sys, "# connectivity"):])
	}
	// Site facts override: sshd.1.ifname + route.1.devname follow mgmt_dev.
	recDev := renderRecord()
	recDev.Extra["mgmt_dev"] = "br0.9"
	resDev, err := Render(recDev, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sshd.1.ifname=br0.9\n", "route.1.devname=br0.9\n", "connectivity.uplink_bridge=br0.9\n"} {
		if !strings.Contains(resDev.Text, want) {
			t.Fatalf("mgmt_dev override missing %q:\n%s", want, resDev.Text)
		}
	}
}

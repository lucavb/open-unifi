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

	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
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

// TestRenderWithPlanIgnoresFactsWLAN pins the RenderWithPlan independence
// contract the docblock claims: inside this entry the plan is the SOLE
// wireless input. For one device and one plan-enveloping pair, feeding the
// facts a DIFFERENT envelope while handing the SAME plan must produce the
// byte-identical text — the renderer's wireless rows come from the plan,
// never from facts.WLANs. Only facts.WLANs is varied here deliberately:
// CountryCode and SSHPassword still render into rows (countrycode and the
// users.1 hash), so varying them would double as unrelated-fixture churn
// rather than an independence pin.
func TestRenderWithPlanIgnoresFactsWLAN(t *testing.T) {
	d := renderRecord()
	envA := planPinEnvelopeA()
	envB := planPinEnvelopeB()
	if len(envA) == 0 || len(envB) == 0 {
		t.Fatal("fixtures must be non-empty")
	}
	planB := wireless.PlanProvisioning(d, envB)
	// Warm the sha512 password cache FIRST: users.1.password salts fresh
	// random on every UNCACHED render, so an uncached pair would differ
	// even with zero facts leak — the cache row is what makes two renders
	// byte-comparable (caching is the settle path's own contract).
	warm, werr := RenderWithPlan(d, SiteFacts{WLANs: envB}, planB)
	if werr != nil {
		t.Fatalf("warm render: %v", werr)
	}
	for k, v := range warm.CredentialDeltas {
		d.Extra[k] = v
	}
	resA, err := RenderWithPlan(d, SiteFacts{WLANs: planPinEnvelopeA()}, planB)
	if err != nil {
		t.Fatalf("render A-facts/B-plan: %v", err)
	}
	resB, err := RenderWithPlan(d, SiteFacts{WLANs: envB}, planB)
	if err != nil {
		t.Fatalf("render B-facts/B-plan: %v", err)
	}
	if resA.Text != resB.Text {
		t.Fatalf("facts.WLANs must not leak into a RenderWithPlan call whose plan is fixed:\n-facts-A:\n%s\n-facts-B:\n%s", resA.Text, resB.Text)
	}
}

// planPinEnvelopeA/B are two materially different envelopes (distinct
// SSIDs, VLANs and counters visible in a render): if facts.WLANs leaked
// into the wireless sections the two texts above would diverge loudly.
func planPinEnvelopeA() []wireless.Wlan {
	return []wireless.Wlan{
		{Name: "corpA", SSID: "corpA", Security: "wpa-p", Passphrase: "correcthorse", VLAN: 42, Enabled: true, ID: "ida"},
	}
}

func planPinEnvelopeB() []wireless.Wlan {
	return []wireless.Wlan{
		{Name: "corpB", SSID: "corpB", Security: "open", VLAN: 7, Enabled: true, ID: "idb"},
	}
}

// TestUsers1CacheStability pins the users.1/users.2 row shape: per-device
// cache stability across renders (moved from package server; the cache now
// rides as CredentialDeltas that the CALLER applies — here the test, as
// the adapter stand-in).
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

// Radio intent (admin-owned layer over the §3 echo rows): intent wins
// where set, the device radio_table echo survives verbatim where unset,
// and the txpower_mode row is never intent-driven (documented omission).
// The row shape/order is pinned elsewhere (golden + worked-example
// tests); these assertions only pin WHICH value each row carries.
func TestRadioIntentWinsOverEcho(t *testing.T) {
	rec := renderRecord()
	// Non-default echoes so "intent wins" is provable per row: ra0 (ng)
	// echoes channel 6 / tx_power 14; rai0 (na) echoes channel 149.
	rec.Extra["radio_table"] = []any{
		map[string]any{"name": "ra0", "radio": "ng", "channel": "6",
			"tx_power_mode": "auto", "tx_power": "14",
			"builtin_antenna": true, "builtin_ant_gain": 0.0},
		map[string]any{"name": "rai0", "radio": "na", "channel": 149.0,
			"tx_power_mode": "auto", "tx_power": "auto",
			"builtin_antenna": true, "builtin_ant_gain": 0.0},
	}
	// Intent: ra0 txpower fixed 10 dBm (float64 — the admin API stores
	// numbers as JSON scalars); rai0 channel fixed 36.
	rec.Extra["radio_intent"] = map[string]any{
		"ra0":  map[string]any{"txpower": 10.0},
		"rai0": map[string]any{"channel": 36.0},
	}
	wls := []wireless.Wlan{{Name: "w", SSID: "w", Security: "open", Enabled: true}}
	res, err := Render(rec, SiteFacts{WLANs: wls})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"radio.1.channel=6\n",         // no channel intent → echo survives
		"radio.1.txpower=10\n",        // txpower intent beats echo "14"
		"radio.2.channel=36\n",        // channel intent beats echo "149"
		"radio.2.txpower=auto\n",      // no txpower intent → echo default
		"radio.1.txpower_mode=auto\n", // mode row NEVER intent-driven
	} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("radio intent resolution wrong, missing %q:\n%s", want, res.Text)
		}
	}

	// Intent "0" (explicit auto) must also WIN over a non-default echo —
	// "0" is a set value, not an unset sentinel.
	recAuto := renderRecord()
	recAuto.Extra["radio_table"] = rec.Extra["radio_table"]
	recAuto.Extra["radio_intent"] = map[string]any{
		"rai0": map[string]any{"channel": 0.0},
	}
	resAuto, err := Render(recAuto, SiteFacts{WLANs: wls})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resAuto.Text, "radio.2.channel=0\n") {
		t.Fatalf("explicit-auto channel intent must beat the 149 echo:\n%s", resAuto.Text)
	}

	// Byte-identity contract: an EMPTY intent map renders byte-identical
	// to a record with no intent layer at all (nil and {} are the same
	// state; existing golden pins cover the no-layer shape). The ssh
	// cache is seeded from the first render so the random salt cannot
	// masquerade as a layer diff.
	recNone := renderRecord()
	recNone.Extra["radio_table"] = rec.Extra["radio_table"]
	resNone, err := Render(recNone, SiteFacts{WLANs: wls})
	if err != nil {
		t.Fatal(err)
	}
	recEmpty := renderRecord()
	recEmpty.Extra["radio_table"] = rec.Extra["radio_table"]
	recEmpty.Extra["radio_intent"] = map[string]any{}
	for _, seed := range []*store.Device{&recNone, &recEmpty} {
		for k, v := range resNone.CredentialDeltas {
			seed.Extra[k] = v
		}
	}
	resNone, err = Render(recNone, SiteFacts{WLANs: wls})
	if err != nil {
		t.Fatal(err)
	}
	resEmpty, err := Render(recEmpty, SiteFacts{WLANs: wls})
	if err != nil {
		t.Fatal(err)
	}
	if resNone.Text != resEmpty.Text {
		t.Fatal("empty radio_intent map must render byte-identical to no intent layer")
	}
	// Malformed intent shapes are skipped row-wise, never panic, and
	// never leak into rows (echo still wins).
	recBad := renderRecord()
	recBad.Extra["radio_table"] = rec.Extra["radio_table"]
	recBad.Extra["ssh_sha512passwd"] = recNone.Extra["ssh_sha512passwd"]
	recBad.Extra["radio_intent"] = map[string]any{"ra0": "garbage", "": map[string]any{"channel": 1.0}}
	resBad, err := Render(recBad, SiteFacts{WLANs: wls})
	if err != nil {
		t.Fatal(err)
	}
	if resBad.Text != resNone.Text {
		t.Fatal("malformed radio_intent must be inert (echo-only render)")
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
		"dhcpd.status=disabled\n" +
		"dhcpd.1.status=disabled\n" +
		"httpd.status=disabled\n"
	if !strings.Contains(sys, echoBlock) {
		t.Fatalf("golden factory-echo block mismatch:\n--- got tail ---\n%s", sys[strings.Index(sys, "# connectivity"):])
	}
	// A2 boot-guard hazard: the row must NEVER be emitted in any value.
	// /lib/preinit/99_21_ubnt_ubntconf replaces a restored blob text
	// containing mgmt.is_default=true with the factory template (fw
	// 6.8.2), factory-resetting the WLANs on every reboot.
	if strings.Contains(sys, "mgmt.is_default") {
		t.Fatalf("mgmt.is_default row emitted — boot guard would factory-reset on reboot:\n%s", sys[strings.Index(sys, "# ebtables"):])
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

// ---- sshd.auth.key.<n>.* + sshd.auth.passwd site facts --------------------

// Synthetic test key material: structurally COMPLETE fabricated blobs (the
// base64 decodes to a marker'd RFC 4253 wire blob — "testkey" padded with
// 'A's to 32 bytes — so the bytes are visibly fake, never a real key).
// No real key material, ever: ParsePublicKey checks the RFC 4253 §6.6
// structure walk (walkWireBlob), so the blobs must at least be
// well-formed on the wire.
//
// ed25519 blob: uint32(11)+"ssh-ed25519"+uint32(32)+32×marker
// rsa blob:     uint32(7)+"ssh-rsa"+uint32(3)+{01 00 01}+uint32(32)+32×marker
const (
	testKeyEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB test@ap"
	testKeyRSA     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB second@ap"
)

// R5(a): one key with a comment emits the exact 4-row family, in the jar's
// row order (status/value/type per the String.txt:2849-2911 format strings,
// comment last), 1-based index 1.
func TestRenderSSHPublicKeySingle(t *testing.T) {
	pk, err := ParsePublicKey(testKeyEd25519)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Render(renderRecord(), SiteFacts{SSHPublicKeys: []PublicKey{pk}})
	if err != nil {
		t.Fatal(err)
	}
	want := "sshd.auth.key.1.status=enabled\n" +
		"sshd.auth.key.1.value=AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n" +
		"sshd.auth.key.1.type=ssh-ed25519\n" +
		"sshd.auth.key.1.comment=test@ap\n"
	if !strings.Contains(res.Text, want) {
		t.Fatalf("single-key row family mismatch:\n%s", res.Text)
	}
	// And nothing beyond index 1.
	for _, absent := range []string{"sshd.auth.key.2.", "sshd.auth.key.0."} {
		if strings.Contains(res.Text, absent) {
			t.Fatalf("unexpected row %q emitted:\n%s", absent, res.Text)
		}
	}
}

// R5(b): two keys are numbered 1, 2 in slice order — no dedup, no resort.
func TestRenderSSHPublicKeysTwoNumbered(t *testing.T) {
	k1, err := ParsePublicKey(testKeyEd25519)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParsePublicKey(testKeyRSA)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Render(renderRecord(), SiteFacts{SSHPublicKeys: []PublicKey{k1, k2}})
	if err != nil {
		t.Fatal(err)
	}
	want := "sshd.auth.key.1.value=AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n" +
		"sshd.auth.key.1.type=ssh-ed25519\n" +
		"sshd.auth.key.1.comment=test@ap\n" +
		"sshd.auth.key.2.status=enabled\n" +
		"sshd.auth.key.2.value=AAAAB3NzaC1yc2EAAAADAQABAAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n" +
		"sshd.auth.key.2.type=ssh-rsa\n" +
		"sshd.auth.key.2.comment=second@ap\n"
	if !strings.Contains(res.Text, want) {
		t.Fatalf("two-key numbering/order mismatch:\n%s", res.Text)
	}
}

// R5(b2): identical parsed keys are BOTH rendered — the documented no-dedup
// contract: slice position is the only identity on the wire (firmware row
// name is the index), so dedup at the controller would silently drop a
// deliberately repeated key entry.
func TestRenderSSHPublicKeysIdenticalNoDedup(t *testing.T) {
	k, err := ParsePublicKey(testKeyEd25519)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Render(renderRecord(), SiteFacts{SSHPublicKeys: []PublicKey{k, k}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"sshd.auth.key.1.type=ssh-ed25519\n", "sshd.auth.key.1.comment=test@ap\n",
		"sshd.auth.key.2.type=ssh-ed25519\n", "sshd.auth.key.2.comment=test@ap\n",
	} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("no-dedup pin: missing %q:\n%s", want, res.Text)
		}
	}
}

// R5(c): a commentless key emits NO comment row (the firmware's three-field
// line writer only sees type+value).
func TestRenderSSHPublicKeyNoCommentOmitsRow(t *testing.T) {
	pk, err := ParsePublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Render(renderRecord(), SiteFacts{SSHPublicKeys: []PublicKey{pk}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Text, "sshd.auth.key.1.comment") {
		t.Fatalf("comment row emitted for a commentless key:\n%s", res.Text)
	}
	if !strings.Contains(res.Text, "sshd.auth.key.1.value=AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n") {
		t.Fatalf("value row missing:\n%s", res.Text)
	}
}

// R5(c2): zero keys emit zero sshd.auth.key rows — the default-facts render
// is byte-identical to the pre-feature contract.
func TestRenderSSHNoKeysNoKeyRows(t *testing.T) {
	res, err := Render(renderRecord(), SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(res.Text, "sshd.auth.key.") {
		t.Fatalf("key rows emitted with zero configured keys:\n%s", res.Text)
	}
}

// R5(d): the ParsePublicKey fail-closed table — structurally complete
// synthetic ed25519 and rsa lines parse, and every malformed shape is an
// error (never a lenient pass).
func TestParsePublicKeyTable(t *testing.T) {
	valid := map[string]PublicKey{
		testKeyEd25519: {
			Type:    "ssh-ed25519",
			Value:   "AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
			Comment: "test@ap",
		},
		testKeyRSA: {
			Type:    "ssh-rsa",
			Value:   "AAAAB3NzaC1yc2EAAAADAQABAAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
			Comment: "second@ap",
		},
	}
	for line, want := range valid {
		got, err := ParsePublicKey(line)
		if err != nil {
			t.Fatalf("ParsePublicKey(%q) = err %v, want ok", line, err)
		}
		if got != want {
			t.Fatalf("ParsePublicKey(%q) = %+v, want %+v", line, got, want)
		}
	}
	for _, line := range []string{
		"AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", // 1 field
		"", // 0 fields
		"opendir3 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",    // bad type token
		"ssh-ed25519 !!!not-base64!!! test@ap",                                             // invalid base64
		"SSH-ED25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB", // uppercase rejected
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXk!!!",                               // invalid base64 padding
		// Structure-walk rejects (the RFC 4253 §6.6 wire shape):
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5", // name-only blob: 1 field < 2 total
		// Mid-body truncation: the 32-byte final field cut at byte 9
		// ("AAAAC3...QUFB" prefix of the good blob, trailing "=" gone).
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFB",
		// Type/value mismatch: token ssh-rsa but the blob names ssh-ed25519.
		"ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
		// The newline pin: a \n inside the value yields 4 tokens —
		// strings.Fields tokenization, NOT the base64 decoder (which
		// silently skips \n), is the newline gate.
		"ssh-rsa AAAA\nBBBB",
	} {
		if _, err := ParsePublicKey(line); err == nil {
			t.Fatalf("ParsePublicKey(%q) unexpectedly succeeded", line)
		}
	}
}

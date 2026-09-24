package server

// zz_live_candidate_scratch_test.go — live-round successive-push candidate
// gates for the 2026-09-19 full-chain validation round (the nine commits
// after 34082cd0, the last device-verified round): blocked_sta delivery, the
// per-radio channel intent, and the WPA-EAP envelope; for the
// 2026-09-20 DAS/DAD round: the standing full-accounting candidate
// (auth + acct + interim + das); and for the 2026-09-24 WPA3 round: the
// wpa3-p and wpa2-wpa3 re-security candidates. Every gate loads
// the CURRENT live fixtures (live-devices.json + live-wireless.json) and
// parse-diffs its candidate against the DEVICE-VERIFIED applied bytes
// (live-applied-sys.txt, sha256 11cb0472… — re-seeded by the 2026-09-21
// site-settings round, whose key-rows full-provisioning render the device
// confirmed byte-identical; earlier re-seeds: the 2026-09-20
// factory-window set-inform round, sha ad41cdad…. The 2026-09-20
// DAS/DAD round's das-state push is archived row-for-row in
// live-das-applied-sys.txt, sha256 f60d458e…), because the live question
// is exactly "which on-device plugins would this push restart". Gates
// skip when the harness is absent (it lives only on this workstation
// under tmpwork/harness-20260917/, which is gitignored).
//
// Gate discipline (WLAN-ACCEPTANCE-6.8.2.15592.md): zero violations — no
// unmanaged row may differ — and the intended deltas must stay inside the
// section the feature owns:
//   - blocked_sta: the set rides the §4 wire field OUTSIDE system_cfg, so
//     the render must stay byte-identical to the applied bytes: no plugin
//     restarts at all on the blocked_sta drift cycle.
//   - radio intent: exactly one row, radio.2.channel "0"→"36"; the
//     restart set stays {radio} — evidenced survivable since the accepted
//     2026-09-17 factory push, but this round is its first dedicated
//     live evidence (radio-lane obligation).
//   - wpa-eap: deltas confined to {wireless, aaa} — the same restart set
//     as the proven C1/A2 security rounds. zzLiveEapSecret is synthetic
//     bench material, not a site secret; the live PUT must send the same
//     constant so the gated candidate and the pushed bytes are identical.
//   - wpa3-p / wpa2-wpa3: deltas confined to {aaa} (authmode stays 1);
//     pmf flips to enabled 2|1, wpa 3->2, the wpa3.* rows arrive, mgmt
//     WPA-PSK -> SAE. The passphrase is KEPT (the live PUT preserves it);
//     the sae.psk.1 pair (wpa3-p) and the DUPLICATE wpa.psk pair
//     (wpa2-wpa3) are raw-count asserted — a parse-diff collapses
//     duplicate rows and cannot see them (the das dad.status precedent).
//
// The LED override rides mgmt_cfg (§2), not system_cfg: its system_cfg
// invariance is the TestZZLiveIntentVsApplied steady state, its mgmt_cfg
// bytes are unit-goldened, and the live round observes the LED directly —
// no gate here can check a lamp.
//
// Unlike the synthetic-baseline gates these do NOT apply the
// zzExemptIsDefaultMigration filter: the live applied bytes were captured
// POST-fix, so a renderer that ever emits mgmt.is_default again must
// FAIL here (the fw 6.8.2 boot path would factory-reset the WLAN text on
// the next device reboot — see the zzZZAllowPrefix comment). Since the
// 2026-09-20 re-seed they also do NOT apply zzExemptLedBarMigration: the
// live applied capture is POST-ledbar, so a ledbar.* drift must FAIL here
// too (the filter stays only at the synthetic-baseline gates, whose
// pinned night reference and factory capture predate the lane).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

// zzLiveFixtures loads the live record, the live envelope, the live
// site-settings record, and the device-verified applied bytes; the gates
// skip when any is absent.
func zzLiveFixtures(t *testing.T) (rec store.Device, env []Wlan, appliedRaw []byte) {
	t.Helper()
	raw, err := os.ReadFile(zzHarnessDir + "/live-devices.json")
	if err != nil {
		t.Skipf("live record not present (%v)", err)
	}
	wraw, err := os.ReadFile(zzHarnessDir + "/live-wireless.json")
	if err != nil {
		t.Skipf("live envelope not present (%v)", err)
	}
	araw, err := os.ReadFile(zzHarnessDir + "/live-applied-sys.txt")
	if err != nil {
		t.Skipf("device-verified applied bytes not present (%v)", err)
	}
	var file struct {
		Devices map[string]store.Device `json:"devices"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("live devices.json: %v", err)
	}
	var ok bool
	rec, ok = file.Devices["aabbccddee02"]
	if !ok {
		t.Fatalf("live device aa:bb:cc:dd:ee:02 absent from fetched record: %d devices", len(file.Devices))
	}
	var envFile struct {
		Wlans []Wlan `json:"wlans"`
	}
	if err := json.Unmarshal(wraw, &envFile); err != nil {
		t.Fatalf("live wireless.json: %v", err)
	}
	if len(envFile.Wlans) == 0 {
		t.Fatalf("live wireless envelope is empty")
	}
	zzApplyLiveDeviceIntentFixture(t, &rec)
	return rec, envFile.Wlans, araw
}

// zzFailIsDefaultRegression trips when a render against the post-fix live
// applied bytes emits the mgmt.is_default row anyway — that is not an
// exempted migration here, it is the boot-guard regression that would
// factory-reset the WLAN text on the next device reboot.
func zzFailIsDefaultRegression(t *testing.T, intended []string) {
	t.Helper()
	for _, r := range intended {
		if strings.HasPrefix(r, "mgmt.is_default:") {
			t.Fatalf("renderer emitted mgmt.is_default against the post-fix applied bytes — the 2026-09-19 boot-guard fix regressed (the fw 6.8.2 boot path would factory-reset the WLAN text on the next device reboot); ABORT: %s", r)
		}
	}
}

// TestZZLiveBlockedStaRenderUnchanged — the blocked_sta push gate: the
// admin-owned client set (docs/PROTOCOL-mgmt.md §4) rides the blocked_sta
// response field OUTSIDE system_cfg, so adding a client must leave the
// rendered system_cfg byte-identical to the device-verified applied bytes.
// The blocked_sta drift cycle mints cfgversion and re-provisions, but the
// device-side apply must restart NO plugin. Any row delta here means the
// blocked set leaked into system_cfg and the push is aborted.
func TestZZLiveBlockedStaRenderUnchanged(t *testing.T) {
	rec, env, appliedRaw := zzLiveFixtures(t)
	if _, err := store.AddBlockedClient(&rec, "00:11:22:33:44:55"); err != nil {
		t.Fatalf("seed blocked client: %v", err)
	}
	if got := store.BlockedClients(rec); len(got) != 1 || got[0] != "001122334455" {
		t.Fatalf("blocked set = %v, want [001122334455]", got)
	}
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	intended, violations := zzRunGate(t, "live-blocked-candidate vs DEVICE-VERIFIED APPLIED bytes (must be byte-identical)", appliedRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the blocked_sta candidate: %d unmanaged row(s) differ — ABORT the push: %v", len(violations), violations)
	}
	zzFailIsDefaultRegression(t, intended)
	if len(intended) > 0 {
		t.Fatalf("blocked_sta must not touch system_cfg: %d managed row(s) differ — ABORT the push: %v", len(intended), intended)
	}
	fmt.Printf("[live-blocked-candidate] system_cfg byte-identical to the applied bytes; the blocked set rides the §4 wire field only — PUSH-PRE-CLEARED\n")
}

// TestZZLiveRadioIntentCandidateVsApplied — the live channel-intent push
// gate (radio lane): the live record + the admin-owned
// Extra["radio_intent"] layer (wifi1 = the na radio, channel 36) with the
// live envelope, diffed against the device-verified applied bytes. The
// intended delta must be the ONE row radio.2.channel "0"→"36"; every
// unmanaged section must stay byte-identical. The restart set is {radio}:
// evidenced survivable since the accepted 2026-09-17 factory push, but
// this round is its first dedicated live evidence — the push happens only
// after this gate passes, and the live result is recorded in the
// acceptance doc (radio-lane obligation).
func TestZZLiveRadioIntentCandidateVsApplied(t *testing.T) {
	rec, env, appliedRaw := zzLiveFixtures(t)
	rec.Extra["radio_intent"] = map[string]any{
		"wifi1": map[string]any{"channel": 36.0},
	}
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-radio-intent-candidate-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[live-radio-intent-candidate] render sha256=%s\n",
		func() string { sum := sha256.Sum256([]byte(sys)); return hex.EncodeToString(sum[:]) }())
	intended, violations := zzRunGate(t, "live-radio-intent-candidate vs DEVICE-VERIFIED APPLIED bytes", appliedRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the radio-intent candidate: %d unmanaged row(s) differ — ABORT the push: %v", len(violations), violations)
	}
	zzFailIsDefaultRegression(t, intended)
	if len(intended) != 1 || !strings.HasPrefix(intended[0], `radio.2.channel: "0" -> "36"`) {
		t.Fatalf("radio-intent candidate must change exactly one row (radio.2.channel 0->36); got %v", intended)
	}
	fmt.Printf("[live-radio-intent-candidate] restart set = {radio}: one intended row radio.2.channel 0->36 — PUSH-PRE-CLEARED shape\n")
}

// zzLiveEapSecret is the test-only RADIUS shared secret for the wpa-eap
// live push (synthetic bench material, not a site secret; the bench host
// runs no RADIUS daemon on 1812 — the push validates the envelope shape
// and the {wireless, aaa} restart, not client auth). The same constant
// must be sent by the PUT that performs the live push so the gated
// candidate and the pushed bytes are identical.
const zzLiveEapSecret = "openunifi-fake-eap-secret-20260919"

// TestZZLiveEapCandidateVsApplied — the WPA-EAP push gate: the live
// envelope (id preserved verbatim) re-secured to wpa-eap with an inline
// RADIUS profile, rendered and diffed against the running bytes.
// Enforced: zero violations and every intended delta inside {wireless,
// aaa} — the same restart set as the proven C1/A2 wpa-p rounds; any
// netconf/bridge/connectivity/dhcpc row moving is the fatal shape and
// aborts the push. The live round reverts the envelope to the wpa-p
// baseline afterwards, so this gate stays a standing shape gate rather
// than a completed-round skip.
func TestZZLiveEapCandidateVsApplied(t *testing.T) {
	rec, env, appliedRaw := zzLiveFixtures(t)
	if len(env) != 1 {
		t.Fatalf("expected exactly the one live gate-check WLAN, got %d", len(env))
	}
	cand := env[0]
	if cand.Security == "wpa-eap" {
		t.Skipf("live envelope already wpa-eap — the candidate would be the steady state; see TestZZLiveIntentVsApplied")
	}
	if cand.Security != "wpa-p" {
		t.Fatalf("live envelope security = %q, expected the wpa-p baseline before the EAP mutation", cand.Security)
	}
	cand.Security, cand.Passphrase = "wpa-eap", ""
	cand.RadiusServers = []wireless.RadiusServer{{IP: "10.10.10.10", Port: 1812}}
	cand.RadiusSecret = zzLiveEapSecret
	cand.RadiusVLANMode = "disabled"
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return []Wlan{cand} }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-eap-candidate-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[live-eap-candidate] render sha256=%s\n",
		func() string { sum := sha256.Sum256([]byte(sys)); return hex.EncodeToString(sum[:]) }())
	intended, violations := zzRunGate(t, "live-eap-candidate vs DEVICE-VERIFIED APPLIED bytes", appliedRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the wpa-eap candidate: %d unmanaged row(s) differ — ABORT the push: %v", len(violations), violations)
	}
	zzFailIsDefaultRegression(t, intended)
	for _, d := range intended {
		if !strings.HasPrefix(d, "wireless.") && !strings.HasPrefix(d, "aaa.") {
			t.Fatalf("wpa-eap candidate touches rows beyond {wireless, aaa} — ABORT the push: %s", d)
		}
	}
	var radius, mgmt bool
	for _, d := range intended {
		switch {
		case strings.Contains(d, "radius.auth."):
			radius = true
		case strings.Contains(d, `aaa.1.wpa.key.1.mgmt: "WPA-PSK" -> "WPA-EAP"`):
			mgmt = true
		}
	}
	if !radius {
		t.Fatalf("wpa-eap candidate emits no aaa.*.radius.auth.* row — the RADIUS profile did not reach the render; got %v", intended)
	}
	if !mgmt {
		t.Fatalf("wpa-eap candidate leaves aaa.1.wpa.key.1.mgmt at WPA-PSK — the mutation did not reach the render; got %v", intended)
	}
	// wpa-p and wpa-eap share authmode=1, so NO wireless.* row may change:
	// the EAP shape lives entirely in aaa.* (the jar's placeholder
	// aaa.<n>.wpa.psk "letmeinnow" included — byte-exact §5 emission, see
	// the wireless_eap goldens). The restart set is therefore {aaa}.
	var wirelessRows int
	for _, d := range intended {
		if strings.HasPrefix(d, "wireless.") {
			wirelessRows++
		}
	}
	if wirelessRows != 0 {
		t.Fatalf("wpa-eap candidate changed %d wireless.* row(s) — authmode must stay 1 across the security flip; got %v", wirelessRows, intended)
	}
	fmt.Printf("[live-eap-candidate] %d intended deltas, all inside aaa.* (restart set = {aaa}; {wireless, aaa} pre-cleared shape) — PUSH-PRE-CLEARED\n", len(intended))
}

// zzLiveDasSecret is the test-only RADIUS shared secret for the 2026-09-20
// DAS/DAD live round (synthetic bench material, not a site secret; the
// bench host runs no RADIUS daemon — the round validated the envelope
// shape, the {aaa} restart set, and the das/dad byte shape on the wire,
// not client accounting). The same constant was sent by the live PUT, so
// the gated candidate and the device-verified das-state capture
// (live-das-applied-sys.txt, sha256 f60d458e…) are the same document.
// Unlike the EAP gate's mutation the passphrase is KEPT: the live push
// preserved it, and the applied bytes pin the psk row at the real value
// (the jar's "letmeinnow" default appears only for an empty passphrase).
const zzLiveDasSecret = "openunifi-fake-radius-20260920"

// TestZZLiveDasCandidateVsApplied — the standing full-accounting push gate
// (2026-09-20 DAS/DAD round): the live envelope re-secured to wpa-eap
// with the complete profile — auth + acct servers, interim_update, and
// radius_das_enabled — rendered and checked two ways:
//
//  1. against the DEVICE-VERIFIED das-state capture (live-das-applied-sys.txt,
//     the device's /tmp/system.cfg during the accepted push, sha256 f60d458e…):
//     the render must reproduce it exactly — parse-level zero-diff — and
//     must preserve the jar's duplicate aaa.<n>.radius.dad.status row in
//     the raw emission (the once-per-render dad block re-emits dad.status
//     inside the das block; a parse-diff collapses it, so the raw counts
//     are asserted: twice under aaa.1, once under aaa.2).
//  2. against the wpa-p applied baseline: zero violations and every
//     intended delta inside {wireless, aaa} — the {aaa} restart set the
//     round evidenced live (3 offers, echo caught ≤ 15 s, settle
//     confirmed, no other plugin moved, accounting-off revert clean).
//
// The live round reverts the envelope to the wpa-p baseline afterwards,
// so this stays a standing shape gate; it skips when the envelope is
// already in the das shape or when the das capture is absent (the
// harness lives only on this workstation).
func TestZZLiveDasCandidateVsApplied(t *testing.T) {
	rec, env, appliedRaw := zzLiveFixtures(t)
	if len(env) != 1 {
		t.Fatalf("expected exactly the one live gate-check WLAN, got %d", len(env))
	}
	cand := env[0]
	if cand.Security == "wpa-eap" && cand.RadiusDASEnabled {
		t.Skipf("live envelope already in the das shape — the candidate would be the steady state; see TestZZLiveIntentVsApplied")
	}
	if cand.Security != "wpa-p" {
		t.Fatalf("live envelope security = %q, expected the wpa-p baseline before the das mutation", cand.Security)
	}
	cand.Security = "wpa-eap" // passphrase KEPT — see the zzLiveDasSecret note
	cand.RadiusServers = []wireless.RadiusServer{{IP: "10.10.10.10", Port: 1812}}
	cand.RadiusSecret = zzLiveDasSecret
	cand.RadiusVLANMode = "disabled"
	cand.AccountingEnabled = true
	cand.AcctServers = []wireless.RadiusAcctServer{{IP: "10.10.10.10", Port: 1813}}
	cand.InterimUpdateEnabled = true
	cand.RadiusDASEnabled = true
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return []Wlan{cand} }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-das-candidate-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(sys))
	fmt.Printf("[live-das-candidate] render sha256=%s\n", hex.EncodeToString(sum[:]))

	// (1) the device-verified das-state capture — parse-identical, and the
	// jar's duplicate dad.status preserved in the raw emission.
	dasRaw, err := os.ReadFile(zzHarnessDir + "/live-das-applied-sys.txt")
	if err != nil {
		t.Skipf("device-verified das-state capture not present (%v)", err)
	}
	intended, violations := zzRunGate(t, "live-das-candidate vs DEVICE-VERIFIED DAS-STATE bytes (must be parse-identical)", dasRaw, sys, zzManagedAllow)
	// The das-state archive predates two record changes it cannot carry:
	// the 2026-09-20 factory-window re-adoption (setdefault → Forget →
	// console Accept), which re-minted the controller-owned ssh_sha512
	// cache (a new users.1.password hash), and the 2026-09-21
	// site-settings round, whose live record first carried a provisioned
	// public key (the sshd.auth.key.<n>.* row family every later render
	// emits). Those rows are exempt until the next DAS round re-seeds the
	// capture; every other row still trips the parse-identical
	// requirement.
	intended = zzExemptSSHReMint(zzExemptSSHKeyRows(intended))
	if len(intended) != 0 || len(violations) != 0 {
		t.Fatalf("the das candidate must reproduce the device-verified das-state bytes exactly: intended=%d violations=%d — %v %v", len(intended), len(violations), intended, violations)
	}
	for _, row := range []struct {
		row  string
		want int
	}{
		{"aaa.1.radius.dad.status=enabled", 2}, // the jar's duplicate survives
		{"aaa.2.radius.dad.status=enabled", 1}, // the das block re-emits dad.status; no dad.port here
	} {
		if got := strings.Count(sys, row.row); got != row.want {
			t.Fatalf("raw emission lost the jar's duplicate dad.status shape: %s count=%d, want %d", row.row, got, row.want)
		}
	}

	// (2) the standing shape gate vs the applied wpa-p baseline.
	intended, violations = zzRunGate(t, "live-das-candidate vs DEVICE-VERIFIED APPLIED bytes", appliedRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the das candidate: %d unmanaged row(s) differ — ABORT the push: %v", len(violations), violations)
	}
	zzFailIsDefaultRegression(t, intended)
	for _, d := range intended {
		if !strings.HasPrefix(d, "wireless.") && !strings.HasPrefix(d, "aaa.") {
			t.Fatalf("das candidate touches rows beyond {wireless, aaa} — ABORT the push: %s", d)
		}
	}
	var auth, acct, das, dad, interim, mgmt bool
	for _, d := range intended {
		switch {
		case strings.Contains(d, "radius.auth."):
			auth = true
		case strings.Contains(d, "radius.acct."):
			acct = true
		case strings.Contains(d, "radius.das."):
			das = true
		case strings.Contains(d, "radius.dad."):
			dad = true
		case strings.Contains(d, "interim_update."):
			interim = true
		case strings.Contains(d, `aaa.1.wpa.key.1.mgmt: "WPA-PSK" -> "WPA-EAP"`):
			mgmt = true
		}
	}
	for _, c := range []struct {
		ok   bool
		rows string
	}{
		{auth, "aaa.*.radius.auth.*"}, {acct, "aaa.*.radius.acct.*"},
		{das, "aaa.*.radius.das.*"}, {dad, "aaa.*.radius.dad.*"},
		{interim, "aaa.*.interim_update.*"}, {mgmt, `aaa.*.wpa.key.1.mgmt WPA-PSK -> WPA-EAP`},
	} {
		if !c.ok {
			t.Fatalf("das candidate emits no %s row — the accounting profile did not reach the render; got %v", c.rows, intended)
		}
	}
	// wpa-p and wpa-eap share authmode=1: NO wireless.* row may change (the
	// EAP gate's precedent — the security flip lives entirely in aaa.*).
	var wirelessRows int
	for _, d := range intended {
		if strings.HasPrefix(d, "wireless.") {
			wirelessRows++
		}
	}
	if wirelessRows != 0 {
		t.Fatalf("das candidate changed %d wireless.* row(s) — authmode must stay 1 across the security flip; got %v", wirelessRows, intended)
	}
	fmt.Printf("[live-das-candidate] %d intended deltas, all inside aaa.* (restart set = {aaa}; parse-identical to the device-verified das-state capture) — PUSH-PRE-CLEARED\n", len(intended))
}

// TestZZLiveWpa3CandidateVsApplied — the WPA3-Personal push gate (2026-09-24
// WPA3 round): the live envelope (id and passphrase preserved verbatim —
// the live PUT keeps them, so the gated candidate and the pushed bytes are
// identical) re-secured to wpa3-p, rendered and diffed against the running
// bytes. Enforced: zero violations, every intended delta inside {wireless,
// aaa}, and NO wireless.* delta at all (authmode stays 1 across the
// security flip — the WPA3 shape lives entirely in aaa.*, the EAP gate's
// precedent). Shape proof: pmf flips to enabled/2 (PmfMode REQUIRED), the
// B/F-forced wpa 3→2, the wpa3.support/transition/ft rows, the broadcast
// sae.psk.1 pair, and mgmt WPA-PSK → SAE. The raw emission must carry the
// sae.psk.1 pair exactly once per vap and a SINGLE wpa.psk row per vap
// (the duplicate pair is the transition shape, not this one).
func TestZZLiveWpa3CandidateVsApplied(t *testing.T) {
	rec, env, appliedRaw := zzLiveFixtures(t)
	if len(env) != 1 {
		t.Fatalf("expected exactly the one live gate-check WLAN, got %d", len(env))
	}
	cand := env[0]
	if cand.Security == "wpa3-p" {
		t.Skipf("live envelope already wpa3-p — the candidate would be the steady state; see TestZZLiveIntentVsApplied")
	}
	if cand.Security != "wpa-p" {
		t.Fatalf("live envelope security = %q, expected the wpa-p baseline before the WPA3 mutation", cand.Security)
	}
	cand.Security = "wpa3-p" // passphrase KEPT — the live push preserves it
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return []Wlan{cand} }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-wpa3-candidate-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(sys))
	fmt.Printf("[live-wpa3-candidate] render sha256=%s\n", hex.EncodeToString(sum[:]))
	intended, violations := zzRunGate(t, "live-wpa3-candidate vs DEVICE-VERIFIED APPLIED bytes", appliedRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the wpa3-p candidate: %d unmanaged row(s) differ — ABORT the push: %v", len(violations), violations)
	}
	zzFailIsDefaultRegression(t, intended)
	for _, d := range intended {
		if !strings.HasPrefix(d, "wireless.") && !strings.HasPrefix(d, "aaa.") {
			t.Fatalf("wpa3-p candidate touches rows beyond {wireless, aaa} — ABORT the push: %s", d)
		}
	}
	var pmfStatus, pmfMode, wpaRow, mgmt, support, transition, ft, sae bool
	for _, d := range intended {
		switch {
		case strings.Contains(d, `aaa.1.pmf.status: "disabled" -> "enabled"`):
			pmfStatus = true
		case strings.Contains(d, `aaa.1.pmf.mode: "0" -> "2"`):
			pmfMode = true
		case strings.Contains(d, `aaa.1.wpa: "3" -> "2"`):
			wpaRow = true
		case strings.Contains(d, `aaa.1.wpa.key.1.mgmt: "WPA-PSK" -> "SAE"`):
			mgmt = true
		case strings.Contains(d, "aaa.1.wpa3.support"):
			support = true
		case strings.Contains(d, "aaa.1.wpa3.transition"):
			transition = true
		case strings.Contains(d, "aaa.1.wpa3.ft.status"):
			ft = true
		case strings.Contains(d, "aaa.1.sae.psk.1.psk"):
			sae = true
		}
	}
	for _, c := range []struct {
		ok   bool
		rows string
	}{
		{pmfStatus, `aaa.*.pmf.status disabled -> enabled`},
		{pmfMode, `aaa.*.pmf.mode 0 -> 2 (PmfMode REQUIRED)`},
		{wpaRow, `aaa.*.wpa 3 -> 2 (B/F.Ó00000 forces wpa_mode="wpa2" on WPA3 vaps)`},
		{mgmt, `aaa.*.wpa.key.1.mgmt WPA-PSK -> SAE`},
		{support, "aaa.*.wpa3.support"},
		{transition, "aaa.*.wpa3.transition"},
		{ft, "aaa.*.wpa3.ft.status"},
		{sae, "aaa.*.sae.psk.1.psk"},
	} {
		if !c.ok {
			t.Fatalf("wpa3-p candidate emits no %s row — the WPA3 mutation did not reach the render; got %v", c.rows, intended)
		}
	}
	var wirelessRows int
	for _, d := range intended {
		if strings.HasPrefix(d, "wireless.") {
			wirelessRows++
		}
	}
	if wirelessRows != 0 {
		t.Fatalf("wpa3-p candidate changed %d wireless.* row(s) — authmode must stay 1 across the security flip; got %v", wirelessRows, intended)
	}
	// Raw-count shape (parse-level invisible): the broadcast sae.psk.1
	// pair exactly once per vap, a SINGLE wpa.psk row per vap (the mgmt
	// writer's — no transition duplicate here), and the mac literal.
	for _, row := range []struct {
		row  string
		want int
	}{
		{"aaa.1.sae.psk.1.mac=ff:ff:ff:ff:ff:ff", 1},
		{"aaa.2.sae.psk.1.mac=ff:ff:ff:ff:ff:ff", 1},
		{"aaa.1.sae.psk.1.psk=", 1},
		{"aaa.2.sae.psk.1.psk=", 1},
		{"aaa.1.wpa.psk=", 1},
		{"aaa.2.wpa.psk=", 1},
	} {
		if got := strings.Count(sys, row.row); got != row.want {
			t.Fatalf("wpa3-p raw emission broke the jar byte shape: %s count=%d, want %d", row.row, got, row.want)
		}
	}
	fmt.Printf("[live-wpa3-candidate] %d intended deltas, all inside aaa.* (restart set = {aaa}; sae.psk.1 pair raw-verified) — PUSH-PRE-CLEARED\n", len(intended))
}

// TestZZLiveWpa2Wpa3CandidateVsApplied — the WPA2/WPA3 transition push gate
// (2026-09-24 WPA3 round): the live envelope re-secured to wpa2-wpa3
// (passphrase kept). Same discipline as the wpa3-p gate; transition
// deltas: pmf.mode 0→1 (PmfMode OPTIONAL), wpa3.transition=enabled, and
// NO sae.psk.1 pair. The jar's transition DUPLICATE — the B/O0OO psk
// sub-writer's wpa.psk row ahead of the mgmt writer's own — is invisible
// to the parse-diff (same key, same value), so like the DAS gate's
// dad.status duplicate it is asserted as a RAW count: exactly two
// aaa.<n>.wpa.psk rows per vap.
func TestZZLiveWpa2Wpa3CandidateVsApplied(t *testing.T) {
	rec, env, appliedRaw := zzLiveFixtures(t)
	if len(env) != 1 {
		t.Fatalf("expected exactly the one live gate-check WLAN, got %d", len(env))
	}
	cand := env[0]
	if cand.Security == "wpa2-wpa3" {
		t.Skipf("live envelope already wpa2-wpa3 — the candidate would be the steady state; see TestZZLiveIntentVsApplied")
	}
	if cand.Security != "wpa-p" {
		t.Fatalf("live envelope security = %q, expected the wpa-p baseline before the transition mutation", cand.Security)
	}
	cand.Security = "wpa2-wpa3" // passphrase KEPT — the live push preserves it
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return []Wlan{cand} }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-wpa23-candidate-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(sys))
	fmt.Printf("[live-wpa23-candidate] render sha256=%s\n", hex.EncodeToString(sum[:]))
	intended, violations := zzRunGate(t, "live-wpa23-candidate vs DEVICE-VERIFIED APPLIED bytes", appliedRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the wpa2-wpa3 candidate: %d unmanaged row(s) differ — ABORT the push: %v", len(violations), violations)
	}
	zzFailIsDefaultRegression(t, intended)
	for _, d := range intended {
		if !strings.HasPrefix(d, "wireless.") && !strings.HasPrefix(d, "aaa.") {
			t.Fatalf("wpa2-wpa3 candidate touches rows beyond {wireless, aaa} — ABORT the push: %s", d)
		}
	}
	var pmfStatus, pmfMode, wpaRow, mgmt, support, transition bool
	for _, d := range intended {
		switch {
		case strings.Contains(d, `aaa.1.pmf.status: "disabled" -> "enabled"`):
			pmfStatus = true
		case strings.Contains(d, `aaa.1.pmf.mode: "0" -> "1"`):
			pmfMode = true
		case strings.Contains(d, `aaa.1.wpa: "3" -> "2"`):
			wpaRow = true
		case strings.Contains(d, `aaa.1.wpa.key.1.mgmt: "WPA-PSK" -> "SAE"`):
			mgmt = true
		case strings.Contains(d, "aaa.1.wpa3.support"):
			support = true
		case strings.Contains(d, "aaa.1.wpa3.transition"):
			transition = true
		}
	}
	for _, c := range []struct {
		ok   bool
		rows string
	}{
		{pmfStatus, `aaa.*.pmf.status disabled -> enabled`},
		{pmfMode, `aaa.*.pmf.mode 0 -> 1 (PmfMode OPTIONAL)`},
		{wpaRow, `aaa.*.wpa 3 -> 2 (B/F.Ó00000 forcing)`},
		{mgmt, `aaa.*.wpa.key.1.mgmt WPA-PSK -> SAE`},
		{support, "aaa.*.wpa3.support"},
		{transition, "aaa.*.wpa3.transition"},
	} {
		if !c.ok {
			t.Fatalf("wpa2-wpa3 candidate emits no %s row — the transition mutation did not reach the render; got %v", c.rows, intended)
		}
	}
	var wirelessRows int
	for _, d := range intended {
		if strings.HasPrefix(d, "wireless.") {
			wirelessRows++
		}
	}
	if wirelessRows != 0 {
		t.Fatalf("wpa2-wpa3 candidate changed %d wireless.* row(s) — authmode must stay 1 across the security flip; got %v", wirelessRows, intended)
	}
	// Raw-count shape (parse-invisible): the transition DUPLICATE wpa.psk
	// pair (B/O0OO psk sub-writer + mgmt writer, same value) — exactly two
	// per vap; and no sae.psk.* row at all (the pair is the wpa3-only
	// shape).
	if got := strings.Count(sys, "aaa.1.wpa.psk="); got != 2 {
		t.Fatalf("wpa2-wpa3 raw emission lost the jar's DUPLICATE wpa.psk pair: aaa.1.wpa.psk count=%d, want 2", got)
	}
	if got := strings.Count(sys, "aaa.2.wpa.psk="); got != 2 {
		t.Fatalf("wpa2-wpa3 raw emission lost the jar's DUPLICATE wpa.psk pair: aaa.2.wpa.psk count=%d, want 2", got)
	}
	if strings.Contains(sys, "sae.psk.") {
		t.Fatalf("wpa2-wpa3 must emit no sae.psk.* row (wpa3-only shape):\n%s", sys)
	}
	fmt.Printf("[live-wpa23-candidate] %d intended deltas, all inside aaa.* (restart set = {aaa}; duplicate wpa.psk pair raw-verified) — PUSH-PRE-CLEARED\n", len(intended))
}

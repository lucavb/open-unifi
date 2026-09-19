package server

// zz_live_candidate_scratch_test.go — live-round successive-push candidate
// gates for the 2026-09-19 full-chain validation round (the nine commits
// after 34082cd0, the last device-verified round): blocked_sta delivery, the
// per-radio channel intent, and the WPA-EAP envelope. Every gate loads
// the CURRENT live fixtures (live-devices.json + live-wireless.json) and
// parse-diffs its candidate against the DEVICE-VERIFIED applied bytes
// (live-applied-sys.txt, sha256 3da7ce3e… — seeded by the 2026-09-19 A2
// reboot round), because the live question is exactly "which on-device
// plugins would this push restart". Gates skip when the harness is
// absent (it lives only on this workstation under
// tmpwork/harness-20260917/, which is gitignored).
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
// the next AP reboot — see the zzZZAllowPrefix comment).

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

// zzLiveFixtures loads the live record, the live envelope, and the
// device-verified applied bytes; the gates skip when any is absent.
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
		t.Fatalf("live AP aa:bb:cc:dd:ee:02 absent from fetched record: %d devices", len(file.Devices))
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
	return rec, envFile.Wlans, araw
}

// zzFailIsDefaultRegression trips when a render against the post-fix live
// applied bytes emits the mgmt.is_default row anyway — that is not an
// exempted migration here, it is the boot-guard regression that would
// factory-reset the WLAN text on the next AP reboot.
func zzFailIsDefaultRegression(t *testing.T, intended []string) {
	t.Helper()
	for _, r := range intended {
		if strings.HasPrefix(r, "mgmt.is_default:") {
			t.Fatalf("renderer emitted mgmt.is_default against the post-fix applied bytes — the 2026-09-19 boot-guard fix regressed (the fw 6.8.2 boot path would factory-reset the WLAN text on the next AP reboot); ABORT: %s", r)
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
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	intended, violations := zzRunGate(t, "live-blocked-candidate vs DEVICE-VERIFIED APPLIED bytes (must be byte-identical)", appliedRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
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
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-radio-intent-candidate-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[live-radio-intent-candidate] render sha256=%s\n",
		func() string { sum := sha256.Sum256([]byte(sys)); return hex.EncodeToString(sum[:]) }())
	intended, violations := zzRunGate(t, "live-radio-intent-candidate vs DEVICE-VERIFIED APPLIED bytes", appliedRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
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
	s := New(Config{WirelessSource: func() []Wlan { return []Wlan{cand} }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-eap-candidate-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[live-eap-candidate] render sha256=%s\n",
		func() string { sum := sha256.Sum256([]byte(sys)); return hex.EncodeToString(sum[:]) }())
	intended, violations := zzRunGate(t, "live-eap-candidate vs DEVICE-VERIFIED APPLIED bytes", appliedRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
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

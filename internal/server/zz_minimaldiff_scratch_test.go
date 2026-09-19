package server

// zz_minimaldiff_scratch_test.go — postmortem scratch (2026-09-17) +
// successive-push gates (night pass 2026-09-17). LOCAL harness gates for
// the factory-echo system_cfg renderer. They skip when the harness files
// are absent (the harness lives only on this workstation under
// tmpwork/harness-20260917/, which is gitignored).
//
// Part 1 — factory acceptance gates (restored from
// zz_minimaldiff_scratch_test.go.bak with paths repointed from
// /tmp/harness/ to this worktree's tmpwork/harness-20260917/).
// The system_cfg apply is a FULL-CONFIG REPLACEMENT and ubntconf
// fast-apply restarts the on-device plugin for every section whose
// parsed tree changes — including changes caused by row deletion (the
// two fatal live pushes 2026-09-16; root cause: our netconf carried one
// mgmt instance where the running factory config has four, so the `net`
// plugin tore br0/eth0/ath* down and never recovered).
// The gate renders the FIXED generator's system_cfg on the synthetic
// adopted record (the exact harness devices.json shape: U7PG2, if_table
// eth0, radio_table wifi0/wifi1, vap_table factory essid) with the
// gate-check both-band open WLAN, parse-diffs it against the FACTORY
// BASELINE (ap-forensics/tmp/system.cfg, fetched from the factory-reset
// AP 2026-09-17) and enforces the minimal-diff invariant:
//
//	permitted diffs (intended-managed sections):
//	  unifi.* (new)  users.* (ubnt/nobody vs ui/ubnt)  sshd.* (new)
//	  radio.* / wireless.* / aaa.* (our WLANs)  vlan.* (new rows)
//	everything else — netconf.*, connectivity.*, route.*, ebtables.*,
//	syslog.*, ntpclient.*, mgmt.*, dhcpd.*, httpd.*, bridge.*, dhcpc.* —
//	must be IDENTICAL to the factory tree, or the push restarts (or
//	deletes state from) a section we do not manage.
//
// Part 2 — successive-push gates (night extension). render-fixed-sys.txt
// is the SYNTHETIC night reference (sha256
// 48dbb631f05d9ff4… — the zzHarnessRecord + gate-check open-WLAN render,
// regenerated 2026-09-19 with the post-is_default-fix generator); the
// live AP's device-verified running bytes live separately in
// live-applied-sys.txt (sha256 3da7ce3e…, re-seeded from the 2026-09-19
// A2 reboot round that proved them retained across a raw reboot). Each
// next-push candidate — both-band open
// (control), 2g-only open, both-band wpa-p — is diffed against the
// APPLIED bytes, because the live question is exactly "which on-device
// plugins would this next push restart": managed prefixes may differ,
// but any unmanaged row that differs would restart (or delete state
// from) a section we do not manage. The 2g-only candidate additionally
// removes the intended bridge port row (bridge.1.port.3.devname=ath1);
// per the bridge apply forensics (see WLAN-ACCEPTANCE-6.8.2.15592.md
// §Bridge-apply verdict) a bridge-tree change restarts the bridge
// plugin, whose stop path deletes br0 — the 2g-only push is therefore
// NOT pre-cleared regardless of this gate, while the control and wpa-p
// candidates change no unmanaged section at all.
//
// Gate listings append to tmpwork/harness-20260917/night-deltas.txt.
// Spec: tmpwork/harness-20260917/minimal-diff-spec.md.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

const (
	zzKeyHex      = "11112222333344445555666677778888"
	zzHarnessDir  = "../../tmpwork/harness-20260917"
	zzFactoryCfg  = zzHarnessDir + "/ap-forensics/tmp/system.cfg"
	zzAppliedCfg  = zzHarnessDir + "/render-fixed-sys.txt"
	zzNightDeltas = zzHarnessDir + "/night-deltas.txt"
	// mgmt.is_default is permitted as an EXACT row-key (not the mgmt.
	// prefix): the renderer deliberately omits it since 2026-09-19. The
	// fw 6.8.2 boot path (/lib/preinit/99_21_ubnt_ubntconf do_ubntconf)
	// greps the MTD-restored blob text for `mgmt.is_default=true` and
	// replaces it with the factory template — the pre-fix factory-echo
	// carried the row, so every reboot of a provisioned AP
	// factory-reset the WLAN text while mgmt/authkey survived via the
	// tar part (WLAN-ACCEPTANCE A2). Baselines captured before the fix
	// still contain the row; its removal is intended. Any OTHER mgmt.*
	// delta remains a violation.
	zzZZAllowPrefix = "unifi. users. sshd. radio. wireless. aaa. vlan. mgmt.is_default"
)

// zzHarnessRecord mirrors harness devices.json (mac aabbccddeeff):
// live-record-shaped passthrough tables so ethPortNames/storedRadios
// resolve exactly like the adopted AP's record does. The
// ssh_sha512passwd seed is the cache value the accepted 2026-09-17 push
// minted into the live record (usersPasswordHash reuses the cached hash
// on every later render, server.go:1145-1156), so successive-push
// candidates model the adopted record exactly as the controller holds
// it NOW — users.1.password must stay byte-identical to the APPLIED
// baseline, i.e. the users plugin must not restart on these pushes.
func zzHarnessRecord() store.Device {
	return store.Device{
		MAC: "aabbccddeeff", Model: "U7PG2", State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
		XAuthkey: zzKeyHex, Authkeys: []string{zzKeyHex},
		Extra: store.JSONMap{
			"model": "U7PG2", "version": "6.8.2.15592", "has_eth1": false,
			"ssh_sha512passwd": "$6$A1b2C3d4$pFWD0kBTy6HJtOX7lJgY0ZzefwGXNS9NGqKx6R236Zudk1utl8z7tDkBuV4eFAUi64xM3W5Ny9y0O4Ibnhewz1",
			"wifi_caps":        559857373.0, "wifi_caps2": 48.0,
			"fw_caps": 3892247871.0, "fw2_caps": 1208549376.0,
			"radio_table": []any{
				map[string]any{"name": "wifi0", "radio": "ng", "builtin_antenna": true, "builtin_ant_gain": 3.0,
					"ieee_modes": 10.0, "max_txpower": 22.0, "min_txpower": 6.0, "nss": 3.0,
					"radio_caps": 16420.0, "radio_caps2": 27.0},
				map[string]any{"name": "wifi1", "radio": "na", "builtin_antenna": true, "builtin_ant_gain": 3.0,
					"ieee_modes": 21.0, "max_txpower": 22.0, "min_txpower": 6.0, "nss": 3.0,
					"has_dfs": true, "has_fccdfs": true, "is_11ac": true,
					"radio_caps": 50479140.0, "radio_caps2": 27.0},
			},
			"vap_table": []any{
				map[string]any{"name": "ath0", "radio": "ng", "radio_name": "wifi0", "essid": "AABBCCDDEE02",
					"state": "RUN", "up": true, "usage": "user", "id": "user", "channel": 6.0, "bw": 20.0,
					"num_sta": 0.0, "bssid": "aa:bb:cc:dd:ee:12", "ccq": 0.0, "is_guest": false},
			},
			"if_table": []any{
				map[string]any{"name": "eth0", "mac": "aa:bb:cc:dd:ee:02", "max_vlan": 96.0, "num_port": 2.0,
					"up": true, "speed": 1000.0, "full_duplex": true},
			},
		},
	}
}

// zzParseCfg reduces a config blob to its key=value tree (comments and
// blank lines dropped; parse() semantics — row order is not a fact).
func zzParseCfg(s string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if i := strings.Index(ln, "="); i > 0 {
			m[ln[:i]] = ln[i+1:]
		}
	}
	return m
}

// zzManagedAllow is the minimal-diff invariant's allow predicate: only
// intended-managed prefixes may differ from the baseline.
func zzManagedAllow(k string) bool {
	for _, p := range strings.Fields(zzZZAllowPrefix) {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// zzExemptIsDefaultMigration filters the known one-time renderer
// migration delta (the mgmt.is_default row removal, 2026-09-19 — see the
// zzZZAllowPrefix comment for the fw 6.8.2 boot-guard rationale) out of
// an intended-delta list. The APPLIED baselines were captured from
// pushes rendered BEFORE the fix, so every current render differs from
// them by exactly this row until the next live apply refreshes the
// capture. Once the device-verified applied bytes are re-captured
// post-fix this filter becomes inert. Any other intended row still
// trips the zero-drift gates.
func zzExemptIsDefaultMigration(rows []string) (out []string) {
	for _, r := range rows {
		if strings.HasPrefix(r, "mgmt.is_default:") {
			continue
		}
		out = append(out, r)
	}
	return out
}

var zzDeltasOnce sync.Once

// zzRunGate parse-diffs a rendered system_cfg against a baseline tree
// and classifies every row delta as intended (allowed by the allow
// predicate) or a violation (an unmanaged row the push would restart or
// delete state from). It prints and appends the listing to
// night-deltas.txt and returns the two lists; callers enforce.
func zzRunGate(t *testing.T, label string, baseRaw []byte, sys string, allow func(string) bool) (intended, violations []string) {
	t.Helper()
	base := zzParseCfg(string(baseRaw))
	render := zzParseCfg(sys)

	keys := map[string]bool{}
	for k := range base {
		keys[k] = true
	}
	for k := range render {
		keys[k] = true
	}
	for k := range keys {
		bv, bOK := base[k]
		rv, rOK := render[k]
		switch {
		case !bOK && rOK && allow(k), bOK && !rOK && allow(k), bOK && rOK && bv != rv && allow(k):
			intended = append(intended, fmt.Sprintf("%s: %q -> %q", k, bv, rv))
		case !bOK && rOK, bOK && !rOK, bv != rv:
			violations = append(violations, fmt.Sprintf("%s: base=%q render=%q", k, bv, rv))
		}
	}
	sort.Strings(intended)
	sort.Strings(violations)

	fmt.Printf("[%s] intended diffs (%d):\n", label, len(intended))
	for _, l := range intended {
		fmt.Printf("  I %s\n", l)
	}
	fmt.Printf("[%s] violations (%d):\n", label, len(violations))
	for _, l := range violations {
		fmt.Printf("  V %s\n", l)
	}

	zzDeltasOnce.Do(func() {
		_ = os.WriteFile(zzNightDeltas, []byte("night successive-push delta log — 2026-09-17\n"+
			"worktree omos/night-pushsafe; factory acceptance gates (restored) + successive-push candidates vs APPLIED baseline\n"+
			"applied baseline sha256 b25a2c80007f564c3331d98ce8b020e96321701785740e824fc4f29d0ca8235e\n\n"), 0o644)
	})
	var b strings.Builder
	fmt.Fprintf(&b, "=== %s ===\nintended (%d):\n", label, len(intended))
	for _, l := range intended {
		fmt.Fprintf(&b, "  I %s\n", l)
	}
	fmt.Fprintf(&b, "violations (%d):\n", len(violations))
	for _, l := range violations {
		fmt.Fprintf(&b, "  V %s\n", l)
	}
	b.WriteString("\n")
	f, err := os.OpenFile(zzNightDeltas, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err == nil {
		_, _ = f.WriteString(b.String())
		_ = f.Close()
	}
	return intended, violations
}

func TestZZMinimalDiffGate(t *testing.T) {
	factoryRaw, err := os.ReadFile(zzFactoryCfg)
	if err != nil {
		t.Skipf("factory baseline not present (%v); scratch gate runs only on the postmortem workstation", err)
	}
	// the gate-check both-band open WLAN from harness wireless.json
	env := []Wlan{{
		ID: "7a5326f64be2c3c13c18eb4f", Name: "gate-check",
		SSID: "openunifi-gate-check", Security: "open",
		VLAN: 1, Enabled: true, Band: "both",
	}}
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, zzHarnessRecord())
	_, violations := zzRunGate(t, "minimal-diff gate: synthetic record vs factory baseline", factoryRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken: %d unmanaged row(s) differ from the factory baseline — the push would restart/delete unmanaged plugins", len(violations))
	}
}

// TestZZMinimalDiffGateLiveRecord — the same gate on the REAL live record
// fetched from lab-bench (harness live-devices.json, store file shape).
// This verifies the EXACT system_cfg bytes the live AP would receive on
// the gate-check push, before anything is deployed or pushed. Skips when
// the fetched record is absent.
// zzRecordFacts echoes the record's eth inventory and mgmt dev for the gate
// listing. The production resolvers are unexported inside
// internal/server/systemcfg (ethPortNames: ethernet_table → if_table ethN →
// uplink → "eth0"; mgmtDevOf: Extra["mgmt_dev"] → "br0" —
// systemcfg/wireless.go); this echo re-derives only the facts the gate
// records actually exercise (6.8.2 sends no ethernet_table and neither
// gate record carries a mgmt_dev override) so the gate stays in package
// server. Faithful only for records of that shape.
func zzRecordFacts(rec store.Device) (eth []string, mgmt string) {
	mgmt = "br0"
	if v, ok := rec.Extra["mgmt_dev"].(string); ok && v != "" {
		mgmt = v
	}
	if rows, ok := rec.Extra["if_table"].([]any); ok {
		for _, r := range rows {
			if m, ok := r.(map[string]any); ok {
				if n, ok := m["name"].(string); ok && strings.HasPrefix(n, "eth") {
					eth = append(eth, n)
				}
			}
		}
	}
	return eth, mgmt
}

func TestZZMinimalDiffGateLiveRecord(t *testing.T) {
	factoryRaw, err := os.ReadFile(zzFactoryCfg)
	if err != nil {
		t.Skipf("factory baseline not present (%v)", err)
	}
	raw, err := os.ReadFile(zzHarnessDir + "/live-devices.json")
	if err != nil {
		t.Skipf("live record not present (%v)", err)
	}
	var file struct {
		Devices map[string]store.Device `json:"devices"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("live devices.json: %v", err)
	}
	rec, ok := file.Devices["aabbccddee02"]
	if !ok {
		t.Fatalf("live AP aa:bb:cc:dd:ee:02 absent from fetched record: %d devices", len(file.Devices))
	}
	ports, mgmt := zzRecordFacts(rec)
	fmt.Printf("[minimal-diff gate:live] eth inventory %v, radios %d, mgmt dev %q, vap rows %d\n",
		ports, len(wireless.StoredRadios(rec)), mgmt, len(rec.Extra["vap_table"].([]any)))
	env := []Wlan{{
		ID: "7a5326f64be2c3c13c18eb4f", Name: "gate-check",
		SSID: "openunifi-gate-check", Security: "open",
		VLAN: 1, Enabled: true, Band: "both",
	}}
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/render-live-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	_, violations := zzRunGate(t, "minimal-diff gate: live record vs factory baseline", factoryRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken: %d unmanaged row(s) differ from the factory baseline — the push would restart/delete unmanaged plugins", len(violations))
	}
}

// TestZZLiveIntentVsApplied — the CURRENT live intent: the record and the
// wireless envelope as fetched from the RUNNING controller
// (live-devices.json + live-wireless.json), rendered and diffed against
// the DEVICE-VERIFIED running bytes (live-applied-sys.txt — seeded by a
// confirmed round: the 2026-09-19 post-is_default-fix push, whose bytes
// the AP's /tmp/system.cfg reproduced at sha256 3da7ce3e… and, after a
// raw reboot, the boot-restored text preserved row-for-row) and against
// the factory baseline. This is the steady-state drift check: in steady
// state the render must be byte-identical to what the device runs (zero
// intended, zero violations); ANY delta is real drift or record change to
// investigate before the next push. History: the 2026-09-18 round found
// the night-pass "APPLIED" baseline (render-fixed-sys.txt, id
// 7a5326f6…=sha256("gate-check")[:24]) was never the pushed bytes — the
// live envelope carries the admin API's sha256(name+ssid)[:24] stamp
// (internal/app/app.go:530) and the accepted 2026-09-17 19:17 CEST push
// rendered from it — so that file stays only as the night regression
// gates' reference, not as the live baseline.
func TestZZLiveIntentVsApplied(t *testing.T) {
	factoryRaw, err := os.ReadFile(zzFactoryCfg)
	if err != nil {
		t.Skipf("factory baseline not present (%v)", err)
	}
	appliedRaw, err := os.ReadFile(zzHarnessDir + "/live-applied-sys.txt")
	if err != nil {
		t.Skipf("device-verified live applied baseline not present — seed it from a confirmed push (%v)", err)
	}
	raw, err := os.ReadFile(zzHarnessDir + "/live-devices.json")
	if err != nil {
		t.Skipf("live record not present (%v)", err)
	}
	wraw, err := os.ReadFile(zzHarnessDir + "/live-wireless.json")
	if err != nil {
		t.Skipf("live envelope not present (%v)", err)
	}
	var file struct {
		Devices map[string]store.Device `json:"devices"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("live devices.json: %v", err)
	}
	rec, ok := file.Devices["aabbccddee02"]
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
	s := New(Config{WirelessSource: func() []Wlan { return envFile.Wlans }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-intent-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[live-intent] envelope wlans=%d, render sha256=%s\n",
		len(envFile.Wlans), func() string { sum := sha256.Sum256([]byte(sys)); return hex.EncodeToString(sum[:]) }())

	_, violations := zzRunGate(t, "live-intent vs FACTORY baseline (factory-echo invariant)", factoryRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the live intent: %d unmanaged row(s) differ from the factory baseline", len(violations))
	}
	intended, violations := zzRunGate(t, "live-intent vs DEVICE-VERIFIED APPLIED bytes (steady state)", appliedRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the live intent: %d unmanaged row(s) differ from the device-verified applied bytes", len(violations))
	}
	intended = zzExemptIsDefaultMigration(intended)
	if len(intended) > 0 {
		t.Fatalf("steady-state drift: %d row(s) differ between the live intent and the device-verified applied bytes — investigate before any push: %v", len(intended), intended)
	}
	fmt.Printf("[live-intent] steady state: byte-identical to the device-verified applied bytes\n")
}

// zzLiveWpaPSK is the test-only passphrase for the 2026-09-18 C1-shape
// live push. It is synthetic bench material, not a site secret; the same
// constant must be used by the PUT that performs the live push so the
// gated candidate and the pushed bytes are identical.
const zzLiveWpaPSK = "openunifi-fake-c1-psk-20260918"

// TestZZLiveWpaCandidateVsApplied — the push gate that pre-cleared the
// 2026-09-18 C1 round: the live record + the live envelope (id preserved
// verbatim) mutated to wpa-p, rendered and diffed against the RUNNING
// config. The round EXECUTED and the AP verified: /tmp/system.cfg
// reproduced the candidate at sha256 9891d9ff… byte-for-byte, wpa rows
// present, AP reachable through the {wireless, aaa} restart. Kept as the
// template for the next candidate gate (any future push shape: mutate the
// envelope here, enforce zero deltas outside the intended sections,
// ABORT on anything else). Enforced: zero deltas outside the managed
// aaa.*/wireless.* prefixes — the restart set stays {wireless, aaa},
// both live-evidenced survivable; any netconf/bridge/connectivity/
// dhcpc row moving is the fatal shape and must abort the push.
func TestZZLiveWpaCandidateVsApplied(t *testing.T) {
	raw, err := os.ReadFile(zzHarnessDir + "/live-devices.json")
	if err != nil {
		t.Skipf("live record not present (%v)", err)
	}
	wraw, err := os.ReadFile(zzHarnessDir + "/live-wireless.json")
	if err != nil {
		t.Skipf("live envelope not present (%v)", err)
	}
	runningRaw, err := os.ReadFile(zzHarnessDir + "/live-applied-sys.txt")
	if err != nil {
		t.Skipf("device-verified running bytes not present — run TestZZLiveIntentVsApplied or seed from a confirmed push (%v)", err)
	}
	var file struct {
		Devices map[string]store.Device `json:"devices"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("live devices.json: %v", err)
	}
	rec, ok := file.Devices["aabbccddee02"]
	if !ok {
		t.Fatalf("live AP aa:bb:cc:dd:ee:02 absent from fetched record: %d devices", len(file.Devices))
	}
	var envFile struct {
		Wlans []Wlan `json:"wlans"`
	}
	if err := json.Unmarshal(wraw, &envFile); err != nil {
		t.Fatalf("live wireless.json: %v", err)
	}
	if len(envFile.Wlans) != 1 {
		t.Fatalf("expected exactly the one live gate-check WLAN, got %d", len(envFile.Wlans))
	}
	cand := envFile.Wlans[0]
	if cand.Security == "wpa-p" {
		t.Skipf("a wpa-p round is complete and device-verified (2026-09-18 C1, superseded by the 2026-09-19 A2 passphrase round, device-verified at sha256 3da7ce3e… and proven retained across a raw reboot); the steady-state check lives in TestZZLiveIntentVsApplied")
	}
	if cand.Security != "open" {
		t.Fatalf("live envelope security = %q, expected the open baseline before the C1 mutation", cand.Security)
	}
	cand.Security, cand.Passphrase = "wpa-p", zzLiveWpaPSK
	env := []Wlan{cand}
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-wpa-candidate-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[live-wpa-candidate] render sha256=%s\n",
		func() string { sum := sha256.Sum256([]byte(sys)); return hex.EncodeToString(sum[:]) }())

	intended, violations := zzRunGate(t, "live-wpa-candidate vs RUNNING (device-verified bytes)", runningRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the wpa-p candidate: %d unmanaged row(s) differ — ABORT the push: %v", len(violations), violations)
	}
	var outside []string
	for _, d := range intended {
		k := strings.SplitN(d, ":", 2)[0]
		if !strings.HasPrefix(k, "aaa.") && !strings.HasPrefix(k, "wireless.") {
			outside = append(outside, d)
		}
	}
	if len(outside) > 0 {
		t.Fatalf("wpa-p candidate touches rows beyond {wireless, aaa} — ABORT the push: %v", outside)
	}
	fmt.Printf("[live-wpa-candidate] %d intended deltas, all inside {wireless, aaa}; restart set = {wireless, aaa} — PUSH-PRE-CLEARED shape\n", len(intended))
}

// TestZZSuccessivePushControlVsApplied — the both-band open control
// re-renders the exact envelope the AP already runs and must reproduce
// the APPLIED bytes row-for-row: zero intended, zero violations. Any
// nonzero diff is generator drift since the accepted push and must be
// investigated before the next live push.
func TestZZSuccessivePushControlVsApplied(t *testing.T) {
	appliedRaw, err := os.ReadFile(zzAppliedCfg)
	if err != nil {
		t.Skipf("applied baseline not present (%v); successive-push gates run only on the postmortem workstation", err)
	}
	env := []Wlan{{
		ID: "7a5326f64be2c3c13c18eb4f", Name: "gate-check",
		SSID: "openunifi-gate-check", Security: "open",
		VLAN: 1, Enabled: true, Band: "both",
	}}
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, zzHarnessRecord())
	if err := os.WriteFile(zzHarnessDir+"/night-cand-both-open-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	intended, violations := zzRunGate(t, "successive-push CONTROL: both-band open vs APPLIED", appliedRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken: %d unmanaged row(s) differ from the APPLIED baseline — the push would restart/delete unmanaged plugins", len(violations))
	}
	intended = zzExemptIsDefaultMigration(intended)
	if len(intended) > 0 {
		t.Fatalf("generator drift: %d managed row(s) differ from the APPLIED baseline (control must be byte-stable): %v", len(intended), intended)
	}
}

// TestZZSuccessivePush2gOnlyVsApplied — the 2g-only candidate (gate-check
// WLAN narrowed to Band "2g") against the APPLIED bytes. Allowed deltas:
// managed prefixes plus exactly one intended bridge row — the
// bridge.1.port.3.devname=ath1 port removal, because the 5g vap ath1
// disappears. netconf.* / connectivity.* / dhcpc.* and every other
// unmanaged section must stay byte-identical (they do: netconf echoes
// the radio inventory, which is unchanged). NOTE: passing this gate does
// NOT pre-clear the push — the bridge-tree change restarts the bridge
// plugin, which deletes and recreates br0 without an IP bootstrap; see
// WLAN-ACCEPTANCE-6.8.2.15592.md §Bridge-apply verdict.
func TestZZSuccessivePush2gOnlyVsApplied(t *testing.T) {
	appliedRaw, err := os.ReadFile(zzAppliedCfg)
	if err != nil {
		t.Skipf("applied baseline not present (%v)", err)
	}
	env := []Wlan{{
		ID: "7a5326f64be2c3c13c18eb4f", Name: "gate-check",
		SSID: "openunifi-gate-check", Security: "open",
		VLAN: 1, Enabled: true, Band: "2g",
	}}
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, zzHarnessRecord())
	if err := os.WriteFile(zzHarnessDir+"/night-cand-2g-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	allow := func(k string) bool {
		return zzManagedAllow(k) || k == "bridge.1.port.3.devname"
	}
	intended, violations := zzRunGate(t, "successive-push 2g-ONLY vs APPLIED (+intended bridge port removal)", appliedRaw, sys, allow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken: %d unmanaged row(s) differ from the APPLIED baseline — the push would restart/delete unmanaged plugins", len(violations))
	}
	var bridge []string
	for _, d := range intended {
		if strings.HasPrefix(d, "bridge.") {
			bridge = append(bridge, d)
		}
	}
	if len(bridge) != 1 || !strings.HasPrefix(bridge[0], `bridge.1.port.3.devname: "ath1" -> ""`) {
		t.Fatalf("2g-only candidate must change exactly one bridge row (the ath1 port removal); got %v", bridge)
	}
}

// TestZZSuccessivePushWpaPskVsApplied — the wpa-p candidate (gate-check
// WLAN re-secured to wpa-p) against the APPLIED bytes. The vap shape is
// unchanged (both-band, same WLAN id/ssid, VLAN 1 untagged), so no
// bridge row may differ at all; expected deltas are confined to the
// aaa.* (wpa rows appear) and wireless.* (authmode 0->1) managed rows.
func TestZZSuccessivePushWpaPskVsApplied(t *testing.T) {
	appliedRaw, err := os.ReadFile(zzAppliedCfg)
	if err != nil {
		t.Skipf("applied baseline not present (%v)", err)
	}
	env := []Wlan{{
		ID: "7a5326f64be2c3c13c18eb4f", Name: "gate-check",
		SSID: "openunifi-gate-check", Security: "wpa-p",
		Passphrase: "openunifi-fake-gate-psk-20260917",
		VLAN:       1, Enabled: true, Band: "both",
	}}
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, zzHarnessRecord())
	if err := os.WriteFile(zzHarnessDir+"/night-cand-wpa-p-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	intended, violations := zzRunGate(t, "successive-push WPA-PSK vs APPLIED", appliedRaw, sys, zzManagedAllow)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken: %d unmanaged row(s) differ from the APPLIED baseline — the push would restart/delete unmanaged plugins", len(violations))
	}
	for _, d := range intended {
		if strings.HasPrefix(d, "bridge.") {
			t.Fatalf("wpa-p candidate must not touch any bridge.* row (vap shape unchanged); got %s", d)
		}
	}
}

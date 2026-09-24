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
// device 2026-09-17) and enforces the minimal-diff invariant:
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
// live device's device-verified running bytes live separately in
// live-applied-sys.txt (sha256 11cb0472…, re-seeded by the 2026-09-21
// site-settings round, whose key-rows full-provisioning render the device
// confirmed byte-identical; earlier re-seeds: the 2026-09-20
// factory-window set-inform round at ad41cdad…, whose render the device
// confirmed byte-identical — the 2026-09-19 A2 round proved
// the 3da7ce3e… bytes retained row-for-row across a raw reboot). Each
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

	"github.com/lucavb/open-unifi/internal/server/systemcfg"
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
	// carried the row, so every reboot of a provisioned device
	// factory-reset the WLAN text while mgmt/authkey survived via the
	// tar part (WLAN-ACCEPTANCE A2). Baselines captured before the fix
	// still contain the row; its removal is intended. Any OTHER mgmt.*
	// delta remains a violation.
	zzZZAllowPrefix = "unifi. users. sshd. radio. wireless. aaa. vlan. mgmt.is_default"
)

// zzHarnessRecord mirrors harness devices.json (mac aabbccddeeff):
// live-record-shaped passthrough tables so ethPortNames/storedRadios
// resolve exactly like the adopted device's record does. The
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

// zzExemptSSHReMint filters the known one-time record-change delta
// (users.1.password, the 2026-09-20 factory-window re-adoption): the
// console set-inform push lane's live round factory-reset the device
// (setdefault), Forget removed the round-2 record, and the fresh
// state-0 seed re-minted the controller-owned ssh_sha512 password
// cache with a fresh crypt salt — same underlying site password, new
// hash representation. Every device-verified capture taken BEFORE the
// re-adoption differs from every render made AFTER it by exactly this
// row. The live applied bytes were re-captured post-round so this
// filter is inert there; the DAS-state archive (live-das-applied-sys.txt)
// predates the re-adoption and can only be re-seeded by the next DAS
// push round, so the das gate carries this filter until then. Any other
// row still trips the zero-drift gates everywhere.
func zzExemptSSHReMint(rows []string) (out []string) {
	for _, r := range rows {
		if strings.HasPrefix(r, "users.1.password:") {
			continue
		}
		out = append(out, r)
	}
	return out
}

// zzExemptSSHKeyRows filters the known record-change delta (the
// sshd.auth.key.<n>.* row family, the 2026-09-21 site-settings round):
// the live site-settings record first carried a provisioned public key
// that round, so every render made after it emits the key row family
// that device-verified captures taken BEFORE the round cannot carry.
// The live applied bytes were re-captured post-round so this filter is
// inert there; the DAS-state archive (live-das-applied-sys.txt)
// predates the round and can only be re-seeded by the next DAS push
// round, so the das gate carries this filter until then. Any other row
// still trips the zero-drift gates everywhere.
func zzExemptSSHKeyRows(rows []string) (out []string) {
	for _, r := range rows {
		if strings.HasPrefix(r, "sshd.auth.key.") {
			continue
		}
		out = append(out, r)
	}
	return out
}

// zzLiveSiteSettings loads the live site-settings record fixture
// (live-site-settings.json, the on-disk record shape — the
// device-intent facts) and builds the render's SiteSettings for the live
// gates: the record's raw authorized_keys lines parse through the
// single fail-closed parser (the adapter-conversion seam cmd/openunifi
// uses), so every candidate gate renders the CURRENT live sshd rows
// exactly as the running controller does — without this fixture the
// applied baseline's key rows would read as drift. A stale record may
// still carry the REMOVED device_ssh_password key: json tolerates unknown
// keys, the site password concept is gone (the per-device record field
// carries it now), and the render reuses the device's cached password
// hash. Skips when the fixture is absent (the harness lives only on this
// workstation); a present-but-invalid line fails the gate — the fixture
// must be a fetch of the live record, never hand input.
func zzLiveSiteSettings(t *testing.T) SiteSettings {
	t.Helper()
	raw, err := os.ReadFile(zzHarnessDir + "/live-site-settings.json")
	if err != nil {
		t.Skipf("live site-settings record not present (%v)", err)
	}
	var doc struct {
		RegulatoryCountryCode int      `json:"regulatory_country_code"`
		DeviceSSHPublicKeys   []string `json:"device_ssh_public_keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("live site-settings.json: %v", err)
	}
	// keys tolerates the PRE-RENAME wire spelling ap_ssh_public_keys as
	// well as the current device_ssh_public_keys: the checked-in fixture
	// is a bench fetch of the live record whose latest capture predates
	// the site-settings key rename. Both spellings mean the same content;
	// the next live re-fetch will carry the current spelling and this
	// fallback can go away — it exists ONLY here in the bench harness,
	// never on any shipped wire path.
	keys := doc.DeviceSSHPublicKeys
	if keys == nil {
		var legacy struct {
			APSSHPublicKeys []string `json:"ap_ssh_public_keys"`
		}
		if err := json.Unmarshal(raw, &legacy); err != nil {
			t.Fatalf("live site-settings.json: %v", err)
		}
		keys = legacy.APSSHPublicKeys
	}
	facts := SiteSettings{
		CountryCode: doc.RegulatoryCountryCode,
	}
	for _, line := range keys {
		k, perr := systemcfg.ParsePublicKey(line)
		if perr != nil {
			t.Fatalf("live site-settings key line does not parse (the fixture must be a fetch of the live record): %v", perr)
		}
		facts.SSHPublicKeys = append(facts.SSHPublicKeys, k)
	}
	return facts
}

// zzExemptLedBarMigration filters the known renderer-evolution delta
// (the §12 row 1007 ledbar block, 2026-09-19 — jar-cited row-for-row in
// internal/server/systemcfg/ledbar.go, emitted for every supportLedBar
// model) out of a violation list. The synthetic-baseline captures
// (factory forensics, the night reference render, the pinned night
// candidates) predate the lane, so every current U7PG2 render differs
// from them by exactly this block — the filter stays at those gates.
// The LIVE gates (zz_live_candidate_scratch_test.go) dropped the filter
// at the 2026-09-20 DAS/DAD round re-capture: their device-verified
// applied bytes are post-ledbar, so a ledbar.* drift must FAIL there.
// Any other row still trips the zero-drift gates everywhere.
func zzExemptLedBarMigration(rows []string) (out []string) {
	for _, r := range rows {
		if strings.HasPrefix(r, "ledbar.") {
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
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, zzHarnessRecord())
	_, violations := zzRunGate(t, "minimal-diff gate: synthetic record vs factory baseline", factoryRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken: %d unmanaged row(s) differ from the factory baseline — the push would restart/delete unmanaged plugins", len(violations))
	}
}

// TestZZMinimalDiffGateLiveRecord — the same gate on the REAL live record
// fetched from lab-bench (harness live-devices.json, store file shape).
// This verifies the EXACT system_cfg bytes the live device would receive on
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
		t.Fatalf("live device aa:bb:cc:dd:ee:02 absent from fetched record: %d devices", len(file.Devices))
	}
	ports, mgmt := zzRecordFacts(rec)
	fmt.Printf("[minimal-diff gate:live] eth inventory %v, radios %d, mgmt dev %q, vap rows %d\n",
		ports, len(wireless.StoredRadios(rec)), mgmt, len(rec.Extra["vap_table"].([]any)))
	env := []Wlan{{
		ID: "7a5326f64be2c3c13c18eb4f", Name: "gate-check",
		SSID: "openunifi-gate-check", Security: "open",
		VLAN: 1, Enabled: true, Band: "both",
	}}
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/render-live-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	_, violations := zzRunGate(t, "minimal-diff gate: live record vs factory baseline", factoryRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken: %d unmanaged row(s) differ from the factory baseline — the push would restart/delete unmanaged plugins", len(violations))
	}
}

// TestZZLiveIntentVsApplied — the CURRENT live intent: the record, the
// wireless envelope, and the site-settings record as fetched from the
// RUNNING controller
// (live-devices.json + live-wireless.json + live-site-settings.json),
// rendered and diffed against
// the DEVICE-VERIFIED running bytes (live-applied-sys.txt — seeded by a
// confirmed round, most recently the 2026-09-21 site-settings round at
// sha256 11cb0472…, byte-identical to that round's pushed key-rows
// full-provisioning render; before it the 2026-09-20 factory-window
// set-inform round at ad41cdad…; the 2026-09-19 A2 round
// proved the 3da7ce3e… bytes retained row-for-row across a raw reboot)
// and against
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
	facts := zzLiveSiteSettings(t)
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return envFile.Wlans }, SiteSettings: func() (SiteSettings, error) { return facts, nil }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-intent-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[live-intent] envelope wlans=%d, render sha256=%s\n",
		len(envFile.Wlans), func() string { sum := sha256.Sum256([]byte(sys)); return hex.EncodeToString(sum[:]) }())

	_, violations := zzRunGate(t, "live-intent vs FACTORY baseline (factory-echo invariant)", factoryRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken for the live intent: %d unmanaged row(s) differ from the factory baseline", len(violations))
	}
	intended, violations := zzRunGate(t, "live-intent vs DEVICE-VERIFIED APPLIED bytes (steady state)", appliedRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
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
// config. The round EXECUTED and the device verified: /tmp/system.cfg
// reproduced the candidate at sha256 9891d9ff… byte-for-byte, wpa rows
// present, device reachable through the {wireless, aaa} restart. Kept as the
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
		t.Fatalf("live device aa:bb:cc:dd:ee:02 absent from fetched record: %d devices", len(file.Devices))
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
		t.Skipf("a wpa-p round is complete and device-verified (2026-09-18 C1, superseded by the 2026-09-19 A2 passphrase round, proven retained across a raw reboot, re-verified by the 2026-09-20 DAS/DAD round's accounting-off revert at sha256 c4b7f3bf…); the steady-state check lives in TestZZLiveIntentVsApplied")
	}
	if cand.Security != "open" {
		t.Fatalf("live envelope security = %q, expected the open baseline before the C1 mutation", cand.Security)
	}
	cand.Security, cand.Passphrase = "wpa-p", zzLiveWpaPSK
	env := []Wlan{cand}
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/live-wpa-candidate-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("[live-wpa-candidate] render sha256=%s\n",
		func() string { sum := sha256.Sum256([]byte(sys)); return hex.EncodeToString(sum[:]) }())

	intended, violations := zzRunGate(t, "live-wpa-candidate vs RUNNING (device-verified bytes)", runningRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
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
// re-renders the exact envelope the device already runs and must reproduce
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
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, zzHarnessRecord())
	if err := os.WriteFile(zzHarnessDir+"/night-cand-both-open-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	intended, violations := zzRunGate(t, "successive-push CONTROL: both-band open vs APPLIED", appliedRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
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
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, zzHarnessRecord())
	if err := os.WriteFile(zzHarnessDir+"/night-cand-2g-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	allow := func(k string) bool {
		return zzManagedAllow(k) || k == "bridge.1.port.3.devname"
	}
	intended, violations := zzRunGate(t, "successive-push 2g-ONLY vs APPLIED (+intended bridge port removal)", appliedRaw, sys, allow)
	violations = zzExemptLedBarMigration(violations)
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

// TestZZSuccessivePushChannelIntentVsApplied — the per-radio admin
// channel-intent candidate (radio lane): zzHarnessRecord + the
// admin-owned Extra["radio_intent"] layer (wifi1 = the na radio, channel
// 36) with the SAME gate-check both-band open WLAN, diffed against the
// APPLIED bytes. The channel-intent push is exactly the kind the
// minimal-diff invariant exists for: the intended delta must be the ONE
// row radio.2.channel "0"→"36" (radio 2 = wifi1 na; runtime channels
// live in vap_table, WLAN-ACCEPTANCE 2026-09-17 §channel rows), with
// every unmanaged section byte-identical — the restart set stays
// {radio}, which is NOT live-evidenced (the {radio} plugin restart has
// no live round yet; see the radio-lane obligations in
// WLAN-ACCEPTANCE-6.8.2.15592.md). Post-merge activation evidence: run
// on the postmortem workstation main checkout (tmpwork/harness-20260917
// present) and record the gate listing + candidate sha256 in the
// acceptance doc before the first live channel-intent push.
func TestZZSuccessivePushChannelIntentVsApplied(t *testing.T) {
	appliedRaw, err := os.ReadFile(zzAppliedCfg)
	if err != nil {
		t.Skipf("applied baseline not present (%v); successive-push gates run only on the postmortem workstation", err)
	}
	env := []Wlan{{
		ID: "7a5326f64be2c3c13c18eb4f", Name: "gate-check",
		SSID: "openunifi-gate-check", Security: "open",
		VLAN: 1, Enabled: true, Band: "both",
	}}
	rec := zzHarnessRecord()
	rec.Extra["radio_intent"] = map[string]any{
		"wifi1": map[string]any{"channel": 36.0},
	}
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if err := os.WriteFile(zzHarnessDir+"/night-cand-channel-intent-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	intended, violations := zzRunGate(t, "successive-push CHANNEL-INTENT vs APPLIED", appliedRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken: %d unmanaged row(s) differ from the APPLIED baseline — the push would restart/delete unmanaged plugins: %v", len(violations), violations)
	}
	intended = zzExemptIsDefaultMigration(intended)
	if len(intended) != 1 || !strings.HasPrefix(intended[0], `radio.2.channel: "0" -> "36"`) {
		t.Fatalf("channel-intent candidate must change exactly one row (radio.2.channel 0->36); got %v", intended)
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
	s := New(Config{WirelessForDevice: func(_ store.Device) []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, zzHarnessRecord())
	if err := os.WriteFile(zzHarnessDir+"/night-cand-wpa-p-sys.txt", []byte(sys), 0o644); err != nil {
		t.Fatal(err)
	}
	intended, violations := zzRunGate(t, "successive-push WPA-PSK vs APPLIED", appliedRaw, sys, zzManagedAllow)
	violations = zzExemptLedBarMigration(violations)
	if len(violations) > 0 {
		t.Fatalf("minimal-diff invariant broken: %d unmanaged row(s) differ from the APPLIED baseline — the push would restart/delete unmanaged plugins", len(violations))
	}
	for _, d := range intended {
		if strings.HasPrefix(d, "bridge.") {
			t.Fatalf("wpa-p candidate must not touch any bridge.* row (vap shape unchanged); got %s", d)
		}
	}
}

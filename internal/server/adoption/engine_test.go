package adoption

// Engine-direct table tests: every converted test crosses ONLY the engine
// interface (Decide) with deterministic injected randomness — no store, no
// HTTP, no crypto. The transport adapter (package server) applies the
// outcome deltas exactly like its applyOutcome does; the tiny applyDeltas
// helper here mirrors that contract.

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

const engineMAC = "aabbccddeeff"

// newTestEngine builds an Engine with fully deterministic injections: the
// random source returns 0.5, key generation mints an incrementing hex
// sequence (distinct per call), the wireless source is empty, and the
// system_cfg producer returns a canned blob. Tests override e.random /
// e.wireless / e.systemCfg directly (in-package).
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	counter := 0
	e := New(Deps{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Random:   func() float64 { return 0.5 },
		KeyChars: func(n int) (string, error) { return "", nil }, // replaced below
		Wireless: func(store.Device) []wireless.Wlan { return nil },
		SystemCfg: func(store.Device, []wireless.Wlan, wireless.ProvisioningPlan) (string, map[string]string, error) {
			return "# unifi\nunifi.version=0.1.0-dev\n", nil, nil
		},
	})
	e.keyChars = func(n int) (string, error) {
		counter++
		s := strconv.FormatInt(int64(counter), 16)
		return strings.Repeat("0", n-len(s)) + s, nil
	}
	return e
}

// engineBody builds a decoded inform body for the engine tests (the engine
// reads only _type; the mac mirrors the adapter's identity contract).
func engineBody(appliedCfg string) map[string]any {
	jm := map[string]any{
		"_type": "info",
		"mac":   "aa:bb:cc:dd:ee:ff",
	}
	if appliedCfg != "" {
		jm["cfgversion"] = appliedCfg
	}
	return jm
}

// applyDeltas mirrors the adapter's applyOutcome record-delta application
// (the noop-target persistence is not simulated here; tests carry
// PrevNoopTarget explicitly).
func applyDeltas(dev *store.Device, out Outcome) {
	if out.SetState {
		dev.State = out.State
	}
	if out.SetXAuthkey {
		dev.XAuthkey = out.XAuthkey
	}
	if out.SetCfgVersion {
		dev.CfgVersion = out.CfgVersion
	}
	if out.SetAppliedCfg {
		dev.AppliedCfg = out.AppliedCfg
	}
	if out.SetAuthkeys {
		dev.Authkeys = out.Authkeys
	}
	dev.Extra = out.Extra
	for k, v := range out.CredentialDeltas {
		dev.Extra[k] = v
	}
}

func isHexStr(s string) bool { return len(s) > 0 && strings.Trim(s, "0123456789abcdef") == "" }

func containsKeyStr(keys []string, k string) bool {
	for _, x := range keys {
		if strings.EqualFold(x, k) {
			return true
		}
	}
	return false
}

// decideNoop drives the engine's noop scheduling through the plaintext
// no-assignment path (the only branch that reaches the pure formula without
// further state): XAuthkey unset → noop.
func decideNoop(t *testing.T, e *Engine, dev store.Device, now int64, prevTarget int64) Outcome {
	t.Helper()
	out, err := e.Decide(Request{
		Transport:      TransportPlaintext,
		Device:         dev,
		Body:           map[string]any{"mac": "aa:bb:cc:dd:ee:ff"},
		Now:            time.Unix(now, 0),
		PrevNoopTarget: prevTarget,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestNoopIntervalScheduling: the jar-cited non-ubios UAP scheduler with
// deterministic random injection — identical interval assertions to the
// former handler-level test.
func TestNoopIntervalScheduling(t *testing.T) {
	tests := []struct {
		name string
		r    float64
		rec  store.Device
		now  int64
		want int64
	}{
		{"first low", 0, store.Device{Model: "U7PG2", Extra: store.JSONMap{}}, 1000, 10},
		{"first high", .9, store.Device{Model: "U7PG2", Extra: store.JSONMap{}}, 1000, 14},
		{"watching", .5, store.Device{Model: "U7PG2", Extra: store.JSONMap{"watching": true}}, 1000, 5},
		{"ubios fallback", .5, store.Device{Model: "UDM-Pro", Extra: store.JSONMap{}}, 1000, 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newTestEngine(t)
			e.random = func() float64 { return tt.r }
			got := decideNoop(t, e, tt.rec, tt.now, 0).Interval
			if got != tt.want {
				t.Fatalf("interval = %v, want %d", got, tt.want)
			}
		})
	}
	t.Run("target advances and cap fallback does not persist", func(t *testing.T) {
		e := newTestEngine(t)
		e.random = func() float64 { return 0 }
		r := store.Device{MAC: engineMAC, Model: "U7PG2", Extra: store.JSONMap{}}
		out := decideNoop(t, e, r, 1000, 0)
		if out.Interval != 10 || !out.PersistNoopTarget || out.NewNoopTarget != 1010 {
			t.Fatalf("first: %+v", out)
		}
		out = decideNoop(t, e, r, 1005, out.NewNoopTarget)
		if out.Interval != 10 || !out.PersistNoopTarget || out.NewNoopTarget != 1015 {
			t.Fatalf("second: %+v", out)
		}
		e.random = func() float64 { return .5 }
		out = decideNoop(t, e, r, 1000, 1100)
		if out.Interval != 58 || out.PersistNoopTarget {
			t.Fatalf("cap fallback must not persist: %+v", out)
		}
	})
}

// (c) happy adoption path: pending + default-key inform → adoption push with
// fresh x_authkey; re-keyed inform with matching cfgversion → noop
// (+adopted). The transport-level assertions of the former handler test
// (sealed-envelope flags, fresh IV, MAC echo) stay covered by the
// server-package GCM/CBC matrix test through the real handler.
func TestHappyAdoption(t *testing.T) {
	e := newTestEngine(t)
	dev := store.Device{MAC: engineMAC, State: store.StatePending}

	// Inform #1: factory default key, no cfgversion applied yet.
	out, err := e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody(""),
		UsedKey:   defaultKeyHex,
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Adoption push (§6.2 a/c/f): mgmt_cfg ONLY.
	if out.Kind != KindSetparam || out.FullProvision {
		t.Fatalf("inform#1 kind = %v full=%v, want adoption push", out.Kind, out.FullProvision)
	}
	mgmt := out.MgmtCfg
	if mgmt == "" || !strings.HasSuffix(mgmt, "\n") {
		t.Fatalf("inform#1 mgmt_cfg not \\n-terminated: %q", mgmt)
	}
	if !strings.Contains(mgmt, "cfgversion=") ||
		!strings.Contains(mgmt, "capability=notif,notif-assoc-stat") {
		t.Fatalf("inform#1 mgmt_cfg = %q", mgmt)
	}
	if strings.Contains(mgmt, "unifi.") {
		t.Fatalf("inform#1 mgmt_cfg has superseded unifi.* keys: %q", mgmt)
	}
	if !strings.Contains(mgmt, "authkey=") {
		t.Fatalf("inform#1 adoption mgmt_cfg missing authkey rotation line: %q", mgmt)
	}
	// Deltas: State → adopting, fresh 32-hex x_authkey (in Authkeys), fresh
	// 16-hex cfgversion. NO wireless baseline is seeded at adoption (the
	// 2026-09-18 F-row live round: a seed equal to the current envelope
	// hash suppressed delivery; settle captures the baseline after
	// delivery proof instead).
	if !out.SetState || out.State != store.StateAdopting {
		t.Fatalf("state delta after inform#1: %+v", out)
	}
	xkey := out.XAuthkey
	if !out.SetXAuthkey || len(xkey) != 32 || !isHexStr(xkey) {
		t.Fatalf("x_authkey not stored as 32 hex: %q", xkey)
	}
	if !out.SetAuthkeys || !containsKeyStr(out.Authkeys, out.XAuthkey) {
		t.Fatalf("x_authkey not in authkeys: %v", out.Authkeys)
	}
	cfg := out.CfgVersion
	if !out.SetCfgVersion || len(cfg) != 16 || !isHexStr(cfg) {
		t.Fatalf("cfgversion not 16 hex: %q", cfg)
	}
	if _, ok := out.Extra["wlan_cfg_sha"]; ok {
		t.Fatalf("adoption push seeded wlan_cfg_sha = %v, want none", out.Extra["wlan_cfg_sha"])
	}
	applyDeltas(&dev, out)

	// Inform #2: device re-keyed to x_authkey and echoes the adoption
	// mgmt_cfg's cfgversion. No baseline was seeded, so the self-heal
	// answers a noop and mints a fresh cfgversion (forcing full
	// provisioning on the next inform); the state stays adopting until
	// that delivery settles.
	dev.AppliedCfg = cfg
	out, err = e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody(cfg),
		UsedKey:   xkey,
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("inform#2 kind = %v, want noop", out.Kind)
	}
	// FID-11: interval is a JSON number of seconds (deterministic rand 0.5 →
	// target max(prev+5, now+10)+2 = now+12 with no prior target).
	if out.Interval != 12 {
		t.Fatalf("interval = %d, want 12", out.Interval)
	}
	if !out.SetCfgVersion || out.CfgVersion == cfg {
		t.Fatalf("post-adoption echo did not self-heal-mint a cfgversion: %q vs %q", out.CfgVersion, cfg)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopting {
		t.Fatalf("state after inform#2 = %d, want adopting (delivery outstanding)", dev.State)
	}

	// Inform #3: device still echoes the mgmt cfgversion → mismatch against
	// the minted one → full provisioning (the real-controller post-adoption
	// sequence captured on 2026-09-16).
	out, err = e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody(cfg),
		UsedKey:   xkey,
		Now:       time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" {
		t.Fatalf("inform#3 outcome = %+v, want setparam full provisioning", out)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopting {
		t.Fatalf("state after inform#3 = %d, want adopting", dev.State)
	}

	// Inform #4: device applied the provisioned config and reports an
	// (empty) vap_table → settle confirms, connected noop, adopted.
	dev.AppliedCfg = dev.CfgVersion
	dev.Extra["vap_table"] = []any{}
	out, err = e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody(dev.CfgVersion),
		UsedKey:   xkey,
		Now:       time.Unix(1020, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("inform#4 kind = %v, want noop", out.Kind)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopted {
		t.Fatalf("state after inform#4 = %d, want adopted", dev.State)
	}
	if _, ok := dev.Extra["wlan_cfg_sha"]; !ok {
		t.Fatal("settle did not capture the envelope baseline")
	}
}

// notRunningHarness builds the settled-state fixture family the
// not-running watchdog tests share: an adopted device on its per-device
// key whose stored baseline matches the live envelope and whose applied
// snapshot is that envelope (the state settle leaves behind).
// factoryTable disposes the applied SSID; runningTable proves it RUN.
func notRunningHarness(t *testing.T) (e *Engine, fixture func(vaps any) store.Device, factoryTable, runningTable []any) {
	t.Helper()
	env := []wireless.Wlan{{Name: "corp", SSID: "corpnet", Security: "wpa-p", Passphrase: "pw", VLAN: 1, Enabled: true}}
	counter := 0
	e = New(Deps{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Random: func() float64 { return 0.5 },
		KeyChars: func(n int) (string, error) {
			counter++
			s := strconv.FormatInt(int64(counter), 16)
			return strings.Repeat("0", n-len(s)) + s, nil
		},
		Wireless: func(store.Device) []wireless.Wlan { return env },
		SystemCfg: func(store.Device, []wireless.Wlan, wireless.ProvisioningPlan) (string, map[string]string, error) {
			return "sys\n", nil, nil
		},
	})
	snap, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	const k = "11112222333344445555666677778888"
	factoryTable = []any{map[string]any{"essid": "factory-default", "state": "RUN", "radio_name": "ra0", "name": "ath0"}}
	runningTable = []any{map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": "ra0", "name": "ath0"}}
	fixture = func(vaps any) store.Device {
		return store.Device{
			MAC: engineMAC, State: store.StateAdopted,
			CfgVersion: "aaaa", AppliedCfg: "aaaa",
			XAuthkey: k, Authkeys: []string{k}, Model: "U7PG2",
			Extra: store.JSONMap{
				"wlan_cfg_sha":           wireless.WlanListHash(env),
				"wlan_cfg_applied_wlans": string(snap),
				"vap_table":              vaps,
			},
		}
	}
	return e, fixture, factoryTable, runningTable
}

// missCounter reads the persisted consecutive-miss counter out of an
// outcome Extra (engine writes int; tolerant of the JSON float64 shape).
func missCounter(extra store.JSONMap) (int, bool) {
	v, ok := extra["wlan_cfg_not_running_misses"]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	}
	return 0, false
}

// Settled-state regression (2026-09-18 F-row live round, A2 finding) under
// the two-consecutive-miss arming (2026-09-19 boot-race finding): a
// PRESENT vap_table that disproves the confirmed WLAN set re-arms delivery
// only on the SECOND consecutive proof. Miss#1 is the boot-race grace — a
// plain connected noop with the miss recorded as controller-owned
// bookkeeping; miss#2 fires with the one-shot mechanics (minting noop →
// full provisioning on the next inform) and resets the window. Absent or
// empty tables stay unknown (sparse heartbearts never re-arm) and a table
// proving the applied SSID RUNNING is steady state.
func TestSettledRegressionRearms(t *testing.T) {
	e, fixture, factoryTable, runningTable := notRunningHarness(t)
	decide := func(dev store.Device, now int64) Outcome {
		t.Helper()
		out, err := e.Decide(Request{
			Transport: TransportEncrypted, Device: dev,
			Body: engineBody("aaaa"), UsedKey: dev.XAuthkey,
			Now: time.Unix(now, 0),
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Miss#1 (genuine factory, or the boot race): recorded, not fired.
	dev := fixture(factoryTable)
	out := decide(dev, 1000)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("miss#1 outcome = %+v, want plain connected noop (no mint under the boot-race grace)", out)
	}
	if n, ok := missCounter(out.Extra); !ok || n != 1 {
		t.Fatalf("miss#1 counter = %v/%v, want recorded 1", n, ok)
	}

	// Miss#2 (the proof is consecutive): fire — minting noop, window reset.
	applyDeltas(&dev, out)
	dev.Extra["vap_table"] = factoryTable
	out = decide(dev, 1010)
	if out.Kind != KindNoop || !out.SetCfgVersion || out.CfgVersion == "aaaa" {
		t.Fatalf("miss#2 outcome = %+v, want minting noop (fire)", out)
	}
	if _, ok := missCounter(out.Extra); ok {
		t.Fatalf("counter not reset after fire: %v", out.Extra["wlan_cfg_not_running_misses"])
	}

	// Next inform (device still echoes the old stamp) → full provisioning.
	applyDeltas(&dev, out)
	out = decide(dev, 1020)
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" {
		t.Fatalf("post-fire outcome = %+v, want full provisioning", out)
	}

	// Unknown (absent table): plain connected noop, no re-arm, no counter.
	out = decide(fixture(nil), 1030)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("absent-table outcome = %+v, want plain connected noop", out)
	}
	if _, ok := missCounter(out.Extra); ok {
		t.Fatalf("absent table disturbed the window: %v", out.Extra["wlan_cfg_not_running_misses"])
	}
	// Unknown (empty table): plain connected noop, no re-arm.
	out = decide(fixture([]any{}), 1040)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("empty-table outcome = %+v, want plain connected noop", out)
	}
	if _, ok := missCounter(out.Extra); ok {
		t.Fatalf("empty table disturbed the window: %v", out.Extra["wlan_cfg_not_running_misses"])
	}
	// Steady state (applied SSID RUNNING): plain connected noop, no re-arm.
	out = decide(fixture(runningTable), 1050)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("running-table outcome = %+v, want plain connected noop", out)
	}
	if _, ok := missCounter(out.Extra); ok {
		t.Fatalf("RUN proof must not write an idle counter: %v", out.Extra["wlan_cfg_not_running_misses"])
	}
}

// Boot-race (2026-09-19 A2 re-run finding, WLAN-ACCEPTANCE 6.8.2.15592):
// a rebooted device's first re-inform can carry a present, non-empty
// vap_table whose radios are still in bring-up — the applied SSID not yet
// RUN is the race, not genuine factory regression. miss → later RUN = NO
// fire, the RUN proof resets the window, and the reset window re-arms
// fresh (it again takes two new consecutive misses to fire).
func TestNotRunningBootRaceGrace(t *testing.T) {
	e, fixture, factoryTable, runningTable := notRunningHarness(t)
	decide := func(dev store.Device, now int64) Outcome {
		t.Helper()
		out, err := e.Decide(Request{
			Transport: TransportEncrypted, Device: dev,
			Body: engineBody("aaaa"), UsedKey: dev.XAuthkey,
			Now: time.Unix(now, 0),
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// The boot race: the first post-boot table shows the applied SSID not
	// yet running — one miss, no fire.
	dev := fixture(factoryTable)
	out := decide(dev, 1000)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("boot-race miss = %+v, want plain connected noop (a single miss must not fire)", out)
	}
	if n, ok := missCounter(out.Extra); !ok || n != 1 {
		t.Fatalf("boot-race miss not recorded: counter = %v/%v, want 1", n, ok)
	}

	// The race resolves: the next table proves the applied SSID RUN. No
	// fire ever happened and the RUN proof resets the window.
	applyDeltas(&dev, out)
	dev.Extra["vap_table"] = runningTable
	out = decide(dev, 1010)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("post-race RUN = %+v, want plain connected noop (boot race: no fire)", out)
	}
	if _, ok := missCounter(out.Extra); ok {
		t.Fatalf("RUN proof did not reset the window: %v", out.Extra["wlan_cfg_not_running_misses"])
	}

	// The reset window re-arms fresh: the next single miss still does not
	// fire...
	applyDeltas(&dev, out)
	dev.Extra["vap_table"] = factoryTable
	out = decide(dev, 1020)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("post-race miss#1 = %+v, want plain connected noop (window re-armed, no fire)", out)
	}
	// ...and the second consecutive miss does.
	applyDeltas(&dev, out)
	dev.Extra["vap_table"] = factoryTable
	out = decide(dev, 1030)
	if out.Kind != KindNoop || !out.SetCfgVersion || out.CfgVersion == "aaaa" {
		t.Fatalf("post-race miss#2 = %+v, want minting noop (re-armed window fires)", out)
	}
}

// Reboot is a lifecycle boundary for the not-running window: a miss
// recorded BEFORE an admin-armed reboot must not fire on the first
// post-boot bring-up table — the KindReboot emission clears the
// consecutive-miss counter with the flag, so the post-reboot boot race
// gets its full two-miss grace again (the review's cross-cycle carry).
func TestRebootEmissionClearsNotRunningWindow(t *testing.T) {
	e, fixture, factoryTable, runningTable := notRunningHarness(t)
	decide := func(dev store.Device, now int64) Outcome {
		t.Helper()
		out, err := e.Decide(Request{
			Transport: TransportEncrypted, Device: dev,
			Body: engineBody("aaaa"), UsedKey: dev.XAuthkey,
			Now: time.Unix(now, 0),
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Pre-reboot miss#1: recorded, no fire (the boot-race grace shape).
	dev := fixture(factoryTable)
	out := decide(dev, 1000)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("pre-reboot miss#1 = %+v, want plain connected noop", out)
	}
	if n, ok := missCounter(out.Extra); !ok || n != 1 {
		t.Fatalf("pre-reboot miss#1 counter = %v/%v, want 1", n, ok)
	}

	// Admin arms the reboot; the next inform emits it and must clear the
	// window with the flag (the next table is a fresh boot window).
	applyDeltas(&dev, out)
	dev.Extra[FlagRebootOnConnect] = true
	out = decide(dev, 1010)
	if out.Kind != KindReboot {
		t.Fatalf("armed inform = %+v, want reboot", out)
	}
	applyDeltas(&dev, out)
	if _, ok := dev.Extra["wlan_cfg_not_running_misses"]; ok {
		t.Fatalf("reboot emission left the miss window armed: %v", dev.Extra["wlan_cfg_not_running_misses"])
	}

	// First post-reboot table is the bring-up race (a miss): plain
	// connected noop — the window re-armed from zero, not a fire.
	dev.Extra["vap_table"] = factoryTable
	out = decide(dev, 1020)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("post-reboot boot-race miss = %+v, want plain connected noop (window cleared at emission)", out)
	}
	if n, ok := missCounter(out.Extra); !ok || n != 1 {
		t.Fatalf("post-reboot miss counter = %v/%v, want the window re-armed at 1", n, ok)
	}

	// The race resolves: RUN proof, steady state, window reset.
	applyDeltas(&dev, out)
	dev.Extra["vap_table"] = runningTable
	out = decide(dev, 1030)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("post-race RUN = %+v, want plain connected noop", out)
	}
	if _, ok := missCounter(out.Extra); ok {
		t.Fatalf("RUN proof must reset the window: %v", out.Extra["wlan_cfg_not_running_misses"])
	}
}

// Sparse heartbeats (absent or empty vap_table) are UNKNOWN: they never
// increment and never reset the window. A sparse inform between two
// not-running proofs leaves the miss chain intact — the second consecutive
// proof still fires — and sparse informs after a single miss leave the
// counter armed.
func TestNotRunningSparseHeartbeatNeutral(t *testing.T) {
	e, fixture, factoryTable, _ := notRunningHarness(t)
	decide := func(dev store.Device, now int64) Outcome {
		t.Helper()
		out, err := e.Decide(Request{
			Transport: TransportEncrypted, Device: dev,
			Body: engineBody("aaaa"), UsedKey: dev.XAuthkey,
			Now: time.Unix(now, 0),
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Miss#1 arms the window.
	dev := fixture(factoryTable)
	out := decide(dev, 1000)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("miss#1 = %+v, want plain connected noop", out)
	}
	if n, ok := missCounter(out.Extra); !ok || n != 1 {
		t.Fatalf("miss#1 counter = %v/%v, want 1", n, ok)
	}

	// Sparse heartbeat (no vap_table in the body): unknown — no increment,
	// no reset, no fire.
	applyDeltas(&dev, out)
	delete(dev.Extra, "vap_table")
	out = decide(dev, 1010)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("sparse-absent outcome = %+v, want plain connected noop (sparse must never re-arm)", out)
	}
	if n, ok := missCounter(out.Extra); !ok || n != 1 {
		t.Fatalf("sparse-absent counter = %v/%v, want kept 1 (no change)", n, ok)
	}

	// Empty table (present but zero rows): same neutrality.
	applyDeltas(&dev, out)
	dev.Extra["vap_table"] = []any{}
	out = decide(dev, 1020)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("sparse-empty outcome = %+v, want plain connected noop (sparse must never re-arm)", out)
	}
	if n, ok := missCounter(out.Extra); !ok || n != 1 {
		t.Fatalf("sparse-empty counter = %v/%v, want kept 1 (no change)", n, ok)
	}

	// The unknowns did not break the chain: the next full factory proof is
	// the SECOND consecutive miss → fire.
	applyDeltas(&dev, out)
	dev.Extra["vap_table"] = factoryTable
	out = decide(dev, 1030)
	if out.Kind != KindNoop || !out.SetCfgVersion || out.CfgVersion == "aaaa" {
		t.Fatalf("post-sparse miss#2 = %+v, want minting noop (unknowns must not break the miss chain)", out)
	}
}

// appliedNotRunning's proof semantics are the watchdog's evidence bar and
// MUST NOT change (the two-consecutive-miss lane changes only the arming
// policy around them): SSID presence is the proof bar (not per-radio
// placement), absent/empty tables and absent/no-enabled/unparsable applied
// snapshots are unknown, and the snapshot is re-read from extra verbatim.
// notRunningEvidence carries the same bar as a three-way classification
// (the policy's increment/reset/neutral inputs).
func TestAppliedNotRunningProofSemantics(t *testing.T) {
	enabled := []wireless.Wlan{{Name: "corp", SSID: "corpnet", Security: "open", Enabled: true}}
	disabled := []wireless.Wlan{{Name: "corp", SSID: "corpnet", Security: "open", Enabled: false}}
	snap := func(w []wireless.Wlan) string {
		b, err := json.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	factory := []any{map[string]any{"essid": "factory-default", "state": "RUN", "radio_name": "ra0"}}
	runEssid := []any{map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": "ra0"}}
	runLegacy := []any{map[string]any{"ssid": "corpnet", "status": "RUN"}}                          // legacy fixture spellings
	runOtherRadio := []any{map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": "ra9"}} // placement is NOT the bar
	appliedNotRun := []any{map[string]any{"essid": "corpnet", "state": "INIT", "radio_name": "ra0"}}

	tests := []struct {
		name  string
		extra store.JSONMap
		class notRunningClass
	}{
		{"absent table is unknown", store.JSONMap{"wlan_cfg_applied_wlans": snap(enabled)}, nrUnknown},
		{"empty table is unknown", store.JSONMap{"wlan_cfg_applied_wlans": snap(enabled), "vap_table": []any{}}, nrUnknown},
		{"no applied snapshot is unknown", store.JSONMap{"vap_table": factory}, nrUnknown},
		{"unparsable snapshot is unknown", store.JSONMap{"wlan_cfg_applied_wlans": "{bad", "vap_table": factory}, nrUnknown},
		{"nothing enabled is unknown", store.JSONMap{"wlan_cfg_applied_wlans": snap(disabled), "vap_table": factory}, nrUnknown},
		{"factory table is a miss", store.JSONMap{"wlan_cfg_applied_wlans": snap(enabled), "vap_table": factory}, nrMiss},
		{"applied ssid not RUN is a miss", store.JSONMap{"wlan_cfg_applied_wlans": snap(enabled), "vap_table": appliedNotRun}, nrMiss},
		{"run essid proves running", store.JSONMap{"wlan_cfg_applied_wlans": snap(enabled), "vap_table": runEssid}, nrRun},
		{"legacy run spellings prove running", store.JSONMap{"wlan_cfg_applied_wlans": snap(enabled), "vap_table": runLegacy}, nrRun},
		{"run on any radio proves running", store.JSONMap{"wlan_cfg_applied_wlans": snap(enabled), "vap_table": runOtherRadio}, nrRun},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := loadWlanCfgState(tt.extra)
			if got := st.notRunningEvidence(); got != tt.class {
				t.Fatalf("notRunningEvidence = %v, want %v", got, tt.class)
			}
			if got, want := st.appliedNotRunning(), tt.class == nrMiss; got != want {
				t.Fatalf("appliedNotRunning = %v, want %v (miss class only)", got, want)
			}
		})
	}

	// The counter loads from both the engine's int write and the JSON
	// round-trip float64 shape (persisted-store reload).
	if got := loadWlanCfgState(store.JSONMap{"wlan_cfg_not_running_misses": 1}).notRunningMisses; got != 1 {
		t.Fatalf("int counter load = %d, want 1", got)
	}
	if got := loadWlanCfgState(store.JSONMap{"wlan_cfg_not_running_misses": float64(2)}).notRunningMisses; got != 2 {
		t.Fatalf("float64 counter load = %d, want 2", got)
	}
}

// (d) cfgversion drift after adoption → FULL provisioning setparam (all four
// config keys), state back to adopting. Device is on its x_authkey, so the
// mgmt_cfg must NOT carry the authkey rotation line. The system_cfg CONTENT
// assertions of the former handler test are covered by the builder-direct
// tests that stay in package server (the producer is injected this
// checkpoint).
func TestCfgVersionDriftFullProvisioning(t *testing.T) {
	e := newTestEngine(t)
	const k = "11112222333344445555666677778888"
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateAdopted,
		CfgVersion: "aaaa",
		AppliedCfg: "",
		XAuthkey:   k,
		Authkeys:   []string{k},
		Model:      "U7PG2",
		InformURL:  "http://10.0.0.5:8080/inform",
	}
	out, err := e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody("bogus-drift"),
		UsedKey:   k,
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("drift reply kind = %v full=%v, want setparam full provisioning", out.Kind, out.FullProvision)
	}
	if out.CfgVersion != "aaaa" {
		t.Fatalf("top-level cfgversion = %q, want record value %q", out.CfgVersion, "aaaa")
	}
	if out.BlockedSta != "" {
		t.Fatalf("blocked_sta = %q, want empty (no block list yet)", out.BlockedSta)
	}
	if out.SystemCfg == "" {
		t.Fatal("system_cfg missing in full provisioning outcome")
	}
	mgmt := out.MgmtCfg
	if strings.Contains(mgmt, "authkey=") {
		t.Fatalf("full-provisioning mgmt_cfg must omit authkey when device is on x_authkey: %q", mgmt)
	}
	if !strings.Contains(mgmt, "cfgversion=aaaa\n") {
		t.Fatalf("full-provisioning mgmt_cfg missing record cfgversion: %q", mgmt)
	}
	for _, want := range []string{
		"capability=notif,notif-assoc-stat\n",
		"selfrun_guest_mode=pass\n",
		"led_enabled=true\n",
		"stun_url=stun://10.0.0.5:3478/\n",
		"mgmt_url=https://10.0.0.5:8443/manage/site/default\n",
		// FID-16: no inform_url row — the row is emitted only when the
		// controller URL is explicitly overridden (not set here).
		"use_aes_gcm=true\n",
		"report_crash=true\n",
	} {
		if !strings.Contains(mgmt, want) {
			t.Fatalf("mgmt_cfg missing %q:\n%s", want, mgmt)
		}
	}
	if strings.Contains(mgmt, "inform_url=") {
		t.Fatalf("unoverridden mgmt_cfg must omit the inform_url row:\n%s", mgmt)
	}
	if strings.Contains(mgmt, "is_setup_completed") {
		t.Fatalf("mgmt_cfg is UDM-only line: %q", mgmt)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopting {
		t.Fatalf("drift state = %d, want adopting", dev.State)
	}
	if dev.CfgVersion != "aaaa" {
		t.Fatalf("full provisioning must keep the record cfgversion, got %q", dev.CfgVersion)
	}
}

// (e) inform with the forbidden default key AFTER adoption → REJECTED: the
// state-gated factory key (FID-1) maps to the classic 404 marker and the
// engine must produce NO record deltas (the adapter aborts the store cycle,
// so the record stays completely untouched).
func TestDefaultKeyAfterAdoptionRejected(t *testing.T) {
	e := newTestEngine(t)
	const k = "99998888777766665555444433332222"
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateAdopted,
		CfgVersion: "aaaa",
		AppliedCfg: "aaaa",
		XAuthkey:   k,
		Authkeys:   []string{k},
		Model:      "U7PG2",
	}
	out, err := e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody("aaaa"),
		UsedKey:   defaultKeyHex,
		Now:       time.Unix(1000, 0),
	})
	if err != ErrDefaultKeyRejected {
		t.Fatalf("err = %v, want default-key rejection (404 marker)", err)
	}
	if out.Kind != "" || out.SetState || out.SetXAuthkey || out.SetCfgVersion || out.SetAuthkeys || out.Extra != nil {
		t.Fatalf("rejected default-key inform produced deltas: %+v", out)
	}
}

// A known-but-stale authkey (≠ x_authkey) used during adoption → hostile/
// unexpected, but FID-36 (jar §1348 rotation pending path): the broker
// RE-PUSHES the existing per-device key via the authkey= line WITHOUT
// rotating it.
func TestUnexpectedKeyDuringAdoption(t *testing.T) {
	e := newTestEngine(t)
	// Seeded mid-adoption record: our assigned x_authkey is "deadbeef...", but
	// the device still holds the older admin key "1111..." from a previous cycle.
	const stale = "11112222333344445555666677778888"
	const xauth = "deadbeefdeadbeefdeadbeefdeadbeef"
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateAdopting,
		CfgVersion: "aaaa",
		AppliedCfg: "",
		XAuthkey:   xauth,
		Authkeys:   []string{stale, defaultKeyHex},
	}
	out, err := e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody(""),
		UsedKey:   stale,
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Stale-x_authkey inform → adoption-push shape (mgmt_cfg only) carrying
	// the CURRENT assignment, no rotation (FID-36).
	if out.Kind != KindSetparam || out.FullProvision {
		t.Fatalf("kind = %v full=%v, want setparam adoption push", out.Kind, out.FullProvision)
	}
	if out.SetXAuthkey || out.SetState || out.SetAuthkeys {
		t.Fatalf("re-push must not mutate the assignment: %+v", out)
	}
	applyDeltas(&dev, out)
	if dev.XAuthkey != xauth {
		t.Fatalf("x_authkey must be re-pushed unchanged, got %q (want %q)", dev.XAuthkey, xauth)
	}
	if dev.State != store.StateAdopting {
		t.Fatalf("state = %d, want adopting", dev.State)
	}
	if len(dev.Authkeys) != 2 || !containsKeyStr(dev.Authkeys, stale) || !containsKeyStr(dev.Authkeys, defaultKeyHex) {
		t.Fatalf("authkeys touched by re-push: %v", dev.Authkeys)
	}
	if !strings.Contains(out.MgmtCfg, "authkey="+xauth+"\n") {
		t.Fatalf("adoption push mgmt_cfg %q missing current assignment authkey line", out.MgmtCfg)
	}
}

// After three default-key rotations only the newest two assigned keys may be
// stored; the first rotated key is gone. (The DECRYPT capability of the
// pruned/kept keys is transport-level and stays covered by the server-package
// adapter test through the real handler.)
func TestAuthkeysPrunedToTwo(t *testing.T) {
	e := newTestEngine(t)
	dev := store.Device{MAC: engineMAC, State: store.StatePending}
	keys := []string{}
	for i := 0; i < 3; i++ {
		out, err := e.Decide(Request{
			Transport: TransportEncrypted,
			Device:    dev,
			Body:      engineBody(""),
			UsedKey:   defaultKeyHex,
			Now:       time.Unix(1000, 0),
		})
		if err != nil {
			t.Fatalf("rotation#%d: %v", i+1, err)
		}
		if !out.SetAuthkeys || !containsKeyStr(out.Authkeys, out.XAuthkey) {
			t.Fatalf("rotation#%d: XAuthkey missing from Authkeys", i+1)
		}
		if len(out.Authkeys) > 2 {
			t.Fatalf("rotation#%d: Authkeys not capped (len %d): %v", i+1, len(out.Authkeys), out.Authkeys)
		}
		keys = append(keys, out.XAuthkey)
		applyDeltas(&dev, out)
	}
	if len(keys) != 3 || keys[0] == keys[1] || keys[1] == keys[2] {
		t.Fatalf("rotations did not mint distinct keys: %v", keys)
	}
	// The first rotated key is pruned (only the newest two remain).
	if containsKeyStr(dev.Authkeys, keys[0]) {
		t.Fatalf("first rotated key not pruned: %v", dev.Authkeys)
	}
	if !containsKeyStr(dev.Authkeys, keys[1]) || !containsKeyStr(dev.Authkeys, keys[2]) {
		t.Fatalf("newest two keys must survive: %v (rotations %v)", dev.Authkeys, keys)
	}
}

// (a4) plaintext claim = stale/missing key → mgmt_cfg-only push carrying
// the CURRENT XAuthkey, NO rotation, state unchanged. (The handler defaults
// an empty _authkey claim to the factory key before calling the engine.)
func TestPlainRekeyPushNoRotation(t *testing.T) {
	const xk = "11112222333344445555666677778888"
	e := newTestEngine(t)
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateAdopted,
		CfgVersion: "aaaa",
		AppliedCfg: "aaaa",
		XAuthkey:   xk,
		Authkeys:   []string{xk},
		Model:      "U7PG2",
	}
	out, err := e.Decide(Request{
		Transport: TransportPlaintext,
		Device:    dev,
		Body:      engineBody("aaaa"), // no _authkey claim in body
		UsedKey:   defaultKeyHex,
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || out.FullProvision {
		t.Fatalf("plain push kind = %v full=%v, want adoption push", out.Kind, out.FullProvision)
	}
	if !strings.Contains(out.MgmtCfg, "authkey="+xk+"\n") {
		t.Fatalf("plain push mgmt_cfg missing current assignment: %q", out.MgmtCfg)
	}
	if out.SetXAuthkey || out.SetCfgVersion || out.SetState || out.SetAuthkeys {
		t.Fatalf("plain push rotated/mutated assignment: %+v", out)
	}
	applyDeltas(&dev, out)
	if dev.XAuthkey != xk || dev.CfgVersion != "aaaa" || dev.State != store.StateAdopted {
		t.Fatalf("plain push rotated/mutated assignment: %+v", dev)
	}
}

// (a5) plaintext claim == XAuthkey with cfgversion drift → full provisioning.
func TestPlainClaimDriftFullProvision(t *testing.T) {
	const xk = "11112222333344445555666677778888"
	e := newTestEngine(t)
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateAdopted,
		CfgVersion: "aaaa",
		AppliedCfg: "stale-1",
		XAuthkey:   xk,
		Authkeys:   []string{xk},
		Model:      "U7PG2",
	}
	// with the claim equal to the assigned key
	out, err := e.Decide(Request{
		Transport: TransportPlaintext,
		Device:    dev,
		Body:      engineBody("stale-1"),
		UsedKey:   xk,
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" || out.CfgVersion != "aaaa" {
		t.Fatalf("plain claim drift outcome = %+v, want full provisioning", out)
	}
}

// Adopted U7PG2 on 6.8.2.15592 with a managed WLAN and cfgversion drift
// proceeds to full provisioning on the encrypted transport.
func TestEncryptedU7PG2WLANFullProvisioning(t *testing.T) {
	e := New(Deps{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Random:   func() float64 { return 0.5 },
		KeyChars: func(n int) (string, error) { return strings.Repeat("0", n), nil },
		Wireless: func(store.Device) []wireless.Wlan { return workedEnvelopeAdoption() },
		SystemCfg: func(store.Device, []wireless.Wlan, wireless.ProvisioningPlan) (string, map[string]string, error) {
			return "# unifi\nunifi.version=0.1.0-dev\n", nil, nil
		},
	})
	const k = "11112222333344445555666677778888"
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateAdopted,
		CfgVersion: "aaaa",
		AppliedCfg: "",
		XAuthkey:   k,
		Authkeys:   []string{k},
		Model:      "U7PG2",
		Firmware:   "6.8.2.15592",
	}
	out, err := e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody(""),
		UsedKey:   k,
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatalf("inform err = %v, want nil", err)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" {
		t.Fatalf("outcome = %+v, want full provisioning with system_cfg", out)
	}
}

// Plaintext mgmt_cfg-only re-send (XAuthkey mismatch → adoption push) does
// not carry system_cfg.
func TestPlainMgmtResendNotGated(t *testing.T) {
	e := newTestEngine(t)
	e.wireless = func(store.Device) []wireless.Wlan { return workedEnvelopeAdoption() }
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateAdopted,
		CfgVersion: "aaaa",
		AppliedCfg: "aaaa",
		XAuthkey:   "22223333444455556666777788889999",
		Authkeys:   []string{"22223333444455556666777788889999"},
		Model:      "U7PG2",
		Firmware:   "6.8.2.15592",
	}
	out, err := e.Decide(Request{
		Transport: TransportPlaintext,
		Device:    dev,
		Body:      engineBody("aaaa"),
		UsedKey:   "stale-claim", // ≠ rec.XAuthkey → re-send current assignment
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam {
		t.Fatalf("mgmt re-send kind = %v, want setparam (adoption push)", out.Kind)
	}
	if out.SystemCfg != "" {
		t.Fatalf("mgmt-only push must not carry system_cfg: %+v", out)
	}
	if out.MgmtCfg == "" {
		t.Fatal("mgmt re-send missing mgmt_cfg")
	}
}

// H4(a): plaintext, claim == XAuthkey, AND the applied wlan_cfg_sha already
// equals the current envelope hash → the engine STILL returns full
// provisioning. The plaintext lane runs no drift-settle and has NO
// cfgversion-match noop branch: the assigned-key flow always full-provisions
// on a claim match (this pins the actual behavior — the former doc comment
// wrongly claimed "cfgversion match → noop + StateAdopted").
func TestPlainClaimMatchAlwaysFullProvisions(t *testing.T) {
	const k = "11112222333344445555666677778888"
	e := newTestEngine(t)
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateAdopted,
		CfgVersion: "aaaa",
		AppliedCfg: "aaaa",
		XAuthkey:   k,
		Authkeys:   []string{k},
		Model:      "U7PG2",
		Extra:      store.JSONMap{"wlan_cfg_sha": wireless.WlanListHash(nil)},
	}
	out, err := e.Decide(Request{
		Transport: TransportPlaintext,
		Device:    dev,
		Body:      engineBody("aaaa"), // even an APPLIED cfgversion must not noop
		UsedKey:   k,
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" || out.CfgVersion != "aaaa" {
		t.Fatalf("claim-match outcome = %+v, want full provisioning", out)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopting {
		t.Fatalf("state after claim-match provision = %d, want adopting", dev.State)
	}
}

// H4(b): the FID-1 default-key rejection covers EVERY state that is neither
// StatePending nor StateAdopting — including StateLost (only StateAdopted is
// exercised by the converted base test).
func TestDefaultKeyLostStateRejected(t *testing.T) {
	const k = "99998888777766665555444433332222"
	e := newTestEngine(t)
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateLost,
		CfgVersion: "aaaa",
		AppliedCfg: "aaaa",
		XAuthkey:   k,
		Authkeys:   []string{k},
		Model:      "U7PG2",
	}
	out, err := e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody("aaaa"),
		UsedKey:   defaultKeyHex,
		Now:       time.Unix(1000, 0),
	})
	if err != ErrDefaultKeyRejected {
		t.Fatalf("err = %v, want default-key rejection for a LOST device", err)
	}
	if out.Kind != "" || out.SetState || out.SetXAuthkey || out.SetCfgVersion || out.SetAuthkeys || out.Extra != nil {
		t.Fatalf("rejected default-key inform produced deltas: %+v", out)
	}
}

// H4(c): a failing system_cfg producer (FID-23 lane) aborts the whole push:
// Decide surfaces the producer error and returns ZERO record deltas — the
// adapter's store cycle aborts, so nothing is persisted.
func TestSystemCfgProducerErrorAbortsDecide(t *testing.T) {
	const k = "11112222333344445555666677778888"
	e := newTestEngine(t)
	e.systemCfg = func(store.Device, []wireless.Wlan, wireless.ProvisioningPlan) (string, map[string]string, error) {
		return "", nil, errors.New("render failed")
	}
	dev := store.Device{
		MAC:        engineMAC,
		State:      store.StateAdopted,
		CfgVersion: "aaaa",
		AppliedCfg: "aaaa",
		XAuthkey:   k,
		Authkeys:   []string{k},
		Model:      "U7PG2",
	}
	out, err := e.Decide(Request{
		Transport: TransportPlaintext, // claim match → assigned-key flow
		Device:    dev,
		Body:      engineBody("aaaa"),
		UsedKey:   k,
		Now:       time.Unix(1000, 0),
	})
	if err == nil || err.Error() != "render failed" {
		t.Fatalf("err = %v, want the producer error", err)
	}
	if out.Kind != "" || out.SystemCfg != "" || out.SetState || out.SetXAuthkey ||
		out.SetCfgVersion || out.SetAuthkeys || out.Extra != nil {
		t.Fatalf("failed push produced deltas: %+v", out)
	}
}

// workedEnvelopeAdoption mirrors the server-side worked envelope (doc §7):
// corp (wpa-p / correcthorse / VLAN 42) + guest (open, DISABLED).
func workedEnvelopeAdoption() []wireless.Wlan {
	return []wireless.Wlan{
		{Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correcthorse",
			VLAN: 42, Enabled: true, ID: "5629b670e3f80a139930d113"},
		{Name: "guest", SSID: "guest", Security: "open", Enabled: false},
	}
}

// ---- mgmt_cfg golden (§8f) --------------------------------------------------

// TestMgmtCfgGolden moved from package server with identical assertions: the
// mgmt_cfg builder is engine-owned since the extraction.
func TestMgmtCfgGolden(t *testing.T) {
	e := newTestEngine(t)
	e.controllerURL = "http://10.0.0.5:8080"
	d := store.Device{
		MAC: engineMAC,
	}
	d.CfgVersion = "aaaaaaaaaaaaaaaa"
	d.XAuthkey = "11112222333344445555666677778888"
	d.InformURL = "http://10.0.0.9:8080/inform"
	got := e.BuildMgmtCfg(d, defaultKeyHex) // the factory key, single-sourced in internal/inform
	want := "capability=notif,notif-assoc-stat\n" +
		"selfrun_guest_mode=pass\n" +
		"cfgversion=aaaaaaaaaaaaaaaa\n" +
		"led_enabled=true\n" +
		"stun_url=stun://10.0.0.5:3478/\n" +
		"mgmt_url=https://10.0.0.5:8443/manage/site/default\n" +
		"authkey=11112222333344445555666677778888\n" +
		"inform_url=http://10.0.0.5:8080/inform\n" +
		"use_aes_gcm=true\n" +
		"report_crash=true\n"
	if got != want {
		t.Fatalf("mgmt_cfg golden mismatch:\n got %q\nwant %q", got, want)
	}
	// same-key inform → no authkey line
	got2 := e.BuildMgmtCfg(d, d.XAuthkey)
	if strings.Contains(got2, "authkey=") {
		t.Fatalf("authkey line must be omitted when keys match: %q", got2)
	}
}

// TestMgmtCfgLEDOverride pins the led_enabled row to the §2 B-writer
// semantics (docs/PROTOCOL-mgmt.md §2): disabled wins over every override;
// else "on" → true, "off" → false, "default"/unset → the site default (the
// jar default true — no site table yet). Every case asserts the FULL golden
// so the row's position (cfgversion → led_enabled → stun_url) and the byte
// values ("true"/"false" only) are both pinned, not just the row's presence.
func TestMgmtCfgLEDOverride(t *testing.T) {
	e := newTestEngine(t)
	e.controllerURL = "http://10.0.0.5:8080"
	const k = "11112222333344445555666677778888"
	base := store.Device{
		MAC:        engineMAC,
		CfgVersion: "aaaaaaaaaaaaaaaa",
		XAuthkey:   k,
		Authkeys:   []string{k},
	}
	cases := []struct {
		name        string
		override    string // record field; "" ≡ jar "default"
		disabled    bool
		wantLEDLine string // the exact led_enabled=<v>\n row
	}{
		{"default follows site default (jar true)", "", false, "led_enabled=true\n"},
		{"explicit default follows site default (jar true)", "default", false, "led_enabled=true\n"},
		{"override on", "on", false, "led_enabled=true\n"},
		{"override off", "off", false, "led_enabled=false\n"},
		{"disabled wins over default", "", true, "led_enabled=false\n"},
		{"disabled wins over on", "on", true, "led_enabled=false\n"},
		{"disabled wins over off", "off", true, "led_enabled=false\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := base
			d.LEDOverride = tc.override
			d.Disabled = tc.disabled
			got := e.BuildMgmtCfg(d, d.XAuthkey) // on-key inform: no authkey row
			want := "capability=notif,notif-assoc-stat\n" +
				"selfrun_guest_mode=pass\n" +
				"cfgversion=aaaaaaaaaaaaaaaa\n" +
				tc.wantLEDLine +
				"stun_url=stun://10.0.0.5:3478/\n" +
				"mgmt_url=https://10.0.0.5:8443/manage/site/default\n" +
				"inform_url=http://10.0.0.5:8080/inform\n" +
				"use_aes_gcm=true\n" +
				"report_crash=true\n"
			if got != want {
				t.Fatalf("mgmt_cfg mismatch:\n got %q\nwant %q", got, want)
			}
		})
	}
}

// TestOperatorMintEscapesExhaustedDeliveryGate: at the WLAN delivery retry
// cap with the envelope UNCHANGED, the exhausted gate answers
// noop-pending-wlan indefinitely — but an operator cfgversion mint (the
// putRadioIntent / LED-override save shape: Extra write + fresh CfgVersion,
// envelope unchanged) must still deliver in the same inform, exactly like a
// blocked-set change: the mint bypasses the exhausted early return and the
// re-offer carries the minted cfgversion. The escape is one-shot per mint —
// the follow-up inform holds at the gate again (rate-limit semantics for the
// unchanged record). The device never proves its VAPs (no vap_table), so
// settle cannot clear the pending bookkeeping.
func TestOperatorMintEscapesExhaustedDeliveryGate(t *testing.T) {
	e := newTestEngine(t)
	// The render stub records whether the operator intent reached it, so
	// the escape offer is proven to render the minted record, not just to
	// answer setparam.
	sawIntent := false
	e.systemCfg = func(d store.Device, wls []wireless.Wlan, plan wireless.ProvisioningPlan) (string, map[string]string, error) {
		if _, ok := d.Extra["radio_intent"]; ok {
			sawIntent = true
		}
		return "# unifi\n", nil, nil
	}
	dev := driveToProvisioned(t, e) // attempts=1, lastAttempt=1010, pending outstanding
	xkey := dev.XAuthkey
	inform := func(now int64) Outcome {
		t.Helper()
		out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.AppliedCfg), UsedKey: xkey, Now: time.Unix(now, 0)})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Burn the whole bounded retry budget on the unchanged envelope: five
	// re-offers (2s,4s,8s,16s,32s backoff), each a full provisioning.
	for _, tt := range []int64{1012, 1016, 1024, 1040, 1072} {
		out := inform(tt)
		if out.Kind != KindSetparam || !out.FullProvision {
			t.Fatalf("re-offer @%d = %+v, want full provisioning", tt, out)
		}
		applyDeltas(&dev, out)
	}

	// Cap reached: the delivery status flips to exhausted and the gate
	// holds (noop-pending-wlan, not re-offer).
	out := inform(1080)
	if out.Kind != KindNoopPendingWLAN {
		t.Fatalf("exhausted inform = %+v, want noop-pending-wlan", out)
	}
	applyDeltas(&dev, out)
	if status, _ := dev.Extra["wlan_cfg_delivery_status"].(string); status != "exhausted" {
		t.Fatalf("delivery status = %q, want exhausted", status)
	}

	// Operator radio-intent save: the app layer's mint shape (Extra write +
	// fresh cfgversion, envelope unchanged). Same inform: full provisioning
	// despite the exhausted budget — the mint cannot be held hostage.
	const radioMint = "cccccccccccccccc"
	dev.Extra["radio_intent"] = map[string]any{"rai0": map[string]any{"channel": 36.0}}
	dev.CfgVersion = radioMint
	out = inform(1090)
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("radio-intent mint under exhausted retry = %+v, want full provisioning", out)
	}
	if out.CfgVersion != radioMint {
		t.Fatalf("the escape offer must carry the minted cfgversion: %q", out.CfgVersion)
	}
	if !sawIntent {
		t.Fatal("the escape offer rendered without the radio intent")
	}
	applyDeltas(&dev, out)
	if offered, _ := dev.Extra["wlan_cfg_offered_cfgversion"].(string); offered != radioMint {
		t.Fatalf("offered-cfgversion bookkeeping not stamped at emission: %v", dev.Extra["wlan_cfg_offered_cfgversion"])
	}

	// The escape is one-shot per mint: the follow-up inform (record
	// unchanged since the re-offer) holds at the gate again.
	out = inform(1100)
	if out.Kind != KindNoopPendingWLAN {
		t.Fatalf("post-escape inform = %+v, want the exhausted gate to hold again", out)
	}
	applyDeltas(&dev, out)

	// Same escape for the LED-override mint: the LED row rides the full
	// provisioning's mgmt_cfg (BuildMgmtCfg led_enabled).
	const ledMint = "dddddddddddddddd"
	dev.LEDOverride = "off"
	dev.CfgVersion = ledMint
	out = inform(1110)
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("LED-override mint under exhausted retry = %+v, want full provisioning", out)
	}
	if !strings.Contains(out.MgmtCfg, "led_enabled=false\n") {
		t.Fatalf("LED re-offer missing led_enabled=false:\n%s", out.MgmtCfg)
	}
}

// TestEnvelopeDriftDeliveryIsBounded reproduces the 2026-09-19 EAP live
// storm (WLAN-ACCEPTANCE 6.8.2.15592, the wpa-eap push): a SETTLED record
// whose envelope is admin-changed underneath it, against a device that
// only ever sends SPARSE informs — no vap_table, so settle can never
// confirm the delivery. The pre-fix engine re-minted the cfgversion on
// EVERY drifted inform, which kept the pending gate's operatorMint
// escape permanently true: WlanRetryDue never engaged and the re-offers
// were unbounded (37 pushes in 3.5 live minutes), each carrying a fresh
// version the device echo could never land on. The fixed contract, in
// order: ONE mint for the genuinely new envelope; re-offers carry the
// SAME version; the bounded budget caps them (exhausted at
// WlanMaxAttempts); an echoed offer answers noop-pending-wlan without
// re-offering; a later full inform settles the pending; and a NEW
// envelope after settle mints fresh again.
func TestEnvelopeDriftDeliveryIsBounded(t *testing.T) {
	base := []wireless.Wlan{{Name: "gate-check", SSID: "openunifi-gate-check", Security: "wpa-p", Passphrase: "pw", VLAN: 1, Enabled: true}}
	eap := []wireless.Wlan{{
		Name: "gate-check", SSID: "openunifi-gate-check", Security: "wpa-eap", VLAN: 1, Enabled: true,
		RadiusServers: []wireless.RadiusServer{{IP: "10.10.10.10", Port: 1812}}, RadiusSecret: "eap-secret",
	}}
	e := newTestEngine(t)
	e.wireless = func(store.Device) []wireless.Wlan { return base }
	snap, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	const xkey = "11112222333344445555666677778888"
	dev := store.Device{
		MAC: engineMAC, State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
		XAuthkey: xkey, Authkeys: []string{xkey}, Model: "U7PG2",
		Extra: store.JSONMap{
			"wlan_cfg_sha":           wireless.WlanListHash(base),
			"wlan_cfg_applied_wlans": string(snap),
		},
	}
	inform := func(now int64) Outcome {
		t.Helper()
		out, derr := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.AppliedCfg), UsedKey: xkey, Now: time.Unix(now, 0)})
		if derr != nil {
			t.Fatal(derr)
		}
		return out
	}

	// (a) Settled sanity: connected noop, no mint.
	if out := inform(1000); out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("settled inform = %+v, want connected noop without mint", out)
	}

	// (b) Admin WLAN save: the EAP envelope drifts a SETTLED record. The
	// first drifted inform mints ONCE and offers full provisioning.
	e.wireless = func(store.Device) []wireless.Wlan { return eap }
	out := inform(1005)
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("first drifted inform = %+v, want setparam full provisioning", out)
	}
	minted := out.CfgVersion
	if minted == "" || minted == "aaaa" {
		t.Fatalf("drift mint = %q, want a fresh cfgversion", minted)
	}
	applyDeltas(&dev, out)
	if dev.CfgVersion != minted {
		t.Fatalf("mint not persisted: record %q vs outcome %q", dev.CfgVersion, minted)
	}
	if attempts, _ := dev.Extra["wlan_cfg_attempts"].(int); attempts != 1 {
		t.Fatalf("first offer attempts = %v, want 1", dev.Extra["wlan_cfg_attempts"])
	}
	if offered, _ := dev.Extra["wlan_cfg_offered_cfgversion"].(string); offered != minted {
		t.Fatalf("offered-cfgversion = %q, want the minted %q", offered, minted)
	}

	// (c) The storm window at the live cadence — sparse informs every
	// ~5s (the device's post-apply quick-inform loop), never a vap_table,
	// the echo never catching up. Re-offers must stay on the SAME
	// version, respect the backoff windows, and stop at the budget.
	pushes := 1
	for now := int64(1010); now <= 1235; now += 5 {
		out = inform(now)
		switch out.Kind {
		case KindSetparam:
			pushes++
			if out.CfgVersion != minted {
				t.Fatalf("re-offer @%d re-minted: %q, want the stable %q", now, out.CfgVersion, minted)
			}
		case KindNoopPendingWLAN:
		default:
			t.Fatalf("inform @%d = %+v, want re-offer or noop-pending-wlan", now, out)
		}
		applyDeltas(&dev, out)
		if pushes > WlanMaxAttempts {
			t.Fatalf("push storm: %d offers, want the budget of %d", pushes, WlanMaxAttempts)
		}
	}
	if pushes != WlanMaxAttempts {
		t.Fatalf("pushes = %d, want the full budget %d", pushes, WlanMaxAttempts)
	}
	if status, _ := dev.Extra["wlan_cfg_delivery_status"].(string); status != "exhausted" {
		t.Fatalf("delivery status = %q, want exhausted at the cap", status)
	}

	// (d) Echo catch-up under exhaustion: the device applies the offered
	// version. The gate must hold — noop-pending-wlan, not a re-offer,
	// and no mint to push the echo off the equality branch.
	dev.AppliedCfg = dev.CfgVersion
	if out = inform(1240); out.Kind != KindNoopPendingWLAN {
		t.Fatalf("echoed offer under exhaustion = %+v, want noop-pending-wlan", out)
	}
	applyDeltas(&dev, out)

	// (e) Recovery: a full inform with RUN VAPs proves the pending
	// envelope and settles — connected noop, confirmed, baseline moved.
	dev.Extra["vap_table"] = []any{
		map[string]any{"essid": "openunifi-gate-check", "state": "RUN", "radio_name": "wifi0", "name": "ath0"},
		map[string]any{"essid": "openunifi-gate-check", "state": "RUN", "radio_name": "wifi1", "name": "ath1"},
	}
	if out = inform(1245); out.Kind != KindNoop {
		t.Fatalf("settling full inform = %+v, want connected noop", out)
	}
	applyDeltas(&dev, out)
	if status, _ := dev.Extra["wlan_cfg_delivery_status"].(string); status != "confirmed" {
		t.Fatalf("delivery status after settle = %q, want confirmed", status)
	}
	if sha, _ := dev.Extra["wlan_cfg_sha"].(string); sha != wireless.WlanListHash(eap) {
		t.Fatalf("settled baseline = %q, want the EAP envelope hash", sha)
	}
	if _, still := dev.Extra["wlan_cfg_pending_sha"]; still {
		t.Fatal("settle did not clear the pending hash")
	}

	// (f) A NEW envelope after settle is a new delivery operation: fresh
	// mint, fresh budget.
	e.wireless = func(store.Device) []wireless.Wlan { return base }
	if out = inform(1250); out.Kind != KindSetparam || out.CfgVersion == minted {
		t.Fatalf("post-settle new envelope = %+v (cfg %q), want a fresh-minted re-provision", out, out.CfgVersion)
	}
	applyDeltas(&dev, out)
	if attempts, _ := dev.Extra["wlan_cfg_attempts"].(int); attempts != 1 {
		t.Fatalf("new delivery attempts = %v, want a fresh budget of 1", dev.Extra["wlan_cfg_attempts"])
	}
}

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
// sequence (distinct per call), the wireless source is empty and the
// system_cfg producer returns a canned blob. Tests override e.random /
// e.wireless / e.systemCfg directly (in-package).
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	counter := 0
	e := New(Deps{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Random:   func() float64 { return 0.5 },
		KeyChars: func(n int) (string, error) { return "", nil }, // replaced below
		Wireless: func() []wireless.Wlan { return nil },
		SystemCfg: func(store.Device, []wireless.Wlan) (string, map[string]string, error) {
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

// Settled-state regression (2026-09-18 F-row live round, A2 finding): a
// PRESENT vap_table that disproves the confirmed WLAN set must re-arm
// delivery (minting noop → full provisioning on the next inform), while an
// absent or empty table is unknown (sparse heartbearts never re-arm) and a
// table proving the applied SSID RUNNING is steady state.
func TestSettledRegressionRearms(t *testing.T) {
	env := []wireless.Wlan{{Name: "corp", SSID: "corpnet", Security: "wpa-p", Passphrase: "pw", VLAN: 1, Enabled: true}}
	counter := 0
	e := New(Deps{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Random: func() float64 { return 0.5 },
		KeyChars: func(n int) (string, error) {
			counter++
			s := strconv.FormatInt(int64(counter), 16)
			return strings.Repeat("0", n-len(s)) + s, nil
		},
		Wireless: func() []wireless.Wlan { return env },
		SystemCfg: func(store.Device, []wireless.Wlan) (string, map[string]string, error) {
			return "sys\n", nil, nil
		},
	})
	snap, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	const k = "11112222333344445555666677778888"
	factoryTable := []any{map[string]any{"essid": "factory-default", "state": "RUN", "radio_name": "ra0", "name": "ath0"}}
	runningTable := []any{map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": "ra0", "name": "ath0"}}
	fixture := func(vaps any) store.Device {
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

	// Regression: present table, applied SSID missing → minting noop.
	dev := fixture(factoryTable)
	out, oerr := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody("aaaa"), UsedKey: k, Now: time.Unix(1000, 0)})
	if oerr != nil {
		t.Fatal(oerr)
	}
	if out.Kind != KindNoop || !out.SetCfgVersion || out.CfgVersion == "aaaa" {
		t.Fatalf("regression outcome = %+v, want minting noop", out)
	}
	// Next inform (device still echoes the old stamp) → full provisioning.
	applyDeltas(&dev, out)
	out, oerr = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody("aaaa"), UsedKey: k, Now: time.Unix(1010, 0)})
	if oerr != nil {
		t.Fatal(oerr)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" {
		t.Fatalf("post-regression outcome = %+v, want full provisioning", out)
	}

	// Unknown (absent table): plain connected noop, no re-arm.
	out, oerr = e.Decide(Request{Transport: TransportEncrypted, Device: fixture(nil), Body: engineBody("aaaa"), UsedKey: k, Now: time.Unix(1020, 0)})
	if oerr != nil {
		t.Fatal(oerr)
	}
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("absent-table outcome = %+v, want plain connected noop", out)
	}
	// Unknown (empty table): plain connected noop, no re-arm.
	out, oerr = e.Decide(Request{Transport: TransportEncrypted, Device: fixture([]any{}), Body: engineBody("aaaa"), UsedKey: k, Now: time.Unix(1030, 0)})
	if oerr != nil {
		t.Fatal(oerr)
	}
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("empty-table outcome = %+v, want plain connected noop", out)
	}
	// Steady state (applied SSID RUNNING): plain connected noop, no re-arm.
	out, oerr = e.Decide(Request{Transport: TransportEncrypted, Device: fixture(runningTable), Body: engineBody("aaaa"), UsedKey: k, Now: time.Unix(1040, 0)})
	if oerr != nil {
		t.Fatal(oerr)
	}
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("running-table outcome = %+v, want plain connected noop", out)
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

// The ENCRYPTED transport (the only one a real U7PG2 uses) is also gated:
// the unsupported-live-WLAN rejection lives in the engine's assigned-key
// flow (the single emission point both transports share), so a
// drifted/adopted U7PG2 on 6.8.2.15592 with a managed WLAN yields the
// unsupported error and NO record deltas — and no system_cfg payload.
func TestEncryptedGateBlocksSystemCfg(t *testing.T) {
	e := newTestEngine(t)
	e.wireless = func() []wireless.Wlan { return workedEnvelopeAdoption() }
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
	if err != ErrLiveWLANProvisioningUnsupported {
		t.Fatalf("gated inform err = %v, want unsupported-live-WLAN", err)
	}
	if out.Kind != "" || out.SystemCfg != "" || out.SetState || out.SetXAuthkey ||
		out.SetCfgVersion || out.SetAuthkeys || out.Extra != nil {
		t.Fatalf("gate must not mutate the record or emit system_cfg: %+v", out)
	}
}

// The explicit bench opt-in lifts the fail-closed gate: the same drifted
// adopted U7PG2 inform that TestEncryptedGateBlocksSystemCfg rejects
// proceeds to FULL provisioning when Deps.AllowGatedLiveWLAN is set —
// proving both the Deps→Engine wiring and that the unlock changes nothing
// else (still a normal full-provision outcome, no other bypass).
func TestEncryptedGateLiftedByOptIn(t *testing.T) {
	e := New(Deps{
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Random:   func() float64 { return 0.5 },
		KeyChars: func(n int) (string, error) { return strings.Repeat("0", n), nil },
		Wireless: func() []wireless.Wlan { return workedEnvelopeAdoption() },
		SystemCfg: func(store.Device, []wireless.Wlan) (string, map[string]string, error) {
			return "# unifi\nunifi.version=0.1.0-dev\n", nil, nil
		},
		AllowGatedLiveWLAN: true,
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
		t.Fatalf("opted-in inform err = %v, want nil (gate lifted)", err)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" {
		t.Fatalf("opted-in outcome = %+v, want full provisioning with system_cfg", out)
	}
}

// With the gate moved into the engine's assigned-key flow, a plaintext
// mgmt_cfg-only re-send (XAuthkey mismatch → adoption push) from a gated
// device SUCCEEDS: mgmt pushes keep working, only system_cfg emission is
// blocked.
func TestPlainMgmtResendNotGated(t *testing.T) {
	e := newTestEngine(t)
	e.wireless = func() []wireless.Wlan { return workedEnvelopeAdoption() }
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
	e.systemCfg = func(store.Device, []wireless.Wlan) (string, map[string]string, error) {
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

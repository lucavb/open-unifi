package adoption

// blocked_sta delivery tests: the admin-owned blocked-client set is
// provisioned CONTENT delivered inside full provisioning (§6.2(d)) in the
// §4 wire shape (newline-joined colon-hex, "" when none). Every test drives
// ONLY the engine interface with deterministic injections, mirroring the
// adapter's applyDeltas contract.

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

// driveToProvisioned replays the TestHappyAdoption prefix (default-key
// adoption push, post-adoption echo self-heal, full provisioning) and
// returns the device mid-delivery: pending WLAN bookkeeping outstanding
// (attempts=1), blocked baseline hash("") stamped by the provisioning, no
// apply proof yet.
func driveToProvisioned(t *testing.T, e *Engine) store.Device {
	t.Helper()
	dev := store.Device{MAC: engineMAC, State: store.StatePending}

	out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || out.FullProvision {
		t.Fatalf("adoption push = %+v", out)
	}
	xkey, cfg := out.XAuthkey, out.CfgVersion
	applyDeltas(&dev, out)

	// Post-adoption echo: self-heal noop + fresh mint (no blocked content
	// yet, so the absent baseline must NOT drift here).
	dev.AppliedCfg = cfg
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(cfg), UsedKey: xkey, Now: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("post-adoption echo = %+v, want self-heal noop", out)
	}
	applyDeltas(&dev, out)

	// Full provisioning (the real-controller post-adoption sequence).
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(cfg), UsedKey: xkey, Now: time.Unix(1010, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("post-adoption provisioning = %+v", out)
	}
	if out.BlockedSta != "" {
		t.Fatalf("empty set must provision blocked_sta=\"\", got %q", out.BlockedSta)
	}
	if got, ok := out.Extra[extraBlockedStaSha].(string); !ok || got != blockedStaHash("") {
		t.Fatalf("full provisioning did not stamp the empty-set baseline: %v", out.Extra[extraBlockedStaSha])
	}
	applyDeltas(&dev, out)
	return dev
}

// driveToSettled continues from driveToProvisioned through the applied
// confirmation (settle + connected noop + adopted). This is the steady
// state from which blocked_sta delivery starts: envelope baseline captured,
// no pending WLAN, blocked baseline hash("") stamped.
func driveToSettled(t *testing.T, e *Engine) store.Device {
	t.Helper()
	dev := driveToProvisioned(t, e)
	dev.AppliedCfg = dev.CfgVersion
	dev.Extra["vap_table"] = []any{}
	out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey, Now: time.Unix(1020, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("settle inform = %+v, want noop", out)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopted {
		t.Fatalf("state = %d, want adopted", dev.State)
	}
	return dev
}

// TestBlockedStaRidesFullProvisioning walks the full block/unblock delivery
// cycle from settled state: same-inform mint + full provisioning with the
// exact §4 wire string, the offer standing during the device's apply
// window, bounded re-offer after the retry backoff, unblock-one and
// unblock-all re-provisioning, and settle back to the connected noop.
func TestBlockedStaRidesFullProvisioning(t *testing.T) {
	e := newTestEngine(t)
	dev := driveToSettled(t, e)
	xkey := dev.XAuthkey
	// The un-applied device echoes its last APPLIED stamp, which lags
	// dev.CfgVersion whenever a mint is outstanding.
	inform := func(now int64) Outcome {
		t.Helper()
		out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.AppliedCfg), UsedKey: xkey, Now: time.Unix(now, 0)})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// (a) Settled: connected noop, no mint.
	out := inform(1030)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("settled inform = %+v, want connected noop", out)
	}
	applyDeltas(&dev, out)

	// Admin blocks two clients — the §6.2(d) example pair. Stored set is
	// canonical and sorted, so the wire string is byte-exact regardless of
	// the admin's spelling or call order.
	if _, err := store.AddBlockedClient(&dev, "AA:BB:CC:DD:EE:FF"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddBlockedClient(&dev, "11:22:33:44:55:66"); err != nil {
		t.Fatal(err)
	}
	const wantWire = "11:22:33:44:55:66\naa:bb:cc:dd:ee:ff"

	// (b) Same inform: fresh mint + full provisioning carrying blocked_sta.
	out = inform(1040)
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" {
		t.Fatalf("blocked drift inform = %+v, want same-inform full provisioning", out)
	}
	if !out.SetCfgVersion || out.CfgVersion == dev.CfgVersion {
		t.Fatalf("blocked drift did not mint a fresh cfgversion: %+v", out)
	}
	if out.BlockedSta != wantWire {
		t.Fatalf("blocked_sta = %q, want the exact §4 wire string %q", out.BlockedSta, wantWire)
	}
	if got, ok := out.Extra[extraBlockedStaSha].(string); !ok || got != blockedStaHash(wantWire) {
		t.Fatalf("delivery baseline not stamped at emission: %v", out.Extra[extraBlockedStaSha])
	}
	newCfg := out.CfgVersion
	applyDeltas(&dev, out)

	// The device now sends sparse heartbeats while it applies: no
	// vap_table reach the record, so settle cannot confirm the pending
	// (empty) WLAN set and the offer stands.
	delete(dev.Extra, "vap_table")

	// (c) Device still echoes the OLD stamp within the retry backoff: the
	// offer stands — noop-pending-wlan, no re-mint of the unchanged set.
	out = inform(1041)
	if out.Kind != KindNoopPendingWLAN || out.SetCfgVersion {
		t.Fatalf("in-backoff inform = %+v, want noop-pending-wlan holding the offer", out)
	}
	applyDeltas(&dev, out)

	// (d) Backoff elapsed (attempt 2's 4s window): the unchanged offer is
	// re-sent — same wire, same cfgversion (no re-mint: the baseline
	// confirms the set unchanged).
	out = inform(1045)
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("retry inform = %+v, want re-offer full provisioning", out)
	}
	if out.SetCfgVersion || out.CfgVersion != newCfg {
		t.Fatalf("unchanged set re-provision must not re-mint: %+v", out)
	}
	if out.BlockedSta != wantWire {
		t.Fatalf("re-offer blocked_sta = %q, want %q", out.BlockedSta, wantWire)
	}
	applyDeltas(&dev, out)

	// (e) Device applies and proves the VAPs: settle + connected noop.
	dev.AppliedCfg = dev.CfgVersion
	dev.Extra["vap_table"] = []any{}
	out = inform(1050)
	if out.Kind != KindNoop {
		t.Fatalf("post-apply inform = %+v, want connected noop", out)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopted {
		t.Fatalf("state after apply = %d, want adopted", dev.State)
	}

	// (f) Unblock one client: content change → fresh mint + full
	// provisioning with the one-client wire string.
	if _, err := store.RemoveBlockedClient(&dev, "112233445566"); err != nil {
		t.Fatal(err)
	}
	out = inform(1060)
	if out.Kind != KindSetparam || !out.FullProvision || out.BlockedSta != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unblock-one inform = %+v (blocked=%q), want re-provision", out, out.BlockedSta)
	}
	if !out.SetCfgVersion || out.CfgVersion == dev.CfgVersion {
		t.Fatalf("unblock-one did not mint: %+v", out)
	}
	applyDeltas(&dev, out)
	dev.AppliedCfg = dev.CfgVersion
	dev.Extra["vap_table"] = []any{}

	// (g) Unblock the last client: re-provision with the §4 EMPTY string
	// (not omission — the wire field is present and empty).
	if _, err := store.RemoveBlockedClient(&dev, "aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatal(err)
	}
	out = inform(1070)
	if out.Kind != KindSetparam || !out.FullProvision || out.BlockedSta != "" {
		t.Fatalf("unblock-all inform = %+v (blocked=%q), want re-provision with empty wire", out, out.BlockedSta)
	}
	applyDeltas(&dev, out)
	dev.AppliedCfg = dev.CfgVersion
	dev.Extra["vap_table"] = []any{}

	// (h) Settled again: connected noop.
	out = inform(1080)
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("final settled inform = %+v, want connected noop", out)
	}
}

// TestBlockedStaExhaustedRetryCannotHoldDelivery: at the WLAN delivery
// retry cap the exhausted status answers noop-pending-wlan indefinitely —
// but a blocked_sta change must still deliver in the same inform: the drift
// gate bypasses the exhausted early return (an exhausted WLAN retry must
// not hold the blocked set hostage). The device here NEVER proves its VAPs
// (no vap_table), so settle cannot clear the pending bookkeeping.
func TestBlockedStaExhaustedRetryCannotHoldDelivery(t *testing.T) {
	e := newTestEngine(t)
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

	// Burn the whole bounded retry budget on the unchanged (empty) envelope:
	// five re-offers (2s,4s,8s,16s,32s backoff), each a full provisioning.
	// The set is empty and matches its baseline, so these are pure WLAN
	// delivery retries — the blocked logic must not mint or force anything.
	for _, tt := range []int64{1012, 1016, 1024, 1040, 1072} {
		out := inform(tt)
		if out.Kind != KindSetparam || !out.FullProvision {
			t.Fatalf("re-offer @%d = %+v, want full provisioning", tt, out)
		}
		if out.SetCfgVersion || out.BlockedSta != "" {
			t.Fatalf("unchanged empty set re-offer must not mint/re-block: %+v", out)
		}
		applyDeltas(&dev, out)
	}

	// Cap reached: the delivery status flips to exhausted and the
	// controller holds (noop-pending-wlan, not re-offer).
	out := inform(1080)
	if out.Kind != KindNoopPendingWLAN {
		t.Fatalf("exhausted inform = %+v, want noop-pending-wlan", out)
	}
	applyDeltas(&dev, out)
	if status, _ := dev.Extra["wlan_cfg_delivery_status"].(string); status != "exhausted" {
		t.Fatalf("delivery status = %q, want exhausted", status)
	}

	// Admin blocks a client: same inform, full provisioning despite the
	// exhausted WLAN budget — the blocked set cannot be held hostage.
	if _, err := store.AddBlockedClient(&dev, "00:11:22:33:44:55"); err != nil {
		t.Fatal(err)
	}
	out = inform(1090)
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("blocked drift under exhausted retry = %+v, want full provisioning", out)
	}
	if out.BlockedSta != "00:11:22:33:44:55" {
		t.Fatalf("blocked_sta = %q", out.BlockedSta)
	}
	if !out.SetCfgVersion {
		t.Fatalf("blocked drift under exhaustion must still mint: %+v", out)
	}
}

// TestBlockedStaEmptySetNoDrift pins the steady-state rule: a KNOWN
// baseline plus an empty set is confirmed content (connected noop), and an
// ABSENT baseline plus an empty set is not drift either — the post-adoption
// equal path must keep answering noops (2026-09-16 live round), with the
// equality self-heal minting exactly once.
func TestBlockedStaEmptySetNoDrift(t *testing.T) {
	e := newTestEngine(t)
	dev := driveToSettled(t, e)

	// Known baseline hash("") + empty set → plain connected noop.
	out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey, Now: time.Unix(1030, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop || out.SetCfgVersion || out.SetState {
		t.Fatalf("known-empty-set inform = %+v, want plain connected noop", out)
	}

	// Absent baseline + empty set: adopt-shaped record whose baseline was
	// never stamped — the equality self-heal mints once (KindNoop), it
	// must not full-provision over blocked content that does not exist.
	bare := store.Device{MAC: engineMAC, State: store.StateAdopting, CfgVersion: "aaaa", AppliedCfg: "aaaa", XAuthkey: dev.XAuthkey, Authkeys: []string{dev.XAuthkey}, Extra: store.JSONMap{}}
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: bare, Body: engineBody("aaaa"), UsedKey: dev.XAuthkey, Now: time.Unix(1030, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop || !out.SetCfgVersion {
		t.Fatalf("absent-baseline empty-set inform = %+v, want self-heal minting noop", out)
	}
}

// TestBlockedStaPreAdoptionPending: a pending candidate the admin blocked
// BEFORE adoption receives the set with the first full provisioning, never
// in the adoption push (§6.2 a/c/f is mgmt_cfg-only).
func TestBlockedStaPreAdoptionPending(t *testing.T) {
	e := newTestEngine(t)
	dev := store.Device{MAC: engineMAC, State: store.StatePending}
	if _, err := store.AddBlockedClient(&dev, "11:22:33:44:55:66"); err != nil {
		t.Fatal(err)
	}

	// Inform #1 (factory key): adoption push, mgmt_cfg ONLY — blocked
	// content never rides the adoption push.
	out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || out.FullProvision || out.BlockedSta != "" {
		t.Fatalf("adoption push = %+v (blocked=%q), want mgmt_cfg-only", out, out.BlockedSta)
	}
	xkey, cfg := out.XAuthkey, out.CfgVersion
	applyDeltas(&dev, out)

	// Inform #2 (post-key-rotation echo): the undelivered blocked set is
	// drift (absent baseline + content), so full provisioning happens NOW —
	// earlier than the empty-record self-heal sequence — with the set
	// aboard and the baseline stamped at emission.
	dev.AppliedCfg = cfg
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(cfg), UsedKey: xkey, Now: time.Unix(1000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.BlockedSta != "11:22:33:44:55:66" {
		t.Fatalf("post-adoption inform = %+v (blocked=%q), want full provisioning carrying the pre-blocked set", out, out.BlockedSta)
	}
	if got, ok := out.Extra[extraBlockedStaSha].(string); !ok || got != blockedStaHash("11:22:33:44:55:66") {
		t.Fatalf("baseline = %v, want hash of the delivered wire", out.Extra[extraBlockedStaSha])
	}
	applyDeltas(&dev, out)

	// Inform #3 (applied + proven): settle back to the connected noop.
	dev.AppliedCfg = dev.CfgVersion
	dev.Extra["vap_table"] = []any{}
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1010, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("post-apply inform = %+v, want noop", out)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopted {
		t.Fatalf("state = %d, want adopted", dev.State)
	}
}

// TestBlockedStaWireShape pins the §4 projection: sorted colon-hex join,
// empty string when none, and a stable delivery hash.
func TestBlockedStaWireShape(t *testing.T) {
	empty := store.Device{MAC: engineMAC, Extra: store.JSONMap{}}
	if got := blockedStaWire(empty); got != "" {
		t.Fatalf("empty set wire = %q, want \"\"", got)
	}
	d := store.Device{MAC: engineMAC, Extra: store.JSONMap{}}
	if _, err := store.AddBlockedClient(&d, "aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddBlockedClient(&d, "11:22:33:44:55:66"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddBlockedClient(&d, "00:11:22:33:44:55"); err != nil {
		t.Fatal(err)
	}
	want := "00:11:22:33:44:55\n11:22:33:44:55:66\naa:bb:cc:dd:ee:ff"
	if got := blockedStaWire(d); got != want {
		t.Fatalf("wire = %q, want %q", got, want)
	}
	// The hash is the plain sha256 of the wire string: deterministic and
	// distinguishable across the empty and non-empty shapes.
	sum := sha256.Sum256([]byte(want))
	if blockedStaHash(want) != hex.EncodeToString(sum[:]) {
		t.Fatal("blockedStaHash is not sha256-hex of the wire string")
	}
	if blockedStaHash("") == blockedStaHash(want) {
		t.Fatal("empty and non-empty wires must hash differently")
	}
	if len(blockedStaHash("")) != 64 {
		t.Fatalf("hash length = %d, want 64 hex chars", len(blockedStaHash("")))
	}
}

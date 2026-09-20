package adoption

// Engine-direct lifecycle tests (§6.5 reboot / §6.6 setdefault): the
// admin-armed remote-command lane, its one-shot semantics and precedence,
// the setdefault demotion to the pending-candidate shape, and the
// post-reset re-adoption on the factory default key. The BYTE shape of
// the two responses is pinned at the adapter's serialization boundary in
// package server (lifecycle_test.go there); these tests pin the decisions
// and record deltas only.

import (
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

const lifecycleKey = "11112222333344445555666677778888"

// settledLifecycleDevice builds the connected steady-state record: adopted,
// cfgversion echo matching, baseline captured, no vap_table (sparse
// heartbeat — nothing to disprove the running set). The engine's wireless
// source is empty, so the baseline is the empty-envelope hash.
func settledLifecycleDevice() store.Device {
	return store.Device{
		MAC: engineMAC, State: store.StateAdopted, Model: "U7PG2",
		CfgVersion: "aaaabbbbccccdddd", AppliedCfg: "aaaabbbbccccdddd",
		XAuthkey: lifecycleKey, Authkeys: []string{lifecycleKey},
		Extra: store.JSONMap{"wlan_cfg_sha": wireless.WlanListHash(nil)},
	}
}

// TestArmedRebootEmitsOnceThenSteadyNoop pins the §6.5 one-shot contract:
// the armed inform answers reboot, the flag is consumed in the same
// decision, NO cfgversion is minted (the §6.2 catalog has no reboot
// site), the record is otherwise untouched (soft reboot keeps device
// config — 2026-09-18 A2 live round), and the next status inform is an
// ordinary connected noop again.
func TestArmedRebootEmitsOnceThenSteadyNoop(t *testing.T) {
	e := newTestEngine(t)
	dev := settledLifecycleDevice()
	dev.Extra[FlagRebootOnConnect] = true

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindReboot {
		t.Fatalf("kind = %v, want reboot", out.Kind)
	}
	if _, armed := out.Extra[FlagRebootOnConnect]; armed {
		t.Fatalf("reboot flag not consumed: %+v", out.Extra)
	}
	if out.SetCfgVersion || out.SetState || out.SetXAuthkey || out.SetAppliedCfg || out.SetAuthkeys {
		t.Fatalf("reboot emission minted or mutated record deltas: %+v", out)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopted || dev.XAuthkey != lifecycleKey ||
		dev.CfgVersion != "aaaabbbbccccdddd" || dev.AppliedCfg != dev.CfgVersion {
		t.Fatalf("record changed by reboot emission: %+v", dev)
	}
	if _, ok := dev.Extra["wlan_cfg_sha"]; !ok {
		t.Fatal("reboot emission must keep the settle baseline")
	}

	// Next status inform: ordinary connected noop (device kept its config
	// through the soft reboot and still echoes the same cfgversion).
	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("post-reboot inform = %+v, want plain connected noop", out)
	}
}

// TestArmedRebootPreemptsPendingProvisioning: an armed reboot outranks a
// delivery that is still outstanding (state adopting, cfgversion not yet
// applied) — the inform carries the reboot, and the DEFERRED provisioning
// is not lost: the post-reboot inform (device still echoing the old
// stamp) gets the full provisioning.
func TestArmedRebootPreemptsPendingProvisioning(t *testing.T) {
	e := newTestEngine(t)
	dev := settledLifecycleDevice()
	dev.State = store.StateAdopting
	dev.AppliedCfg = "" // delivery outstanding
	dev.Extra[FlagRebootOnConnect] = true

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindReboot {
		t.Fatalf("kind = %v, want reboot to preempt the pending provisioning", out.Kind)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopting || dev.CfgVersion != "aaaabbbbccccdddd" {
		t.Fatalf("deferred delivery disturbed by reboot emission: %+v", dev)
	}

	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: lifecycleKey, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" {
		t.Fatalf("post-reboot inform = %+v, want the deferred full provisioning", out)
	}
}

// TestArmedSetdefaultDemotesToPendingCandidate pins the §6.6 emission plus
// demotion: setdefault outranks a simultaneously armed reboot (both flags
// consumed — the pending reboot is moot), the record returns to the
// pending-candidate shape the default-key adoption path accepts, the
// controller-owned WLAN bookkeeping is cleared (a stale wlan_cfg_sha would
// let the re-adopted device settle into connected noops while running
// factory config), and no cfgversion is MINTED — the CfgVersion delta is
// the CLEAR to "" (the fresh 16-hex mint belongs to the re-adoption).
func TestArmedSetdefaultDemotesToPendingCandidate(t *testing.T) {
	e := newTestEngine(t)
	dev := settledLifecycleDevice()
	dev.Extra[FlagSetdefaultArmed] = true
	dev.Extra[FlagRebootOnConnect] = true // pending reboot is moot
	dev.Extra["wlan_cfg_attempts"] = 3.0
	dev.Extra["wlan_cfg_delivery_status"] = "pending"
	// Seed the consecutive-miss counter too (float64 — the persisted
	// reload shape): the demotion's controller-owned sweep must clear it
	// with the rest of the family, or the re-adopted device would inherit
	// a half-armed not-running window.
	dev.Extra["wlan_cfg_not_running_misses"] = 1.0
	// Seed the site ssh password cache too: the sweep must SPARE it (a
	// site-fact cache the first post-reset provisioning re-derives
	// verbatim) — the lane's one deliberately distinctive demotion
	// behavior, pinned here at engine level.
	dev.Extra[store.SSHSha512PasswdKey] = "site-cache-sentinel"

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetdefault {
		t.Fatalf("kind = %v, want setdefault to outrank the armed reboot", out.Kind)
	}
	if _, armed := out.Extra[FlagSetdefaultArmed]; armed {
		t.Fatalf("setdefault flag not consumed: %+v", out.Extra)
	}
	if _, armed := out.Extra[FlagRebootOnConnect]; armed {
		t.Fatalf("pending reboot flag not consumed by setdefault: %+v", out.Extra)
	}
	if !out.SetCfgVersion || out.CfgVersion != "" || !out.SetAppliedCfg || out.AppliedCfg != "" {
		t.Fatalf("setdefault must CLEAR the cfgversions, not mint: %+v", out)
	}
	if !out.SetState || out.State != store.StatePending {
		t.Fatalf("setdefault must demote to pending: %+v", out)
	}
	if !out.SetXAuthkey || out.XAuthkey != "" {
		t.Fatalf("setdefault must drop the per-device key: %+v", out)
	}
	if !out.SetAuthkeys || len(out.Authkeys) != 0 {
		t.Fatalf("setdefault must drop the authkey history: %+v", out)
	}

	applyDeltas(&dev, out)
	if dev.State != store.StatePending || dev.XAuthkey != "" ||
		dev.CfgVersion != "" || dev.AppliedCfg != "" || len(dev.Authkeys) != 0 {
		t.Fatalf("record not in pending-candidate shape: %+v", dev)
	}
	for _, k := range store.FactoryResetSweepKeys {
		if _, ok := dev.Extra[k]; ok {
			t.Fatalf("controller-owned %q survived the setdefault demotion", k)
		}
	}
	// The specific assertion the family loop makes generic: the seeded
	// not-running miss counter must be gone (the loop above would pass
	// vacuously for keys that were never seeded).
	if _, ok := dev.Extra["wlan_cfg_not_running_misses"]; ok {
		t.Fatalf("the not-running miss counter survived the setdefault demotion: %v", dev.Extra["wlan_cfg_not_running_misses"])
	}
	// …and the one member the sweep must NOT touch: the site ssh password
	// cache survives verbatim.
	if got, want := dev.Extra[store.SSHSha512PasswdKey], "site-cache-sentinel"; got != want {
		t.Fatalf("the §6.6 sweep must spare the site ssh password cache: %v, want %q", got, want)
	}
}

// TestSetdefaultReadoptOnDefaultKey closes the loop the task text demands:
// after the demotion the (factory-reset) device re-informs on the factory
// default key and the EXISTING adoption flow re-adopts it — §6.2 a/c/f
// mgmt_cfg-only push with the authkey rotation line, fresh 32-hex
// x_authkey, fresh 16-hex cfgversion, state adopting.
func TestSetdefaultReadoptOnDefaultKey(t *testing.T) {
	e := newTestEngine(t)
	dev := settledLifecycleDevice()
	dev.Extra[FlagSetdefaultArmed] = true

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil || out.Kind != KindSetdefault {
		t.Fatalf("setdefault emission: %v (%+v)", err, out)
	}
	applyDeltas(&dev, out)

	// Post-reset inform: factory default key, factory config (no
	// cfgversion), pending record → ordinary adoption push.
	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1020, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || out.FullProvision {
		t.Fatalf("re-adoption kind = %v full=%v, want mgmt_cfg-only adoption push", out.Kind, out.FullProvision)
	}
	if !strings.Contains(out.MgmtCfg, "authkey=") {
		t.Fatalf("re-adoption mgmt_cfg missing the authkey rotation line: %q", out.MgmtCfg)
	}
	if !out.SetState || out.State != store.StateAdopting {
		t.Fatalf("re-adoption state delta: %+v", out)
	}
	if !out.SetXAuthkey || len(out.XAuthkey) != 32 || !isHexStr(out.XAuthkey) {
		t.Fatalf("re-adoption x_authkey not fresh 32-hex: %q", out.XAuthkey)
	}
	if !out.SetAuthkeys || !containsKeyStr(out.Authkeys, out.XAuthkey) {
		t.Fatalf("re-adoption authkeys: %v", out.Authkeys)
	}
	if !out.SetCfgVersion || len(out.CfgVersion) != 16 || !isHexStr(out.CfgVersion) {
		t.Fatalf("re-adoption cfgversion not fresh 16-hex: %q", out.CfgVersion)
	}
}

// TestSetdefaultFiresOnDefaultKeyInform pins the PRE-KEY-GATE placement:
// a device that already factory-reset itself and re-informed on the
// factory default key BEFORE the controller emitted still gets its
// setdefault — the same inform without the flag is the FID-1
// default-key-in-adopted-state reject (mirrors the classic dispatcher,
// where the state-8 check precedes the §11006+ key gate).
func TestSetdefaultFiresOnDefaultKeyInform(t *testing.T) {
	e := newTestEngine(t)

	// Contrast first: same inform, no flag → FID-1 reject.
	plain := settledLifecycleDevice()
	if _, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: plain,
		Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1000, 0),
	}); err != ErrDefaultKeyRejected {
		t.Fatalf("unarmed default-key inform in adopted state: err = %v, want ErrDefaultKeyRejected", err)
	}

	// With the flag armed: setdefault fires before the key gate.
	dev := settledLifecycleDevice()
	dev.Extra[FlagSetdefaultArmed] = true
	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatalf("armed default-key inform: %v", err)
	}
	if out.Kind != KindSetdefault {
		t.Fatalf("kind = %v, want setdefault ahead of the key gate", out.Kind)
	}
}

// TestArmedLifecycleFiresOnPlaintextLane: the admin intent is
// record-level, so both transports honor it (the §6.6 A2-style plaintext
// lane included). Same one-shot semantics.
func TestArmedLifecycleFiresOnPlaintextLane(t *testing.T) {
	e := newTestEngine(t)
	dev := settledLifecycleDevice()
	dev.Extra[FlagRebootOnConnect] = true

	out, err := e.Decide(Request{
		Transport: TransportPlaintext, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindReboot {
		t.Fatalf("plaintext lane kind = %v, want reboot", out.Kind)
	}
	applyDeltas(&dev, out)

	out, err = e.Decide(Request{
		Transport: TransportPlaintext, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The plain lane's claim-match arm always runs assignedKeyFlow (full
	// provisioning) — existing plaintext semantics the armed emission must
	// not disturb: the reboot fired, the flag is gone, and the next plain
	// inform is the ordinary plain-lane setparam again.
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("plaintext post-reboot kind = %v full=%v, want the ordinary plain-lane full provisioning", out.Kind, out.FullProvision)
	}

	// Same for setdefault on the plaintext lane.
	dev = settledLifecycleDevice()
	dev.Extra[FlagSetdefaultArmed] = true
	out, err = e.Decide(Request{
		Transport: TransportPlaintext, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1020, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetdefault {
		t.Fatalf("plaintext lane kind = %v, want setdefault", out.Kind)
	}
}

// TestArmedLifecycleYieldsToGentleNoop pins the ordering: an unknown
// non-empty _type (outside the adoption engine's §6.2 decision catalog)
// gets the gentle noop FIRST — the armed command is not consumed by it and
// still rides the next status inform.
func TestArmedLifecycleYieldsToGentleNoop(t *testing.T) {
	e := newTestEngine(t)
	dev := settledLifecycleDevice()
	dev.Extra[FlagRebootOnConnect] = true

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body:    map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "_type": "scan"},
		UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("gentle-noop precedence: kind = %v, want noop", out.Kind)
	}
	if _, armed := out.Extra[FlagRebootOnConnect]; !armed {
		t.Fatalf("gentle noop consumed the armed reboot: %+v", out.Extra)
	}

	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindReboot {
		t.Fatalf("next status inform kind = %v, want the deferred reboot", out.Kind)
	}
}

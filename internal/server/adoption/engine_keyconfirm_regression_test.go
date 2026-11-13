package adoption

// Regression tests for the key-confirmation gate: once a record has
// authenticated its per-device key, it must reject the factory key even in
// StateAdopting and even when a lifecycle command is armed. The documented
// mid-adoption window remains open for a keyed, not-yet-confirmed record
// (docs/PROTOCOL.md §3 step 4).

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

func keyconfirmDevice(state int, confirmed bool) store.Device {
	return store.Device{
		MAC:          engineMAC,
		State:        state,
		CfgVersion:   "aaaa",
		AppliedCfg:   "",
		XAuthkey:     "11112222333344445555666677778888",
		Authkeys:     []string{"11112222333344445555666677778888"},
		KeyConfirmed: confirmed,
		Model:        "U7PG2",
		Extra:        store.JSONMap{},
	}
}

// TestAdoptingConfirmedRejectsFactoryKey is the C1 flip: StateAdopting +
// assigned key + KeyConfirmed marker → the factory default key is REJECTED
// (the fixture asserted the vulnerable acceptance; state alone did not and
// cannot express "pre-key" since assignedKeyFlow/rotateKeys re-enter
// StateAdopting after a key exists).
func TestAdoptingConfirmedRejectsFactoryKey(t *testing.T) {
	e := newTestEngine(t)
	dev := keyconfirmDevice(store.StateAdopting, true)
	out, err := e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody(""),
		UsedKey:   defaultKeyHex,
		Now:       time.Unix(1000, 0),
	})
	if err != ErrDefaultKeyRejected {
		t.Fatalf("err = %v, want ErrDefaultKeyRejected (C1 flip: the confirmed adopting record rejects the factory key)", err)
	}
	if !reflect.DeepEqual(out, Outcome{}) {
		t.Fatalf("rejected inform leaked an outcome: %+v", out)
	}
}

// TestConfirmedArmedSetdefaultNotFiredOnFactoryKey is the C2 flip (engine
// arm): an armed factory-reset flag on a CONFIRMED record cannot be fired by
// the factory default key — the gate rejects before armedLifecycle, so the
// arming is neither consumed nor reset-confirmed on the unauthenticated
// claim. The adapter-level retry/confirmation chain is pinned end-to-end in package server
// (TestFactoryResetLifecycleEndToEnd).
func TestConfirmedArmedSetdefaultNotFiredOnFactoryKey(t *testing.T) {
	e := newTestEngine(t)
	dev := keyconfirmDevice(store.StateAdopting, true)
	dev.Extra[FlagSetdefaultArmed] = true
	out, err := e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody(""),
		UsedKey:   defaultKeyHex,
		Now:       time.Unix(1000, 0),
	})
	if err != ErrDefaultKeyRejected {
		t.Fatalf("err = %v, want ErrDefaultKeyRejected BEFORE the armed lifecycle (C2 flip)", err)
	}
	// Outcome zero value = no deltas, no Extra: the armed flag was NOT
	// consumed by the rejected inform (unauthenticated reset confirmation is denied).
	if !reflect.DeepEqual(out, Outcome{}) {
		t.Fatalf("gate must not consume the armed flag nor emit deltas: %+v", out)
	}
}

func TestPlaintextAuthkeyClaimDoesNotConfirmAssignedKey(t *testing.T) {
	e := newTestEngine(t)
	dev := keyconfirmDevice(store.StateAdopting, false)
	out, err := e.Decide(Request{
		Transport: TransportPlaintext,
		Device:    dev,
		Body:      engineBody(dev.CfgVersion),
		UsedKey:   lifecycleKey, // plaintext _authkey is an assertion, not an authenticator
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.SetKeyConfirmed || out.KeyConfirmed {
		t.Fatalf("plaintext claim stamped key confirmation: %+v", out)
	}
}

func TestPlaintextAssignedProvisioningCannotReopenFactoryKeyAdmission(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state int
	}{{"adopted", store.StateAdopted}, {"lost", store.StateLost}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEngine(t)
			dev := keyconfirmDevice(tc.state, false)
			out, err := e.Decide(Request{
				Transport: TransportPlaintext, Device: dev,
				Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey, Now: time.Unix(1000, 0),
			})
			if err != nil || out.Kind != KindSetparam || !out.FullProvision {
				t.Fatalf("assigned plaintext response = %+v, err=%v; want successful full provisioning", out, err)
			}
			applyDeltas(&dev, out)
			if dev.State != tc.state {
				t.Fatalf("plaintext provisioning changed state %d to %d", tc.state, dev.State)
			}
			if dev.KeyConfirmed {
				t.Fatal("plaintext claim established key confirmation")
			}
			_, err = e.Decide(Request{
				Transport: TransportEncrypted, Device: dev,
				Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1010, 0),
			})
			if err != ErrDefaultKeyRejected {
				t.Fatalf("factory key after plaintext takeover = %v, want ErrDefaultKeyRejected", err)
			}
		})
	}
}

func TestPlaintextAssignedProvisioningPreservesLegitimateAdoptingState(t *testing.T) {
	e := newTestEngine(t)
	dev := keyconfirmDevice(store.StateAdopting, false)
	out, err := e.Decide(Request{
		Transport: TransportPlaintext, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey, Now: time.Unix(1000, 0),
	})
	if err != nil || out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("adopting plaintext provisioning = %+v, err=%v", out, err)
	}
	applyDeltas(&dev, out)
	if dev.State != store.StateAdopting || dev.KeyConfirmed {
		t.Fatalf("legitimate onboarding state/confirmation changed: state=%d confirmed=%v", dev.State, dev.KeyConfirmed)
	}
	if _, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1010, 0),
	}); err != nil {
		t.Fatalf("mid-adoption factory-key window was closed: %v", err)
	}
}

func TestLegacyArmedPreKeyRecordAdoptsBeforeResetEmission(t *testing.T) {
	e := newTestEngine(t)
	dev := keyconfirmDevice(store.StateAdopting, false)
	dev.Extra[FlagSetdefaultArmed] = true
	dev.Extra[FlagRebootOnConnect] = true
	store.ArmCmdTask(&dev, "restart")

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1000, 0),
	})
	if err != nil || out.Kind != KindSetparam || out.FullProvision || out.SetFactoryResetInFlight {
		t.Fatalf("legacy factory-key pre-key inform = %+v, err=%v; want ordinary adoption", out, err)
	}
	applyDeltas(&dev, out)
	if !truthy(dev.Extra[FlagSetdefaultArmed]) || !truthy(dev.Extra[FlagRebootOnConnect]) || store.ArmedCmdTask(dev) == nil {
		t.Fatalf("pre-key adoption consumed an armed lifecycle command: %+v", dev.Extra)
	}
	if dev.KeyConfirmed {
		t.Fatal("factory-key adoption stamped key confirmation")
	}

	// The assigned-key encrypted inform may now emit reset and establishes
	// confirmation in that same decision. setdefault supersedes the other arms.
	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey, Now: time.Unix(1010, 0),
	})
	if err != nil || out.Kind != KindSetdefault || !out.SetKeyConfirmed || !out.KeyConfirmed {
		t.Fatalf("assigned-key reset emission = %+v, err=%v; want atomic reset + confirmation", out, err)
	}
	if truthy(out.Extra[FlagSetdefaultArmed]) || truthy(out.Extra[FlagRebootOnConnect]) || store.ArmedCmdTask(store.Device{Extra: out.Extra}) != nil {
		t.Fatalf("setdefault emission did not consume superseded arms: %+v", out.Extra)
	}
}

func TestUnconfirmedPlaintextResetArmIsLifecyclePrecedenceBarrier(t *testing.T) {
	for _, withReboot := range []bool{true, false} {
		name := "reset-and-task"
		if withReboot {
			name = "reset-reboot-and-task"
		}
		t.Run(name, func(t *testing.T) {
			e := newTestEngine(t)
			dev := keyconfirmDevice(store.StateAdopting, false)
			dev.Extra[FlagSetdefaultArmed] = true
			if withReboot {
				dev.Extra[FlagRebootOnConnect] = true
			}
			store.ArmCmdTask(&dev, "restart")
			dev.Extra[store.WlanCfgNotRunningMissesKey] = 2
			dev.Extra[store.WlanCfgVapNotRunningMissesKey] = 1

			// An unconfirmed plaintext claim cannot emit reset, but the reset
			// arm remains a precedence barrier: repeated calls must preserve all
			// competing command arms and both watchdog windows.
			for n := 0; n < 2; n++ {
				out, err := e.Decide(Request{
					Transport: TransportPlaintext, Device: dev,
					Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey,
					Now: time.Unix(int64(1000+n), 0),
				})
				if err != nil || out.Kind == KindReboot || out.Kind == KindCmd || out.Kind == KindSetdefault {
					t.Fatalf("plaintext reset-barrier call %d = %+v, err=%v; must not consume/emit a command", n+1, out, err)
				}
				applyDeltas(&dev, out)
				if !truthy(dev.Extra[FlagSetdefaultArmed]) ||
					(withReboot && !truthy(dev.Extra[FlagRebootOnConnect])) ||
					(!withReboot && truthy(dev.Extra[FlagRebootOnConnect])) || store.ArmedCmdTask(dev) == nil {
					t.Fatalf("plaintext reset-barrier call %d consumed a competing arm: %+v", n+1, dev.Extra)
				}
				if dev.Extra[store.WlanCfgNotRunningMissesKey] != 2 || dev.Extra[store.WlanCfgVapNotRunningMissesKey] != 1 {
					t.Fatalf("plaintext reset-barrier call %d changed watchdog counters: %+v", n+1, dev.Extra)
				}
				if dev.KeyConfirmed {
					t.Fatalf("plaintext reset-barrier call %d confirmed the key", n+1)
				}
			}

			// The later assigned-key encrypted inform is allowed to emit reset,
			// confirm that key atomically, and consume reset-superseded commands.
			out, err := e.Decide(Request{
				Transport: TransportEncrypted, Device: dev,
				Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey,
				Now: time.Unix(1010, 0),
			})
			if err != nil || out.Kind != KindSetdefault || !out.SetKeyConfirmed || !out.KeyConfirmed {
				t.Fatalf("assigned encrypted reset after plaintext calls = %+v, err=%v", out, err)
			}
			if truthy(out.Extra[FlagSetdefaultArmed]) || truthy(out.Extra[FlagRebootOnConnect]) || store.ArmedCmdTask(store.Device{Extra: out.Extra}) != nil {
				t.Fatalf("encrypted reset did not consume superseded arms: %+v", out.Extra)
			}
			if out.Extra[store.WlanCfgNotRunningMissesKey] != 2 || out.Extra[store.WlanCfgVapNotRunningMissesKey] != 1 {
				t.Fatalf("reset emission disturbed watchdog counters before confirmation: %+v", out.Extra)
			}
		})
	}
}

func TestPlaintextCommandsStillFireWithoutResetBarrier(t *testing.T) {
	e := newTestEngine(t)
	dev := keyconfirmDevice(store.StateAdopting, false)
	dev.Extra[FlagRebootOnConnect] = true
	store.ArmCmdTask(&dev, "restart")
	out, err := e.Decide(Request{
		Transport: TransportPlaintext, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey, Now: time.Unix(1000, 0),
	})
	if err != nil || out.Kind != KindReboot || truthy(out.Extra[FlagRebootOnConnect]) || store.ArmedCmdTask(store.Device{Extra: out.Extra}) == nil {
		t.Fatalf("plaintext reboot without reset = %+v, err=%v; want reboot while task remains", out, err)
	}
	applyDeltas(&dev, out)
	out, err = e.Decide(Request{
		Transport: TransportPlaintext, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey, Now: time.Unix(1010, 0),
	})
	if err != nil || out.Kind != KindCmd || store.ArmedCmdTask(store.Device{Extra: out.Extra}) != nil {
		t.Fatalf("plaintext task without reset = %+v, err=%v; want cmd replay", out, err)
	}
}

func TestLegacyUnconfirmedInFlightResetRequiresAssignedKeyRetry(t *testing.T) {
	e := newTestEngine(t)
	dev := keyconfirmDevice(store.StateAdopted, false)
	dev.FactoryResetInFlight = true
	dev.Extra[store.FactoryResetInFlightKey] = true
	before := dev
	if _, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1000, 0),
	}); err != ErrDefaultKeyRejected {
		t.Fatalf("legacy unconfirmed factory-key inform = %v, want rejection", err)
	}
	if dev.XAuthkey != before.XAuthkey || dev.State != before.State || dev.FactoryResetInFlight != before.FactoryResetInFlight {
		t.Fatalf("rejected legacy confirmation mutated identity: before=%+v after=%+v", before, dev)
	}

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey, Now: time.Unix(1010, 0),
	})
	if err != nil || out.Kind != KindSetdefault || !out.SetKeyConfirmed || !out.KeyConfirmed || out.Extra[store.FactoryResetInFlightKey] != true {
		t.Fatalf("assigned-key reset retry = %+v, err=%v; want retry + key confirmation", out, err)
	}
	applyDeltas(&dev, out)
	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1020, 0),
	})
	if err != nil || out.Kind != KindSetparam || !out.SetFactoryResetInFlight || out.FactoryResetInFlight {
		t.Fatalf("confirmed factory-key reset completion = %+v, err=%v", out, err)
	}
}

func TestPlaintextResetRequiresPriorEncryptedConfirmation(t *testing.T) {
	e := newTestEngine(t)
	for _, confirmed := range []bool{false, true} {
		dev := keyconfirmDevice(store.StateAdopted, confirmed)
		dev.FactoryResetInFlight = true
		dev.Extra[store.FactoryResetInFlightKey] = true
		out, err := e.Decide(Request{
			Transport: TransportPlaintext, Device: dev,
			Body: engineBody(dev.CfgVersion), UsedKey: dev.XAuthkey, Now: time.Unix(1000, 0),
		})
		if err != nil {
			t.Fatal(err)
		}
		if confirmed && out.Kind != KindSetdefault {
			t.Fatalf("confirmed assigned plaintext retry = %+v, want setdefault", out)
		}
		if !confirmed && out.Kind == KindSetdefault {
			t.Fatalf("unconfirmed plaintext claim emitted reset: %+v", out)
		}
		if out.SetKeyConfirmed || out.KeyConfirmed {
			t.Fatalf("plaintext claim changed key confirmation: %+v", out)
		}
	}
}

// TestAdoptingUnconfirmedFactoryKeyWindowStillAccepted pins the remaining
// legitimate window: adopting state + assigned key + NO confirmation marker
// → the factory key is accepted (docs/PROTOCOL.md §3 step 4 — the device
// has not applied the pushed key yet, so the controller rotates and
// re-pushes), with the classic §8 shape: fresh key, fresh cfgversion,
// adopting state, authkey= forward line in the mgmt_cfg.
func TestAdoptingUnconfirmedFactoryKeyWindowStillAccepted(t *testing.T) {
	e := newTestEngine(t)
	dev := keyconfirmDevice(store.StateAdopting, false)
	out, err := e.Decide(Request{
		Transport: TransportEncrypted,
		Device:    dev,
		Body:      engineBody(""),
		UsedKey:   defaultKeyHex,
		Now:       time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatalf("window inform must be accepted: %v", err)
	}
	if out.Kind != KindSetparam || out.FullProvision {
		t.Fatalf("kind = %v full=%v, want the mgmt_cfg-only adoption push", out.Kind, out.FullProvision)
	}
	if !out.SetXAuthkey || out.XAuthkey == "11112222333344445555666677778888" {
		t.Fatalf("window inform must still rotate the per-device key: %+v", out)
	}
	// The window re-push keeps the record adopting: either no state delta
	// (the record already sat in StateAdopting, so change-only deltas emit
	// nothing) or an explicit adopting-state delta.
	if out.SetState && out.State != store.StateAdopting {
		t.Fatalf("window inform must not leave the adopting state: %+v", out)
	}
	applied := dev
	applyDeltas(&applied, out)
	mgmt := e.BuildMgmtCfg(applied, defaultKeyHex)
	if !containsKeyStr(applied.Authkeys, applied.XAuthkey) {
		t.Fatalf("rotated key missing from authkeys: %v", applied.Authkeys)
	}
	if !strings.Contains(mgmt, "authkey="+out.XAuthkey) {
		t.Fatalf("window mgmt_cfg missing the rotated-key forward line: %q", mgmt)
	}
}

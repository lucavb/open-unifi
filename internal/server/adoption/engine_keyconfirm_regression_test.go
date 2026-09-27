package adoption

// Regression tests for the audit run-1 key-confirmation gate (findings C1
// adopting-state-factory-key-acceptance and C2 armed-lifecycle-before-
// default-key-rejection, ref f839fae). Ported from the validation fixture
// engine_factorykeyrepro_test.go with the assertions FLIPPED to the secure
// behavior: a record that has authenticated its per-device key (the
// persisted KeyConfirmed marker, stamped by the Decide wrapper on any
// key-authenticated inform) must reject the factory default key even in
// StateAdopting, and even when a lifecycle command is armed — while the
// documented mid-adoption window (docs/PROTOCOL.md §3 step 4: a keyed,
// never-yet-confirmed adopting record) stays open for the legitimate
// double-rotation.

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
// arming is neither consumed nor the record demoted on the unauthenticated
// claim. The adapter-level chain (armed persists + device-key inform still
// demotes + post-demotion recovery) is pinned end-to-end in package server
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
	// consumed by the rejected inform (the unauthenticated demotion is dead).
	if !reflect.DeepEqual(out, Outcome{}) {
		t.Fatalf("gate must not consume the armed flag nor emit deltas: %+v", out)
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

package adoption

// Engine-direct stored-task tests (§6.3 cmd passthrough): the armed task
// OUTRANKS the drift machinery (a drifted device with an armed task gets
// the task response, not the drift outcome), task delivery disarms the
// queue (the next inform falls back to the drift outcome), the settled
// no-task/no-drift noop, the one-shot consumption with no cfgversion mint,
// the verbatim outcome payload, the precedence against the other armed
// remote commands, and the gentle-noop/plaintext/key-gate behaviors. The
// BYTE shape of the replayed response is pinned at the adapter's
// serialization boundary in package server (cmdtask_test.go there); these
// tests pin the decisions and record deltas only.

import (
	"reflect"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

// cmdTaskDevice builds the connected steady-state record with an armed
// stored task (the §6.3 lane's arming shape on the settledLifecycleDevice
// baseline).
func cmdTaskDevice() store.Device {
	dev := settledLifecycleDevice()
	store.ArmCmdTask(&dev, "restart")
	return dev
}

// TestArmedCmdTaskOutranksDrift is the lane's ranking gate: a device with
// BOTH a wireless-envelope drift (stale wlan_cfg_sha against the current
// envelope) AND an armed task answers the TASK response, not the drift
// outcome — and the replay mints no cfgversion (the §6.2 mint-site list
// has no cmd-replay site, same reasoning as §6.5/§6.6). Delivery then
// disarms the queue: the very next inform, drift still pending, gets the
// deferred full provisioning.
func TestArmedCmdTaskOutranksDrift(t *testing.T) {
	e := newTestEngine(t)
	dev := settledLifecycleDevice()
	dev.Extra["wlan_cfg_sha"] = "stalebaseline" // ≠ empty-envelope hash → drift
	store.ArmCmdTask(&dev, "restart")

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindCmd {
		t.Fatalf("kind = %v, want the armed cmd task to outrank the drift outcome", out.Kind)
	}
	// The replay carries the stored row VERBATIM (§6.3 mergeFrom).
	want := store.JSONMap{"cmd": "restart", "mac": engineMAC}
	if !reflect.DeepEqual(map[string]any(out.CmdTask), map[string]any(want)) {
		t.Fatalf("CmdTask = %+v, want the verbatim stored row %+v", out.CmdTask, want)
	}
	// One-shot + no mint: the arming is consumed and NO record delta fires.
	if _, armed := out.Extra[store.CmdTaskKey]; armed {
		t.Fatalf("stored task not consumed by its replay: %+v", out.Extra)
	}
	if out.SetCfgVersion || out.SetState || out.SetXAuthkey || out.SetAppliedCfg || out.SetAuthkeys {
		t.Fatalf("cmd replay minted or mutated record deltas: %+v", out)
	}
	applyDeltas(&dev, out)
	if dev.CfgVersion != "aaaabbbbccccdddd" {
		t.Fatalf("cmd replay minted a cfgversion: %q", dev.CfgVersion)
	}

	// Delivery disarmed the queue: the next inform falls back to the
	// DRIFT outcome (full provisioning) on the same standing drift.
	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.SystemCfg == "" {
		t.Fatalf("post-task inform = kind %v full=%v, want the deferred drift full provisioning", out.Kind, out.FullProvision)
	}
	if out.CfgVersion == "" || out.CfgVersion == "aaaabbbbccccdddd" {
		t.Fatalf("drift full provisioning must mint a fresh cfgversion: %q", out.CfgVersion)
	}
}

// TestArmedCmdTaskOutranksCfgversionMismatch pins the same ranking on the
// plain cfgversion-mismatch flavor of drift (the dispatcher's default arm:
// the device echoes a stale stamp): the task wins, the mismatch full
// provisioning is deferred to the next inform.
func TestArmedCmdTaskOutranksCfgversionMismatch(t *testing.T) {
	e := newTestEngine(t)
	dev := cmdTaskDevice()
	dev.AppliedCfg = "0000000000000000" // stale echo → full provisioning due

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody("0000000000000000"), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindCmd {
		t.Fatalf("kind = %v, want the armed cmd task to outrank the pending cfgversion mismatch", out.Kind)
	}
	applyDeltas(&dev, out)

	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody("0000000000000000"), UsedKey: lifecycleKey, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("post-task inform = kind %v full=%v, want the deferred mismatch full provisioning", out.Kind, out.FullProvision)
	}
}

// TestNoTaskNoDriftStaysNooped pins the trio's third leg: a settled device
// (cfgversion echo matching, baseline captured, no vap_table) with no
// armed task and no drift answers the plain connected noop and mints
// nothing.
func TestNoTaskNoDriftStaysNooped(t *testing.T) {
	e := newTestEngine(t)
	dev := settledLifecycleDevice()

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("kind = %v, want the settled connected noop", out.Kind)
	}
	if out.SetCfgVersion || out.SetState || out.SetXAuthkey {
		t.Fatalf("settled noop minted or mutated record deltas: %+v", out)
	}
	if _, armed := out.Extra[store.CmdTaskKey]; armed {
		t.Fatalf("noop invented a stored task: %+v", out.Extra)
	}
}

// TestArmedCmdTaskPrecedenceVersusLifecycleCommands pins the armed-chain
// ordering: setdefault outranks the task and discards it (a queued task
// must not preempt the post-reset pending candidate's re-adoption push);
// reboot outranks the task but KEEPS it armed (a soft reboot defers the
// replay by exactly one inform without losing it).
func TestArmedCmdTaskPrecedenceVersusLifecycleCommands(t *testing.T) {
	e := newTestEngine(t)

	// setdefault armed + task armed → setdefault, task discarded.
	dev := cmdTaskDevice()
	dev.Extra[FlagSetdefaultArmed] = true
	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetdefault {
		t.Fatalf("kind = %v, want setdefault to outrank the armed cmd task", out.Kind)
	}
	if _, armed := out.Extra[store.CmdTaskKey]; armed {
		t.Fatalf("queued task survived the factory-reset demotion: %+v", out.Extra)
	}

	// reboot armed + task armed → reboot first, task still armed.
	dev = cmdTaskDevice()
	dev.Extra[FlagRebootOnConnect] = true
	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindReboot {
		t.Fatalf("kind = %v, want reboot to outrank the armed cmd task", out.Kind)
	}
	if _, armed := out.Extra[store.CmdTaskKey]; !armed {
		t.Fatalf("reboot emission must keep the queued task armed: %+v", out.Extra)
	}
	applyDeltas(&dev, out)

	// The post-reboot inform replays the surviving task.
	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1020, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindCmd {
		t.Fatalf("post-reboot kind = %v, want the deferred cmd replay", out.Kind)
	}
}

// TestArmedCmdTaskFiresBeforeKeyGate pins the family placement: the §6.3
// hook runs before the default-key state gate, so a PENDING candidate on
// the factory key with an armed task gets the task response — its
// adoption is deferred by exactly one inform, and the next default-key
// inform runs the ordinary adoption push.
func TestArmedCmdTaskFiresBeforeKeyGate(t *testing.T) {
	e := newTestEngine(t)
	dev := store.Device{
		MAC: engineMAC, State: store.StatePending, Model: "U7PG2",
		Extra: store.JSONMap{},
	}
	store.ArmCmdTask(&dev, "restart")

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindCmd {
		t.Fatalf("kind = %v, want the armed task ahead of the default-key adoption", out.Kind)
	}
	if out.SetXAuthkey || out.SetCfgVersion {
		t.Fatalf("task replay must not half-adopt: %+v", out)
	}
	applyDeltas(&dev, out)

	out, err = e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(""), UsedKey: defaultKeyHex, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || out.FullProvision {
		t.Fatalf("post-task default-key inform = kind %v full=%v, want the ordinary mgmt_cfg-only adoption push", out.Kind, out.FullProvision)
	}
}

// TestArmedCmdTaskYieldsToGentleNoopAndFiresOnPlaintext pins the two
// lane behaviors shared with the §6.5/§6.6 family: an unknown non-empty
// request _type gets the gentle noop FIRST (the task is not consumed and
// rides the next status inform), and the plaintext lane honors the same
// one-shot replay (the admin intent is record-level, transport-blind).
func TestArmedCmdTaskYieldsToGentleNoopAndFiresOnPlaintext(t *testing.T) {
	e := newTestEngine(t)

	// Gentle noop does not consume the task.
	dev := cmdTaskDevice()
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
	if _, armed := out.Extra[store.CmdTaskKey]; !armed {
		t.Fatalf("gentle noop consumed the armed task: %+v", out.Extra)
	}

	// Plaintext lane: same one-shot replay.
	out, err = e.Decide(Request{
		Transport: TransportPlaintext, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1010, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindCmd {
		t.Fatalf("plaintext lane kind = %v, want the cmd replay", out.Kind)
	}
	applyDeltas(&dev, out)

	// And the plain lane's next inform is the ordinary claim-match full
	// provisioning again (existing plaintext semantics the replay must
	// not disturb).
	out, err = e.Decide(Request{
		Transport: TransportPlaintext, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1020, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("plaintext post-task kind = %v full=%v, want the ordinary plain-lane full provisioning", out.Kind, out.FullProvision)
	}
}

// TestArmedCmdTaskEmptyEnvelopeBaselineKeepsRanking pins the ranking in
// the no-baseline shape too (a freshly adopted record with no settle
// baseline yet): the armed task still outranks the self-heal path that
// would otherwise force provisioning.
func TestArmedCmdTaskEmptyEnvelopeBaselineKeepsRanking(t *testing.T) {
	e := newTestEngine(t)
	dev := cmdTaskDevice()
	delete(dev.Extra, "wlan_cfg_sha") // no baseline → self-heal would fire

	out, err := e.Decide(Request{
		Transport: TransportEncrypted, Device: dev,
		Body: engineBody(dev.CfgVersion), UsedKey: lifecycleKey, Now: time.Unix(1000, 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindCmd {
		t.Fatalf("kind = %v, want the cmd replay ahead of the no-baseline self-heal", out.Kind)
	}
	if out.SetCfgVersion {
		t.Fatalf("cmd replay minted a cfgversion against the missing baseline: %+v", out)
	}
}

// TestCmdTaskString is the log-render helper: nil-safe and cmd-only.
func TestCmdTaskString(t *testing.T) {
	if got := CmdTaskString(nil); got != "" {
		t.Fatalf("nil row renders %q", got)
	}
	if got := CmdTaskString(store.JSONMap{"cmd": "restart", "mac": engineMAC}); got != "restart" {
		t.Fatalf("row renders %q, want restart", got)
	}
}

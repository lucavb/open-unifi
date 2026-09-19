package adoption

// §6.2(e) reconnect-push tests: a client-disconnect event (the session
// store's one-shot flag) pending on a connected device fires the
// reconnect-only blocked_sta push — setparam carrying blocked_sta ONLY,
// no cfgversion mint — while a settled device with no event stays nooped.
// The events are derived through store.RefreshSessions (the real arming
// path the adapter uses), not hand-planted flags.

import (
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

// armDisconnectEvent drives the session refresh the server adapter runs
// inside its RMW cycle: one full inform with the client present (connect),
// one without (disconnect) — arming the one-shot disconnect event.
func armDisconnectEvent(t *testing.T, dev *store.Device, client string) {
	t.Helper()
	cons, dsc := store.RefreshSessions(dev, []string{client}, 1040)
	if len(cons) != 1 || len(dsc) != 0 {
		t.Fatalf("setup connect refresh = %v / %v", cons, dsc)
	}
	cons, dsc = store.RefreshSessions(dev, nil, 1050)
	if len(cons) != 0 || len(dsc) != 1 || dsc[0] != "001122334455" {
		t.Fatalf("setup disconnect refresh = %v / %v, want the one disconnect", cons, dsc)
	}
	if !truthy(dev.Extra[store.SessionDisconnectEventExtraKey]) {
		t.Fatal("setup did not arm the disconnect event")
	}
}

// TestDisconnectEventFiresBlockedStaReconnectPush is the §6.2(e) gate: an
// adopted, settled device with blocked clients answers a
// client-disconnect event with the reconnect push — blocked_sta ONLY
// (no mgmt_cfg, no full provisioning, NO cfgversion mint), and the event
// is consumed one-shot.
func TestDisconnectEventFiresBlockedStaReconnectPush(t *testing.T) {
	e := newTestEngine(t)
	dev := driveToSettled(t, e)
	xkey := dev.XAuthkey

	// Block one client and deliver it through the ordinary (d) machinery
	// (mint + full provisioning), then settle — the (e) push re-delivers
	// confirmed content, so the set must be at rest first.
	if _, err := store.AddBlockedClient(&dev, "11:22:33:44:55:66"); err != nil {
		t.Fatal(err)
	}
	out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.AppliedCfg), UsedKey: xkey, Now: time.Unix(1030, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("block delivery = %+v, want full provisioning", out)
	}
	applyDeltas(&dev, out)
	dev.AppliedCfg = dev.CfgVersion
	dev.Extra["vap_table"] = []any{}
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1040, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("settle inform = %+v, want noop", out)
	}
	applyDeltas(&dev, out)

	// A client disconnects (the session refresh the adapter runs before
	// Decide): the event arms, and this inform answers with (e).
	armDisconnectEvent(t, &dev, "00:11:22:33:44:55")
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1060, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindBlockedStaReconnect {
		t.Fatalf("disconnect-event inform = %+v, want the §6.2(e) reconnect push", out)
	}
	if out.BlockedSta != "11:22:33:44:55:66" {
		t.Fatalf("blocked_sta = %q, want the confirmed set re-delivered verbatim", out.BlockedSta)
	}
	if out.FullProvision || out.MgmtCfg != "" || out.SystemCfg != "" {
		t.Fatalf("(e) push must carry blocked_sta ONLY (no full provisioning, no mgmt_cfg/system_cfg): %+v", out)
	}
	// NO mint: the §6.2 mint-site list has no (e) site — the record's
	// cfgversion must not move.
	if out.SetCfgVersion || out.SetXAuthkey || out.SetState {
		t.Fatalf("(e) push must mint nothing and not touch the key: %+v", out)
	}
	if truthy(out.Extra[store.SessionDisconnectEventExtraKey]) {
		t.Fatal("(e) push must consume the disconnect event one-shot")
	}
	applyDeltas(&dev, out)

	// The next connected inform is the ordinary noop again: the event is
	// spent, no further pushes.
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1070, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("post-(e) inform = %+v, want the connected noop", out)
	}
}

// TestDisconnectEventNoBlockedClientsStaysNoop pins the other §6.2(e)
// gate half: a settled device with NO blocked clients keeps answering the
// connected noop — same interval, no mint — and the event is still
// consumed (nothing to push; no stale phantom push after a later block).
func TestDisconnectEventNoBlockedClientsStaysNoop(t *testing.T) {
	e := newTestEngine(t)
	dev := driveToSettled(t, e)
	xkey := dev.XAuthkey

	// Baseline: the settled noop's interval at this now/prevTarget.
	out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1030, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("baseline inform = %+v, want noop", out)
	}
	wantInterval := out.Interval
	applyDeltas(&dev, out)

	// The event arms and fires nothing: no blocked clients to re-push.
	armDisconnectEvent(t, &dev, "00:11:22:33:44:55")
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1030, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop {
		t.Fatalf("no-blocked-clients inform = %+v, want the noop to stand", out)
	}
	if out.Interval != wantInterval {
		t.Fatalf("interval = %d, want %d (the noop schedule is unchanged by the event)", out.Interval, wantInterval)
	}
	if out.SetCfgVersion || out.SetState {
		t.Fatalf("no-push consumption must mint nothing: %+v", out)
	}
	if truthy(out.Extra[store.SessionDisconnectEventExtraKey]) {
		t.Fatal("event must be consumed even when there is nothing to push")
	}
	applyDeltas(&dev, out)

	// After a LATER block, the (d) drift machinery delivers the set — the
	// long-dead event must not fire a phantom (e) push.
	if _, err := store.AddBlockedClient(&dev, "aa:bb:cc:dd:ee:ff"); err != nil {
		t.Fatal(err)
	}
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.AppliedCfg), UsedKey: xkey, Now: time.Unix(1040, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("post-block inform = %+v, want the ordinary (d) full provisioning", out)
	}
}

// TestDisconnectEventConsumedByFullProvisioning: a disconnect event that
// coincides with a cfgversion mismatch is satisfied by the full
// provisioning that answers it — §6.2(d) carries blocked_sta, so the
// event must not survive to fire a redundant (e) push after settle.
func TestDisconnectEventConsumedByFullProvisioning(t *testing.T) {
	e := newTestEngine(t)
	dev := driveToSettled(t, e)
	xkey := dev.XAuthkey
	if _, err := store.AddBlockedClient(&dev, "11:22:33:44:55:66"); err != nil {
		t.Fatal(err)
	}
	// Deliver + settle the blocked set.
	out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.AppliedCfg), UsedKey: xkey, Now: time.Unix(1030, 0)})
	if err != nil {
		t.Fatal(err)
	}
	applyDeltas(&dev, out)
	dev.AppliedCfg = dev.CfgVersion
	dev.Extra["vap_table"] = []any{}
	if out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1035, 0)}); err != nil {
		t.Fatal(err)
	}
	applyDeltas(&dev, out)

	// Arm the event, then have the device echo a STALE cfgversion: the
	// mismatch answers with full provisioning, which consumes the event.
	armDisconnectEvent(t, &dev, "00:11:22:33:44:55")
	dev.AppliedCfg = "stale-echo"
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody("stale-echo"), UsedKey: xkey, Now: time.Unix(1060, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision || out.BlockedSta != "11:22:33:44:55:66" {
		t.Fatalf("stale-echo inform = %+v, want full provisioning carrying the set", out)
	}
	if truthy(out.Extra[store.SessionDisconnectEventExtraKey]) {
		t.Fatal("full provisioning must satisfy the disconnect event")
	}
	applyDeltas(&dev, out)

	// Settle, then the connected inform is the plain noop — no (e) push.
	dev.AppliedCfg = dev.CfgVersion
	dev.Extra["vap_table"] = []any{}
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1070, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoop || out.SetCfgVersion {
		t.Fatalf("post-settle inform = %+v, want the plain connected noop", out)
	}
}

// TestDisconnectEventWaitsForPendingDelivery pins the dispatcher order:
// an outstanding WLAN delivery is an unfinished (d) operation that
// outranks (e) — the event survives the pending gate's noop-pending-wlan
// and fires only once the delivery settles.
func TestDisconnectEventWaitsForPendingDelivery(t *testing.T) {
	e := newTestEngine(t)
	dev := driveToSettled(t, e)
	xkey := dev.XAuthkey
	if _, err := store.AddBlockedClient(&dev, "11:22:33:44:55:66"); err != nil {
		t.Fatal(err)
	}
	// The blocked drift mints + full provisions (pending delivery armed).
	out, err := e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.AppliedCfg), UsedKey: xkey, Now: time.Unix(1030, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindSetparam || !out.FullProvision {
		t.Fatalf("block delivery = %+v, want full provisioning", out)
	}
	applyDeltas(&dev, out)
	// The device then sends sparse heartbeats while it applies: no
	// vap_table reach the record, so settle cannot confirm the pending
	// delivery and the hold stands.
	delete(dev.Extra, "vap_table")

	// The event arms while the delivery is outstanding. The device echoes
	// the OFFERED cfgversion (equality) but proves nothing (no vap_table):
	// the pending gate answers noop-pending-wlan and the event survives.
	armDisconnectEvent(t, &dev, "00:11:22:33:44:55")
	dev.AppliedCfg = dev.CfgVersion
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1031, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindNoopPendingWLAN {
		t.Fatalf("echoed-offer inform = %+v, want noop-pending-wlan holding the delivery", out)
	}
	if !truthy(out.Extra[store.SessionDisconnectEventExtraKey]) {
		t.Fatal("the event must survive the pending-WLAN hold (the (d) operation outranks (e))")
	}
	applyDeltas(&dev, out)

	// The device proves its VAPs: settle clears the pending bookkeeping,
	// the equality branch is reached, and the (e) push fires now.
	dev.Extra["vap_table"] = []any{}
	out, err = e.Decide(Request{Transport: TransportEncrypted, Device: dev, Body: engineBody(dev.CfgVersion), UsedKey: xkey, Now: time.Unix(1050, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != KindBlockedStaReconnect || out.BlockedSta != "11:22:33:44:55:66" {
		t.Fatalf("post-settle inform = %+v, want the (e) push firing after settle", out)
	}
	applyDeltas(&dev, out)
}

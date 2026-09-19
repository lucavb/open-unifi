// Client-session event decisions: the §6.2(e) reconnect-only blocked_sta
// push (docs/PROTOCOL-mgmt.md §6.2 catalog row (e)) fires when a session
// refresh observed a previously-connected client disconnect. The trigger
// in the jar is the DEVICE-level `!consideredConnected` condition
// (§6.2(e) provenance); open-unifi has no device-level consideredConnected
// tracking, so the lane maps it onto the client-level disconnect event
// the session store derives (internal/store.RefreshSessions arming
// store.SessionDisconnectEventExtraKey) — recorded in the lane report as
// the recovered-side interpretation, with the device-level condition as
// the live-proof obligation.
//
// The push shape is the catalog's: setparam carrying blocked_sta ONLY
// (plus server_time_in_utc, which rides every response per §5) — NOT full
// provisioning, no cfgversion mint (the §6.2 mint-site list contains no
// (e) site), no mgmt_cfg. The set re-delivered is BY CONSTRUCTION
// identical to the last emission: any admin blocked-set change would
// have fired the blocked-drift full provisioning before the equality
// branch is reachable, so no baseline re-stamp is needed here.
package adoption

import (
	"github.com/lucavb/open-unifi/internal/store"
)

// KindBlockedStaReconnect is the §6.2(e) reconnect-only push: a setparam
// carrying blocked_sta only (the third setparam shape after the
// mgmt_cfg-only adoption push and full provisioning).
const KindBlockedStaReconnect Kind = "setparam-blocked-sta"

// blockedStaReconnectPush is the (e) decision point on the connected
// path. It runs only inside the cfgversion-equality branch (after the
// pending-WLAN gate — an outstanding WLAN delivery is an unfinished (d)
// operation that outranks (e), exactly like the jar's dispatcher, where
// (d) §1316 fires ahead of (e) §1391) and consumes the disconnect event
// ONE-SHOT in the same decision (the armedLifecycle pattern: fired or
// not, the flag never survives a connected decision, so a stale event
// cannot fire a phantom push after a later admin block).
//
// fired=false with the event consumed means "the event asked for a
// blocked_sta re-push, and there is nothing to push" (no blocked
// clients): the caller proceeds with the ordinary connected noop. The
// push itself fires only when the blocked set is non-empty.
func (e *Engine) blockedStaReconnectPush(d *store.Device) (out Outcome, fired bool) {
	if !truthy(d.Extra[store.SessionDisconnectEventExtraKey]) {
		return Outcome{}, false
	}
	// One-shot consumption: delete first, decide after — the outcome's
	// Extra delta (deltas()) carries the deletion either way.
	delete(d.Extra, store.SessionDisconnectEventExtraKey)
	wire := blockedStaWire(*d)
	if wire == "" {
		e.lg.Debug("inform: client disconnect event consumed, no blocked clients to push", "mac", d.MAC)
		return Outcome{}, false
	}
	e.lg.Debug("inform: blocked_sta reconnect push (client disconnect event)", "mac", d.MAC)
	return Outcome{
		Kind:       KindBlockedStaReconnect,
		BlockedSta: wire,
	}, true
}

// consumeSessionDisconnectEvent satisfies a pending disconnect event with
// any blocked_sta-carrying emission: full provisioning (§6.2(d)) delivers
// the set, so the event must not survive it to fire a redundant (e) push
// after settle. Called from assignedKeyFlow next to its baseline stamp.
func consumeSessionDisconnectEvent(d *store.Device) {
	delete(d.Extra, store.SessionDisconnectEventExtraKey)
}

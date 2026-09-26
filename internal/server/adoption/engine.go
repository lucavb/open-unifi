// Package adoption hosts the adoption engine: the single decider for every
// decoded inform — adoption, drift settle, delivery retry, full provisioning,
// or noop — given the device state (CONTEXT.md: decision modules). Transport
// and crypto sit outside it: the engine is a PURE decider with injected
// dependencies (logger, randomness, injected key generation, wireless source,
// system_cfg producer, controller URL/listen-addr facts) and performs no
// store calls, no HTTP, no crypto, and no time.Now() — everything is injected
// or passed through the Request.
//
// The engine reads and mutates a WORKING CLONE of the device snapshot and
// returns an Outcome carrying the response payload plus record deltas; the
// transport adapter (package server) applies the deltas to its record inside
// the per-MAC read-modify-write cycle and serializes the payload to exactly
// the same JSON as before the extraction.
package adoption

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

// defaultKeyHex is the factory pre-adoption AES key (docs/PROTOCOL.md §2);
// internal/inform owns the single canonical literal (inform is a leaf
// package, so aliasing it introduces no cycle).
const defaultKeyHex = inform.DefaultKeyHex

// WLAN delivery retry budget (bounded attempt bookkeeping per pushed hash).
const (
	WlanRetryBase   = 2 * time.Second
	WlanRetryMax    = 60 * time.Second
	WlanMaxAttempts = 6
)

// ErrDefaultKeyRejected (FID-1): an adopted device must never re-authenticate
// with the factory key (devmgr "used default key in X state, reject it" →
// Object.ÖoÓ000 → 404). The transport adapter maps this onto the HTTP 404.
var ErrDefaultKeyRejected = errors.New("default key used by an adopted device")

// informKnownTypes labels the NON-EMPTY request _type values the inform
// state machine processes specially. Real firmware sends its periodic
// status informs with an EMPTY _type (live evidence: U7PG2 on BZ.6.8.2,
// captured during the 2026-09-16 acceptance session), and the jar runs its
// main dispatcher (voidsuper — docs/PROTOCOL-mgmt.md §6.2) on exactly those
// informs: adoption, re-key, and provisioning all ride the empty-_type
// status inform. informTypeGentleNoop therefore lets "" through and only
// noops unknown NON-EMPTY types.
var informKnownTypes = map[string]bool{
	"info": true, "heartbeat": true, "cmd": true,
	"setparam": true, "setparam-ack": true, "cmd-ack": true,
	"alarms": true, "disconnect": true,
}

// informTypeGentleNoop reports whether the request _type falls outside the
// inform state machine: the empty _type IS the main-dispatcher status
// inform (see informKnownTypes), so only unknown NON-EMPTY types get the
// gentle noop.
func informTypeGentleNoop(rtype string) bool {
	return rtype != "" && !informKnownTypes[rtype]
}

// Transport identifies the inform transport the decision runs for. The
// plaintext rules live INSIDE the engine (branch on this input): no rotation,
// no adoption initiation, no default-key rejection, no drift settle —
// mirroring the former plainAdvance exactly.
type Transport int

const (
	// TransportEncrypted is the CBC/GCM inform path (the only one real
	// firmware uses).
	TransportEncrypted Transport = iota
	// TransportPlaintext is the AllowPlainText inform path.
	TransportPlaintext
)

// Request carries one decoded inform into the pure decider.
type Request struct {
	// Context carries the active trace for system_cfg rendering and logging.
	Context context.Context
	// Transport selects the encrypted or plaintext decision lane.
	Transport Transport
	// Device is the device snapshot the transport adapter absorbed the
	// inform body into (the record absorption lives on store.Device). The
	// engine works on an internal clone and never mutates it.
	Device store.Device
	// Body is the decoded inform body (JSON object).
	Body map[string]any
	// UsedKey is the lowercase hex key that authenticated the inform
	// (encrypted path) or the _authkey claim (plaintext path, defaulted to
	// the factory key by the adapter when absent).
	UsedKey string
	// Now is the timestamp of the inform currently being handled.
	Now time.Time
	// PrevNoopTarget is the controller-owned steady-state noop target for
	// this MAC (0 when none is tracked); the adapter keeps the noopTarget
	// map and persists the outcome's NewNoopTarget.
	PrevNoopTarget int64
}

// Kind labels the response shape (exactly the kind strings the adapter logs).
type Kind string

const (
	KindNoop            Kind = "noop"
	KindNoopPendingWLAN Kind = "noop-pending-wlan"
	KindSetparam        Kind = "setparam"

	// KindReboot is the remote-reboot response, docs/PROTOCOL-mgmt.md §6.5
	// (voidsuper: `new Object("reboot")` + `put("reboot_type", "soft")` —
	// the only reboot form the jar emits, from the reboot_on_connect
	// record flag). Fired once on the device's next decoded inform after
	// an admin arms that flag; the engine clears the flag in the same
	// decision. NO cfgversion is minted (see armedLifecycle for the §6.2
	// catalog match).
	KindReboot Kind = "reboot"

	// KindSetdefault is the factory-reset response, docs/PROTOCOL-mgmt.md
	// §6.6 (voidsuper line 1018, device state 8: `return new
	// Object("setdefault")` — a bare _type with no payload keys). Fired
	// once on the device's next decoded inform after an admin arms the
	// flag; at emission the record returns to the pending-candidate shape
	// (see armedLifecycle) so the post-reset re-inform on the factory
	// default key runs the ordinary adoption path unchanged. NO
	// cfgversion is minted.
	KindSetdefault Kind = "setdefault"

	// KindCmd is the §6.3 stored-task replay, docs/PROTOCOL-mgmt.md §6.3
	// (voidsuper `o00000(Device, Task)`: `new Object("cmd")` +
	// `object.mergeFrom((X)task)` — the stored task's Mongo fields become
	// response keys VERBATIM, then task cleanup `\u00d300000`). Fired once
	// on the device's next decoded inform after an admin enqueues a cmd
	// for it (inform hook `task != null`, §1353-1359); the engine consumes
	// the stored task in the same decision (one-shot), and the outcome
	// carries the row for the adapter to serialize verbatim. NO
	// cfgversion is minted: the §6.2 mint-site list (§501, §676, §826,
	// §1117/1122, §1269, §3068) has no cmd-replay site — same reasoning
	// as the §6.5/§6.6 emissions, and the follow-on inform re-enters the
	// ordinary decisions (drift full provisioning, §6.1 noop) unchanged.
	KindCmd Kind = "cmd"
)

// Lifecycle command flags (the trust-policy "admin-owned rows" class,
// CONTEXT.md: record absorption preserves them from the previous record
// through the store registry's admin-owned class, so a refreshable
// device body can neither wipe nor introduce them). One-shot
// ownership differs per command:
//
//   - FlagSetdefaultArmed is ADMIN-ONLY: only an admin can set or change
//     it (POST /api/v1/devices/{mac}/factory-reset; CONTEXT.md's literal
//     "only an admin can set or change them" claim holds for it).
//   - FlagRebootOnConnect has TWO non-device writers: the ordinary admin
//     POST /api/v1/devices/{mac}/reboot, AND the adoption engine's own
//     devname materialization watchdog (below, decideEncrypted) — the
//     controller arms it autonomously, one shot per cfgversion, for a
//     planned vap whose interface never materialized.
//
// Both are one-shot: the engine fires the corresponding response on the
// device's next decoded inform (armedLifecycle) and clears the flag in
// the same decision.
const (
	// FlagRebootOnConnect is the jar-verbatim record flag name the §6.5
	// reboot response is emitted from (voidsuper comment: "only from
	// reboot_on_connect flag"). Arming rides the admin POST
	// /api/v1/devices/{mac}/reboot AND the engine's devname
	// materialization watchdog (decideEncrypted's connected-noop arm —
	// one shot per cfgversion, budget tracked in the
	// wlan_cfg_materialization_reboot marker).
	FlagRebootOnConnect = store.FlagRebootOnConnect

	// FlagSetdefaultArmed is open-unifi's arming flag for the §6.6
	// setdefault response (POST /api/v1/devices/{mac}/factory-reset).
	// The jar arms factory reset as device STATE 8, a controller-side
	// enum member this store deliberately lacks (adding one would
	// redesign the pending-candidate lifecycle this lane must reuse), so
	// the arming rides an admin-owned Extra key instead. DEVIATION from
	// the jar's state-8 arming shape — recorded with the unrecoverable
	// jar facts in docs/PROTOCOL-mgmt.md §6.6.
	FlagSetdefaultArmed = store.FlagSetdefaultArmed
)

// Outcome carries the response payload plus the record deltas the adapter
// applies inside its read-modify-write cycle.
type Outcome struct {
	Kind Kind

	// Noop payload (KindNoop / KindNoopPendingWLAN — identical JSON).
	Interval int64

	// NewNoopTarget is persisted by the adapter ONLY when PersistNoopTarget
	// is set (the cap-fallback branch never persists, byte-for-byte as the
	// former noopRespFor).
	NewNoopTarget     int64
	PersistNoopTarget bool

	// setparam payloads. The adoption push (§6.2 a/b/c/f) carries ONLY
	// MgmtCfg; full provisioning additionally carries CfgVersion, SystemCfg
	// and BlockedSta (the §4 wire string rendered from the admin-owned
	// blocked-client set; "" when none). The §6.2(e) reconnect push
	// (KindBlockedStaReconnect) carries BlockedSta ONLY — no MgmtCfg, no
	// CfgVersion, no FullProvision. CfgVersion is also the record delta
	// target value.
	FullProvision bool
	SystemCfg     string
	BlockedSta    string
	MgmtCfg       string

	// CredentialDeltas carries the renderer's ssh password-cache writes
	// (ssh_md5passwd/ssh_sha512passwd); the adapter applies them inside
	// its RMW cycle — the pure renderer mutates nothing.
	CredentialDeltas map[string]string

	// Record deltas: applied by the adapter to its record. Extra is the
	// FULL final map (the engine works on a clone), so the adapter assigns
	// it wholesale — byte-identical persistence guaranteed by the typed
	// state's exact key names and value formats.
	SetState      bool
	State         int
	SetXAuthkey   bool
	XAuthkey      string
	SetCfgVersion bool
	CfgVersion    string // also the full-provision payload top-level cfgversion
	// SetAppliedCfg clears the record's last-reported applied cfgversion.
	// Carried only by the setdefault demotion to the pending-candidate
	// shape (every other outcome leaves AppliedCfg to the record
	// absorption).
	SetAppliedCfg bool
	AppliedCfg    string
	SetAuthkeys   bool
	Authkeys      []string
	Extra         store.JSONMap

	// CmdTask is the stored-task row replayed VERBATIM as the §6.3 cmd
	// response's payload keys (`mergeFrom((X)task)`): non-nil only for
	// KindCmd. The ADAPTER assembles the response JSON from it and the
	// inform codec seals the already-built bytes (CONTEXT.md seam) — the
	// engine never touches framing or crypto.
	CmdTask store.JSONMap
}

// Deps are the engine's injected dependencies (no store, no HTTP, no crypto,
// no wall clock inside the engine).
type Deps struct {
	// Logger receives the engine's debug/warn lines (discardable in tests).
	Logger *slog.Logger

	// Random is the per-response random source for the noop scheduler
	// (crypto/rand based at the adapter).
	Random func() float64

	// KeyChars generates n random lowercase hex characters (crypto/rand at
	// the adapter); failures surface as errors and abort the inform.
	KeyChars func(n int) (string, error)

	// Wireless supplies the per-device WLAN envelope for the record being
	// decided (nil ⇒ empty list).
	Wireless func(store.Device) []wireless.Wlan

	// SystemCfg renders the system_cfg blob for the record with the NEUTRAL
	// producer shape: (text, credential deltas, error). The adapter wires
	// it as a thin closure over the pure systemcfg.RenderWithPlan (assembling
	// SiteFacts from the server config); the closure also performs the
	// render's observability (diagnostic) and diagnostics logging, so this
	// decision module NEVER depends on the renderer package — the only
	// things crossing back are the text and the credential deltas, which
	// the ADAPTER applies inside its RMW cycle. The decision's computed
	// provisioning plan rides alongside the (record, envelope) args —
	// systemcfg.RenderWithPlan — so the renderer emits rows from the same
	// plan whose drift hash the branches below compared (one computation,
	// never a re-derivation).
	SystemCfg func(context.Context, store.Device, []wireless.Wlan, wireless.ProvisioningPlan) (text string, credentialDeltas map[string]string, err error)

	// ControllerURL is the configured controller base URL (mgmt_cfg host
	// facts). Empty means "not overridden".
	ControllerURL string

	// InformListenAddr is the inform TCP listen address (inform_url port
	// fallback).
	InformListenAddr string
}

// Engine is the pure adoption decider.
type Engine struct {
	lg               *slog.Logger
	random           func() float64
	keyChars         func(n int) (string, error)
	wireless         func(store.Device) []wireless.Wlan
	systemCfg        func(context.Context, store.Device, []wireless.Wlan, wireless.ProvisioningPlan) (string, map[string]string, error)
	controllerURL    string
	informListenAddr string
}

// New builds an Engine. A nil logger falls back to a discarding one.
func New(d Deps) *Engine {
	lg := d.Logger
	if lg == nil {
		lg = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	return &Engine{
		lg:               lg,
		random:           d.Random,
		keyChars:         d.KeyChars,
		wireless:         d.Wireless,
		systemCfg:        d.SystemCfg,
		controllerURL:    d.ControllerURL,
		informListenAddr: d.InformListenAddr,
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// wirelessForDevice resolves the configured source for one device; nil
// source ⇒ empty list.
func (e *Engine) wirelessForDevice(d store.Device) []wireless.Wlan {
	if e.wireless == nil {
		return nil
	}
	return e.wireless(d)
}

// Decide applies the adoption state machine (docs/PROTOCOL-mgmt.md §6.2) for
// one decoded inform and returns the response outcome plus record deltas.
//
//		setparam variants (exactly four shapes):
//		  - adoption push:  {"_type":"setparam","mgmt_cfg":...} + server_time
//		    (mgmt_cfg ONLY; fresh 16-hex cfgversion stored on the record first,
//		    carried in the mgmt_cfg "cfgversion=" line).
//		  - full provisioning: {"_type":"setparam","cfgversion":...,
//		    "system_cfg":...,"blocked_sta":...,"mgmt_cfg":...} + server_time.
//		  - blocked_sta reconnect push (§6.2(e)):
//		    {"_type":"setparam","blocked_sta":...} + server_time — blocked_sta
//		    ONLY, fired once on the connected path when a session refresh armed
//		    a client-disconnect event; NO cfgversion mint (see
//		    blockedStaReconnectPush).
//	  - noop: {"_type":"noop","interval":N} + server_time (N = 10 default,
//	    5 while watching, else the devmgr scheduling formula — see noopFor).
//
// usedKey is the lowercase hex key that authenticated the inform (encrypted)
// or the _authkey claim (plaintext). usedKey == defaultKeyHex selects the
// adoption branch on the encrypted lane.
func (e *Engine) Decide(req Request) (Outcome, error) {
	work := cloneDevice(req.Device)
	snapshot := req.Device
	// One wireless snapshot per decision: every envelope read inside this
	// decision (drift hash, gate, rendered system_cfg, delivery snapshot and
	// placements) sees the SAME slice, so the drift hash and the rendered
	// config can never disagree.
	wls := e.wirelessForDevice(work)
	// One provisioning plan per decision: the single value computed from a
	// device and the wireless envelope (CONTEXT.md) — drift hash, vap
	// placements, wireless rows together — threaded through both lanes and
	// into the renderer, so no consumer re-derives a half of it.
	// radio_table is THE device-refreshable plan input (PlanVaps reads it);
	// radio_intent is ADMIN-OWNED (store's adminOwnedKeys trust policy,
	// prev-or-delete) and is read by the renderer from the record at
	// emission (systemcfg's emitWirelessCfg) — it is NOT a plan input.
	// The load-bearing statement either way: no branch below touches the
	// plan inputs before consuming the plan.
	plan := wireless.PlanProvisioning(work, wls)
	var out Outcome
	var err error
	switch req.Transport {
	case TransportPlaintext:
		out, err = e.decidePlain(req, wls, plan, &work)
	default:
		out, err = e.decideEncrypted(req, wls, plan, &work)
	}
	if err != nil {
		return Outcome{}, err
	}
	// Stamp the record deltas the branch performed onto the working clone.
	out.deltas(&snapshot, &work)
	return out, nil
}

// armedLifecycle is the admin-armed remote-command lane (§6.5 reboot /
// §6.6 setdefault / §6.3 stored cmd task): the admin API sets
// admin-owned record rows; the NEXT decoded inform for that device
// answers with the corresponding response instead of entering the
// key/drift machinery, and the engine consumes the arming in the same
// decision (one-shot). All transports run it, after their gentle-noop
// gate (the armed commands ride the main status inform, exactly the
// empty-_type informs real firmware sends).
//
// Precedence: setdefault outranks reboot (a factory reset subsumes a
// pending reboot, and clearing the reboot flag keeps the post-reset
// default-key re-adoption from being preempted by a stale command), and
// both fire BEFORE the key/state gate — mirroring the classic
// dispatcher, where the state-8 setdefault check (voidsuper line 1018)
// precedes every §6.2 setparam site (§1117+), the §6.3 task hook
// (§1353-1359) and the default-key state gate. The jar's reboot emission
// site itself is not line-pinned in docs/PROTOCOL-mgmt.md §6.5 (byte
// shape only); placing it in the same early arm keeps the
// "next inform carries the response" contract — recorded as a
// live-proof obligation in the lane docs. The §6.3 cmd task slots AFTER
// both: §6.3 is silent on the task's ordering against the other armed
// commands — chosen: last, so the line-pinned setdefault check keeps
// winning and a one-shot reboot merely defers the task by exactly one
// inform without losing it (the post-reboot inform replays it). An armed
// task OUTRANKS the drift machinery: the §6.3 hook runs before the
// wireless/blocked drift arms below, so a drifted device with an armed
// task gets the task response, and after it delivers the SAME device
// falls back to the drift outcome on its next inform (the replay is not
// lost — §6.3's task cleanup is consumption, and the deferred
// provisioning re-fires exactly like the §6.5 deferred delivery).
//
// cfgversion-mint semantics — §6.2 catalog entries matched: NONE for the
// emissions themselves. Neither §6.5 reboot nor §6.6 setdefault nor the
// §6.3 replay is a §6.2 setparam emission site, and the §6.2 mint-site
// list (§501, §676, §826, §1117/1122, §1269, §3068) contains no
// reboot/setdefault/cmd site, so arming and emitting mint NO cfgversion.
// The follow-on decisions reuse existing catalog entries unchanged:
//   - after a reboot, the device's retained-key re-inform re-enters the
//     ordinary dispatcher (§6.1 noop on cfgversion match; §6.2 d full
//     provisioning on mismatch — the appliedNotRunning re-arm covers the
//     reboot regression the 2026-09-18 F-row round captured);
//   - after a setdefault, the post-reset default-key re-inform runs the
//     §8 default-key rotation path (the §6.2 a/c/f mgmt_cfg-only
//     family), which mints the fresh 16-hex cfgversion exactly as every
//     adoption does (rotateKeys — the §6.2 c "+ fresh 16-hex cfgversion
//     stored" semantics);
//   - after a cmd replay, the next inform re-enters the ordinary
//     dispatcher wherever the record stood (a drifted record full
//     provisions; a settled record noops).
func (e *Engine) armedLifecycle(d *store.Device) (Outcome, bool) {
	if truthy(d.Extra[FlagSetdefaultArmed]) {
		e.lg.Debug("inform: armed setdefault (factory reset)", "mac", d.MAC)
		// §6.6 emission plus the pending-candidate demotion: after the
		// device applies the factory reset it re-informs on the factory
		// default key, and the record must be the shape the existing
		// default-key adoption path accepts. Clearing the per-device key
		// assignment means a pre-reset inform on the old key can no
		// longer be decrypted (keyCandidates holds only Authkeys entries
		// plus the factory key) — the same 400 a genuinely unknown
		// record's non-default-key payload gets; the jar's own
		// post-emission record mutation (whether it clears x_authkey at
		// emission or keeps state 8 until the re-inform) was not
		// recoverable from the decompile and is recorded in §6.6.
		d.State = store.StatePending
		d.XAuthkey = ""
		d.CfgVersion = ""
		d.AppliedCfg = ""
		d.Authkeys = nil
		// Drop the controller-owned per-device bookkeeping (store
		// trust-policy registry, FactoryResetSweepKeys): a stale
		// wlan_cfg_sha would let the re-adopted device settle into
		// connected noops while running factory config. The baseline is
		// re-captured by the post-adoption self-heal + drift settle,
		// exactly like a fresh adoption (which deliberately seeds no
		// baseline). The ssh password caches are deliberately NOT
		// swept: they hold the DEVICE's last controller-pushed password
		// and deliberately survive factory reset/setdefault demotion;
		// the exclude keeps that survival.
		for _, k := range store.FactoryResetSweepKeys {
			delete(d.Extra, k)
		}
		delete(d.Extra, FlagSetdefaultArmed)
		// A pending reboot is moot once the device factory-resets.
		delete(d.Extra, FlagRebootOnConnect)
		// A queued §6.3 cmd task is moot too: the post-reset re-inform
		// arrives on the factory default key as a pending candidate, and
		// a replayed task would preempt the re-adoption push that record
		// must answer with. §6.3 is silent on task-vs-setdefault
		// interplay — chosen: the reset discards the queued task (the
		// same moot-clearing as the pending reboot).
		delete(d.Extra, store.CmdTaskKey)
		return Outcome{Kind: KindSetdefault}, true
	}
	if truthy(d.Extra[FlagRebootOnConnect]) {
		e.lg.Debug("inform: armed reboot", "mac", d.MAC)
		delete(d.Extra, FlagRebootOnConnect)
		// A reboot is a lifecycle boundary for the not-running window: the
		// next vap_table opens a fresh boot window (the 2026-09-19 A2
		// record: every raw reboot starts with a bring-up miss), so the
		// consecutive-miss counter must not straddle the reboot — a miss
		// recorded before it would otherwise fire a byte-identical
		// re-provision on the first post-boot table, re-opening exactly the
		// boot-race false fire the two-consecutive-miss arming closes.
		// The setdefault demotion already sweeps the whole
		// controller-owned family, so only the reboot path needs this.
		// The devname-level watchdog's counter (below) carries the same
		// rule: its window must re-arm from zero for the post-boot
		// materialization grace.
		delete(d.Extra, "wlan_cfg_not_running_misses")
		delete(d.Extra, "wlan_cfg_vap_not_running_misses")
		return Outcome{Kind: KindReboot}, true
	}
	// §6.3 stored cmd task (last in the armed chain — see the precedence
	// note above): replay the stored row VERBATIM and consume the arming
	// in the same decision, exactly the jar's `o00000(device, task)`
	// build-then-cleanup order. The task is opaque passthrough — whether
	// the cmd reboots the device (e.g. "restart") is the DEVICE's
	// business, so unlike the reboot branch this deliberately touches no
	// other record rows; a restart's boot window re-opens through the
	// ordinary two-consecutive-miss grace on the next inform.
	if task := store.ArmedCmdTask(*d); task != nil {
		e.lg.Debug("inform: armed cmd task", "mac", d.MAC, "cmd", CmdTaskString(task))
		delete(d.Extra, store.CmdTaskKey)
		return Outcome{Kind: KindCmd, CmdTask: task}, true
	}
	return Outcome{}, false
}

// CmdTaskString renders an armed task row's cmd for logs — the one §6.3
// field with operator meaning. Never logs the whole row: future task
// fields may carry more than the admin typed.
func CmdTaskString(task store.JSONMap) string {
	if task == nil {
		return ""
	}
	cmd, _ := task["cmd"].(string)
	return cmd
}

// decideEncrypted ports the former Server.advance for ENCRYPTED informs.
// usedKey is the lowercase hex key that authenticated the inform.
func (e *Engine) decideEncrypted(req Request, wls []wireless.Wlan, plan wireless.ProvisioningPlan, d *store.Device) (Outcome, error) {
	now := req.Now

	rtype, _ := req.Body["_type"].(string)
	if informTypeGentleNoop(rtype) {
		e.lg.Debug("inform: gentle noop for _type", "mac", d.MAC, "type", rtype)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
	}

	// Admin-armed remote commands (§6.3/§6.5/§6.6) preempt the drift and
	// key machinery: the armed response is what this inform must carry,
	// and the post-lifecycle inform re-enters the ordinary decisions
	// below (deferred provisioning is not lost — see armedLifecycle).
	if out, armed := e.armedLifecycle(d); armed {
		return out, nil
	}

	// Wireless envelope drift (FSM hash bump): BEFORE the cfgversion drift
	// check, compare sha256(canonical wireless envelope) with the stored
	// Extra["wlan_cfg_sha"]. A mismatch regenerates CfgVersion, which the
	// drift check then sees as unknown → full provisioning. The baseline
	// is captured exclusively by settle — the drift-settle confirmation of
	// a delivered system_cfg — and adoption deliberately does NOT seed it
	// (2026-09-18 F-row live round: a seed equal to the current envelope
	// hash made this check compare the intent against itself, so a freshly
	// adopted device answered connected noops forever without ever
	// receiving system_cfg). Live finding (2026-09-16 acceptance session,
	// U7PG2 on BZ.6.8.2): real firmware echoes the adoption mgmt_cfg's
	// cfgversion back on its first re-keyed inform — matching the jar's
	// equal path (voidsuper bytes 3287-3306 jump to 3549) — so full
	// provisioning never follows adoption on its own, and the drift
	// baseline must NOT depend on assignedKeyFlow having run first. The
	// jar bumps device.cfgversion on operator config saves ("CONFIG
	// changed" log); this hash comparison is open-unifi's equivalent
	// trigger.
	// A system_cfg transmission is only an offer.  Its hash remains pending
	// until a later inform proves the VAPs are actually running.
	st := loadWlanCfgState(d.Extra)
	// The record's CURRENT cfgversion rides settle for the materialization
	// marker's one-shot budget (see settle's doc): the record's desired
	// version is read BEFORE any mint this decision might make (an operator
	// or drift mint below concerns the NEXT operation, not the config the
	// pending bookkeeping was written under).
	st.settle(d.CfgVersion)
	wlanDrift := false
	if st.sha != "" {
		if cur := plan.DriftHash; cur != st.sha {
			wlanDrift = true
			// Mint ONLY for a genuinely NEW envelope. Live finding
			// (2026-09-19 EAP round, WLAN-ACCEPTANCE 6.8.2.15592): a
			// drifted-but-still-pending envelope re-minted on EVERY
			// inform — 37 offers in 3.5 minutes against a device that
			// only sent sparse informs (no vap_table, so settle could
			// never confirm) — and each fresh mint kept operatorMint
			// true in the pending gate below, so WlanRetryDue never
			// bounded the re-offers and the device's echo could never
			// land on ours. While cur == the pending hash the delivery
			// operation is UNCHANGED: keep the offered cfgversion
			// stable (assignedKeyFlow re-offers it verbatim), let the
			// pending gate's bounded budget govern re-offers, and let
			// an echoed offer reach the equality branch's
			// noop-pending-wlan instead of minting the equality away.
			if !st.pendingSHAPresent || st.pendingSHA != cur {
				nv, kerr := e.keyChars(16)
				if kerr != nil {
					return Outcome{}, kerr
				}
				d.CfgVersion = nv
			}
			e.lg.Debug("inform: wireless envelope drift", "mac", d.MAC)
		}
	}
	blockedDrift := false
	// blocked_sta drift (§6.2(d), engine.go's §4 writer): the admin-owned
	// blocked-client set is provisioned CONTENT, delivered only inside full
	// provisioning — the jar has no standalone blocked push short of the
	// reconnect-only variant §6.2(e) records as a named open-unifi
	// follow-up. So a set change rides exactly the WLAN envelope change
	// machinery: mint a fresh cfgversion here (a blocked edit is a content
	// change, so the echoed cfgversion must never enter the equality/noop
	// branch), and the switch below forces assignedKeyFlow in THIS inform.
	// The baseline semantics differ from wlan_cfg_sha in one way: absent
	// baseline + EMPTY set is steady state, not drift — that combination is
	// what a freshly adopted device presents (2026-09-16 live round: the
	// equal path answers connected noops after adoption), and baseline
	// capture happens at EMISSION (blocked content has no vap_table to
	// observe; the cfgversion echo the equality path already tracks is the
	// only confirmation there is).
	if _, blockedChanged := blockedStaDrift(*d); blockedChanged {
		blockedDrift = true
		nv, kerr := e.keyChars(16)
		if kerr != nil {
			return Outcome{}, kerr
		}
		d.CfgVersion = nv
		e.lg.Debug("inform: blocked_sta drift", "mac", d.MAC)
	}
	if st.pendingSHAPresent && st.pendingSHA != "" {
		// A changed envelope is a new delivery operation. For the unchanged
		// operation, rate-limit retries before the switch below; importantly,
		// this does not clear pending or treat cfgversion equality as success.
		// A blocked_sta change must bypass the rate limit: an exhausted WLAN
		// delivery retry would otherwise hold the blocked set hostage — the
		// pending operation is re-offered alongside the new content anyway,
		// since assignedKeyFlow emits system_cfg unconditionally.
		// An operator cfgversion mint (radio-intent / LED-override saves —
		// the §6.2 "CONFIG changed" operator-save trigger) gets the SAME
		// escape: applyProvisioning records the cfgversion the pending
		// operation was last offered with (wlan_cfg_offered_cfgversion), and
		// a record whose cfgversion has moved past that offer carries
		// operator content this gate must not hold hostage while the
		// envelope is unchanged. The rate limit still holds the UNCHANGED
		// case (no mint since the last offer), and records whose pending
		// predates the offered bookkeeping keep the hold-at-gate behavior.
		operatorMint := st.offeredPresent && d.CfgVersion != st.offeredCfgversion
		if !blockedDrift && !operatorMint && st.pendingSHA == plan.DriftHash && !st.retryDue(now) {
			return e.noopFor(d, now, req.PrevNoopTarget, KindNoopPendingWLAN), nil
		}
		wlanDrift = true
	}

	onAssigned := d.XAuthkey != "" && strings.EqualFold(d.XAuthkey, req.UsedKey)
	switch {
	// The factory/default key is still (or again) in use: adopt. Rotate the
	// per-device key AND the config version, respond with a fresh adoption
	// push in the same key the device just sent (classic: send non-default
	// authkey while the device still holds the default — §8 of the doc).
	// FID-1: the shared default key is only ACCEPTED for a device that has
	// not yet authenticated its per-device key — our StatePending stands in
	// for the jar's UNKNOWN(0) pre-adoption record and StateAdopting for the
	// jar's ADOPTING(7) two-phase default-key window (gate ôØ0000, devmgr
	// §11006-11020). An adopted (or lost) device claiming the default key is
	// REJECTED (devmgr "used default key in X state, reject it!" returns the
	// ÖoÓ000 marker → servlet 404). No INFORM_ERROR(9) re-adopt state exists
	// in the store yet — flagged for the store lane.
	case req.UsedKey == defaultKeyHex:
		prev := d.State
		if prev != store.StatePending && prev != store.StateAdopting {
			return Outcome{}, ErrDefaultKeyRejected
		}
		if err := e.rotateKeys(d); err != nil {
			return Outcome{}, err
		}
		// No baseline is seeded here (see the drift block above): the
		// post-adoption echo reaches the no-baseline self-heal below,
		// which forces exactly one full provisioning — the real-controller
		// sequence the 2026-09-16 session captured — and settle captures
		// the baseline only once that delivery is proven on the wire.
		e.lg.Debug("inform: adoption push (default key)", "mac", d.MAC, "prevState", prev)
		return e.adoptionPush(*d, req.UsedKey), nil

	// A non-default key that is neither the default nor our current
	// assignment: a stale or rogue x_authkey. FID-36 (jar §1348 rotation
	// pending path): do NOT rotate — RE-PUSH the existing per-device key in
	// the authkey= line; the device re-keys to the assignment it was given.
	case !onAssigned:
		e.lg.Debug("inform: adoption push (stale/rogue key, re-push existing assignment)", "mac", d.MAC)
		return e.adoptionPush(*d, req.UsedKey), nil

	// A WLAN change is a content change, not merely a version change.  In
	// particular, U7 firmware commonly echoes the cfgversion from the previous
	// mgmt_cfg on the first inform after an admin WLAN save.  Do not let that
	// echoed value enter the equality/noop branch: the response must contain the
	// newly rendered system_cfg in this inform.  A blocked_sta edit is the same
	// kind of content change (§6.2(d) delivers it only inside full
	// provisioning), so the arm is shared.
	case wlanDrift || blockedDrift:
		out, err := e.assignedKeyFlow(req.Context, d, now, wls, plan)
		if err != nil {
			return Outcome{}, err
		}
		e.lg.Debug("inform: content drift (wireless/blocked_sta), forcing full provisioning", "mac", d.MAC)
		return out, nil

	// Authenticated with our per-device key and the config applied → noop.
	case d.CfgVersion != "" && d.AppliedCfg == d.CfgVersion:
		// Self-heal for records without a drift baseline (e.g. adopted
		// before the hash was seeded at adoption time): mint a fresh
		// cfgversion so the NEXT inform mismatches and flows through
		// full provisioning, which captures the hash. Terminates: the
		// provisioning path always stores it.
		if st.sha == "" {
			nv, kerr := e.keyChars(16)
			if kerr != nil {
				return Outcome{}, kerr
			}
			d.CfgVersion = nv
			e.lg.Debug("inform: no envelope baseline, forcing provisioning", "mac", d.MAC)
			return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
		}
		if st.pendingSHAPresent {
			return e.noopFor(d, now, req.PrevNoopTarget, KindNoopPendingWLAN), nil
		}
		// §6.2(e) reconnect push: a client-disconnect event pending on a
		// connected device preempts the noop (the session store arms
		// store.SessionDisconnectEventExtraKey; this is the only §6.2
		// catalog row with no mint site, so NO cfgversion is minted). The
		// event is consumed one-shot whether or not the push fires — see
		// blockedStaReconnectPush. This runs AFTER the pending-WLAN gate
		// above: an outstanding WLAN delivery is an unfinished (d)
		// operation that outranks (e) (the jar's dispatcher order, §1316
		// before §1391), and BEFORE the not-running watchdog: the (e) push
		// is a real pending outcome; the miss counter re-arms on the next
		// inform.
		if out, fired := e.blockedStaReconnectPush(d); fired {
			d.State = store.StateAdopted
			return out, nil
		}
		// Settled-state regression (2026-09-18 F-row live round, A2
		// finding): a device can echo a matching cfgversion while running
		// something else — a rebooted device re-materializes factory config
		// yet still reports the provisioned stamp, and the settle
		// watchdog is one-shot. A PRESENT vap_table that disproves the
		// applied WLANs re-arms delivery the same way the self-heal
		// does: mint a fresh cfgversion so the NEXT inform mismatches
		// and flows through full provisioning, re-entering drift
		// settle. Absent/empty tables are unknown, not regression —
		// sparse heartbeats must never re-arm delivery.
		//
		// Two-consecutive-miss arming (2026-09-19 boot-race finding,
		// WLAN-ACCEPTANCE 6.8.2.15592 A2 re-run): the first post-boot
		// inform can carry a present, non-empty table whose radios are
		// still in bring-up — one not-running proof is the boot race,
		// not genuine factory regression, so a single miss no longer
		// fires. The controller-owned counter (wlan_cfg_not_running_misses)
		// records the first miss; the SECOND consecutive miss fires with
		// the same mechanics as before (mint → the next inform full
		// provisions) and resets the window so it can re-arm; a RUN
		// proof resets it; unknown informs (absent/empty table) leave it
		// untouched in both directions.
		// The evidence classification is computed ONCE (the watchdog arm
		// below reuses it): nothing between the switch and the block
		// mutates its inputs (the applied snapshot and vap_table — the
		// counters are writes), so the reuse is the same value the review
		// verified ad hoc on all reachable paths.
		ev := st.notRunningEvidence()
		switch ev {
		case nrMiss:
			if misses := st.recordNotRunningMiss(); misses < 2 {
				e.lg.Debug("inform: applied WLANs not running (miss 1 of 2, boot-race grace)", "mac", d.MAC)
				break
			}
			st.clearNotRunningMisses()
			nv, kerr := e.keyChars(16)
			if kerr != nil {
				return Outcome{}, kerr
			}
			d.CfgVersion = nv
			e.lg.Debug("inform: applied WLANs not running, forcing re-provisioning", "mac", d.MAC)
			return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
		case nrRun:
			st.clearNotRunningMisses()
		}
		// Devname-level materialization watchdog (2026-09-26 production
		// incident, 2.4 guest guest-net ath3): 6.8.2.15592 only
		// MATERIALIZES new vap interfaces at boot — a live push
		// reconfigures existing ones only, so the 4th 2.4 vap (ath3) sat
		// configured-not-running forever while hostapd crash-looped. The
		// SSID watchdog above cannot see this shape: a band=both WLAN
		// reads RUN on ONE radio (SSID present in vap_table), so the SSID
		// view is nrRun and the missing devname is invisible. This block
		// runs ONLY on the SSID view's nrRun arm (the invisible case) and
		// only when NO delivery can be in flight: for a REAL pending sha
		// (the non-empty string applyProvisioning stores) this branch is
		// unreachable — the flow either answered noop-pending-wlan above
		// when the unchanged-envelope retry was not yet due, or flagged
		// wlanDrift and full-provisioned below — and the pendingSHAPresent
		// precede-check here only catches a MALFORMED pending row (key
		// present, "": a shape applyProvisioning never writes) to keep
		// delivery out of an armed watchdog. A plan vap whose devname is
		// absent (or not RUN) from THIS inform's vap_table is the real
		// gap. Monitored with the same two-consecutive-miss boot-race
		// grace: the first miss can be the post-reboot bring-up race on
		// the freshly materialized set. Evidence semantics are
		// wireless.MissingVaps — absent/empty tables are UNKNOWN and leave
		// the window untouched, exactly like notRunningEvidence above.
		if ev == nrRun {
			missing := wireless.MissingVaps(plan.Vaps, st.extra["vap_table"])
			if len(missing) == 0 {
				// RUN proof at the devname level: everything planned is
				// live on the wire. Reset the window AND retire the
				// one-shot arm marker (fresh cfgversion ⇒ a fresh budget
				// is the settle() path's job; same-version RUN proof
				// means the materialization gap is GONE and the marker's
				// purpose is served).
				st.clearVapNotRunningMisses()
				delete(d.Extra, "wlan_cfg_materialization_reboot")
			} else {
				alreadyPending := truthy(d.Extra[FlagRebootOnConnect])
				armedCv, wasArmed := materializationRebootArmedFor(d.Extra)
				switch {
				case alreadyPending:
					// Unreachable today: armedLifecycle consumes a truthy
					// flag at the top of BOTH decide lanes and returns
					// before this decision ever runs its bodies. Kept as
					// a DEFENSIVE guard against a future non-returning
					// writer of the flag — without it this default arm
					// would stack the miss counter and mis-stamp the
					// materialization marker OVER an unrelated pending
					// reboot, suppressing a future genuine arm for the
					// same cfgversion (a marker standing for the current
					// config is the watchdog's own do-not-repeat rule).
				case wasArmed && armedCv == d.CfgVersion:
					// The reboot was already delivered for THIS config
					// and the devname is STILL missing: a devname the
					// firmware will not materialize for this record
					// (the capacity case). The watchdog never re-arms
					// while the marker stands for the same cfgversion —
					// a marker only retires on a NEW config settling
					// (st.settle deletes a stale-cfgversion one) or on a
					// RUN proof (which, for a recovery→regression under
					// the SAME cfgversion, deliberately re-arms: each
					// arm is separated by a delivered reboot and a
					// genuine proof) — and the view surfaces
					// vaps_not_running while the gap lasts.
					// The counter clear here is defensive idempotent
					// symmetry, not state repair: no reachable record
					// carries a counter>0 alongside a same-cfgversion
					// marker (the arm path clears the counter in the
					// same decision it stamps, and the reboot emission
					// deletes the counter outright); re-running this
					// branch stays a no-op.
					st.clearVapNotRunningMisses()
				default:
					if misses := st.recordVapNotRunningMiss(); misses < 2 {
						e.lg.Debug("inform: planned vap not running (miss 1 of 2, boot-race grace)", "mac", d.MAC, "vaps", missing)
						// Fall through to the connected-noop flow below,
						// byte-identical to miss#1 handling in the SSID
						// watchdog (no early return).
					} else {
						st.clearVapNotRunningMisses()
						// §6.5 reboot arm — the jar-verbatim one-shot
						// flag (adminOwnedKeys carries it through the
						// adapter's wholesale Extra assignment; the
						// armedLifecycle fired on the NEXT decoded
						// inform answers with the §6.5 response, docs/
						// PROTOCOL-mgmt.md §6.5). The marker records the
						// arm's cfgversion — the watchdog never re-arms
						// while it stands for the SAME cfgversion (the
						// one-shot guard above), and a marker only
						// retires via a new config settling (st.settle
						// deletes a stale-cfgversion one) or a RUN proof.
						d.Extra[FlagRebootOnConnect] = true
						setMaterializationRebootArmed(d.Extra, d.CfgVersion)
						// Deliberate divergence — this is the adoption
						// package's ONLY lg.Info call (even the §6.5
						// reboot emission logs Debug, as does the SSID
						// watchdog above): at the default log level this
						// arm is the only operator-visible record of why
						// a device will spontaneously reboot — the
						// 2026-09-26 incident was silent.
						e.lg.Info("inform: planned vaps not running after settle, arming materialization reboot", "mac", d.MAC, "vaps", missing)
						return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
					}
				}
			}
		}
		d.State = store.StateAdopted
		e.lg.Debug("inform: connected noop", "mac", d.MAC, "cfg", d.CfgVersion)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil

	default:
		out, err := e.assignedKeyFlow(req.Context, d, now, wls, plan)
		if err != nil {
			return Outcome{}, err
		}
		e.lg.Debug("inform: full provisioning", "mac", d.MAC, "ours", d.CfgVersion, "device", d.AppliedCfg)
		return out, nil
	}
}

// decidePlain is the PLAINTEXT inform state machine. It NEVER rotates
// keys (deviation from the classic debug-build rotation path — we treat
// plaintext claims as assertions, not authenticators):
//
//   - XAuthkey unset  → noop; the record stays StatePending (plaintext can
//     never initiate adoption — rotating/adopting from an unauthenticated
//     channel would let any network observer seed a device's mgmt_cfg with
//     an empty cfgversion/authkey);
//   - claim ≠ XAuthkey → mgmt_cfg-only push carrying the CURRENT XAuthkey
//     via the authkey= line (re-key me), no rotation, no cfgversion regen;
//   - claim == XAuthkey → the assigned-key flow, which ALWAYS emits full
//     provisioning (the plaintext lane runs no drift-settle and has no
//     cfgversion-match noop — the encrypted lane's connected-noop branch
//     is unreachable here).
//
// It NEVER rotates keys, NEVER initiates adoption, has no default-key
// rejection, and performs no drift settle — it shares noopFor,
// assignedKeyFlow and the adoption push with the encrypted lane.
func (e *Engine) decidePlain(req Request, wls []wireless.Wlan, plan wireless.ProvisioningPlan, d *store.Device) (Outcome, error) {
	now := req.Now
	rtype, _ := req.Body["_type"].(string)
	if informTypeGentleNoop(rtype) {
		e.lg.Debug("inform-plain: gentle noop for _type", "mac", d.MAC, "type", rtype)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
	}

	// Admin-armed remote commands fire on this lane too (same record,
	// same admin intent; the outcome serialization is shared).
	if out, armed := e.armedLifecycle(d); armed {
		return out, nil
	}

	switch {
	case d.XAuthkey == "":
		e.lg.Debug("inform-plain: noop without assignment", "mac", d.MAC)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil

	case !strings.EqualFold(d.XAuthkey, req.UsedKey):
		e.lg.Debug("inform-plain: re-send current assignment", "mac", d.MAC)
		return e.adoptionPush(*d, req.UsedKey), nil

	default:
		return e.assignedKeyFlow(req.Context, d, now, wls, plan)
	}
}

// assignedKeyFlow is the shared tail of the assigned-key (x_authkey-held)
// path: it emits FULL PROVISIONING — fresh cfgversion when unset, adopting
// state, ssh password-hash cache, and capture of the emitted wireless
// envelope hash (the next identical-envelope inform after apply must noop).
// It is reached from the encrypted lane both on plain cfgversion mismatch
// (the default arm) AND at cfgversion match when the wireless envelope
// drifted (the wlanDrift arm — a WLAN change is a content change, so the
// echoed cfgversion must never enter the equality/noop branch), and from
// the plaintext lane on every claim match.
// It is the single emission point for system_cfg + drift hash + delivery
// bookkeeping shared by BOTH transports (the encrypted decideEncrypted and
// the plaintext decidePlain). mgmt_cfg-only paths (re-key pushes, adoption
// pushes, noop) never reach this function.
// plan is the decision's provisioning plan: the drift hash captured here and
// the delivery placements come from the same value the renderer emitted the
// rows from — no re-derivation inside this tail.
func (e *Engine) assignedKeyFlow(ctx context.Context, d *store.Device, now time.Time, wls []wireless.Wlan, plan wireless.ProvisioningPlan) (Outcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if d.CfgVersion == "" {
		nv, err := e.keyChars(16)
		if err != nil {
			return Outcome{}, err
		}
		d.CfgVersion = nv
	}
	d.State = store.StateAdopting
	sys, deltas, serr := e.systemCfg(ctx, *d, wls, plan)
	if serr != nil {
		// FID-23: provisioning content that cannot be rendered (e.g. an
		// unusable/empty SSH password hash) fails the whole push, like the
		// classic L.ÔO0000 crypt call — it must never silently emit a
		// degraded config. Nothing was persisted (the store cycle aborts).
		return Outcome{}, serr
	}
	cur := plan.DriftHash
	// Do not mark the configuration applied merely because system_cfg was
	// sent.  Keep the desired snapshot as delivery evidence for the next
	// device inform (including deletions, where absence must be observed).
	placements := plan.Placements
	st := loadWlanCfgState(d.Extra)
	st.applyProvisioning(cur, now.Unix(), wls, placements, d.CfgVersion)
	// blocked_sta rides every full provisioning (§6.2(d)): render the §4
	// wire string from the admin-owned set, carry it in the outcome, and
	// stamp the delivery baseline so the next inform can tell confirmed
	// content from drift. Baseline capture at EMISSION (not apply) is
	// correct here: blocked content has no observable on-device state to
	// settle against — the cfgversion echo the equality path already
	// tracks is the only confirmation there is — and stamping keeps an
	// unconfirmed-but-unchanged set from re-MINTING on every inform while
	// the plain cfgversion mismatch keeps re-OFFERING it until applied.
	blocked := blockedStaWire(*d)
	stampBlockedSta(d, blocked)
	// A pending client-disconnect event is satisfied by this emission:
	// full provisioning carries blocked_sta (§6.2(d)), so the event must
	// not survive it to fire a redundant §6.2(e) push after settle.
	consumeSessionDisconnectEvent(d)
	return Outcome{
		Kind:             KindSetparam,
		FullProvision:    true,
		CfgVersion:       d.CfgVersion,
		SystemCfg:        sys,
		BlockedSta:       blocked,
		MgmtCfg:          e.BuildMgmtCfg(*d, d.XAuthkey),
		CredentialDeltas: deltas,
	}, nil
}

// adoptionPush is the §6.2 a/b/c/f setparam variant: mgmt_cfg ONLY,
// with a freshly stored cfgversion carried inside the mgmt_cfg blob. The
// response is encrypted with the key the device just used, so a pending
// authkey= line forwards the rotated key.
func (e *Engine) adoptionPush(d store.Device, usedKey string) Outcome {
	return Outcome{
		Kind:    KindSetparam,
		MgmtCfg: e.BuildMgmtCfg(d, usedKey),
	}
}

// rotateKeys assigns a fresh per-device key and config version to the working
// device and moves it back into the adopting state. An error here
// (crypto/rand failure, practically impossible) aborts the inform — the
// caller must never persist half-rotated records.
func (e *Engine) rotateKeys(d *store.Device) error {
	xk, err := e.keyChars(32)
	if err != nil {
		return err
	}
	cv, err := e.keyChars(16)
	if err != nil {
		return err
	}
	d.XAuthkey = xk
	d.CfgVersion = cv
	d.Authkeys = addKey(d.Authkeys, xk)
	// Keep only the NEWEST TWO assigned keys: the device might still be
	// finishing one rotation cycle when the next starts, so its previous
	// key must keep decrypting, but everything older is useless ballast.
	// The factory default key is never stored in this list — the adapter's
	// keyCandidates appends it at decrypt time — so factory-reset recovery
	// is unaffected.
	if len(d.Authkeys) > 2 {
		d.Authkeys = d.Authkeys[len(d.Authkeys)-2:]
	}
	d.State = store.StateAdopting
	return nil
}

// addKey appends a lowercase key to the deduped authkey list.
func addKey(keys []string, key string) []string {
	key = strings.ToLower(key)
	for _, k := range keys {
		if strings.ToLower(k) == key {
			return keys
		}
	}
	return append(keys, key)
}

// noopFor implements devmgr's ordinary UAP noop scheduling. now is the
// timestamp of the inform currently being handled, not a poller snapshot.
// prevTarget is the controller-owned steady-state noop target for the MAC
// (0 when none is tracked); the adapter persists out.NewNoopTarget only
// when out.PersistNoopTarget is set (the cap-fallback branch never
// persists).
func (e *Engine) noopFor(d *store.Device, now time.Time, prevTarget int64, kind Kind) Outcome {
	out := Outcome{Kind: kind}
	interval := int64(10)
	if !isUbios(d.Model) {
		if truthy(d.Extra["watching"]) {
			interval = 5
		} else {
			const capSeconds int64 = 90
			r := e.random()
			if r < 0 {
				r = 0
			} else if r >= 1 {
				r = math.Nextafter(1, 0)
			}
			previous := prevTarget
			if previous == 0 {
				previous = now.Unix()
			}
			target := maxInt64(previous+5, now.Unix()+10) + int64(math.Floor(r*5))
			candidate := target - now.Unix()
			if candidate < capSeconds {
				interval = candidate
				out.NewNoopTarget = target
				out.PersistNoopTarget = true
			} else {
				interval = int64(math.Floor(float64(capSeconds) * (1 - 0.7*r)))
			}
		}
	}
	out.Interval = interval
	return out
}

func isUbios(model string) bool {
	m := strings.ToUpper(model)
	return strings.Contains(m, "UDM") || strings.Contains(m, "UXG")
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != "" && x != "false" && x != "0"
	case float64:
		return x != 0
	default:
		return v != nil
	}
}

// ---- working clone + delta computation -------------------------------------

// cloneDevice deep-copies a device record so the engine can work on it
// without mutating the adapter's snapshot (every field the engine can change
// is carried back as an explicit delta in the Outcome). Extra is always
// materialized non-nil: the adapter's absorbInform guarantees a non-nil map
// before the engine runs, and engine writes must never panic on one.
func cloneDevice(d store.Device) store.Device {
	out := d
	out.Authkeys = append([]string(nil), d.Authkeys...)
	out.Extra = cloneExtra(d.Extra)
	if out.Extra == nil {
		out.Extra = store.JSONMap{}
	}
	if d.LastUps != nil {
		out.LastUps = cloneExtra(d.LastUps)
	}
	return out
}

// cloneExtra deep-copies a JSON map (maps, []any may nest arbitrarily).
func cloneExtra(m store.JSONMap) store.JSONMap {
	if m == nil {
		return nil
	}
	out := make(store.JSONMap, len(m))
	for k, v := range m {
		out[k] = cloneValue(v)
	}
	return out
}

func cloneValue(v any) any {
	switch t := v.(type) {
	case store.JSONMap:
		out := make(store.JSONMap, len(t))
		for k, val := range t {
			out[k] = cloneValue(val)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = cloneValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = cloneValue(val)
		}
		return out
	default:
		return v // scalars are values in Go
	}
}

// deltas fills the Outcome's record-delta fields by comparing the engine's
// working clone against the request snapshot.
func (out *Outcome) deltas(snapshot, work *store.Device) {
	if work.State != snapshot.State {
		out.SetState, out.State = true, work.State
	}
	if work.XAuthkey != snapshot.XAuthkey {
		out.SetXAuthkey, out.XAuthkey = true, work.XAuthkey
	}
	if work.CfgVersion != snapshot.CfgVersion {
		out.SetCfgVersion, out.CfgVersion = true, work.CfgVersion
	}
	if work.AppliedCfg != snapshot.AppliedCfg {
		out.SetAppliedCfg, out.AppliedCfg = true, work.AppliedCfg
	}
	if !equalStrings(work.Authkeys, snapshot.Authkeys) {
		out.SetAuthkeys, out.Authkeys = true, work.Authkeys
	}
	out.Extra = work.Extra
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

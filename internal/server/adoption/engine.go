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

// WlanMaxAttempts is the WLAN delivery attempt budget, owned by
// wireless.DeliveryState and aliased here for the engine's tests and the
// server lifecycle tests.
const WlanMaxAttempts = wireless.WlanMaxAttempts

// ErrDefaultKeyRejected (FID-1): an adopted device must never re-authenticate
// with the factory key (devmgr "used default key in X state, reject it" →
// Object.ÖoÓ000 → 404). The transport adapter maps this onto the HTTP 404.
var ErrDefaultKeyRejected = errors.New("default key used by an adopted device")

// informKnownTypes labels the non-empty _type values the state machine
// processes specially. The empty _type is the main status inform and must
// reach the dispatcher; only unknown non-empty types take the gentle-noop
// path (docs/PROTOCOL-mgmt.md §6.2).
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
	// SetKeyConfirmed carries the key-confirmation marker delta: the
	// Decide wrapper stamps the working clone KeyConfirmed=true when the
	// inform authenticated with a per-device key (Authkeys never holds the
	// factory key), the armed setdefault demotion clears it (true→false)
	// with XAuthkey/Authkeys. Emits only on change, both directions.
	SetKeyConfirmed bool
	KeyConfirmed    bool
	Extra           store.JSONMap

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
	// Key-confirmation write (the persisted partner of the
	// decideEncrypted gate): an inform authenticated with a per-device
	// key — UsedKey equal to ANY Authkeys entry, case-insensitively
	// (Authkeys never holds the factory default key, docs/PROTOCOL.md
	// §6, so the gate's factory-key informs can never stamp this) proves
	// the device runs controller-issued key material. The stamp rides
	// the engine's deltas: deltas() emits the record delta only on
	// change and the armed setdefault demotion clears it, so the wire
	// effect is one marker field kept truthful by the same RMW cycle.
	// Compared against the WORKING clone's Authkeys so a demotion in
	// THIS decision (arm, then keys cleared) cannot re-confirm the
	// record it just demoted.
	for _, k := range work.Authkeys {
		if strings.EqualFold(k, req.UsedKey) {
			work.KeyConfirmed = true
			break
		}
	}
	// Stamp the record deltas the branch performed onto the working clone.
	out.deltas(&snapshot, &work)
	return out, nil
}

// armedLifecycle handles one-shot admin-armed commands on the next status
// inform. It runs after the gentle-noop check and before key/drift decisions;
// encrypted informs must also pass the key-confirmation gate, and plaintext
// informs must match the assigned-key claim. Setdefault outranks reboot and
// clears stale reboot/task state because factory reset supersedes both.
// Reboot outranks a stored task without consuming it, so the next inform can
// replay the task. A task is last and is consumed only when emitted. None of
// these command responses mints a cfgversion; normal decision-making resumes
// on the following inform (docs/PROTOCOL-mgmt.md §§6.3, 6.5, 6.6).
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
		// The confirmation marker dies with the key assignment: the
		// post-reset re-inform arrives on the factory default key and
		// must re-enter the adoption flow through the pre-key window
		// (the key-confirmation gate at the top of decideEncrypted
		// rejects factory-key informs for confirmed records — recovery
		// preserved ONLY if the marker is cleared here too).
		d.KeyConfirmed = false
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
		// A reboot starts a new observation window. Do not let a pre-reboot
		// miss combine with the first post-boot bring-up miss and trigger a
		// false re-provision; setdefault already clears these rows in its sweep.
		wireless.ClearWatchdogCounters(d.Extra)
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

	// Key-confirmation gate: the shared factory default
	// key is accepted ONLY for a device that has not yet authenticated
	// its per-device key — StatePending (the pre-adoption record,
	// devmgr UNKNOWN(0)) or a keyed StateAdopting record whose marker is
	// unset (the documented mid-adoption double-rotation window,
	// docs/PROTOCOL.md §3 step 4, where the device has not applied the
	// pushed key yet → rotate then re-push). Once an inform was
	// authenticated with a per-device key the Decide wrapper stamps the
	// persisted KeyConfirmed marker, and a factory-key inform is then
	// rejected ahead of EVERYTHING below — the gentle noop, the armed
	// lifecycle (§6.6 setdefault included: a confirmed record's armed
	// flag cannot be fired on an unauthenticated factory-key claim) and
	// the drift/key machinery. Adopted and lost records keep the classic
	// state rejection (FID-1, devmgr "used default key in X state, reject
	// it!" → Object.ÖoÓ000 → 404); the demotion's marker clear keeps the
	// factory-reset recovery (armedLifecycle) admissible again.
	if strings.EqualFold(req.UsedKey, defaultKeyHex) &&
		d.State != store.StatePending &&
		(d.State != store.StateAdopting || d.KeyConfirmed) {
		return Outcome{}, ErrDefaultKeyRejected
	}

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

	// Compare the canonical WLAN envelope with the last confirmed baseline
	// before cfgversion drift handling. A mismatch mints a version and forces
	// full provisioning. Only Settle captures the baseline, after a later
	// inform proves the offered config is running; adoption must not seed it
	// or a fresh device could compare its intent against itself and noop.
	// A system_cfg transmission is only an offer.  Its hash remains pending
	// until a later inform proves the VAPs are actually running.
	st := wireless.LoadDeliveryState(d.Extra)
	// The record's CURRENT cfgversion rides settle for the materialization
	// marker's one-shot budget (see settle's doc): the record's desired
	// version is read BEFORE any mint this decision might make (an operator
	// or drift mint below concerns the NEXT operation, not the config the
	// pending bookkeeping was written under).
	st.Settle(d.CfgVersion)
	wlanDrift := false
	if st.Baseline() != "" {
		if cur := plan.DriftHash; cur != st.Baseline() {
			wlanDrift = true
			// Mint only for a new pending envelope. Keep the version stable
			// for retries of the same operation so the retry budget can bound
			// delivery and an echoed offer can reach the pending-noop branch.
			if !st.PendingPresent() || st.PendingHash() != cur {
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
	// An absent baseline plus an empty set is steady state, not drift. Capture
	// this baseline when blocked_sta content is emitted; unlike WLAN delivery,
	// it has no runtime table to confirm, so cfgversion echo is the available
	// completion signal.
	if _, blockedChanged := blockedStaDrift(*d); blockedChanged {
		blockedDrift = true
		nv, kerr := e.keyChars(16)
		if kerr != nil {
			return Outcome{}, kerr
		}
		d.CfgVersion = nv
		e.lg.Debug("inform: blocked_sta drift", "mac", d.MAC)
	}
	if st.PendingPresent() && st.PendingHash() != "" {
		// A changed envelope is a new delivery operation. For the unchanged
		// operation, rate-limit retries before the switch below; importantly,
		// this does not clear pending or treat cfgversion equality as success.
		// A blocked_sta change must bypass the rate limit: an exhausted WLAN
		// delivery retry would otherwise hold the blocked set hostage — the
		// pending operation is re-offered alongside the new content anyway,
		// since assignedKeyFlow emits system_cfg unconditionally.
		// An operator cfgversion mint (radio-intent / LED-override saves —
		// the §6.2 "CONFIG changed" operator-save trigger) gets the SAME
		// escape: Offer records the cfgversion the pending
		// operation was last offered with (wlan_cfg_offered_cfgversion), and
		// a record whose cfgversion has moved past that offer carries
		// operator content this gate must not hold hostage while the
		// envelope is unchanged. The rate limit still holds the UNCHANGED
		// case (no mint since the last offer), and records whose pending
		// predates the offered bookkeeping keep the hold-at-gate behavior.
		offered, offeredPresent := st.OfferedCfgversion()
		operatorMint := offeredPresent && d.CfgVersion != offered
		if !blockedDrift && !operatorMint && st.PendingHash() == plan.DriftHash && !st.RetryDue(now) {
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
	// not yet AUTHENTICATED its per-device key — the pre-verified window
	// (StatePending, and keyed-adopting records without the
	// KeyConfirmed marker) is enforced by the gate at the top of this
	// function; every other shape was rejected before the gentle-noop and
	// armedLifecycle arms, so reaching this switch arm IS admission.
	case req.UsedKey == defaultKeyHex:
		prev := d.State
		if err := e.rotateKeys(d); err != nil {
			return Outcome{}, err
		}
		// Leave the WLAN baseline unset. The no-baseline self-heal forces
		// one full provisioning, and settle records the baseline only after
		// the device proves that delivery is running.
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
		if st.Baseline() == "" {
			nv, kerr := e.keyChars(16)
			if kerr != nil {
				return Outcome{}, kerr
			}
			d.CfgVersion = nv
			e.lg.Debug("inform: no envelope baseline, forcing provisioning", "mac", d.MAC)
			return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
		}
		if st.PendingPresent() {
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
		// cfgversion equality alone does not prove the device applied WLANs.
		// A known table that disproves the applied set re-arms provisioning
		// after two consecutive misses; one miss may be radio bring-up. A RUN
		// proof resets the counter, while absent or empty tables are unknown
		// and leave it unchanged. The devname watchdog below reuses this
		// classification.
		ev := st.NotRunningEvidence()
		switch ev {
		case wireless.NotRunningMiss:
			if misses := st.RecordNotRunningMiss(); misses < 2 {
				e.lg.Debug("inform: applied WLANs not running (miss 1 of 2, boot-race grace)", "mac", d.MAC)
				break
			}
			st.ClearNotRunningMisses()
			nv, kerr := e.keyChars(16)
			if kerr != nil {
				return Outcome{}, kerr
			}
			d.CfgVersion = nv
			e.lg.Debug("inform: applied WLANs not running, forcing re-provisioning", "mac", d.MAC)
			return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
		case wireless.NotRunningRun:
			st.ClearNotRunningMisses()
		}
		// SSID presence can hide a missing radio-specific VAP: a band=both
		// WLAN may be RUN on one radio while another planned devname is absent.
		// Check planned devnames only when the SSID set is proven RUN and no
		// delivery is pending. Two consecutive misses allow for boot-time
		// radio bring-up; absent or empty tables remain unknown.
		if ev == wireless.NotRunningRun {
			missing := wireless.MissingVaps(plan.Vaps, d.Extra["vap_table"])
			if len(missing) == 0 {
				// RUN proof at the devname level: everything planned is
				// live on the wire. Reset the window AND retire the
				// one-shot arm marker (fresh cfgversion ⇒ a fresh budget
				// is the settle() path's job; same-version RUN proof
				// means the materialization gap is GONE and the marker's
				// purpose is served).
				st.ClearVapNotRunningMisses()
				wireless.ClearMaterializationReboot(d.Extra)
			} else {
				alreadyPending := truthy(d.Extra[FlagRebootOnConnect])
				armedCv, wasArmed := wireless.MaterializationRebootArmedFor(d.Extra)
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
					// (Settle deletes a stale-cfgversion one) or on a
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
					st.ClearVapNotRunningMisses()
				default:
					if misses := st.RecordVapNotRunningMiss(); misses < 2 {
						e.lg.Debug("inform: planned vap not running (miss 1 of 2, boot-race grace)", "mac", d.MAC, "vaps", missing)
						// Fall through to the connected-noop flow below,
						// byte-identical to miss#1 handling in the SSID
						// watchdog (no early return).
					} else {
						st.ClearVapNotRunningMisses()
						// §6.5 reboot arm — the jar-verbatim one-shot
						// flag (adminOwnedKeys carries it through the
						// adapter's wholesale Extra assignment; the
						// armedLifecycle fired on the NEXT decoded
						// inform answers with the §6.5 response, docs/
						// PROTOCOL-mgmt.md §6.5). The marker records the
						// arm's cfgversion — the watchdog never re-arms
						// while it stands for the SAME cfgversion (the
						// one-shot guard above), and a marker only
						// retires via a new config settling (DeliveryState.Settle
						// deletes a stale-cfgversion one) or a RUN proof.
						d.Extra[FlagRebootOnConnect] = true
						wireless.SetMaterializationRebootArmed(d.Extra, d.CfgVersion)
						// Keep the arm at Info level: operators need to know why
						// the device will reboot, even at the default log level.
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

// decidePlain treats plaintext key claims as assertions, not authenticators.
// It never initiates adoption or rotates keys. An unset assignment noops; a
// mismatched claim gets an mgmt_cfg-only resend with no authkey row; a matching
// claim gets full provisioning. Armed commands also require a matching claim.
// This lane does not perform drift settling or cfgversion-match noops.
func (e *Engine) decidePlain(req Request, wls []wireless.Wlan, plan wireless.ProvisioningPlan, d *store.Device) (Outcome, error) {
	now := req.Now
	rtype, _ := req.Body["_type"].(string)
	if informTypeGentleNoop(rtype) {
		e.lg.Debug("inform-plain: gentle noop for _type", "mac", d.MAC, "type", rtype)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
	}

	// Admin-armed remote commands fire on this lane too (same record,
	// same admin intent; the outcome serialization is shared) — but only
	// behind the claim check (the C3 ordering fix): an inform that did
	// not authenticate as the record's assigned key carries no admin
	// result, gets no key echo, and consumes nothing.
	if d.XAuthkey != "" && strings.EqualFold(d.XAuthkey, req.UsedKey) {
		if out, armed := e.armedLifecycle(d); armed {
			return out, nil
		}
	}

	switch {
	case d.XAuthkey == "":
		e.lg.Debug("inform-plain: noop without assignment", "mac", d.MAC)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil

	case !strings.EqualFold(d.XAuthkey, req.UsedKey):
		e.lg.Debug("inform-plain: re-send current assignment", "mac", d.MAC)
		// The re-send carries the config rows WITHOUT the authkey= line:
		// pass d.XAuthkey (not the unverified claim) so BuildMgmtCfg's
		// used-key comparison always matches and omits the key.
		return e.adoptionPush(*d, d.XAuthkey), nil

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
	st := wireless.LoadDeliveryState(d.Extra)
	st.Offer(cur, now.Unix(), wls, placements, d.CfgVersion)
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
	if work.KeyConfirmed != snapshot.KeyConfirmed {
		out.SetKeyConfirmed, out.KeyConfirmed = true, work.KeyConfirmed
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

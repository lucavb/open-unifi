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
	"errors"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/lucabecker/open-unifi/internal/inform"
	"github.com/lucabecker/open-unifi/internal/store"
	"github.com/lucabecker/open-unifi/internal/wireless"
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

// ErrLiveWLANProvisioningUnsupported is returned for the exact U7PG2
// firmware lane whose system_cfg WLAN template has not been differentially
// verified against the official controller. The caller must not retry this as
// a successful delivery. (The transport adapter maps this onto its typed
// HTTP 501 error.)
var ErrLiveWLANProvisioningUnsupported = errors.New(
	"live WLAN provisioning is unsupported; awaiting an official-controller differential fixture")

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
	// Transport selects the encrypted or plaintext decision lane.
	Transport Transport
	// Device is the device snapshot the adapter absorbed the inform body
	// into (absorbInform stays adapter-side this checkpoint). The engine
	// works on an internal clone and never mutates it.
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
	// and BlockedSta. CfgVersion is also the record delta target value.
	FullProvision bool
	SystemCfg     string
	BlockedSta    string
	MgmtCfg       string

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
	SetAuthkeys   bool
	Authkeys      []string
	Extra         store.JSONMap
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

	// Wireless supplies the current WLAN envelope (nil ⇒ empty list).
	Wireless func() []wireless.Wlan

	// SystemCfg renders the system_cfg blob for the record. Package server
	// fills it with today's buildGeneratedSystemCfg code (UNCHANGED, still
	// living in package server this checkpoint). NOTE: the production
	// producer MUTATES the passed device clone's Extra — the credential
	// cache writes ssh_md5passwd/ssh_sha512passwd so repeated pushes are
	// byte-identical — and those writes ride back to the record inside
	// Outcome.Extra.
	SystemCfg func(store.Device, []wireless.Wlan) (string, error)

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
	wireless         func() []wireless.Wlan
	systemCfg        func(store.Device, []wireless.Wlan) (string, error)
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

// currentWireless resolves the configured source; nil source ⇒ empty list.
func (e *Engine) currentWireless() []wireless.Wlan {
	if e.wireless == nil {
		return nil
	}
	return e.wireless()
}

// Decide applies the adoption state machine (docs/PROTOCOL-mgmt.md §6.2) for
// one decoded inform and returns the response outcome plus record deltas.
//
//		setparam variants (exactly three shapes):
//		  - adoption push:  {"_type":"setparam","mgmt_cfg":...} + server_time
//		    (mgmt_cfg ONLY; fresh 16-hex cfgversion stored on the record first,
//		    carried in the mgmt_cfg "cfgversion=" line).
//		  - full provisioning: {"_type":"setparam","cfgversion":...,
//		    "system_cfg":...,"blocked_sta":...,"mgmt_cfg":...} + server_time.
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
	wls := e.currentWireless()
	var out Outcome
	var err error
	switch req.Transport {
	case TransportPlaintext:
		out, err = e.decidePlain(req, wls, &work)
	default:
		out, err = e.decideEncrypted(req, wls, &work)
	}
	if err != nil {
		return Outcome{}, err
	}
	// Stamp the record deltas the branch performed onto the working clone.
	out.deltas(&snapshot, &work)
	return out, nil
}

// decideEncrypted ports the former Server.advance for ENCRYPTED informs.
// usedKey is the lowercase hex key that authenticated the inform.
func (e *Engine) decideEncrypted(req Request, wls []wireless.Wlan, d *store.Device) (Outcome, error) {
	now := req.Now

	rtype, _ := req.Body["_type"].(string)
	if informTypeGentleNoop(rtype) {
		e.lg.Debug("inform: gentle noop for _type", "mac", d.MAC, "type", rtype)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
	}

	// Wireless envelope drift (FSM hash bump): BEFORE the cfgversion drift
	// check, compare sha256(canonical wireless envelope) with the stored
	// Extra["wlan_cfg_sha"]. A mismatch regenerates CfgVersion, which the
	// drift check then sees as unknown → full provisioning. The hash is
	// minted together with the cfgversion it belongs to: the adoption push
	// seeds it (rotateKeys case below) and full provisioning refreshes it
	// (assignedKeyFlow). Live finding (2026-09-16 acceptance session, U7PG2
	// on BZ.6.8.2): real firmware echoes the adoption mgmt_cfg's cfgversion
	// back on its first re-keyed inform — matching the jar's equal path
	// (voidsuper bytes 3287-3306 jump to 3549) — so full provisioning never
	// follows adoption on its own, and the drift baseline must NOT depend on
	// assignedKeyFlow having run first. The jar bumps device.cfgversion on
	// operator config saves ("CONFIG changed" log); this hash comparison is
	// open-unifi's equivalent trigger.
	// A system_cfg transmission is only an offer.  Its hash remains pending
	// until a later inform proves the VAPs are actually running.
	st := loadWlanCfgState(d.Extra)
	st.settle()
	wlanDrift := false
	if st.sha != "" {
		if cur := wireless.WlanListHash(wls); cur != st.sha {
			wlanDrift = true
			nv, kerr := e.keyChars(16)
			if kerr != nil {
				return Outcome{}, kerr
			}
			d.CfgVersion = nv
			e.lg.Debug("inform: wireless envelope drift", "mac", d.MAC)
		}
	}
	if st.pendingSHAPresent && st.pendingSHA != "" {
		// A changed envelope is a new delivery operation. For the unchanged
		// operation, rate-limit retries before the switch below; importantly,
		// this does not clear pending or treat cfgversion equality as success.
		if st.pendingSHA == wireless.WlanListHash(wls) && !st.retryDue(now) {
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
		// Seed the wireless-envelope baseline for the cfgversion just
		// minted (see the drift block above): the device would reach
		// connected-noop on its very next inform (mgmt_cfg echo) without
		// ever seeing system_cfg, and without a baseline a later WLAN
		// change could never be detected as drift. Envelope changes made
		// AFTER this push then mismatch the seed → full provisioning.
		if cur := wireless.WlanListHash(wls); cur != "" {
			d.Extra["wlan_cfg_sha"] = cur
		}
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
	// newly rendered system_cfg in this inform.
	case wlanDrift:
		out, err := e.assignedKeyFlow(d, now, wls)
		if err != nil {
			return Outcome{}, err
		}
		e.lg.Debug("inform: wireless envelope drift, forcing full provisioning", "mac", d.MAC)
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
		d.State = store.StateAdopted
		e.lg.Debug("inform: connected noop", "mac", d.MAC, "cfg", d.CfgVersion)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil

	default:
		out, err := e.assignedKeyFlow(d, now, wls)
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
func (e *Engine) decidePlain(req Request, wls []wireless.Wlan, d *store.Device) (Outcome, error) {
	now := req.Now
	rtype, _ := req.Body["_type"].(string)
	if informTypeGentleNoop(rtype) {
		e.lg.Debug("inform-plain: gentle noop for _type", "mac", d.MAC, "type", rtype)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil
	}

	switch {
	case d.XAuthkey == "":
		e.lg.Debug("inform-plain: noop without assignment", "mac", d.MAC)
		return e.noopFor(d, now, req.PrevNoopTarget, KindNoop), nil

	case !strings.EqualFold(d.XAuthkey, req.UsedKey):
		e.lg.Debug("inform-plain: re-send current assignment", "mac", d.MAC)
		return e.adoptionPush(*d, req.UsedKey), nil

	default:
		return e.assignedKeyFlow(d, now, wls)
	}
}

// RejectUnsupportedLiveWLAN gates the exact U7PG2 firmware lane whose
// system_cfg WLAN template has not been differentially verified against the
// official controller. wls is the decision's resolved WLAN envelope (the
// caller's single snapshot for this inform), not the live source.
func (e *Engine) RejectUnsupportedLiveWLAN(d store.Device, wls []wireless.Wlan) error {
	if d.Model != "U7PG2" || !fwMatches68215592(d.Firmware) {
		return nil
	}
	for _, w := range wls {
		if w.Name != "" || w.SSID != "" {
			return ErrLiveWLANProvisioningUnsupported
		}
	}
	return nil
}

// fwMatches68215592 reports whether s identifies the U7PG2 6.8.2 build
// 15592. The device-reported version may arrive as the short form
// ("6.8.2.15592") or the long form the docs capture shows
// ("BZ.qca956x_6.8.2+15592.260126.1358", docs/PROTOCOL.md:374-375) — both
// name the same build; nothing else legitimately contains either fragment.
// TODO(firmware): the exact wire form of the inform `version` field is still
// unpinned (the only capture sample in docs shows "6.6.55"); once the
// morning capture is fetched, pin the real string in the fixture
// (docs/PROTOCOL.md:396-398).
func fwMatches68215592(s string) bool {
	return strings.Contains(s, "6.8.2.15592") || strings.Contains(s, "6.8.2+15592")
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
// the plaintext decidePlain), so one call here gates both. mgmt_cfg-only
// paths (re-key pushes, adoption pushes, noop) never reach this function and
// are deliberately NOT gated — mgmt pushes keep working for gated devices.
func (e *Engine) assignedKeyFlow(d *store.Device, now time.Time, wls []wireless.Wlan) (Outcome, error) {
	// The unsupported-live-WLAN gate runs FIRST — before any record
	// mutation (State/CfgVersion must not change on a rejected push) and
	// before any emission.
	if err := e.RejectUnsupportedLiveWLAN(*d, wls); err != nil {
		return Outcome{}, err
	}
	if d.CfgVersion == "" {
		nv, err := e.keyChars(16)
		if err != nil {
			return Outcome{}, err
		}
		d.CfgVersion = nv
	}
	d.State = store.StateAdopting
	sys, serr := e.systemCfg(*d, wls)
	if serr != nil {
		// FID-23: provisioning content that cannot be rendered (e.g. an
		// unusable/empty SSH password hash) fails the whole push, like the
		// classic L.ÔO0000 crypt call — it must never silently emit a
		// degraded config. Nothing was persisted (the store cycle aborts).
		return Outcome{}, serr
	}
	// This is intentionally the only observability of the full config: the
	// diagnostic contains a digest and ordered names, never config values.
	if diagnostic, err := systemCfgDiagnostic(sys); err == nil {
		e.lg.Debug(diagnostic)
	} else {
		// Keep the debug path bounded even for malformed passthrough input; do
		// not log err because it includes a key name copied from the config.
		e.lg.Debug("system_cfg diagnostic unavailable", "reason", "duplicate-key")
	}
	cur := wireless.WlanListHash(wls)
	// Do not mark the configuration applied merely because system_cfg was
	// sent.  Keep the desired snapshot as delivery evidence for the next AP
	// inform (including deletions, where absence must be observed).
	placements := wlanPlacements(*d, wls)
	st := loadWlanCfgState(d.Extra)
	st.applyProvisioning(cur, now.Unix(), wls, placements)
	return Outcome{
		Kind:          KindSetparam,
		FullProvision: true,
		CfgVersion:    d.CfgVersion,
		SystemCfg:     sys,
		BlockedSta:    "",
		MgmtCfg:       e.BuildMgmtCfg(*d, d.XAuthkey),
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

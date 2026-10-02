package wireless

import (
	"encoding/json"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

// DeliveryState is the WLAN delivery state (CONTEXT.md): the typed handle
// over one device record's in-flight WLAN push — the drift baseline, the
// pending and last-applied WLANs with their placements, the attempt budget
// and the watchdog counters. Drift settle and Delivery retry are its
// operations. It is the ONLY reader and writer of the record keys declared
// in store (store.WlanCfg*Key); nothing outside this module touches them by
// name.
//
// It is bound to the record's Extra map: LoadDeliveryState reads with
// EXACTLY the type assertions the former readers used, and the mutating
// operations write back EXACT key names and EXACT value formats
// (string/int/int64, WLAN snapshots via EncodeStoredWlans), so the persisted
// bytes are identical to the pre-extraction behavior. The
// adoption engine stays the only DECIDER; this module exposes evidence and
// bookkeeping transitions and decides nothing about an inform.
//
// Trust classes are the store registry's call, not this module's: all keys
// are controller-owned EXCEPT the devname watchdog's counter and one-shot
// marker, which are admin-owned prev-or-delete rows (the blocked_sta_sha
// shape). TestDeliveryStateKeysSurviveHostileBody pins that a device body
// can neither forge nor clear any key this module writes, and cannot
// introduce the two admin-owned ones.
type DeliveryState struct {
	// extra is the map the state was loaded from (apply functions write here).
	extra store.JSONMap

	// sha is wlan_cfg_sha; "" = no drift baseline (absent or non-string).
	sha string

	// pendingSHA presence/type mirror the two readers: the connected-noop
	// branch tests PRESENCE only (any type, even ""), while the drift-check
	// and settle paths require the STRING-typed non-empty value.
	pendingSHAPresent  bool
	pendingSHAIsString bool
	pendingSHA         string

	// pendingWlans is wlan_cfg_pending_wlans decoded from its stored JSON
	// string (nil when absent/not a string/not valid JSON).
	pendingWlans []Wlan

	// oldWlans is wlan_cfg_pending_old_wlans decoded the same way.
	oldWlans []Wlan

	// appliedRaw is wlan_cfg_applied_wlans VERBATIM (copied to
	// wlan_cfg_pending_old_wlans on the next provisioning, whatever type it
	// carries).
	appliedPresent bool
	appliedRaw     any

	// placements is wlan_cfg_pending_placements decoded (empty when
	// absent/not a string/not valid JSON).
	placements map[string]int

	// attemptSHA/attempts/lastAttempt mirror the typed loads of today's
	// readers. (wlan_cfg_delivery_status is write-only in the engine: the
	// value is stamped pending/confirmed/exhausted; internal/app reads it.)
	attemptSHA  string
	attempts    int
	lastAttempt int64

	// notRunningMisses is wlan_cfg_not_running_misses: the consecutive
	// not-running-proof counter behind the settled-state watchdog's
	// two-consecutive-miss arming (the engine's connected-noop fire site;
	// see NotRunningEvidence). Controller-owned bookkeeping, so it
	// survives sparse heartbeats and device bodies cannot clobber it
	// (the store trust policy's controller-owned class). Absent = 0 =
	// window unarmed.
	notRunningMisses int

	// vapNotRunningMisses is wlan_cfg_vap_not_running_misses: the consecutive
	// miss counter behind the DEVNAME-level materialization watchdog (the
	// engine's connected-noop arming that fires FlagRebootOnConnect — an
	// SSID can read RUN somewhere while a planned band=both vap's devname
	// never materialized, which the SSID-level counter above cannot see).
	// ADMIN-owned prev-or-delete (the blocked_sta_sha shape) rather than
	// controller-owned: a device body must not be able to introduce or
	// forge the counter's window. Absent = 0 = window unarmed.
	vapNotRunningMisses int

	// offeredCfgversion is wlan_cfg_offered_cfgversion: the cfgversion the
	// pending delivery operation was last OFFERED with (written by
	// Offer at emission, cleared by Settle with the rest of the
	// pending bookkeeping). The engine's pending gate compares it with the
	// record's current cfgversion so an operator mint since the last offer
	// (radio-intent / LED-override saves — the same escape blocked-set
	// changes have) cannot be held hostage by an exhausted
	// unchanged-envelope retry. Controller-owned: a device body can
	// neither write nor clear it (the store trust policy's
	// controller-owned class), and the setdefault
	// demotion sweeps it with the rest of the family. Absent = the pending
	// predates this bookkeeping (the gate keeps its hold-at-gate behavior
	// for those records).
	offeredPresent    bool
	offeredCfgversion string
}

// LoadDeliveryState reads the controller-owned keys from extra with exactly
// the type assertions of the pre-extraction readers.
func LoadDeliveryState(extra store.JSONMap) *DeliveryState {
	st := &DeliveryState{extra: extra}
	if v, ok := extra[store.WlanCfgShaKey].(string); ok {
		st.sha = v
	}
	if _, ok := extra[store.WlanCfgPendingShaKey]; ok {
		st.pendingSHAPresent = true
	}
	if v, ok := extra[store.WlanCfgPendingShaKey].(string); ok {
		st.pendingSHAIsString = true
		st.pendingSHA = v
	}
	if raw, ok := extra[store.WlanCfgPendingWlansKey].(string); ok {
		if w, err := DecodeStoredWlans([]byte(raw)); err == nil {
			st.pendingWlans = w
		}
	}
	if raw, ok := extra[store.WlanCfgPendingOldWlansKey].(string); ok {
		if w, err := DecodeStoredWlans([]byte(raw)); err == nil {
			st.oldWlans = w
		}
	}
	if v, ok := extra[store.WlanCfgAppliedWlansKey]; ok {
		st.appliedPresent = true
		st.appliedRaw = v
	}
	if raw, ok := extra[store.WlanCfgPendingPlacementsKey].(string); ok {
		placements := map[string]int{}
		_ = json.Unmarshal([]byte(raw), &placements)
		st.placements = placements
	}
	if v, ok := extra[store.WlanCfgAttemptShaKey].(string); ok {
		st.attemptSHA = v
	}
	switch v := extra[store.WlanCfgAttemptsKey].(type) {
	case int:
		st.attempts = v
	case float64:
		st.attempts = int(v)
	}
	switch v := extra[store.WlanCfgLastAttemptKey].(type) {
	case int64:
		st.lastAttempt = v
	case float64:
		st.lastAttempt = int64(v)
	}
	switch v := extra[store.WlanCfgNotRunningMissesKey].(type) {
	case int:
		st.notRunningMisses = v
	case float64:
		st.notRunningMisses = int(v)
	}
	switch v := extra[store.WlanCfgVapNotRunningMissesKey].(type) {
	case int:
		st.vapNotRunningMisses = v
	case float64:
		st.vapNotRunningMisses = int(v)
	}
	if v, ok := extra[store.WlanCfgOfferedCfgversionKey].(string); ok {
		st.offeredPresent = true
		st.offeredCfgversion = v
	}
	return st
}

// settle promotes a sent WLAN hash only after the latest inform proves both
// sides of the change: every desired SSID has RUN VAPs and every previously
// enabled SSID being removed has disappeared. cfgversion equality is
// deliberately not evidence of WLAN application.
//
// cfgversion is the record's CURRENT cfgversion (the device-reported desired
// version), read for the materialization-marker lifecycle: a NEW config
// settling is a fresh boot-window budget for the devname-level watchdog, so
// the one-shot armed-reboot marker stamped for the PREVIOUS cfgversion is
// deleted here — the arming rule (engine.go) never re-arms while a marker
// for the same cfgversion stands, and a stale marker standing onto a new
// config would suppress a genuinely NEW materialization gap for free.
func (st *DeliveryState) Settle(cfgversion string) {
	if !st.pendingSHAIsString {
		return
	}
	ev := ReadVapEvidence(st.extra["vap_table"])
	if !ev.Present() {
		return
	}
	desired := st.pendingWlans
	old := st.oldWlans
	need := map[string]int{}
	placements := st.placements
	if placements == nil {
		placements = map[string]int{}
	}
	removed := map[string]bool{}
	for _, w := range old {
		if w.Enabled && !containsEnabled(desired, SSIDOf(w)) {
			removed[SSIDOf(w)] = true
		}
	}
	for _, w := range desired {
		if w.Enabled {
			need[SSIDOf(w)]++
		}
	}
	// The old snapshot is not available as a separate desired/current pair in
	// the record, so use the current source for positive proof and only require
	// old names to be absent when they are no longer desired.
	//
	// The wire keys and the RUN rule live in VapEvidence. The
	// placement construction side (the plan's Placements) keys on
	// radio_table `name` values; the device-side radio_name carries the same
	// strings.
	for _, r := range ev.Running() {
		ssid := r.SSID
		if ssid == "" {
			continue
		}
		if removed[ssid] {
			return
		}
		key := ssid + "\x00" + r.Radio
		if placements[key] > 0 {
			placements[key]--
			need[ssid]--
		} else if need[ssid] > 0 && len(placements) == 0 {
			need[ssid]--
		}
	}
	for _, w := range desired {
		if w.Enabled && need[SSIDOf(w)] > 0 {
			return
		}
	}
	// A deleted WLAN is settled only when the old VAP is absent. Positive
	// desired WLANs were checked above; no VAP table means unknown, not success.
	// A NEW config settling also retires the devname watchdog's armed marker
	// when it was stamped for the PREVIOUS cfgversion (fresh one-shot budget —
	// see the doc above); a marker for the current cfgversion stands.
	if armedCv, armed := MaterializationRebootArmedFor(st.extra); armed && armedCv != cfgversion {
		delete(st.extra, store.WlanCfgMaterializationRebootKey)
	}
	st.extra[store.WlanCfgShaKey] = st.pendingSHA
	st.extra[store.WlanCfgAppliedWlansKey] = st.extra[store.WlanCfgPendingWlansKey]
	st.extra[store.WlanCfgDeliveryStatusKey] = "confirmed"
	delete(st.extra, store.WlanCfgPendingShaKey)
	delete(st.extra, store.WlanCfgPendingWlansKey)
	delete(st.extra, store.WlanCfgPendingPlacementsKey)
	delete(st.extra, store.WlanCfgOfferedCfgversionKey)
	// Mirror the promotion in the typed view so the post-settle drift and
	// pending checks read the same values the former direct Extra reads did.
	st.sha = st.pendingSHA
	st.pendingSHAPresent = false
	st.pendingSHAIsString = false
	st.pendingSHA = ""
	st.pendingWlans = nil
	st.placements = nil
	st.offeredPresent = false
	st.offeredCfgversion = ""
}

// NotRunningClass is the settled-state watchdog's three-valued reading of
// ONE inform's vap_table evidence about the applied WLAN set.
type NotRunningClass int

const (
	// NotRunningUnknown: no proof either way — an absent or empty table (a sparse
	// heartbeat carries no vap_table), no applied snapshot, or an applied
	// set with nothing enabled. The arming policy neither increments nor
	// resets the counter on it.
	NotRunningUnknown NotRunningClass = iota
	// NotRunningRun: a present, non-empty table proves every enabled applied SSID
	// has a RUN VAP — the counter's reset condition.
	NotRunningRun
	// NotRunningMiss: a present, non-empty table positively disproves the applied
	// set — an enabled applied SSID has no RUN VAP — the counter's
	// increment condition.
	NotRunningMiss
)

// NotRunningEvidence classifies THIS inform's vap_table evidence about the
// applied WLAN set. Live evidence (2026-09-18 F-row round, A2): a rebooted
// device re-materializes factory config while still echoing the provisioned
// cfgversion — settle's one-shot watchdog must be backed by a continuous
// check or that regression noops forever; the 2026-09-19 A2 re-run then
// proved the complementary hazard (the boot race: the first post-boot
// table can show applied SSIDs not yet RUN while radios bring up), which
// the two-consecutive-miss arming policy over this classification absorbs.
//
// Evidence semantics mirror RuntimeInSync (this package): an absent or
// empty table is UNKNOWN, not regression. That neutrality is real, not a
// defensive default: vap_table is in NO trust class, so Absorb's wholesale
// Extra swap (store trustpolicy.go) REPLACES the record's table with the
// inform body's — a body that omits vap_table DROPS it, there is no "the
// record keeps the last observed one" to fall back on. A sparse heartbeat
// therefore genuinely carries no table at all (unknown is the exact truth),
// and a device that keeps reporting an empty table can never be misread as
// regression evidence. The applied snapshot is re-read from extra (not the
// typed load) because settle() may have promoted it in this same decision.
// SSID presence remains the proof bar, not per-radio placement — re-arming
// must not false-fire on a band detail.
func (st *DeliveryState) NotRunningEvidence() NotRunningClass {
	ev := ReadVapEvidence(st.extra["vap_table"])
	if !ev.Known() {
		return NotRunningUnknown
	}
	raw, _ := st.extra[store.WlanCfgAppliedWlansKey].(string)
	if raw == "" {
		return NotRunningUnknown
	}
	applied, err := DecodeStoredWlans([]byte(raw))
	if err != nil {
		return NotRunningUnknown
	}
	need := map[string]bool{}
	for _, w := range applied {
		if w.Enabled {
			need[SSIDOf(w)] = true
		}
	}
	if len(need) == 0 {
		return NotRunningUnknown
	}
	for _, r := range ev.Running() {
		delete(need, r.SSID)
	}
	if len(need) > 0 {
		return NotRunningMiss
	}
	return NotRunningRun
}

// appliedNotRunning reports whether THIS inform's vap_table positively
// disproves the confirmed WLAN set (the NotRunningMiss class of
// NotRunningEvidence): a present, non-empty table in which an enabled
// applied SSID has no RUN VAP. Proof semantics are unchanged from the
// one-shot watchdog; only the arming policy around them (the
// two-consecutive-miss counter, engine.go) is new.
func (st *DeliveryState) AppliedNotRunning() bool {
	return st.NotRunningEvidence() == NotRunningMiss
}

// recordNotRunningMiss increments the consecutive not-running-proof counter
// (wlan_cfg_not_running_misses) and returns the new count. The write lands
// in the same extra map every controller-owned bookkeeping write uses, so
// it persists through the adapter's wholesale Extra assignment and survives
// later sparse heartbeats via the store trust policy's controller-owned
// class.
func (st *DeliveryState) RecordNotRunningMiss() int {
	st.notRunningMisses++
	st.extra[store.WlanCfgNotRunningMissesKey] = st.notRunningMisses
	return st.notRunningMisses
}

// clearNotRunningMisses resets the consecutive not-running-proof counter so
// the two-consecutive-miss window can re-arm. Zero is stored as an absent
// key, mirroring settle's consumed-key cleanup (no idle noise in the
// persisted record).
func (st *DeliveryState) ClearNotRunningMisses() {
	st.notRunningMisses = 0
	delete(st.extra, store.WlanCfgNotRunningMissesKey)
}

// recordVapNotRunningMiss increments the consecutive devname-level miss
// counter (wlan_cfg_vap_not_running_misses) and returns the new count. The
// write-through shape mirrors recordNotRunningMiss exactly: the typed load
// value increments and lands in the same extra map every bookkeeping write
// uses, so it persists through the adapter's wholesale Extra assignment and
// survives later sparse heartbeats via the store trust policy's admin-owned
// prev-or-delete class.
func (st *DeliveryState) RecordVapNotRunningMiss() int {
	st.vapNotRunningMisses++
	st.extra[store.WlanCfgVapNotRunningMissesKey] = st.vapNotRunningMisses
	return st.vapNotRunningMisses
}

// clearVapNotRunningMisses resets the devname-level miss counter. Zero is
// stored as an absent key, mirroring clearNotRunningMisses (no idle noise in
// the persisted record).
func (st *DeliveryState) ClearVapNotRunningMisses() {
	st.vapNotRunningMisses = 0
	delete(st.extra, store.WlanCfgVapNotRunningMissesKey)
}

// SetMaterializationRebootArmed stamps the one-shot arm marker:
// the engine has armed FlagRebootOnConnect to materialize THIS
// config version's vaps (the devname watchdog miss#2 fire), and while the
// marker stands for the same cfgversion the arming must never repeat — the
// capacity case (a vap that can never materialize on this record) reads as
// a permanent, view-visible gap instead of a silent reboot loop. The row is
// an ADMIN-owned trust row (prev-or-delete — a device body can neither
// introduce nor forge the marker, the blocked_sta_sha shape), a JSONMap
// under the single key ("cfgversion"), the same stored-row shape as the
// §6.3 task (store.ArmCmdTask) — clone-serialized with the rest of the
// record's Extra.
func SetMaterializationRebootArmed(extra store.JSONMap, cfgversion string) {
	extra[store.WlanCfgMaterializationRebootKey] = store.JSONMap{"cfgversion": cfgversion}
}

// MaterializationRebootArmedFor reads the arm marker back: the cfgversion it
// was armed for and whether it stands at all. (json round-trips through a
// map[string]any, so both concrete map shapes are accepted — same tolerance
// ArmedCmdTask uses for the stored task row.)
func MaterializationRebootArmedFor(extra store.JSONMap) (string, bool) {
	var row map[string]any
	switch t := extra[store.WlanCfgMaterializationRebootKey].(type) {
	case store.JSONMap:
		row = t
	case map[string]any:
		row = t
	default:
		return "", false
	}
	cv, _ := row["cfgversion"].(string)
	if cv == "" {
		return "", false
	}
	return cv, true
}

// retryDue rate-limits the unchanged pending WLAN delivery: a bounded
// attempt budget (WlanMaxAttempts) with exponential backoff (WlanRetryBase
// doubling up to WlanRetryMax). At the cap the delivery status flips to
// "exhausted" and retryDue returns false — the engine then answers
// noop-pending-wlan while the pending hash still equals the current
// envelope hash; re-provisioning happens only when the envelope hash
// CHANGES (a changed envelope is a new delivery operation).
func (st *DeliveryState) RetryDue(now time.Time) bool {
	if st.attempts >= WlanMaxAttempts {
		st.extra[store.WlanCfgDeliveryStatusKey] = "exhausted"
		return false
	}
	delay := WlanRetryBase * time.Duration(1<<max(0, st.attempts-1))
	if delay > WlanRetryMax {
		delay = WlanRetryMax
	}
	return st.lastAttempt == 0 || now.Unix() >= st.lastAttempt+int64(delay/time.Second)
}

// WlanRetryDue reports whether the unchanged pending WLAN delivery may retry
// now (the engine's bounded attempt budget with backoff). At the cap the
// delivery status flips to "exhausted" in extra.
func WlanRetryDue(extra store.JSONMap, now time.Time) bool {
	return LoadDeliveryState(extra).RetryDue(now)
}

// Offer records one system_cfg delivery attempt (the assignedKey
// bookkeeping): replacing the pending hash starts a fresh budget; retrying
// the same hash increments it. offeredCfg is the cfgversion THIS offer
// carries — the pending gate reads it back (wlan_cfg_offered_cfgversion) to
// tell an operator mint from a genuinely unchanged record, so an exhausted
// unchanged-envelope retry cannot hold operator content hostage. cur and
// placements arrive from the decision's provisioning plan (the drift hash
// and the Placements half of PlanProvisioning), not separate
// recomputations. EXACT key names and value formats preserved.
func (st *DeliveryState) Offer(cur string, nowUnix int64, wls []Wlan, placements map[string]int, offeredCfg string) {
	st.extra[store.WlanCfgPendingShaKey] = cur
	// Each emitted system_cfg is one bounded delivery attempt. Replacing the
	// pending hash starts a fresh budget; retrying the same hash increments it.
	if st.attemptSHA != cur {
		st.extra[store.WlanCfgAttemptShaKey] = cur
		st.extra[store.WlanCfgAttemptsKey] = 1
	} else {
		st.extra[store.WlanCfgAttemptsKey] = st.attempts + 1
	}
	st.extra[store.WlanCfgLastAttemptKey] = nowUnix
	st.extra[store.WlanCfgDeliveryStatusKey] = "pending"
	st.extra[store.WlanCfgOfferedCfgversionKey] = offeredCfg
	// Keep the previously applied snapshot for the settle check (verbatim
	// value copy, whatever type it carries).
	if st.appliedPresent {
		st.extra[store.WlanCfgPendingOldWlansKey] = st.appliedRaw
	}
	if snapshot, err := EncodeStoredWlans(wls); err == nil {
		st.extra[store.WlanCfgPendingWlansKey] = string(snapshot)
	}
	// Record the intended SSID-to-radio placements so confirmation cannot be
	// satisfied by a VAP on the wrong band/radio.
	if raw, err := json.Marshal(placements); err == nil {
		st.extra[store.WlanCfgPendingPlacementsKey] = string(raw)
	}
}

func containsEnabled(wls []Wlan, ssid string) bool {
	for _, w := range wls {
		if w.Enabled && SSIDOf(w) == ssid {
			return true
		}
	}
	return false
}

// WLAN delivery retry budget (bounded attempt bookkeeping per pushed hash).
const (
	WlanRetryBase   = 2 * time.Second
	WlanRetryMax    = 60 * time.Second
	WlanMaxAttempts = 6
)

// Baseline is the drift baseline (wlan_cfg_sha): the hash of the last WLAN
// set a device was proven running. "" means no baseline yet.
func (st *DeliveryState) Baseline() string { return st.sha }

// PendingPresent reports whether a delivery is in flight by PRESENCE of the
// pending row (any type, even ""): the connected-noop branch asks this.
func (st *DeliveryState) PendingPresent() bool { return st.pendingSHAPresent }

// PendingHash is the in-flight delivery's hash, "" when the row is absent
// or not a string (the drift-check and settle paths need the STRING-typed
// non-empty value).
func (st *DeliveryState) PendingHash() string { return st.pendingSHA }

// OfferedCfgversion is the cfgversion the pending delivery was last offered
// with, and whether that bookkeeping exists at all (a pending that predates
// it keeps the hold-at-gate behavior).
func (st *DeliveryState) OfferedCfgversion() (string, bool) {
	return st.offeredCfgversion, st.offeredPresent
}

// DeliveryStatus is the last stamped status: "pending", "confirmed" or
// "exhausted", "" when none. Write-only for the engine; the admin view reads
// it.
func (st *DeliveryState) DeliveryStatus() string {
	v, _ := st.extra[store.WlanCfgDeliveryStatusKey].(string)
	return v
}

// Attempts is the delivery attempt count for the current pending hash.
func (st *DeliveryState) Attempts() int { return st.attempts }

// LastAttempt is the unix time of the last delivery attempt, 0 when none.
func (st *DeliveryState) LastAttempt() int64 { return st.lastAttempt }

// ClearMaterializationReboot retires the one-shot materialization-reboot
// marker (a RUN proof at the devname level means the gap it guarded is gone).
func ClearMaterializationReboot(extra store.JSONMap) {
	delete(extra, store.WlanCfgMaterializationRebootKey)
}

// ClearWatchdogCounters resets both consecutive-miss counters. A reboot is a
// lifecycle boundary for the not-running windows: the next vap_table opens a
// fresh boot window, so a miss recorded before the reboot must not straddle
// it.
func ClearWatchdogCounters(extra store.JSONMap) {
	delete(extra, store.WlanCfgNotRunningMissesKey)
	delete(extra, store.WlanCfgVapNotRunningMissesKey)
}

// NotRunningMisses is the SSID-level consecutive-miss counter, 0 when
// absent (window unarmed).
func (st *DeliveryState) NotRunningMisses() int { return st.notRunningMisses }

// RuntimeInSync is the admin view's "is the WLAN running?" answer: nil when
// unknown, otherwise whether the device runs the desired WLANs. It
// deliberately does not infer runtime health from the controller/device
// cfgversion pair — devices can echo a matching version before applying the
// WLAN, so that pair is only transport bookkeeping. It is SSID-PRESENCE-ONLY
// by design: a positive result requires a reported vap_table in which every
// enabled desired SSID is observed RUNNING; per-radio placement and the
// disappearance of a deleted WLAN are checked strictly by Settle, which runs
// on every inform before this view is served. A delivery in flight reads
// false; missing runtime evidence reads unknown (nil), while an observed
// table that lacks a desired RUN SSID reads false.
func RuntimeInSync(d store.Device, desired []Wlan) *bool {
	if d.Extra == nil {
		return nil
	}
	if LoadDeliveryState(d.Extra).PendingPresent() {
		v := false
		return &v
	}
	ev := ReadVapEvidence(d.Extra["vap_table"])
	if !ev.Known() {
		return nil
	}
	// A vap_table with no RUN desired SSIDs is meaningful evidence of being
	// out of sync, but a missing/empty table is unknown rather than false.
	want := make(map[string]bool)
	for _, w := range desired {
		if w.Enabled {
			want[w.SSID] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	v := true
	for ssid := range want {
		if !ev.SSIDRunning(ssid) {
			v = false
			break
		}
	}
	return &v
}

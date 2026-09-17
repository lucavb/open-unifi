package adoption

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/lucabecker/open-unifi/internal/store"
	"github.com/lucabecker/open-unifi/internal/wireless"
)

// ControllerOwnedKeys lists the controller-owned wlan_cfg_* Extra keys the
// typed state owns (the trust-policy "controller-owned keys" class), in the
// order the adapter's prev-wins preservation list uses them. Single source:
// package server builds extraPrevWins from this list plus its server-side
// ssh_sha512passwd cache key.
var ControllerOwnedKeys = []string{
	"wlan_cfg_sha", "wlan_cfg_pending_sha", "wlan_cfg_pending_wlans",
	"wlan_cfg_pending_old_wlans", "wlan_cfg_applied_wlans",
	"wlan_cfg_pending_placements", "wlan_cfg_attempt_sha", "wlan_cfg_attempts",
	"wlan_cfg_last_attempt", "wlan_cfg_delivery_status",
}

// wlanCfgState is the typed view over the controller-owned wlan_cfg_* Extra
// keys (the trust-policy "controller-owned keys" class). load reads them with
// EXACTLY the type assertions today's readers used; the apply functions write
// back EXACT key names and EXACT value formats (string/int/int64) so the
// persisted Extra bytes stay identical to the pre-extraction behavior.
//
// Keys covered (all controller-owned):
//
//	wlan_cfg_sha, wlan_cfg_pending_sha, wlan_cfg_pending_wlans,
//	wlan_cfg_pending_old_wlans, wlan_cfg_applied_wlans,
//	wlan_cfg_pending_placements, wlan_cfg_attempt_sha, wlan_cfg_attempts,
//	wlan_cfg_last_attempt, wlan_cfg_delivery_status.
type wlanCfgState struct {
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
	pendingWlans []wireless.Wlan

	// oldWlans is wlan_cfg_pending_old_wlans decoded the same way.
	oldWlans []wireless.Wlan

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
}

// loadWlanCfgState reads the controller-owned keys from extra with exactly
// the type assertions of the pre-extraction readers.
func loadWlanCfgState(extra store.JSONMap) wlanCfgState {
	st := wlanCfgState{extra: extra}
	if v, ok := extra["wlan_cfg_sha"].(string); ok {
		st.sha = v
	}
	if _, ok := extra["wlan_cfg_pending_sha"]; ok {
		st.pendingSHAPresent = true
	}
	if v, ok := extra["wlan_cfg_pending_sha"].(string); ok {
		st.pendingSHAIsString = true
		st.pendingSHA = v
	}
	if raw, ok := extra["wlan_cfg_pending_wlans"].(string); ok {
		var w []wireless.Wlan
		if json.Unmarshal([]byte(raw), &w) == nil {
			st.pendingWlans = w
		}
	}
	if raw, ok := extra["wlan_cfg_pending_old_wlans"].(string); ok {
		var w []wireless.Wlan
		if json.Unmarshal([]byte(raw), &w) == nil {
			st.oldWlans = w
		}
	}
	if v, ok := extra["wlan_cfg_applied_wlans"]; ok {
		st.appliedPresent = true
		st.appliedRaw = v
	}
	if raw, ok := extra["wlan_cfg_pending_placements"].(string); ok {
		placements := map[string]int{}
		_ = json.Unmarshal([]byte(raw), &placements)
		st.placements = placements
	}
	if v, ok := extra["wlan_cfg_attempt_sha"].(string); ok {
		st.attemptSHA = v
	}
	switch v := extra["wlan_cfg_attempts"].(type) {
	case int:
		st.attempts = v
	case float64:
		st.attempts = int(v)
	}
	switch v := extra["wlan_cfg_last_attempt"].(type) {
	case int64:
		st.lastAttempt = v
	case float64:
		st.lastAttempt = int64(v)
	}
	return st
}

// settle promotes a sent WLAN hash only after the latest inform proves both
// sides of the change: every desired SSID has RUN VAPs and every previously
// enabled SSID being removed has disappeared. cfgversion equality is
// deliberately not evidence of WLAN application.
func (st *wlanCfgState) settle() {
	if !st.pendingSHAIsString {
		return
	}
	vaps, ok := st.extra["vap_table"].([]any)
	if !ok {
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
		if w.Enabled && !containsEnabled(desired, wireless.SSIDOf(w)) {
			removed[wireless.SSIDOf(w)] = true
		}
	}
	for _, w := range desired {
		if w.Enabled {
			need[wireless.SSIDOf(w)]++
		}
	}
	// The old snapshot is not available as a separate desired/current pair in
	// the record, so use the current source for positive proof and only require
	// old names to be absent when they are no longer desired.
	//
	// Wire keys: the AP's real vap_table uses essid/state/radio_name/name
	// (firmware-verified, mcad FUN_0041cecc; corroborated by the live log
	// "vap_table reports state RUN", docs/PROTOCOL.md:388;
	// docs/AP-FIRMWARE-APPLY-PATH.md). The ssid/status/parent spellings only
	// ever existed in our synthetic test fixtures — status/parent are kept
	// as fallbacks here pending the capture cross-check so in-flight
	// fixtures keep working. The placement construction side
	// (wlanPlacements) keys on radio_table `name` values; the device-side
	// radio_name carries the same strings.
	for _, raw := range vaps {
		m, ok := raw.(map[string]any)
		if !ok || !strings.EqualFold(wireless.JSONStr(m, "state", wireless.JSONStr(m, "status", "")), "RUN") {
			continue
		}
		ssid := wireless.JSONStr(m, "essid", wireless.JSONStr(m, "ssid", ""))
		if ssid == "" {
			continue
		}
		if removed[ssid] {
			return
		}
		parent := wireless.JSONStr(m, "radio_name", wireless.JSONStr(m, "parent", ""))
		key := ssid + "\x00" + parent
		if placements[key] > 0 {
			placements[key]--
			need[ssid]--
		} else if need[ssid] > 0 && len(placements) == 0 {
			need[ssid]--
		}
	}
	for _, w := range desired {
		if w.Enabled && need[wireless.SSIDOf(w)] > 0 {
			return
		}
	}
	// A deleted WLAN is settled only when the old VAP is absent. Positive
	// desired WLANs were checked above; no VAP table means unknown, not success.
	st.extra["wlan_cfg_sha"] = st.pendingSHA
	st.extra["wlan_cfg_applied_wlans"] = st.extra["wlan_cfg_pending_wlans"]
	st.extra["wlan_cfg_delivery_status"] = "confirmed"
	delete(st.extra, "wlan_cfg_pending_sha")
	delete(st.extra, "wlan_cfg_pending_wlans")
	delete(st.extra, "wlan_cfg_pending_placements")
	// Mirror the promotion in the typed view so the post-settle drift and
	// pending checks read the same values the former direct Extra reads did.
	st.sha = st.pendingSHA
	st.pendingSHAPresent = false
	st.pendingSHAIsString = false
	st.pendingSHA = ""
	st.pendingWlans = nil
	st.placements = nil
}

// retryDue rate-limits the unchanged pending WLAN delivery: a bounded
// attempt budget (WlanMaxAttempts) with exponential backoff (WlanRetryBase
// doubling up to WlanRetryMax). At the cap the delivery status flips to
// "exhausted" and retryDue returns false — the engine then answers
// noop-pending-wlan while the pending hash still equals the current
// envelope hash; re-provisioning happens only when the envelope hash
// CHANGES (a changed envelope is a new delivery operation).
func (st wlanCfgState) retryDue(now time.Time) bool {
	if st.attempts >= WlanMaxAttempts {
		st.extra["wlan_cfg_delivery_status"] = "exhausted"
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
	return loadWlanCfgState(extra).retryDue(now)
}

// applyProvisioning records one system_cfg delivery attempt (the assignedKey
// bookkeeping): replacing the pending hash starts a fresh budget; retrying
// the same hash increments it. EXACT key names and value formats preserved.
func (st wlanCfgState) applyProvisioning(cur string, nowUnix int64, wls []wireless.Wlan, placements map[string]int) {
	st.extra["wlan_cfg_pending_sha"] = cur
	// Each emitted system_cfg is one bounded delivery attempt. Replacing the
	// pending hash starts a fresh budget; retrying the same hash increments it.
	if st.attemptSHA != cur {
		st.extra["wlan_cfg_attempt_sha"] = cur
		st.extra["wlan_cfg_attempts"] = 1
	} else {
		st.extra["wlan_cfg_attempts"] = st.attempts + 1
	}
	st.extra["wlan_cfg_last_attempt"] = nowUnix
	st.extra["wlan_cfg_delivery_status"] = "pending"
	// Keep the previously applied snapshot for the settle check (verbatim
	// value copy, whatever type it carries).
	if st.appliedPresent {
		st.extra["wlan_cfg_pending_old_wlans"] = st.appliedRaw
	}
	if snapshot, err := json.Marshal(wls); err == nil {
		st.extra["wlan_cfg_pending_wlans"] = string(snapshot)
	}
	// Record the intended SSID-to-radio placements so confirmation cannot be
	// satisfied by a VAP on the wrong band/radio.
	if raw, err := json.Marshal(placements); err == nil {
		st.extra["wlan_cfg_pending_placements"] = string(raw)
	}
}

// wlanPlacements records the intended SSID-to-radio placements from the vap
// plan (SSID\x00radio_name → count).
func wlanPlacements(d store.Device, wls []wireless.Wlan) map[string]int {
	out := map[string]int{}
	vaps, _ := wireless.PlanVaps(d, wls)
	for _, v := range vaps {
		out[wireless.SSIDOf(v.Wlan)+"\x00"+v.Phyname]++
	}
	return out
}

func containsEnabled(wls []wireless.Wlan, ssid string) bool {
	for _, w := range wls {
		if w.Enabled && wireless.SSIDOf(w) == ssid {
			return true
		}
	}
	return false
}

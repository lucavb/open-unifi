// The record trust policy (CONTEXT.md): three ownership classes over the
// device record's Extra rows —
//
//	controller-owned keys: the controller preserves the record's value
//	             verbatim against any device-supplied body (the wlan_cfg_*
//	             bookkeeping, the client-session family);
//	device-refreshable caps: only the device can supply them
//	             (radio_table, wifi_caps, fw_caps, if_table,
//	             ethernet_table, uplink, has_eth1) — a sparse heartbeat
//	             keeps the record's last value, a full inform refreshes it;
//	admin-owned rows: only an admin can set or change them — a device
//	             body can neither write nor introduce them (the
//	             system_cfg/site-fact rows, the armed lifecycle rows, the
//	             typed LED/SSH record fields' Extra twins, the blocked-client
//	             set and its delivery baseline, the per-device SSH
//	             password caches, the per-radio channel
//	             intent, the §6.3 stored task).
//
// This file is the single declaration site for every class (Absorb guards
// the ORDINARY record path; the §6.6 factory-reset demotion consults the
// same registry through FactoryResetSweepKeys). Packages that owned their
// own names before the policy consolidated here keep one-line aliases
// (adoption.FlagRebootOnConnect, wireless.RadioIntentExtraKey, …) so their
// call sites and jar-fact comments stay put.
package store

import "time"

const (
	// SSHSha512PasswdKey / SSHMd5PasswdKey are the two Extra rows caching
	// the LAST password hash the controller pushed for this device (the
	// $6$ / $1$ crypts produced by the systemcfg renderer's credential
	// delta). ADMIN-OWNED as prev-or-delete (the same shape as
	// blocked_sta_sha, a controller-written admin-owned row): a device
	// body can neither clobber, wipe, nor INTRODUCE either cache — under
	// the renderer's verbatim unset reuse a device-introduced cache WOULD
	// ship (a forged pre-adoption inform could seed the password a device
	// then keeps), and the only legitimate writer is the controller's own
	// credential delta, applied by the adapter in the applyOutcome dict
	// loop.
	SSHSha512PasswdKey = "ssh_sha512passwd"
	SSHMd5PasswdKey    = "ssh_md5passwd"

	// SystemCfgExtraLinesKey holds the admin's raw extra system_cfg lines
	// (sorted []any of strings).
	SystemCfgExtraLinesKey = "system_cfg_extra_lines"

	// MgmtDevKey steers the netconf device name (admin escape hatch).
	MgmtDevKey = "mgmt_dev"

	// AnonymousControllerIDKey / AnonymousSiteIDKey are the admin-set
	// Telemetry-style random ids the renderer echoes into system_cfg.
	AnonymousControllerIDKey = "anonymous_controller_id"
	AnonymousSiteIDKey       = "anonymous_site_id"

	// FlagRebootOnConnect / FlagSetdefaultArmed are the admin-armed
	// lifecycle command rows (§6.5 reboot, §6.6 factory reset). The jar
	// derives their names from the on-device manager's collection fields —
	// see adoption's flag comment block for the recovered facts.
	FlagRebootOnConnect = "reboot_on_connect"
	FlagSetdefaultArmed = "setdefault_armed"

	// RadioIntentExtraKey is the admin-owned per-radio channel/txpower
	// intent map (wireless.PlanVaps' ProvisioningPlan input).
	RadioIntentExtraKey = "radio_intent"

	// DeviceWLANsExtraKey is the admin-owned per-device WLAN envelope
	// (wireless.DeviceWLANs / SetDeviceWLANs).
	DeviceWLANsExtraKey = "device_wlans"

	// BlockedStaShaExtraKey is the blocked_sta delivery baseline
	// (sha256 of the last EMITTED §4 wire string, adoption-blockedsta's
	// offer-then-confirm bookkeeping). Admin-owned — the same
	// prev-or-delete rule as the set itself hides the row from device
	// bodies; only the engine's own emission may write it.
	BlockedStaShaExtraKey = "blocked_sta_sha"
)

// controllerOwnedKeys is the record's controller-owned Extra key class
// (single source): the wlan_cfg_* WLAN delivery bookkeeping and the
// client-session family. Package-private by design (the sealed surface:
// Absorb is the only reader); nothing outside this file may copy it.
var controllerOwnedKeys = []string{
	"wlan_cfg_sha", "wlan_cfg_pending_sha", "wlan_cfg_pending_wlans",
	"wlan_cfg_pending_old_wlans", "wlan_cfg_applied_wlans",
	"wlan_cfg_pending_placements", "wlan_cfg_attempt_sha", "wlan_cfg_attempts",
	"wlan_cfg_last_attempt", "wlan_cfg_delivery_status",
	"wlan_cfg_not_running_misses", "wlan_cfg_offered_cfgversion",
	SessionsExtraKey, SessionDisconnectEventExtraKey,
}

// deviceRefreshableKeys is the device-refreshable caps class: fields only
// the device can supply. Record absorption keeps the record's value when a
// body omits the key (a sparse heartbeat must not wipe the radio_table) and
// takes the body's value when present (prev-owns would pin device-side
// channel reselection forever). Package-private by design (the sealed
// surface: Absorb is the only reader); nothing outside this file may copy
// it.
var deviceRefreshableKeys = []string{
	"radio_table", "wifi_caps", "fw_caps", "if_table", "ethernet_table",
	"uplink", "has_eth1",
}

// adminOwnedKeys is the admin-owned rows class: a device body can neither
// write nor introduce any of them. The led_override / disabled /
// led_override_color_* entries are the Extra twins of the typed Device
// fields above (the classic controller reads all four rows from its own DB,
// never the wire) — a body echo is dropped so it can neither shadow the
// typed value nor introduce a copy. "ssh_password" is the same twin for the
// typed per-device SSH password field. blocked_sta (the admin-owned
// blocked-client set) and blocked_sta_sha (the delivery baseline) get the
// prev-or-delete rule too: prev-owns alone would let a body INTRODUCE the
// baseline, and a forged baseline matching a forged set would suppress
// delivery — only the engine's own emission ever writes it. The two SSH
// password caches (SSHSha512PasswdKey/SSHMd5PasswdKey) ride the SAME
// prev-or-delete rule: they hold the DEVICE's last controller-pushed
// password hash (the renderer's unset branch reuses that row verbatim, so a
// device-introduced cache would ship verbatim), and the only legitimate
// writer is the controller's own credential delta.
// Package-private by design (the sealed surface: Absorb is the only
// reader); nothing outside this file may copy it.
var adminOwnedKeys = []string{
	SystemCfgExtraLinesKey, MgmtDevKey,
	AnonymousControllerIDKey, AnonymousSiteIDKey,
	FlagRebootOnConnect, FlagSetdefaultArmed,
	BlockedStaExtraKey, BlockedStaShaExtraKey,
	// The devname-level materialization watchdog's two rows (the
	// consecutive-miss counter and the one-shot armed-reboot marker, per
	// cfgversion — engine wlanstate). Admin-owned prev-or-delete, the same
	// shape as blocked_sta_sha: a controller-written row guarded against
	// device-baseline forging. Prev-owns alone would let a device body
	// INTRODUCE either row — the device learns its cfgversion from the
	// adoption echo that AppliedCfg reads, so a pre-planted marker for
	// that version permanently suppresses the auto-heal, and a forged
	// counter=1 plus one genuine miss arms the reboot instantly, skipping
	// the two-inform boot-race grace. Prev-or-delete keeps the survival
	// the watchdog needs either way: once the ENGINE wrote the row, a
	// later sparse heartbeat (no body copy) restores the record's value,
	// and a forged body copy never overwrites it.
	"wlan_cfg_vap_not_running_misses", "wlan_cfg_materialization_reboot",
	SSHSha512PasswdKey, SSHMd5PasswdKey,
	"led_override", "disabled", "led_override_color_brightness",
	"led_override_color", "ssh_password",
	"regulatory_country_code", "ssh_public_keys",
	RadioIntentExtraKey, DeviceWLANsExtraKey, CmdTaskKey,
}

// FactoryResetSweepKeys is the subset of the trust registry the §6.6
// factory-reset demotion clears: the PER-DEVICE controller state whose
// staleness cannot survive a reset (a stale wlan_cfg_sha would let the
// re-adopted device settle into connected noops while running factory
// config), PLUS the devname materialization watchdog's two admin-owned rows
// (wlan_cfg_vap_not_running_misses / wlan_cfg_materialization_reboot). The
// sweep keeps them deliberately, not by class: as admin rows they left the
// controller-owned derivation when they moved to prev-or-delete (moving
// classes the way blocked_sta_sha did — its baseline staleness self-heals,
// because the post-reset re-adoption full-provisions and re-stamps it), but
// a surviving marker would freeze the per-config one-shot budget across a
// reset and a surviving counter would land the re-adopted device one
// genuine miss away from an instant arm. So unlike blocked_sta_sha these
// two are swept explicitly. SSHSha512PasswdKey is deliberately excluded —
// and the same survival holds by CLASS membership, not just by this
// exclude: both password caches are admin-owned (they hold the DEVICE's
// last controller-pushed password and deliberately survive factory
// reset/setdefault demotion; the exclude keeps that survival even if the
// keys ever move classes again). Derived from controllerOwnedKeys for the
// derived half, so that half can never fall out of sync with the class it
// clears. TREAT AS IMMUTABLE (do not append or reorder; it holds the
// registry's own defensive copy). This is the only class slice left
// exported: the adoption engine is its sole consumer, so the class
// membership itself stays sealed.
var FactoryResetSweepKeys = append(excludeKey(controllerOwnedKeys, SSHSha512PasswdKey),
	"wlan_cfg_vap_not_running_misses", "wlan_cfg_materialization_reboot")

// excludeKey copies keys without the one named (copy so a caller that
// appends to one list can never clobber the other's backing array).
func excludeKey(keys []string, skip string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != skip {
			out = append(out, k)
		}
	}
	return out
}

// Absorb is the record absorption (CONTEXT.md): the single merge folding a
// decoded inform body into the device record — the only way device data
// enters a record. The typed columns take exactly the body fields they
// always took; the wholesale Extra swap runs under the trust policy, so the
// three ownership classes survive it intact:
//
//	controller-owned — the record's value wins, whatever the body carries;
//	device-refreshable — the record's value survives only when the body
//	                     omits the key;
//	admin-owned — the record's value when present, DELETED otherwise (a
//	              body can never introduce an admin row).
//
// body is aliased into d.Extra verbatim (the full raw passthrough, freshly
// unmarshal'd per request); the class restores re-take rows from the
// previous record before any later writer can observe the half-merged map
// (the absorption lives inside the device's read-modify-write cycle).
func (d *Device) Absorb(body map[string]any, now time.Time, gcmReq bool) {
	d.Model = jsonString(body, "model")
	d.Firmware = jsonString(body, "version")
	d.Serial = jsonString(body, "serial")
	d.IP = jsonString(body, "ip")
	d.InformURL = jsonString(body, "inform_url")
	prev := d.Extra // caches / admin-owned values live here
	if prev == nil {
		prev = JSONMap{}
	}
	d.Extra = JSONMap(body)
	for _, k := range controllerOwnedKeys {
		if v, ok := prev[k]; ok {
			d.Extra[k] = v
		}
	}
	for _, k := range deviceRefreshableKeys {
		if _, ok := body[k]; !ok {
			if v, ok := prev[k]; ok {
				d.Extra[k] = v
			}
		}
	}
	for _, k := range adminOwnedKeys {
		if v, ok := prev[k]; ok {
			d.Extra[k] = v
		} else {
			delete(d.Extra, k)
		}
	}
	if stat, ok := body["stat"].(map[string]any); ok {
		d.LastUps = JSONMap(stat)
	}
	if cfg, ok := body["cfgversion"].(string); ok && cfg != "" {
		d.AppliedCfg = cfg
	}
	d.LastSeen = now.Unix()
	if d.FirstSeen == 0 {
		d.FirstSeen = now.Unix()
	}
	if gcmReq {
		d.AESGCM = true
	}
	if v, ok := body["x_aes_gcm"].(bool); ok && v {
		d.AESGCM = true
	}
}

// jsonString fetches an untyped inform-body field as a string ("" when the
// key is absent, non-string, or nil).
func jsonString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

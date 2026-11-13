// Record absorption pinned at the store seam: the trust policy's three
// ownership classes (CONTEXT.md) are enforced by Device.Absorb itself, so
// these tests pin the record — not a transport adapter's copy of the rules.
package store

import (
	"reflect"
	"testing"
	"time"
)

var absorbNow = time.Unix(1700000000, 0)

// absorbFixture builds a record with one value per class already in place.
func absorbFixture() Device {
	return Device{
		MAC: "aabbccddeeff", Model: "U7PG2", Firmware: "6.8.2.15592",
		LastSeen: 1699999999, FirstSeen: 1690000000, AppliedCfg: "old-cfg",
		AESGCM: true, FactoryResetInFlight: true,
		Extra: JSONMap{
			// controller-owned: wlan bookkeeping + the client-session family
			"wlan_cfg_sha":    "prev-sha",
			"client_sessions": JSONMap{"aabbccddeeff": JSONMap{"connected": true}},
			// device-refreshable caps
			"radio_table": []any{JSONMap{"name": "ra0"}},
			"wifi_caps":   7,
			// admin-owned rows (incl. the per-device SSH password twin and
			// the two last-controller-pushed password-hash caches)
			"system_cfg_extra_lines":        []any{"set XMII=no"},
			"mgmt_dev":                      "br0",
			"reboot_on_connect":             true,
			"setdefault_armed":              true,
			"factory_reset_in_flight":       true,
			"led_override":                  "on",
			"led_override_color_brightness": 42.0,
			"blocked_sta":                   []any{"112233445566"},
			"cmd_task":                      JSONMap{"cmd": "restart"},
			"ssh_password":                  "prev-pw",
			"ssh_sha512passwd":              "$6$prev-hash$",
			"ssh_md5passwd":                 "$1$prev-hash$",
		},
	}
}

// absorbBody is a FULL inform body broadcasting FORGED device copies of
// every controller-owned and admin-owned row plus fresh device-side caps —
// what the record keeps is the whole story of the absorption.
func absorbBody() map[string]any {
	return map[string]any{
		"model": "U7PG2", "version": "6.8.2.15592", "serial": "F409NEW11111",
		"ip": "10.0.0.9", "inform_url": "http://ctrl:8080/inform",
		"cfgversion": "new-cfg",
		"stat":       map[string]any{"up": 123.0},
		// fresh device-side caps (the device MAY refresh them) — typed
		// exactly as decoding/json would leave them
		"radio_table": []any{map[string]any{"name": "ra0", "channel": "36"}},
		"wifi_caps":   9.0,
		// forged device copies of every guarded class
		"wlan_cfg_sha":                  "forged-sha",
		"client_sessions":               "forged",
		"system_cfg_extra_lines":        []any{"echo pwned"},
		"mgmt_dev":                      "eth9",
		"reboot_on_connect":             "forged",
		"setdefault_armed":              "forged",
		"factory_reset_in_flight":       false,
		"led_override":                  "off",
		"led_override_color_brightness": 99.0,
		"blocked_sta":                   "forged",
		"cmd_task":                      "forged",
		"ssh_password":                  "forged-pw",
		"ssh_sha512passwd":              "$6$forged$",
		"ssh_md5passwd":                 "$1$forged$",
	}
}

// TestAbsorbControllerOwnedPrevWins pins the controller-owned class across
// the wholesale Extra swap (the wlan delivery bookkeeping and the
// client-session family).
func TestAbsorbControllerOwnedPrevWins(t *testing.T) {
	rec := absorbFixture()
	rec.Absorb(absorbBody(), absorbNow, false)
	for _, k := range []string{"wlan_cfg_sha", "client_sessions"} {
		if got, want := rec.Extra[k], absorbFixture().Extra[k]; !reflect.DeepEqual(got, want) {
			t.Fatalf("controller-owned %q missing after absorption: got %v, want %v", k, got, want)
		}
	}
}

// TestAbsorbControllerOwnedKeysPreserveOrDelete exhaustively pins the
// controller-owned class: a prior record value survives a forged or omitted
// body field, while a fresh record deletes the body's attempted introduction.
// Legitimate typed and device-refreshable payload fields continue to absorb.
func TestAbsorbControllerOwnedKeysPreserveOrDelete(t *testing.T) {
	previousValues := []struct {
		name  string
		value any
	}{
		{name: "map", value: JSONMap{"controller_value": "previous"}},
		{name: "false", value: false},
		{name: "zero", value: float64(0)},
		{name: "nil", value: nil},
	}
	bodyWith := func(key string) map[string]any {
		return map[string]any{
			"model":       "fresh-model",
			"radio_table": []any{map[string]any{"name": "radio-from-device"}},
			"wifi_caps":   float64(17),
			key:           "forged-by-device",
		}
	}

	for _, key := range controllerOwnedKeys {
		t.Run(key, func(t *testing.T) {
			fresh := Device{MAC: "aabbccddeeff", State: StatePending, Extra: JSONMap{}}
			fresh.Absorb(bodyWith(key), absorbNow, false)
			if _, ok := fresh.Extra[key]; ok {
				t.Fatalf("fresh record accepted controller-owned %q = %#v", key, fresh.Extra[key])
			}
			if fresh.Model != "fresh-model" || fresh.Extra["wifi_caps"] != float64(17) ||
				fresh.Extra["radio_table"].([]any)[0].(map[string]any)["name"] != "radio-from-device" {
				t.Fatalf("legitimate body fields did not absorb beside %q: %+v", key, fresh)
			}

			for _, tc := range previousValues {
				t.Run(tc.name, func(t *testing.T) {
					seeded := Device{MAC: "aabbccddeeff", Extra: JSONMap{key: tc.value}}
					seededBody := bodyWith(key) // independent: Absorb mutates its map
					if got, ok := seededBody[key]; !ok || got != "forged-by-device" {
						t.Fatalf("seeded input lost forged %q before Absorb: got %#v present=%v", key, got, ok)
					}
					seeded.Absorb(seededBody, absorbNow, false)
					if got, ok := seeded.Extra[key]; !ok || !reflect.DeepEqual(got, tc.value) {
						t.Fatalf("prior controller-owned %q (%s) changed: got %#v present=%v, want %#v", key, tc.name, got, ok, tc.value)
					}

					// A separate sparse body also keeps each prior value; this
					// covers omission independently of forged-value protection.
					seeded.Absorb(sparseBody(), absorbNow, false)
					if got, ok := seeded.Extra[key]; !ok || !reflect.DeepEqual(got, tc.value) {
						t.Fatalf("sparse absorption lost prior controller-owned %q (%s): got %#v present=%v, want %#v", key, tc.name, got, ok, tc.value)
					}
				})
			}
		})
	}

	// The admin-owned SSH cache remains protected by its separate registry and
	// prev-or-delete semantics, independent of the controller-owned class.
	rec := Device{MAC: "aabbccddeeff", Extra: JSONMap{SSHSha512PasswdKey: "$6$prev-hash$"}}
	rec.Absorb(absorbBody(), absorbNow, true)
	if got, want := rec.Extra[SSHSha512PasswdKey], "$6$prev-hash$"; got != want {
		t.Fatalf("ssh cache not restored against forged body: %v, want %v", got, want)
	}
}

func TestFirstRegisteredPendingAbsorbCannotSeedWLANDelivery(t *testing.T) {
	// A manually registered, still-pending device has no controller delivery
	// history. A factory-key inform cannot seed an exhausted pending operation
	// that would suppress the adoption decision in the server engine.
	rec := Device{MAC: "aabbccddeeff", State: StatePending}
	body := map[string]any{
		"model":                       "U7PG2",
		"wlan_cfg_pending_sha":        "forged-current-hash",
		"wlan_cfg_attempt_sha":        "forged-current-hash",
		"wlan_cfg_attempts":           float64(6),
		"wlan_cfg_delivery_status":    "exhausted",
		"wlan_cfg_pending_wlans":      "forged-snapshot",
		"wlan_cfg_pending_placements": "forged-placements",
		"radio_table": []any{
			map[string]any{"name": "ra0", "radio": "ng"},
		},
	}
	rec.Absorb(body, absorbNow, false)
	for _, key := range []string{
		WlanCfgPendingShaKey, WlanCfgAttemptShaKey, WlanCfgAttemptsKey,
		WlanCfgDeliveryStatusKey, WlanCfgPendingWlansKey, WlanCfgPendingPlacementsKey,
	} {
		if value, ok := rec.Extra[key]; ok {
			t.Errorf("first pending inform seeded %s = %#v", key, value)
		}
	}
	if rec.State != StatePending || rec.Model != "U7PG2" || rec.Extra["radio_table"] == nil {
		t.Fatalf("controller-owned filtering changed legitimate pending record fields: %+v", rec)
	}
}

// TestAbsorbDeviceRefreshableClass pins the caps class both ways: a body
// carrying the key refreshes the record's value; a sparse body omitting it
// keeps the record's last value.
func TestAbsorbDeviceRefreshableClass(t *testing.T) {
	rec := absorbFixture()
	rec.Absorb(absorbBody(), absorbNow, false)
	if ch := rec.Extra["radio_table"].([]any)[0].(map[string]any)["channel"]; ch != "36" {
		t.Fatalf("device-refreshable radio_table not refreshed: %v", rec.Extra["radio_table"])
	}
	if got, _ := rec.Extra["wifi_caps"].(float64); got != 9 {
		t.Fatalf("device-refreshable wifi_caps not refreshed: %v", rec.Extra["wifi_caps"])
	}
	// A sparse heartbeat omits the caps wholesale — both rows keep the
	// record's exact previous values.
	sparse := map[string]any{"model": "U7PG2", "version": "6.8.2.15592"}
	prev := absorbFixture()
	rec = absorbFixture()
	rec.Absorb(sparse, absorbNow, false)
	for _, k := range deviceRefreshableKeys {
		if !reflect.DeepEqual(rec.Extra[k], prev.Extra[k]) {
			t.Fatalf("sparse heartbeat changed device-refreshable %q: %v, want %v", k, rec.Extra[k], prev.Extra[k])
		}
	}
}

// TestAbsorbAdminOwnedPrevOrDelete pins the admin-owned class's exact
// prev-or-delete branches: record value present → survive verbatim
// whatever the body carries; record value absent → deleted, so a body can
// never INTRODUCE an admin row.
func TestAbsorbAdminOwnedPrevOrDelete(t *testing.T) {
	rec := absorbFixture()
	rec.Absorb(absorbBody(), absorbNow, false)
	prev := absorbFixture()
	for _, k := range adminOwnedKeys {
		want := prev.Extra[k]
		if got := rec.Extra[k]; !reflect.DeepEqual(got, want) {
			t.Fatalf("admin-owned %q after absorption = %v, want %v", k, got, want)
		}
	}
	// Empty previous record: every admin row the body carries is dropped.
	rec = Device{MAC: "aabbccddeeff", Extra: JSONMap{}}
	rec.Absorb(absorbBody(), absorbNow, false)
	for _, k := range adminOwnedKeys {
		if v, ok := rec.Extra[k]; ok {
			t.Fatalf("admin-owned %q introduced by body: %v", k, v)
		}
	}
}

// TestAbsorbWatchdogRowsRejectIntroduction pins the devname materialization
// watchdog's trust class: both rows (wlan_cfg_vap_not_running_misses /
// wlan_cfg_materialization_reboot) are admin-owned prev-or-delete, the
// blocked_sta_sha shape — a device body can neither introduce, forge, nor
// clear them. The realistic forging shape: the device knows its cfgversion
// from the adoption echo (the same echo Absorb reads into AppliedCfg), so a
// forged marker carrying that very cfgversion plus a forged counter=1 would
// pre-arm the auto-heal and permanently suppress the boot-race grace for
// that config — rejection is the whole point of the class move.
func TestAbsorbWatchdogRowsRejectIntroduction(t *testing.T) {
	cv := "aaaabbbbccccdddd"
	body := map[string]any{
		"model": "U7PG2", "version": "6.8.2.15592",
		"cfgversion":                      cv,
		"wlan_cfg_materialization_reboot": JSONMap{"cfgversion": cv},
		"wlan_cfg_vap_not_running_misses": float64(1),
	}
	rec := Device{MAC: "aabbccddeeff"}
	rec.Absorb(body, absorbNow, false)
	for _, k := range []string{"wlan_cfg_materialization_reboot", "wlan_cfg_vap_not_running_misses"} {
		if v, ok := rec.Extra[k]; ok {
			t.Fatalf("body introduced watchdog row %q: %v", k, v)
		}
	}
	if rec.AppliedCfg != cv {
		t.Fatalf("AppliedCfg = %q, want the forged cfgversion (the forging mechanism the body exploits)", rec.AppliedCfg)
	}

	// Once the engine wrote the rows (the armed and mid-window shapes), a
	// body copy cannot clobber them and a sparse heartbeat cannot drop
	// them — the survival the watchdog needs holds under prev-or-delete.
	seeded := Device{MAC: "aabbccddeeff", Extra: JSONMap{
		"wlan_cfg_materialization_reboot": JSONMap{"cfgversion": cv},
		"wlan_cfg_vap_not_running_misses": float64(1),
	}}
	seeded.Absorb(body, absorbNow, false)
	if got, want := seeded.Extra["wlan_cfg_materialization_reboot"].(JSONMap)["cfgversion"], cv; got != want {
		t.Fatalf("armed marker clobbered by body copy: %v, want %v", got, want)
	}
	if got, want := seeded.Extra["wlan_cfg_vap_not_running_misses"], float64(1); got != want {
		t.Fatalf("armed counter clobbered by body copy: %v, want %v", got, want)
	}
	seeded.Absorb(map[string]any{"model": "U7PG2"}, absorbNow, false)
	if _, ok := seeded.Extra["wlan_cfg_materialization_reboot"]; !ok {
		t.Fatal("sparse heartbeat dropped the armed marker")
	}
	if _, ok := seeded.Extra["wlan_cfg_vap_not_running_misses"]; !ok {
		t.Fatal("sparse heartbeat dropped the armed counter")
	}
}

// TestAbsorbFactoryResetSweepExcludesSiteCache pins reset completion's sweep
// shape: it clears exactly the per-device controller state plus the devname
// materialization watchdog's two admin-owned rows (the marker/counter must
// not survive reset completion — see the factory-reset-sweep comment in
// trustpolicy.go) and never the per-device SSH password caches (they hold
// the DEVICE's last controller-pushed password and deliberately survive the
// demotion; both caches are admin-owned, so the class itself cannot land in
// the sweep either).
func TestAbsorbFactoryResetSweepExcludesSiteCache(t *testing.T) {
	for _, k := range FactoryResetSweepKeys {
		if k == SSHSha512PasswdKey || k == SSHMd5PasswdKey {
			t.Fatal("reset completion must not clear the per-device ssh password caches")
		}
		if !containsKey(controllerOwnedKeys, k) &&
			k != "wlan_cfg_vap_not_running_misses" && k != "wlan_cfg_materialization_reboot" &&
			k != FactoryResetInFlightKey {
			t.Fatalf("sweep key %q is neither controller-owned nor explicitly reset-swept", k)
		}
	}
	if containsKey(controllerOwnedKeys, SSHSha512PasswdKey) || containsKey(controllerOwnedKeys, SSHMd5PasswdKey) {
		t.Fatal("the ssh password caches must be admin-owned")
	}
	if !containsKey(adminOwnedKeys, "wlan_cfg_vap_not_running_misses") ||
		!containsKey(adminOwnedKeys, "wlan_cfg_materialization_reboot") ||
		!containsKey(adminOwnedKeys, FactoryResetInFlightKey) {
		t.Fatal("watchdog/reset rows must be admin-owned while still swept")
	}
}

// TestAbsorbTypedFields pins the non-Extra column behavior: string fields
// take the body verbatim (absent → ""), cfgversion only moves AppliedCfg
// on a non-empty string, the stat snapshot lands in LastUps, timestamps
// follow the first/last-seen rules, and both GCM signals sticky-set
// AESGCM.
func TestAbsorbTypedFields(t *testing.T) {
	rec := absorbFixture()
	rec.Absorb(absorbBody(), absorbNow, false)
	if rec.Model != "U7PG2" || rec.Firmware != "6.8.2.15592" || rec.Serial != "F409NEW11111" ||
		rec.IP != "10.0.0.9" || rec.InformURL != "http://ctrl:8080/inform" {
		t.Fatalf("typed body fields not absorbed: %+v", rec)
	}
	if rec.AppliedCfg != "new-cfg" {
		t.Fatalf("AppliedCfg = %q, want new body cfgversion", rec.AppliedCfg)
	}
	if !reflect.DeepEqual(map[string]any(rec.LastUps), absorbBody()["stat"]) {
		t.Fatalf("LastUps = %v, want the body's stat snapshot", rec.LastUps)
	}
	if rec.LastSeen != absorbNow.Unix() || rec.FirstSeen != 1690000000 {
		t.Fatalf("seen stamps = %d/%d, want preserved first + fresh last", rec.FirstSeen, rec.LastSeen)
	}
	// A NEVER-seen record gets its FirstSeen stamped too.
	fresh := Device{MAC: "aabbccddeeff"}
	fresh.Absorb(sparseBody(), absorbNow, false)
	if fresh.FirstSeen != absorbNow.Unix() {
		t.Fatalf("FirstSeen = %d, want now on first sight", fresh.FirstSeen)
	}
	// an EMPTY cfgversion does not clear the stamped value
	fresh.AppliedCfg = "keep-me"
	fresh.Absorb(sparseBody(), absorbNow, false)
	if fresh.AppliedCfg != "keep-me" {
		t.Fatalf("AppliedCfg = %q, empty body cfgversion must not clear it", fresh.AppliedCfg)
	}
	// GCM: the transport flag sets it, and the body claim sets it too.
	gcm := Device{MAC: "aabbccddeeff"}
	gcm.Absorb(sparseBody(), absorbNow, true)
	if !gcm.AESGCM {
		t.Fatal("gcmReq did not set AESGCM")
	}
	claim := Device{MAC: "aabbccddeeff"}
	claim.Absorb(map[string]any{"x_aes_gcm": true}, absorbNow, false)
	if !claim.AESGCM {
		t.Fatal("body x_aes_gcm claim did not set AESGCM")
	}
}

// sparseBody omits everything interesting — the heartbeat shape.
func sparseBody() map[string]any {
	return map[string]any{"model": "U7PG2", "version": "6.8.2.15592"}
}

// containsKey is a tiny helper the class-shape assertions share.
func containsKey(keys []string, want string) bool {
	for _, k := range keys {
		if k == want {
			return true
		}
	}
	return false
}

// TestTrustRegistrySnapshot is the registry-completeness tripwire: the full
// class lists hard-coded verbatim (wire-named literals, not the governing
// consts — a const drifted from its literal must fail HERE), DeepEqual
// against the package vars. Without this, a class entry silently dropped
// during an edit loses its absorption protection with no failing test
// (append-only edits go unnoticed by the per-key loops above).
func TestTrustRegistrySnapshot(t *testing.T) {
	controllerOwned := []string{
		"wlan_cfg_sha", "wlan_cfg_pending_sha", "wlan_cfg_pending_wlans",
		"wlan_cfg_pending_old_wlans", "wlan_cfg_applied_wlans",
		"wlan_cfg_pending_placements", "wlan_cfg_attempt_sha", "wlan_cfg_attempts",
		"wlan_cfg_last_attempt", "wlan_cfg_delivery_status",
		"wlan_cfg_not_running_misses", "wlan_cfg_offered_cfgversion",
		"client_sessions", "client_disconnect_pending",
	}
	deviceRefreshable := []string{
		"radio_table", "wifi_caps", "fw_caps", "if_table", "ethernet_table",
		"uplink", "has_eth1",
	}
	adminOwned := []string{
		"system_cfg_extra_lines", "mgmt_dev",
		"anonymous_controller_id", "anonymous_site_id",
		"reboot_on_connect", "setdefault_armed",
		"factory_reset_in_flight",
		"blocked_sta", "blocked_sta_sha",
		"wlan_cfg_vap_not_running_misses", "wlan_cfg_materialization_reboot",
		"ssh_sha512passwd", "ssh_md5passwd",
		"led_override", "disabled", "led_override_color_brightness",
		"led_override_color", "ssh_password",
		"regulatory_country_code", "ssh_public_keys",
		"radio_intent", "device_wlans", "cmd_task",
	}
	sweep := []string{
		"wlan_cfg_sha", "wlan_cfg_pending_sha", "wlan_cfg_pending_wlans",
		"wlan_cfg_pending_old_wlans", "wlan_cfg_applied_wlans",
		"wlan_cfg_pending_placements", "wlan_cfg_attempt_sha", "wlan_cfg_attempts",
		"wlan_cfg_last_attempt", "wlan_cfg_delivery_status",
		"wlan_cfg_not_running_misses", "wlan_cfg_offered_cfgversion",
		"client_sessions", "client_disconnect_pending",
		"wlan_cfg_vap_not_running_misses", "wlan_cfg_materialization_reboot",
		"factory_reset_in_flight",
	}
	cases := []struct {
		name string
		got  []string
		want []string
	}{
		{"controller-owned", controllerOwnedKeys, controllerOwned},
		{"device-refreshable", deviceRefreshableKeys, deviceRefreshable},
		{"admin-owned", adminOwnedKeys, adminOwned},
		{"factory-reset sweep", FactoryResetSweepKeys, sweep},
	}
	for _, tc := range cases {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%s registry drifted:\n got %q\nwant %q", tc.name, tc.got, tc.want)
		}
	}
	// The sweep's derived half must be exactly controller-owned minus the
	// ssh password caches — no other exclusion is licensed — plus the
	// admin-owned watchdog rows and reset marker the transition clears; the
	// caches are admin-owned so they cannot be swept by class either.
	for _, k := range []string{SSHSha512PasswdKey, SSHMd5PasswdKey} {
		if containsKey(controllerOwnedKeys, k) {
			t.Error("ssh password cache left the admin-owned class")
		}
		if containsKey(FactoryResetSweepKeys, k) {
			t.Error("the sweep must spare the per-device ssh password caches")
		}
	}
}

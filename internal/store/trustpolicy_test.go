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
		AESGCM: true,
		Extra: JSONMap{
			// controller-owned: wlan bookkeeping + the ssh password cache
			"wlan_cfg_sha":     "prev-sha",
			"ssh_sha512passwd": "$6$prev-hash$",
			"client_sessions":  JSONMap{"aabbccddeeff": JSONMap{"connected": true}},
			// device-refreshable caps
			"radio_table": []any{JSONMap{"name": "ra0"}},
			"wifi_caps":   7,
			// admin-owned rows
			"system_cfg_extra_lines":        []any{"set XMII=no"},
			"mgmt_dev":                      "br0",
			"reboot_on_connect":             true,
			"setdefault_armed":              true,
			"led_override":                  "on",
			"led_override_color_brightness": 42.0,
			"blocked_sta":                   []any{"112233445566"},
			"cmd_task":                      JSONMap{"cmd": "restart"},
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
		"ssh_sha512passwd":              "$6$forged$",
		"client_sessions":               "forged",
		"system_cfg_extra_lines":        []any{"echo pwned"},
		"mgmt_dev":                      "eth9",
		"reboot_on_connect":             "forged",
		"setdefault_armed":              "forged",
		"led_override":                  "off",
		"led_override_color_brightness": 99.0,
		"blocked_sta":                   "forged",
		"cmd_task":                      "forged",
	}
}

// TestAbsorbControllerOwnedPrevWins pins the controller-owned class across
// the wholesale Extra swap — including the ssh_sha512passwd cache, whose
// registry membership is the reason the policy lives in the store now.
func TestAbsorbControllerOwnedPrevWins(t *testing.T) {
	rec := absorbFixture()
	rec.Absorb(absorbBody(), absorbNow, false)
	for _, k := range []string{"wlan_cfg_sha", "ssh_sha512passwd", "client_sessions"} {
		if got, want := rec.Extra[k], absorbFixture().Extra[k]; !reflect.DeepEqual(got, want) {
			t.Fatalf("controller-owned %q missing after absorption: got %v, want %v", k, got, want)
		}
	}
}

// TestAbsorbControllerOwnedRestoresOnlyFromTheRecord pins the loop's exact
// reach: prev-wins can PRESERVE a record value against a forged body, but
// it can never DELETE or FEEL a body copy — a record that never held a class
// member lets a body's forged copy stand (exactly what the inform path
// always did; changing that reach is a behavior change, not a seam move).
func TestAbsorbControllerOwnedRestoresOnlyFromTheRecord(t *testing.T) {
	rec := Device{MAC: "aabbccddeeff", Extra: JSONMap{}}
	body := absorbBody()
	rec.Absorb(body, absorbNow, false)
	for _, k := range ControllerOwnedKeys {
		if v, ok := body[k]; ok {
			if got := rec.Extra[k]; !reflect.DeepEqual(got, v) {
				t.Fatalf("controller-owned %q body copy drifted: %v, want %v", k, got, v)
			}
		} else if v, ok := rec.Extra[k]; ok {
			t.Fatalf("controller-owned %q appeared without record or body: %v", k, v)
		}
	}
	// And even with the transport flag set the restoration still takes the
	// record's cache value, not the forged body copy.
	rec = Device{MAC: "aabbccddeeff", Extra: JSONMap{SSHSha512PasswdKey: "$6$prev-hash$"}}
	rec.Absorb(absorbBody(), absorbNow, true)
	if got, want := rec.Extra[SSHSha512PasswdKey], "$6$prev-hash$"; got != want {
		t.Fatalf("ssh cache not restored against forged body: %v, want %v", got, want)
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
	for _, k := range DeviceRefreshableKeys {
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
	for _, k := range AdminOwnedKeys {
		want := prev.Extra[k]
		if got := rec.Extra[k]; !reflect.DeepEqual(got, want) {
			t.Fatalf("admin-owned %q after absorption = %v, want %v", k, got, want)
		}
	}
	// Empty previous record: every admin row the body carries is dropped.
	rec = Device{MAC: "aabbccddeeff", Extra: JSONMap{}}
	rec.Absorb(absorbBody(), absorbNow, false)
	for _, k := range AdminOwnedKeys {
		if v, ok := rec.Extra[k]; ok {
			t.Fatalf("admin-owned %q introduced by body: %v", k, v)
		}
	}
}

// TestAbsorbFactoryResetSweepExcludesSiteCache pins the demotion sweep's
// shape: it clears exactly the per-device controller state and never the
// site-fact ssh password cache (the first post-reset provisioning
// re-derives that verbatim).
func TestAbsorbFactoryResetSweepExcludesSiteCache(t *testing.T) {
	for _, k := range FactoryResetSweepKeys {
		if k == SSHSha512PasswdKey {
			t.Fatal("the demotion sweep must not clear the site ssh password cache")
		}
		if !containsKey(ControllerOwnedKeys, k) {
			t.Fatalf("sweep key %q is not controller-owned", k)
		}
	}
	if !containsKey(ControllerOwnedKeys, SSHSha512PasswdKey) {
		t.Fatal("ssh_sha512passwd is not declared controller-owned")
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

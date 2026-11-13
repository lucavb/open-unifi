package wireless

import (
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

// exerciseEveryWriter drives each mutating DeliveryState operation against
// one Extra map so that every record key the module can write is present
// afterwards. It is the source of truth for "the keys this module writes":
// the hostile-body test below derives its key list from the map this
// produces, not from a hand-typed list, so a key added to a writer without a
// trust-class decision shows up here automatically.
func exerciseEveryWriter(t *testing.T) store.JSONMap {
	t.Helper()
	wls := []Wlan{{Name: "corp", SSID: "corpnet", Security: "open", Enabled: true, ID: "id1"}}
	extra := store.JSONMap{}

	// A first offer, then a settle that promotes it (writes sha, applied,
	// delivery_status=confirmed), then a second offer (writes pending_old).
	LoadDeliveryState(extra).Offer("h1", 100, wls, map[string]int{"corpnet\x00wifi0": 1}, "cv1")
	extra["vap_table"] = []any{map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": "wifi0", "name": "ath0"}}
	LoadDeliveryState(extra).Settle("cv1")
	LoadDeliveryState(extra).Offer("h2", 200, wls, map[string]int{"corpnet\x00wifi0": 1}, "cv2")

	st := LoadDeliveryState(extra)
	st.RecordNotRunningMiss()
	st.RecordVapNotRunningMiss()
	SetMaterializationRebootArmed(extra, "cv2")
	// RetryDue writes delivery_status=exhausted at the cap.
	extra[store.WlanCfgAttemptsKey] = WlanMaxAttempts
	LoadDeliveryState(extra).RetryDue(time.Unix(300, 0))
	return extra
}

func wlanCfgKeys(m store.JSONMap) []string {
	var out []string
	for k := range m {
		if len(k) >= 9 && k[:9] == "wlan_cfg_" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// declaredWlanCfgKeys is every store.WlanCfg*Key constant.
var declaredWlanCfgKeys = []string{
	store.WlanCfgShaKey, store.WlanCfgPendingShaKey, store.WlanCfgPendingWlansKey,
	store.WlanCfgPendingOldWlansKey, store.WlanCfgAppliedWlansKey,
	store.WlanCfgPendingPlacementsKey, store.WlanCfgAttemptShaKey, store.WlanCfgAttemptsKey,
	store.WlanCfgLastAttemptKey, store.WlanCfgDeliveryStatusKey,
	store.WlanCfgNotRunningMissesKey, store.WlanCfgOfferedCfgversionKey,
	store.WlanCfgVapNotRunningMissesKey, store.WlanCfgMaterializationRebootKey,
}

// TestDeliveryStateKeysSurviveHostileBody is the behavioural close of the
// "a new key silently becomes device-writable" gap: for EVERY key the module
// writes, an inform body that tries to forge it (set a value) or clear it
// (omit it) must leave the record's value untouched through Device.Absorb.
// A record that lacks any of these controller-owned or admin-owned rows must
// also reject a body that tries to introduce one.
func TestDeliveryStateKeysSurviveHostileBody(t *testing.T) {
	written := exerciseEveryWriter(t)
	keys := wlanCfgKeys(written)
	declared := append([]string(nil), declaredWlanCfgKeys...)
	sort.Strings(declared)
	if !reflect.DeepEqual(keys, declared) {
		t.Fatalf("exerciser wrote %v, want every declared key %v — the exerciser lost coverage", keys, declared)
	}

	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			want := written[key]

			// CLEAR: the body omits the key entirely (sparse heartbeat or a
			// device trying to wipe it).
			d := store.Device{MAC: "aabbccddeeff", Extra: cloneExtra(written)}
			d.Absorb(map[string]any{"model": "U7PG2"}, time.Unix(1, 0), false)
			if got, ok := d.Extra[key]; !ok || !reflect.DeepEqual(got, want) {
				t.Fatalf("a body omitting %s changed the record: got %v (present=%v), want %v", key, got, ok, want)
			}

			// FORGE: the body carries its own value for the key.
			d = store.Device{MAC: "aabbccddeeff", Extra: cloneExtra(written)}
			d.Absorb(map[string]any{key: "forged-by-device", "model": "U7PG2"}, time.Unix(1, 0), false)
			if got := d.Extra[key]; !reflect.DeepEqual(got, want) {
				t.Fatalf("a body forging %s overwrote the record: got %v, want %v", key, got, want)
			}

			// INTRODUCE: neither class lets a body create a row absent from
			// the record. Their distinction remains ownership and reset
			// lifecycle, not an inform-body seeding exception.
			d = store.Device{MAC: "aabbccddeeff", Extra: store.JSONMap{}}
			d.Absorb(map[string]any{key: "introduced-by-device", "model": "U7PG2"}, time.Unix(1, 0), false)
			if v, ok := d.Extra[key]; ok {
				t.Fatalf("a body introduced %s = %v", key, v)
			}
		})
	}
}

// TestDeliveryStateWritesOnlyDeclaredKeys pins the reverse direction: every
// wlan_cfg_* key a writer produces is one of the store.WlanCfg*Key constants
// (the single declaration site), so no writer can mint an undeclared key
// that the trust registry has never classed.
func TestDeliveryStateWritesOnlyDeclaredKeys(t *testing.T) {
	declared := map[string]bool{}
	for _, k := range declaredWlanCfgKeys {
		declared[k] = true
	}
	for _, k := range wlanCfgKeys(exerciseEveryWriter(t)) {
		if !declared[k] {
			t.Errorf("writer produced undeclared key %q — declare it in store and class it in the trust registry", k)
		}
	}
}

// cloneExtra shallow-copies the top level, enough here: Absorb replaces the
// map wholesale and the values are never mutated in place by these tests.
func cloneExtra(m store.JSONMap) store.JSONMap {
	out := make(store.JSONMap, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// The persisted bytes are the contract (the byte-compat net the literal-key
// engine tests also guard): exact key names and exact value types.
func TestDeliveryStatePersistedFormatGolden(t *testing.T) {
	wls := []Wlan{{Name: "corp", SSID: "corpnet", Security: "open", Enabled: true, ID: "id1"}}
	extra := store.JSONMap{}
	LoadDeliveryState(extra).Offer("h1", 100, wls, map[string]int{"corpnet\x00wifi0": 1}, "cv1")

	want := store.JSONMap{
		"wlan_cfg_pending_sha":        "h1",
		"wlan_cfg_attempt_sha":        "h1",
		"wlan_cfg_attempts":           1,          // int, not int64/float64
		"wlan_cfg_last_attempt":       int64(100), // int64
		"wlan_cfg_delivery_status":    "pending",
		"wlan_cfg_offered_cfgversion": "cv1",
		"wlan_cfg_pending_wlans":      `[{"Name":"corp","SSID":"corpnet","Security":"open","Passphrase":"","VLAN":0,"Enabled":true,"ID":"id1","Band":"","RadiusServers":null,"RadiusSecret":"","RadiusVLANMode":"","AccountingEnabled":false,"AcctServers":null,"InterimUpdateEnabled":false,"RadiusDASEnabled":false}]`,
		"wlan_cfg_pending_placements": "{\"corpnet\\u0000wifi0\":1}",
	}
	if !reflect.DeepEqual(extra, want) {
		t.Fatalf("persisted Offer bytes changed:\n got %#v\nwant %#v", extra, want)
	}

	// A second offer of the SAME hash increments the budget; a new hash
	// starts a fresh one.
	LoadDeliveryState(extra).Offer("h1", 130, wls, nil, "cv1")
	if extra["wlan_cfg_attempts"] != 2 {
		t.Fatalf("retry of the same hash: attempts = %v, want 2", extra["wlan_cfg_attempts"])
	}
	LoadDeliveryState(extra).Offer("h2", 140, wls, nil, "cv1")
	if extra["wlan_cfg_attempts"] != 1 || extra["wlan_cfg_attempt_sha"] != "h2" {
		t.Fatalf("new hash must reset the budget: %v", extra)
	}
}

func TestDeliveryStateRetryBudget(t *testing.T) {
	extra := store.JSONMap{
		store.WlanCfgAttemptsKey:    WlanMaxAttempts,
		store.WlanCfgLastAttemptKey: int64(0),
	}
	if LoadDeliveryState(extra).RetryDue(time.Unix(1<<30, 0)) {
		t.Fatal("at the attempt cap a retry must never be due")
	}
	if extra[store.WlanCfgDeliveryStatusKey] != "exhausted" {
		t.Fatalf("cap must stamp exhausted, got %v", extra[store.WlanCfgDeliveryStatusKey])
	}
	// Backoff: after attempt 1 the delay is the base; due only once it elapsed.
	extra = store.JSONMap{store.WlanCfgAttemptsKey: 1, store.WlanCfgLastAttemptKey: int64(1000)}
	if LoadDeliveryState(extra).RetryDue(time.Unix(1000+int64(WlanRetryBase/time.Second)-1, 0)) {
		t.Fatal("retry due before the backoff elapsed")
	}
	if !LoadDeliveryState(extra).RetryDue(time.Unix(1000+int64(WlanRetryBase/time.Second), 0)) {
		t.Fatal("retry not due after the backoff elapsed")
	}
}

func TestSettleRequiresPlannedPlacements(t *testing.T) {
	dual := []Wlan{{Name: "corp", SSID: "corpnet", Enabled: true}}
	single := []Wlan{{Name: "corp", SSID: "corpnet", Band: "5g", Enabled: true}}
	placements := `{"corpnet\u0000wifi0":1,"corpnet\u0000wifi1":1}`
	row := func(radio string) any {
		return map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": radio}
	}
	tests := []struct {
		name        string
		wlan        []Wlan
		placement   *string
		vaps        []any
		wantSettled bool
	}{
		{name: "dual-band partial", wlan: dual, placement: &placements, vaps: []any{row("wifi0")}},
		{name: "dual-band complete", wlan: dual, placement: &placements, vaps: []any{row("wifi0"), row("wifi1")}, wantSettled: true},
		{name: "duplicate does not replace missing radio", wlan: dual, placement: &placements, vaps: []any{row("wifi0"), row("wifi0")}},
		{name: "count two duplicate VAP identity rejected", wlan: dual, placement: stringPtr(`{"corpnet\u0000wifi0":2}`), vaps: []any{
			map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": "wifi0", "name": "ath0"},
			map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": "wifi0", "name": "ath0"},
		}},
		{name: "wrong radio", wlan: dual, placement: &placements, vaps: []any{row("other")}},
		{name: "single-band placement", wlan: single, placement: stringPtr(`{"corpnet\u0000wifi1":1}`), vaps: []any{row("wifi1")}, wantSettled: true},
		{name: "legacy metadata uses SSID fallback", wlan: dual, placement: nil, vaps: []any{row("unexpected")}, wantSettled: true},
		{name: "malformed metadata fails closed", wlan: dual, placement: stringPtr(`not-json`), vaps: []any{row("wifi0"), row("wifi1")}},
		{name: "empty metadata fails closed for enabled WLAN", wlan: dual, placement: stringPtr(`{}`), vaps: []any{row("wifi0"), row("wifi1")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extra := settlementExtra(t, tt.wlan, tt.placement, tt.vaps, nil)
			beforePlacements := extra[store.WlanCfgPendingPlacementsKey]
			st := LoadDeliveryState(extra)
			var originalPlacements map[string]int
			if st.placements != nil {
				originalPlacements = make(map[string]int, len(st.placements))
				for k, v := range st.placements {
					originalPlacements[k] = v
				}
			}
			st.Settle("cv1")
			settled := extra[store.WlanCfgDeliveryStatusKey] == "confirmed"
			if settled != tt.wantSettled {
				t.Fatalf("settled = %v, want %v; extra=%v", settled, tt.wantSettled, extra)
			}
			if !settled {
				if got := extra[store.WlanCfgPendingPlacementsKey]; got != beforePlacements {
					t.Fatalf("failed settle mutated persisted placements: got %v, want %v", got, beforePlacements)
				}
				if !reflect.DeepEqual(st.placements, originalPlacements) {
					t.Fatalf("failed settle mutated loaded placements: got %v, want %v", st.placements, originalPlacements)
				}
			}
		})
	}
}

func TestSettleRejectsMalformedPlacementMetadata(t *testing.T) {
	desired := []Wlan{{Name: "corp", SSID: "corpnet", Enabled: true}}
	completeTable := []any{
		map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": "wifi0"},
		map[string]any{"essid": "corpnet", "state": "RUN", "radio_name": "wifi1"},
	}
	tests := []struct {
		name  string
		value any
	}{
		{name: "non-string metadata", value: 7},
		{name: "json null", value: `null`},
		{name: "array shape", value: `[]`},
		{name: "zero count", value: `{"corpnet\u0000wifi0":0}`},
		{name: "negative count", value: `{"corpnet\u0000wifi0":-1}`},
		{name: "missing delimiter", value: `{"corpnet":1}`},
		{name: "empty radio", value: `{"corpnet\u0000":1}`},
		{name: "missing desired SSID", value: `{"other\u0000wifi0":1}`},
		{name: "extraneous SSID", value: `{"corpnet\u0000wifi0":1,"other\u0000wifi1":1}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extra := settlementExtra(t, desired, nil, completeTable, nil)
			extra[store.WlanCfgPendingPlacementsKey] = tt.value
			LoadDeliveryState(extra).Settle("cv1")
			if extra[store.WlanCfgDeliveryStatusKey] == "confirmed" || extra[store.WlanCfgPendingShaKey] != "pending-hash" {
				t.Fatalf("malformed placement metadata settled the delivery: %v", extra)
			}
		})
	}
}

func TestSettleRemovalRequiresEvidenceAndAllowsNoPlacements(t *testing.T) {
	removed := []Wlan{{SSID: "oldnet", Enabled: true}}
	emptyPlacements := stringPtr(`{}`)
	tests := []struct {
		name        string
		vaps        any
		wantSettled bool
	}{
		{name: "removed WLAN still running", vaps: []any{map[string]any{"essid": "oldnet", "state": "RUN", "radio_name": "wifi0"}}},
		{name: "absent table is not evidence", vaps: nil},
		{name: "present empty table proves removal", vaps: []any{}, wantSettled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extra := settlementExtra(t, nil, emptyPlacements, tt.vaps, removed)
			LoadDeliveryState(extra).Settle("cv1")
			settled := extra[store.WlanCfgDeliveryStatusKey] == "confirmed"
			if settled != tt.wantSettled {
				t.Fatalf("settled = %v, want %v; extra=%v", settled, tt.wantSettled, extra)
			}
		})
	}
}

func settlementExtra(t *testing.T, desired []Wlan, placements *string, vaps any, old []Wlan) store.JSONMap {
	t.Helper()
	desiredJSON, err := EncodeStoredWlans(desired)
	if err != nil {
		t.Fatal(err)
	}
	oldJSON, err := EncodeStoredWlans(old)
	if err != nil {
		t.Fatal(err)
	}
	extra := store.JSONMap{
		store.WlanCfgPendingShaKey:      "pending-hash",
		store.WlanCfgPendingWlansKey:    string(desiredJSON),
		store.WlanCfgPendingOldWlansKey: string(oldJSON),
		"vap_table":                     vaps,
	}
	if placements != nil {
		extra[store.WlanCfgPendingPlacementsKey] = *placements
	}
	return extra
}

func stringPtr(s string) *string { return &s }

func TestRuntimeInSync(t *testing.T) {
	run := func(ssid string) []any {
		return []any{map[string]any{"essid": ssid, "state": "RUN"}}
	}
	want := []Wlan{{SSID: "corp", Enabled: true}}
	boolp := func(b bool) *bool { return &b }
	tests := []struct {
		name    string
		extra   store.JSONMap
		desired []Wlan
		want    *bool
	}{
		{"nil extra is unknown", nil, want, nil},
		{"no table is unknown", store.JSONMap{}, want, nil},
		{"empty table is unknown", store.JSONMap{"vap_table": []any{}}, want, nil},
		{"pending delivery reads false even with a RUN table", store.JSONMap{store.WlanCfgPendingShaKey: "h", "vap_table": run("corp")}, want, boolp(false)},
		{"pending row of any type reads false", store.JSONMap{store.WlanCfgPendingShaKey: 5}, want, boolp(false)},
		{"desired RUN reads true", store.JSONMap{"vap_table": run("corp")}, want, boolp(true)},
		{"desired missing reads false", store.JSONMap{"vap_table": run("other")}, want, boolp(false)},
		{"nothing enabled is unknown", store.JSONMap{"vap_table": run("corp")}, []Wlan{{SSID: "corp"}}, nil},
		{"no desired is unknown", store.JSONMap{"vap_table": run("corp")}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RuntimeInSync(store.Device{Extra: tt.extra}, tt.desired)
			switch {
			case got == nil && tt.want == nil:
			case got == nil || tt.want == nil || *got != *tt.want:
				t.Fatalf("RuntimeInSync = %v, want %v", got, tt.want)
			}
		})
	}
}

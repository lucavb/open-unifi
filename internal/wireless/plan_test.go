package wireless

import (
	"reflect"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

// TestWlanListHashRadiusVLANModeEquivalence pins the hash half of the
// ""≡"disabled" radius_vlan_mode equivalence (the render half is
// TestAaaVlanModeSpellingByteIdentity in internal/server/systemcfg): the
// renderer maps both spellings to the same dynamic_vlan=0 row, so an
// envelope whose mode is "" must hash identically to the same envelope
// with "disabled". Before the normalization, a spelling-only flip minted a
// fresh wlan_cfg_sha — one spurious drift full provisioning over
// byte-identical system_cfg. Ports hash at their effective value
// (0 → 1812) for the same reason; the vlan mode follows that precedent.
func TestWlanListHashRadiusVLANModeEquivalence(t *testing.T) {
	base := Wlan{
		ID: "eapcorp", Name: "corp", SSID: "corp",
		Security: "wpa-eap", Enabled: true,
		RadiusServers: []RadiusServer{{IP: "10.1.0.5", Port: 0}},
		RadiusSecret:  "s3cr3t!",
	}
	unset := base // RadiusVLANMode ""
	disabled := base
	disabled.RadiusVLANMode = "disabled"

	hu := WlanListHash([]Wlan{unset})
	hd := WlanListHash([]Wlan{disabled})
	if hu == "" || hu != hd {
		t.Fatalf("radius_vlan_mode %q and %q must hash identically: %q vs %q",
			"", "disabled", hu, hd)
	}
	// Where the render DOES differ, the hash must too: optional/required
	// drive dynamic_vlan 1/2 and keep distinct hashes.
	optional := base
	optional.RadiusVLANMode = "optional"
	if WlanListHash([]Wlan{optional}) == hu {
		t.Fatal("radius_vlan_mode optional must hash differently from disabled (dynamic_vlan 1 vs 0)")
	}
}

// TestWlanListHashAcctFieldsDrift pins the accounting-fields hash rule
// (§12 rows 1013-1014): the fields join the hash ONLY when
// accounting_enabled — an inert profile (acct servers stored, accounting
// off) renders byte-identically to a WLAN with no accounting fields at
// all, so it must hash the same or every stored-but-disabled profile
// mints a spurious drift push. Where rows DO change the hash must
// follow: flipping accounting on, or the interim toggle under it, mints
// a fresh wlan_cfg_sha. Acct ports hash at their effective value
// (0 → 1813), mirroring the auth-port rule. radius_das_enabled never
// joins the hash here (accounting off ⇒ no das/dad rows either — its
// emission gate is accounting_enabled, §12 row 1014 implemented).
func TestWlanListHashAcctFieldsDrift(t *testing.T) {
	base := Wlan{
		ID: "eapcorp", Name: "corp", SSID: "corp",
		Security: "wpa-eap", Enabled: true,
		RadiusServers: []RadiusServer{{IP: "10.1.0.5", Port: 0}},
		RadiusSecret:  "s3cr3t!",
	}
	acct := []RadiusAcctServer{{IP: "10.1.0.9", Port: 0}, {IP: "10.1.0.10", Port: 1813}}

	// Accounting OFF with stored servers: render-inert ⇒ hash-identical
	// to no accounting fields at all.
	inert := base
	inert.AcctServers = acct
	// Defense-shape variant: das set with accounting off changes nothing
	// either (the das gate is accounting_enabled — no das/dad rows).
	dasInert := inert
	dasInert.RadiusDASEnabled = true
	hNone := WlanListHash([]Wlan{base})
	hInert := WlanListHash([]Wlan{inert})
	hDas := WlanListHash([]Wlan{dasInert})
	if hNone == "" || hInert != hNone {
		t.Fatalf("inert acct_servers must hash identically to none: %q vs %q", hInert, hNone)
	}
	if hDas != hNone {
		t.Fatalf("das without accounting must not join the hash (no das/dad rows emit): %q vs %q", hDas, hNone)
	}

	// Accounting ON: rows change, the hash must change.
	on := base
	on.AccountingEnabled = true
	on.AcctServers = acct
	if h := WlanListHash([]Wlan{on}); h == hNone {
		t.Fatal("accounting_enabled must mint a fresh hash (acct rows join the render)")
	}
	// Effective ports: 0 and 1813 render the same row, so they hash the
	// same (the auth-port rule applied to the acct family).
	onExplicit := on
	onExplicit.AcctServers = []RadiusAcctServer{{IP: "10.1.0.9", Port: 1813}, {IP: "10.1.0.10", Port: 1813}}
	if WlanListHash([]Wlan{on}) != WlanListHash([]Wlan{onExplicit}) {
		t.Fatal("acct port 0 and 1813 must hash identically (0 renders as the 1813 default)")
	}
	// The interim toggle under accounting changes rows ⇒ changes the hash.
	onInterim := on
	onInterim.InterimUpdateEnabled = true
	if WlanListHash([]Wlan{onInterim}) == WlanListHash([]Wlan{on}) {
		t.Fatal("interim_update_enabled under accounting must mint a fresh hash (interim rows join the render)")
	}
	// The das toggle under accounting changes rows ⇒ changes the hash
	// (the das/dad rows join the render; the fw_caps residual is
	// documented on WlanListHash).
	onDas := on
	onDas.RadiusDASEnabled = true
	if WlanListHash([]Wlan{onDas}) == WlanListHash([]Wlan{on}) {
		t.Fatal("radius_das_enabled under accounting must mint a fresh hash (das/dad rows join the render)")
	}
}

// planAgreementDevice is a two-radio record (one ng, one na) for the plan
// agreement test; radio_table is the device-refreshable cap the vap plan
// reads.
func planAgreementDevice() store.Device {
	return store.Device{
		MAC: "78:8a:20:00:00:01", Model: "U7PG2",
		Extra: store.JSONMap{
			"radio_table": []any{
				map[string]any{"name": "rai0", "radio": "ng"},
				map[string]any{"name": "rai1", "radio": "na"},
			},
		},
	}
}

// TestPlanProvisioningAgreement pins the plan-level statement of the
// hash/render agreement invariant (the prose block on WlanListHash): the
// drift hash, the vap placements and the wireless rows now travel in ONE
// value computed from ONE (device, envelope) pair, so the drift decision's
// hash can never come from a different envelope read than the rows the
// renderer visits. Two directions hold for the deltas tried here:
//
//   - rows move (a change reflected in the aaa.<n>/wireless.<n> content —
//     the plan's VapPlan rows) ⇒ the hash moves with them, and
//   - the hash stays (the render-inert normalizations: radius port 0≡1812,
//     acct port 0≡1813, accounting-gated inert fields, vlan mode
//     ""≡"disabled", band ""≡"both") ⇒ the settle-relevant rows
//     (placements) stay too.
//
// The DAS residual's device arm (fw_caps, systemcfg's supportsDasDad) is
// outside this package and stays a documented, bounded asymmetry on
// WlanListHash; its live pins remain the zz_* scratch gates, and the render
// halves live in internal/server/systemcfg's renderer tests.
func TestPlanProvisioningAgreement(t *testing.T) {
	d := planAgreementDevice()
	base := []Wlan{
		{Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correcthorse",
			VLAN: 42, Enabled: true, ID: "i1"},
		{Name: "iot", SSID: "iot", Security: "wpa-eap", Enabled: true, ID: "i2",
			RadiusServers: []RadiusServer{{IP: "10.0.0.5", Port: 0}}, RadiusSecret: "s3cr3t!"},
	}
	p := PlanProvisioning(d, base)

	// Composition: one call produces all three halves, mutually consistent.
	if p.DriftHash != WlanListHash(base) {
		t.Fatal("plan drift hash must be WlanListHash of the same envelope")
	}
	vaps, radios := PlanVaps(d, base)
	if !reflect.DeepEqual(p.Vaps, vaps) || !reflect.DeepEqual(p.Radios, radios) {
		t.Fatal("plan rows must be PlanVaps' output for the same (device, envelope)")
	}
	if len(p.Vaps) != 4 { // both wlans ride BOTH radios (band default "both")
		t.Fatalf("want 4 planned vaps, got %d", len(p.Vaps))
	}
	wantPlacements := map[string]int{}
	for _, v := range vaps {
		wantPlacements[SSIDOf(v.Wlan)+"\x00"+v.Phyname]++
	}
	if !reflect.DeepEqual(p.Placements, wantPlacements) {
		t.Fatalf("plan placements = %v, want %v", p.Placements, wantPlacements)
	}

	// rows move ⇒ hash moves: every row-moving delta below changes the
	// emitted aaa/wireless rows (per docs/PROTOCOL-systemcfg-wireless.md
	// §4/§5) and must mint a fresh DriftHash.
	rowMovers := map[string][]Wlan{
		"ssid":     {{Name: "corp", SSID: "corp-hq", Security: "wpa-p", Passphrase: "correcthorse", VLAN: 42, Enabled: true, ID: "i1"}, base[1]},
		"psk":      {{Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correctbat", VLAN: 42, Enabled: true, ID: "i1"}, base[1]},
		"vlan":     {{Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correcthorse", VLAN: 43, Enabled: true, ID: "i1"}, base[1]},
		"enabled":  {{Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correcthorse", VLAN: 42, Enabled: false, ID: "i1"}, base[1]},
		"security": {{Name: "corp", SSID: "corp", Security: "open", Enabled: true, ID: "i1"}, base[1]},
	}
	for name, wls := range rowMovers {
		q := PlanProvisioning(d, wls)
		if q.DriftHash == p.DriftHash {
			t.Errorf("%s: row move must mint a fresh drift hash", name)
		}
		if reflect.DeepEqual(q.Vaps, p.Vaps) {
			t.Errorf("%s: row move must move the planned vaps", name)
		}
	}

	// hash stays ⇒ rows stay: the render-inert normalizations keep the hash
	// identical and the settle projection (placements + vap identity keys)
	// unchanged, so resyncing a stored baseline after one of these flips
	// provokes no full provisioning over a byte-identical render.
	inertMovers := map[string]func([]Wlan) []Wlan{
		"radius port 0→1812": func(w []Wlan) []Wlan {
			out := append(w[:0:0], w...)
			out[1].RadiusServers = []RadiusServer{{IP: "10.0.0.5", Port: 1812}}
			return out
		},
		"vlan mode \"\"→disabled": func(w []Wlan) []Wlan {
			out := append(w[:0:0], w...)
			out[1].RadiusVLANMode = "disabled"
			return out
		},
		"inert acct profile": func(w []Wlan) []Wlan {
			out := append(w[:0:0], w...)
			out[1].AcctServers = []RadiusAcctServer{{IP: "10.0.0.9", Port: 0}}
			return out
		},
		// Band spelling: the base omits Band (zero ""), the mover spells it
		// "both" — a real ""→"both" flip. PlanVaps places "" and "both"
		// identically, and the hash input's effective-value normalization
		// makes the two spellings hash identically too; under the OLD
		// verbatim band hashing this mover would mint a fresh hash and
		// FAIL, so it is the pin the normalization owes.
		// NOTE the in-table accounting movers are deliberately NOT here:
		// accounting-on variants hash differently from the untouched base
		// (acct rows join the render), so they belong to the rowMover side
		// of the acct-fields pin in TestWlanListHashAcctFieldsDrift — the
		// inert-profile mover above is the representation this loop's
		// hash-equals-untouched-base contract can carry.
		"band \"\"→\"both\"": func(w []Wlan) []Wlan {
			out := append(w[:0:0], w...)
			out[0].Band = "both"
			return out
		},
	}
	for name, fn := range inertMovers {
		q := PlanProvisioning(d, fn(base))
		if q.DriftHash != p.DriftHash {
			t.Errorf("%s: render-inert spelling must not mint a drift hash", name)
		}
		if !reflect.DeepEqual(q.Placements, p.Placements) {
			t.Errorf("%s: render-inert spelling must not move the placements", name)
		}
	}
}

// TestMissingVapsEvidenceSemantics pins the devname-level watchdog's evidence
// reader (the same proof bar the engine's notRunningEvidence applies at SSID
// level): absent/empty tables are unknown (nil — no positive gap), a
// non-RUN row for a planned devname is a miss, the legacy `status` spelling
// and EqualFold "RUN" case stay honored, non-map rows are skipped, disabled
// WLANs cannot arm anything, and the result comes out sorted.
func TestMissingVapsEvidenceSemantics(t *testing.T) {
	plan := func(aths ...int) []VapPlan {
		vaps := make([]VapPlan, len(aths))
		for i, a := range aths {
			vaps[i] = VapPlan{Wlan: Wlan{Enabled: true}, AthN: a}
		}
		return vaps
	}
	run := map[string]any{"name": "ath0", "state": "RUN"}
	init := map[string]any{"name": "ath0", "state": "INIT"}
	legacy := map[string]any{"name": "ath0", "status": "RUN"}
	lower := map[string]any{"name": "ath0", "state": "run"}

	tests := []struct {
		name     string
		vaps     []VapPlan
		vapTable any
		want     []string
	}{
		{"absent table is unknown", plan(0), nil, nil},
		{"present but non-slice table is unknown", plan(0), "nope", nil},
		{"empty table is unknown", plan(0), []any{}, nil},
		{"planned devname not RUN is a miss", plan(0), []any{init}, []string{"ath0"}},
		{"row with no devname key cannot clear the miss", plan(0), []any{map[string]any{"state": "RUN"}}, []string{"ath0"}},
		{"legacy status spelling is honored", plan(0), []any{legacy}, nil},
		{"lowercase run proves running", plan(0), []any{lower}, nil},
		{"non-map row is skipped", plan(0), []any{"garbage", init}, []string{"ath0"}},
		{"unplanned devnames are ignored", plan(0), []any{map[string]any{"name": "ath9", "state": "INIT"}}, []string{"ath0"}},
		{"one RUN + one not-RUN row", plan(0, 1), []any{run, init}, []string{"ath1"}},
		{"both missing, sorted output (plan order [1,0])", plan(1, 0), []any{map[string]any{"name": "ath1", "state": "INIT"}, init}, []string{"ath0", "ath1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MissingVaps(tt.vaps, tt.vapTable); !equalStrs(got, tt.want) {
				t.Fatalf("MissingVaps = %v, want %v", got, tt.want)
			}
		})
	}

	// A plan of only disabled WLANs contributes no devnames — nothing to
	// arm on, whatever the table carries.
	disabled := []VapPlan{{Wlan: Wlan{Enabled: false}, AthN: 0}}
	if got := MissingVaps(disabled, run); got != nil {
		t.Fatalf("disabled-only plan MissingVaps = %v, want nil", got)
	}
	if got := MissingVaps(disabled, nil); got != nil {
		t.Fatalf("disabled-only plan absent table = %v, want nil", got)
	}
}

// equalStrs compares two devname lists (nil and empty compare equal —
// safe here because MissingVaps only ever returns nil for the unknown
// cases, never a non-nil empty slice).
func equalStrs(a, b []string) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
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

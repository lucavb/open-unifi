package wireless

import "testing"

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

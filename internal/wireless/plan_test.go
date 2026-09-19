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

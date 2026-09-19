package systemcfg

// WPA-EAP inline RADIUS profile emission tests (doc §4.3): the
// radius.auth.<i>.ip/.port/.secret rows in position (right after
// auth_cache, before dynamic_vlan), the dynamic_vlan 0|1|2 variants from
// the vlan_wlan_mode knob, the jar's fixed 4-slot/empty-skip writer shape
// (renderer defense — the admin API makes both unreachable), and the
// profile-less dead-vap alert that must keep firing.

import (
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

// eapEnvelope is one enabled WPA-EAP WLAN (both bands ⇒ aaa.1 on ng and
// aaa.2 on na) with the given inline profile fields.
func eapEnvelope(mode string, servers ...wireless.RadiusServer) []wireless.Wlan {
	return []wireless.Wlan{{
		Name: "corp", SSID: "corp", Security: "wpa-eap", Enabled: true,
		ID: "eapcorp", RadiusSecret: "s3cr3t!",
		RadiusVLANMode: mode, RadiusServers: servers,
	}}
}

func renderWith(t *testing.T, wls []wireless.Wlan) Result {
	t.Helper()
	res, err := Render(renderRecord(), SiteFacts{WLANs: wls})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// aaaExcerpt returns the wireless compound of a render for failure dumps.
func aaaExcerpt(sys string) string {
	i := strings.Index(sys, "# wlans (radio)")
	if i < 0 {
		return sys
	}
	j := strings.Index(sys[i:], "# vlan")
	if j < 0 {
		return sys[i:]
	}
	return sys[i : i+j]
}

// TestAaaRadiusAuthRows pins the full EAP block byte-for-byte and in
// position: mgmt → psk → auth_cache → radius.auth.<i>.* → dynamic_vlan →
// pairwise → pmf.cipher (FID-25 row order), port 0 rendered as the 1812
// default, the profile-level secret on every server row, and none of the
// omitted §4.3 row families (acct/das/dad/interim/keyid/filter_id — §12).
func TestAaaRadiusAuthRows(t *testing.T) {
	res := renderWith(t, eapEnvelope("optional",
		wireless.RadiusServer{IP: "10.1.0.5"},
		wireless.RadiusServer{IP: "10.1.0.6", Port: 18120}))
	want := "aaa.1.wpa.key.1.mgmt=WPA-EAP\n" +
		"aaa.1.wpa.psk=letmeinnow\n" + // no passphrase ⇒ getWpaPreSharedKey() fallback shape
		"aaa.1.auth_cache=enabled\n" +
		"aaa.1.radius.auth.1.ip=10.1.0.5\n" +
		"aaa.1.radius.auth.1.port=1812\n" +
		"aaa.1.radius.auth.1.secret=s3cr3t!\n" +
		"aaa.1.radius.auth.2.ip=10.1.0.6\n" +
		"aaa.1.radius.auth.2.port=18120\n" +
		"aaa.1.radius.auth.2.secret=s3cr3t!\n" +
		"aaa.1.dynamic_vlan=1\n" +
		"aaa.1.wpa.1.pairwise=CCMP\n" +
		"aaa.1.pmf.cipher=AES-128-CMAC\n"
	if !strings.Contains(res.Text, want) {
		t.Fatalf("EAP radius block mismatch:\n--- want ---\n%s--- got ---\n%s", want, aaaExcerpt(res.Text))
	}
	// A supplied passphrase rides the same psk writer verbatim.
	wls := eapEnvelope("", wireless.RadiusServer{IP: "10.1.0.5"})
	wls[0].Passphrase = "correcthorse"
	res = renderWith(t, wls)
	if !strings.Contains(res.Text, "aaa.1.wpa.psk=correcthorse\n") {
		t.Fatalf("EAP psk must carry the passphrase verbatim:\n%s", aaaExcerpt(res.Text))
	}
	// A profile renders NO alert (the dead-vap warn is profile-less only)
	// and none of the omitted row families.
	for _, a := range res.Alerts {
		if strings.Contains(a.Msg, "RADIUS") {
			t.Fatalf("EAP with a profile must not warn: %+v", a)
		}
	}
	for _, omitted := range []string{
		"radius.acct.", "radius.das.", "radius.dad.", "interim_update.",
		"radius_acct_send_keyid", "filter_id=",
	} {
		if strings.Contains(res.Text, omitted) {
			t.Fatalf("omitted §4.3 row family %q present:\n%s", omitted, aaaExcerpt(res.Text))
		}
	}
}

// TestAaaDynamicVlanVariants pins the vlan_wlan_mode → dynamic_vlan
// mapping: ""/disabled → 0, optional → 1, required → 2.
func TestAaaDynamicVlanVariants(t *testing.T) {
	for _, tc := range []struct{ mode, want string }{
		{"", "aaa.1.dynamic_vlan=0\n"},
		{"disabled", "aaa.1.dynamic_vlan=0\n"},
		{"optional", "aaa.1.dynamic_vlan=1\n"},
		{"required", "aaa.1.dynamic_vlan=2\n"},
	} {
		res := renderWith(t, eapEnvelope(tc.mode, wireless.RadiusServer{IP: "10.1.0.5"}))
		if !strings.Contains(res.Text, tc.want) {
			t.Fatalf("mode %q: missing %q:\n%s", tc.mode, tc.want, aaaExcerpt(res.Text))
		}
	}
}

// TestAaaVlanModeSpellingByteIdentity pins the render half of the
// ""≡"disabled" radius_vlan_mode equivalence (the hash half is
// TestWlanListHashRadiusVLANModeEquivalence in internal/wireless): two
// envelopes differing ONLY in the mode spelling must render
// byte-identically, so a spelling flip is never a content change. The SSH
// password hash salts on first render; the delta from the first render is
// seeded into BOTH records and both are re-rendered, so the salt cannot
// masquerade as a spelling diff (the same pattern
// TestRadioIntentWinsOverEcho uses).
func TestAaaVlanModeSpellingByteIdentity(t *testing.T) {
	srv := wireless.RadiusServer{IP: "10.1.0.5"}
	recUnset, recDisabled := renderRecord(), renderRecord()
	res0, err := Render(recUnset, SiteFacts{WLANs: eapEnvelope("", srv)})
	if err != nil {
		t.Fatal(err)
	}
	for _, seed := range []*store.Device{&recUnset, &recDisabled} {
		for k, v := range res0.CredentialDeltas {
			seed.Extra[k] = v
		}
	}
	resUnset, err := Render(recUnset, SiteFacts{WLANs: eapEnvelope("", srv)})
	if err != nil {
		t.Fatal(err)
	}
	resDisabled, err := Render(recDisabled, SiteFacts{WLANs: eapEnvelope("disabled", srv)})
	if err != nil {
		t.Fatal(err)
	}
	if resUnset.Text != resDisabled.Text {
		t.Fatalf("radius_vlan_mode %q and %q must render byte-identically:\n--- unset ---\n%s--- disabled ---\n%s",
			"", "disabled", aaaExcerpt(resUnset.Text), aaaExcerpt(resDisabled.Text))
	}
}

// TestAaaRadiusSlotSemantics pins the jar's writer shape: row index =
// array position in radius_servers (slots 1..4), an empty-IP slot emits
// no rows and is never backfilled, and entries past slot 4 never emit.
// The admin API rejects empty IPs and >4 entries, so this is renderer
// defense (int §791-840: the writer has exactly four slots).
func TestAaaRadiusSlotSemantics(t *testing.T) {
	res := renderWith(t, eapEnvelope("",
		wireless.RadiusServer{IP: "10.0.0.1"},
		wireless.RadiusServer{}, // slot 2: skipped, no backfill
		wireless.RadiusServer{IP: "10.0.0.2"},
		wireless.RadiusServer{IP: "10.0.0.3"},
		wireless.RadiusServer{IP: "10.0.0.4"}, // slot 5: dropped by the cap
	))
	for _, want := range []string{
		"aaa.1.radius.auth.1.ip=10.0.0.1\n",
		"aaa.1.radius.auth.3.ip=10.0.0.2\n",
		"aaa.1.radius.auth.4.ip=10.0.0.3\n",
	} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("missing %q:\n%s", want, aaaExcerpt(res.Text))
		}
	}
	for _, wrong := range []string{"radius.auth.2.", "radius.auth.5."} {
		if strings.Contains(res.Text, wrong) {
			t.Fatalf("slot violation: %q present:\n%s", wrong, aaaExcerpt(res.Text))
		}
	}
}

// TestAaaEapProfileLessAlerts: an EAP WLAN with zero usable servers keeps
// the dead-vap alert (the jar's requireRadiusProfile() invalid-profile
// warn path still emits the vap) and emits no radius rows.
func TestAaaEapProfileLessAlerts(t *testing.T) {
	for _, servers := range [][]wireless.RadiusServer{
		nil,                  // no profile at all
		{{IP: ""}},           // a profile whose only server is empty
		{{IP: ""}, {IP: ""}}, // only empty slots
	} {
		res := renderWith(t, eapEnvelope("", servers...))
		var hit bool
		for _, a := range res.Alerts {
			if strings.Contains(a.Msg, "RADIUS") {
				hit = true
				if a.Where != "" || a.Key != "" {
					t.Fatalf("RADIUS alert must stay message-only: %+v", a)
				}
			}
		}
		if !hit {
			t.Fatalf("profile-less EAP must keep the dead-vap alert (servers=%d)", len(servers))
		}
		if strings.Contains(res.Text, "radius.auth.") {
			t.Fatalf("profile-less EAP must emit no radius rows:\n%s", aaaExcerpt(res.Text))
		}
		if !strings.Contains(res.Text, "aaa.1.dynamic_vlan=0\n") {
			t.Fatalf("profile-less EAP keeps dynamic_vlan=0:\n%s", aaaExcerpt(res.Text))
		}
	}
}

// TestAaaEmptySecretAlerts: an out-of-API EAP envelope with usable servers
// but an empty profile secret (validateWlanEap rejects it at the admin
// API) keeps the jar-shaped emission — the auth rows with `secret=` and
// an empty value — but must ALERT: the vap cannot authenticate against
// RADIUS, and the sibling out-of-API guards (empty-IP slot skip, 5th-slot
// cap, profile-less dead-vap alert) all flag their shapes.
func TestAaaEmptySecretAlerts(t *testing.T) {
	wls := eapEnvelope("optional", wireless.RadiusServer{IP: "10.1.0.5"})
	wls[0].RadiusSecret = ""
	res := renderWith(t, wls)
	if !strings.Contains(res.Text, "aaa.1.radius.auth.1.ip=10.1.0.5\n") ||
		!strings.Contains(res.Text, "aaa.1.radius.auth.1.secret=\n") {
		t.Fatalf("empty-secret profile must keep the jar-shaped rows (empty secret= value):\n%s", aaaExcerpt(res.Text))
	}
	var hit bool
	for _, a := range res.Alerts {
		if strings.Contains(a.Msg, "without a radius secret") {
			hit = true
			if a.Where != "" || a.Key != "" {
				t.Fatalf("empty-secret alert must stay message-only: %+v", a)
			}
		}
		if strings.Contains(a.Msg, "without RADIUS servers") {
			t.Fatalf("servers are configured: the profile-less alert must not fire: %+v", a)
		}
	}
	if !hit {
		t.Fatalf("empty-secret EAP profile must alert, got %+v", res.Alerts)
	}
}

package systemcfg

// RADIUS accounting row emission tests (§12 rows 1013-1014, doc §4.3):
// the radius.acct.<i>.ip/.port/.secret rows in position (after the auth
// rows, before interim_update/dynamic_vlan), port 0 rendered as the 1813
// default, the interim_update rows gated on accounting_enabled AND
// interim_update_enabled, the accounting-off byte-identity (inert stored
// servers render identically to none at all — the "accounting off ⇒
// byte-identical to the pre-lane render" gate), the mirrored acct slot
// semantics (renderer defense — the admin API makes both unreachable),
// and the radius_das_enabled block: no das/dad rows, message-only Alert
// (the admin API rejects the knob; these pin the out-of-API defense).

import (
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

// acctEapEnvelope is one enabled WPA-EAP WLAN (both bands ⇒ aaa.1 on ng
// and aaa.2 on na) with a one-server auth profile, ready for accounting
// mutations by the caller.
func acctEapEnvelope() []wireless.Wlan {
	return eapEnvelope("", wireless.RadiusServer{IP: "10.1.0.5"})
}

// TestAaaRadiusAcctRows pins the accounting-on block byte-for-byte and in
// position: auth rows → acct rows → interim_update rows → dynamic_vlan →
// pairwise → pmf.cipher (doc §4.3 line order 415→420→421; FID-25 row
// order), port 0 rendered as the 1813 acct default, the profile-level
// secret on every acct row (the doc's `<x_secret>` symbol — same
// profile-level secret the auth rows use), and NO das/dad rows (§12 row
// 1014 block). Accounting on WITHOUT the interim toggle emits the acct
// rows and no interim rows.
func TestAaaRadiusAcctRows(t *testing.T) {
	wls := acctEapEnvelope()
	wls[0].AccountingEnabled = true
	wls[0].InterimUpdateEnabled = true
	wls[0].AcctServers = []wireless.RadiusAcctServer{
		{IP: "10.2.0.1"},              // port 0 ⇒ the 1813 default
		{IP: "10.2.0.2", Port: 18131}, // explicit port rides verbatim
	}
	res := renderWith(t, wls)
	want := "aaa.1.radius.auth.1.ip=10.1.0.5\n" +
		"aaa.1.radius.auth.1.port=1812\n" +
		"aaa.1.radius.auth.1.secret=s3cr3t!\n" +
		"aaa.1.radius.acct.1.ip=10.2.0.1\n" +
		"aaa.1.radius.acct.1.port=1813\n" +
		"aaa.1.radius.acct.1.secret=s3cr3t!\n" +
		"aaa.1.radius.acct.2.ip=10.2.0.2\n" +
		"aaa.1.radius.acct.2.port=18131\n" +
		"aaa.1.radius.acct.2.secret=s3cr3t!\n" +
		"aaa.1.interim_update.status=enabled\n" +
		"aaa.1.interim_update.interval=3600\n" +
		"aaa.1.dynamic_vlan=0\n" +
		"aaa.1.wpa.1.pairwise=CCMP\n" +
		"aaa.1.pmf.cipher=AES-128-CMAC\n"
	if !strings.Contains(res.Text, want) {
		t.Fatalf("accounting-on radius block mismatch:\n--- want ---\n%s--- got ---\n%s", want, aaaExcerpt(res.Text))
	}
	// The §12 row 1014 block: no das/dad rows ever, and no das alert when
	// the knob is unset.
	for _, blocked := range []string{"radius.das.", "radius.dad."} {
		if strings.Contains(res.Text, blocked) {
			t.Fatalf("blocked §12 row 1014 family %q present:\n%s", blocked, aaaExcerpt(res.Text))
		}
	}
	for _, a := range res.Alerts {
		if strings.Contains(a.Msg, "radius_das_enabled") {
			t.Fatalf("das knob unset: the block alert must not fire: %+v", a)
		}
	}

	// Accounting on, interim off: acct rows stay, interim rows go.
	wls = acctEapEnvelope()
	wls[0].AccountingEnabled = true
	wls[0].AcctServers = []wireless.RadiusAcctServer{{IP: "10.2.0.1"}}
	res = renderWith(t, wls)
	if !strings.Contains(res.Text, "aaa.1.radius.acct.1.ip=10.2.0.1\n") ||
		!strings.Contains(res.Text, "aaa.1.radius.acct.1.port=1813\n") {
		t.Fatalf("acct rows missing without the interim toggle:\n%s", aaaExcerpt(res.Text))
	}
	for _, absent := range []string{"interim_update.status", "interim_update.interval"} {
		if strings.Contains(res.Text, "aaa.1."+absent) {
			t.Fatalf("interim rows must not emit without interim_update_enabled: %q present", absent)
		}
	}

	// Accounting on with ZERO acct servers: the toggle emits no acct rows
	// (profile-shaped — the radiusprofile stores the toggle and the
	// server list independently), interim rows still follow their own
	// gate.
	wls = acctEapEnvelope()
	wls[0].AccountingEnabled = true
	wls[0].InterimUpdateEnabled = true
	res = renderWith(t, wls)
	if strings.Contains(res.Text, "radius.acct.") {
		t.Fatalf("accounting on with no servers must emit no acct rows:\n%s", aaaExcerpt(res.Text))
	}
	if !strings.Contains(res.Text, "aaa.1.interim_update.status=enabled\n") {
		t.Fatalf("interim rows must follow the interim toggle, not the server list:\n%s", aaaExcerpt(res.Text))
	}
}

// TestAaaRadiusAcctSlotSemantics pins the acct writer's mirrored slot
// shape (§12 row 1013): row index = array position in acct_servers
// (slots 1..4), an empty-IP slot emits no rows and is never backfilled,
// and entries past slot 4 never emit. The admin API rejects empty IPs
// and >4 entries, so this is renderer defense mirroring the auth family
// (TestAaaRadiusSlotSemantics).
func TestAaaRadiusAcctSlotSemantics(t *testing.T) {
	wls := acctEapEnvelope()
	wls[0].AccountingEnabled = true
	wls[0].AcctServers = []wireless.RadiusAcctServer{
		{IP: "10.2.0.1"},
		{}, // slot 2: skipped, no backfill
		{IP: "10.2.0.2"},
		{IP: "10.2.0.3"},
		{IP: "10.2.0.4"}, // slot 5: dropped by the cap
	}
	res := renderWith(t, wls)
	for _, want := range []string{
		"aaa.1.radius.acct.1.ip=10.2.0.1\n",
		"aaa.1.radius.acct.3.ip=10.2.0.2\n",
		"aaa.1.radius.acct.4.ip=10.2.0.3\n",
	} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("missing %q:\n%s", want, aaaExcerpt(res.Text))
		}
	}
	for _, wrong := range []string{"radius.acct.2.", "radius.acct.5."} {
		if strings.Contains(res.Text, wrong) {
			t.Fatalf("acct slot violation: %q present:\n%s", wrong, aaaExcerpt(res.Text))
		}
	}
	// The auth rows are unaffected by acct slot positions.
	if !strings.Contains(res.Text, "aaa.1.radius.auth.1.ip=10.1.0.5\n") {
		t.Fatalf("auth rows must not move with acct slots:\n%s", aaaExcerpt(res.Text))
	}
}

// TestAaaAcctOffByteIdentity pins the accounting-off gate of the brief:
// an envelope with acct servers stored (and the admin-unreachable
// interim/das defense shapes) but accounting_enabled false renders
// BYTE-IDENTICALLY to the same envelope with no accounting fields at
// all — the pre-lane render. The SSH password hash salts on first
// render; the delta from the first render is seeded into BOTH records
// and both are re-rendered, so the salt cannot masquerade as an
// accounting diff (the same pattern TestAaaVlanModeSpellingByteIdentity
// uses).
func TestAaaAcctOffByteIdentity(t *testing.T) {
	inert := acctEapEnvelope()
	inert[0].AcctServers = []wireless.RadiusAcctServer{{IP: "10.2.0.1", Port: 1813}}
	// Stored-unreachable defense shapes (validateWlanEap rejects both
	// at the admin API): the renderer must not emit for them either.
	inert[0].InterimUpdateEnabled = true // without accounting ⇒ no interim rows
	inert[0].RadiusDASEnabled = true     // blocked knob ⇒ no rows, but the Alert below
	plain := acctEapEnvelope()

	recInert, recPlain := renderRecord(), renderRecord()
	res0, err := Render(recInert, SiteFacts{WLANs: inert})
	if err != nil {
		t.Fatal(err)
	}
	for _, seed := range []*store.Device{&recInert, &recPlain} {
		for k, v := range res0.CredentialDeltas {
			seed.Extra[k] = v
		}
	}
	resInert, err := Render(recInert, SiteFacts{WLANs: inert})
	if err != nil {
		t.Fatal(err)
	}
	resPlain, err := Render(recPlain, SiteFacts{WLANs: plain})
	if err != nil {
		t.Fatal(err)
	}
	if resInert.Text != resPlain.Text {
		t.Fatalf("accounting off must render byte-identically to no accounting fields:\n--- inert ---\n%s--- plain ---\n%s",
			aaaExcerpt(resInert.Text), aaaExcerpt(resPlain.Text))
	}
	// The blocked das knob fires its message-only Alert on the inert
	// envelope (out-of-API defense); the plain envelope stays silent.
	var dasHit bool
	for _, a := range resInert.Alerts {
		if strings.Contains(a.Msg, "radius_das_enabled") {
			dasHit = true
			if a.Where != "" || a.Key != "" {
				t.Fatalf("das block alert must stay message-only: %+v", a)
			}
		}
	}
	if !dasHit {
		t.Fatalf("inert envelope with radius_das_enabled must carry the block alert, got %+v", resInert.Alerts)
	}
	for _, a := range resPlain.Alerts {
		if strings.Contains(a.Msg, "radius_das_enabled") {
			t.Fatalf("plain envelope must not carry the das alert: %+v", a)
		}
	}
}

// TestAaaDASBlockedAlerts pins the §12 row 1014 das/dad block on the
// accounting-ON shape too: an out-of-API envelope carrying
// radius_das_enabled gets its acct/interim rows as configured, NEVER
// any das/dad rows, and the message-only block Alert fires in both
// accounting states (the admin API rejects the knob — validateWlanEap
// — so every carrier here is defense).
func TestAaaDASBlockedAlerts(t *testing.T) {
	for _, accounting := range []bool{false, true} {
		wls := acctEapEnvelope()
		wls[0].RadiusDASEnabled = true
		wls[0].AccountingEnabled = accounting
		wls[0].AcctServers = []wireless.RadiusAcctServer{{IP: "10.2.0.1"}}
		res := renderWith(t, wls)
		for _, blocked := range []string{"radius.das.", "radius.dad."} {
			if strings.Contains(res.Text, blocked) {
				t.Fatalf("accounting=%v: blocked family %q present:\n%s", accounting, blocked, aaaExcerpt(res.Text))
			}
		}
		if accounting && !strings.Contains(res.Text, "aaa.1.radius.acct.1.ip=10.2.0.1\n") {
			t.Fatalf("accounting=%v: the das block must not suppress the acct rows:\n%s", accounting, aaaExcerpt(res.Text))
		}
		var hit bool
		for _, a := range res.Alerts {
			if strings.Contains(a.Msg, "radius_das_enabled") {
				hit = true
				if a.Where != "" || a.Key != "" {
					t.Fatalf("das block alert must stay message-only: %+v", a)
				}
			}
		}
		if !hit {
			t.Fatalf("accounting=%v: the das block alert must fire, got %+v", accounting, res.Alerts)
		}
	}
}

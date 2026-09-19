package systemcfg

// RADIUS accounting row emission tests (§12 rows 1013-1014, doc §4.3):
// the radius.acct.<i>.ip/.port/.secret rows in position (after the auth
// rows, before interim_update/dynamic_vlan), port 0 rendered as the 1813
// default, the interim_update rows gated on accounting_enabled AND
// interim_update_enabled, the accounting-off byte-identity (inert stored
// servers render identically to none at all — the "accounting off ⇒
// byte-identical to the pre-lane render" gate), the mirrored acct slot
// semantics (renderer defense — the admin API makes both unreachable),
// and the radius_das_enabled block: the das/dad rows under their
// accounting && radius_das_enabled && hasCapability(0x100000) gate,
// including the cross-render once-flag shape (§12 row 1014 implemented).

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

// dasRecord is renderRecord with the fw_caps DAS/DAD capability bit
// (0x100000) set alongside the base record's SHA-512 bit — the
// gate-open record shape for the das/dad family below.
func dasRecord() store.Device {
	d := renderRecord()
	d.Extra["fw_caps"] = float64(0x400 | 0x100000)
	return d
}

// renderWithRecord renders wls against the given device record.
func renderWithRecord(t *testing.T, d store.Device, wls []wireless.Wlan) Result {
	t.Helper()
	res, err := Render(d, SiteFacts{WLANs: wls})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestAaaRadiusAcctRows pins the accounting-on block byte-for-byte and in
// position: auth rows → acct rows → interim_update rows → dynamic_vlan →
// pairwise → pmf.cipher (doc §4.3 line order 415→420→421; FID-25 row
// order), port 0 rendered as the 1813 acct default, the profile-level
// secret on every acct row (the doc's `<x_secret>` symbol — same
// profile-level secret the auth rows use), and NO das/dad rows when the
// knob is unset (§12 row 1014 gate). Accounting on WITHOUT the interim
// toggle emits the acct rows and no interim rows.
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
	// The §12 row 1014 gate: no das/dad rows when the knob is unset —
	// and no das alert either (the out-of-API Alert is gone with the
	// implemented rows).
	for _, absent := range []string{"radius.das.", "radius.dad."} {
		if strings.Contains(res.Text, absent) {
			t.Fatalf("das/dad family %q present with the knob unset:\n%s", absent, aaaExcerpt(res.Text))
		}
	}
	for _, a := range res.Alerts {
		if strings.Contains(a.Msg, "radius_das_enabled") {
			t.Fatalf("das knob unset: a das alert must not fire: %+v", a)
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
	inert[0].RadiusDASEnabled = true     // without accounting ⇒ no das/dad rows, no Alert
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
	// The admin-unreachable das knob (accounting off) emits nothing and
	// carries no Alert of any kind — the das block Alert is gone with
	// the implemented rows (silent gate-closed skip is the jar shape).
	for _, a := range append(resInert.Alerts, resPlain.Alerts...) {
		if strings.Contains(a.Msg, "radius_das_enabled") {
			t.Fatalf("das knob without accounting must be silent: %+v", a)
		}
	}
	if strings.Contains(resInert.Text, "radius.das.") || strings.Contains(resInert.Text, "radius.dad.") {
		t.Fatalf("das knob without accounting must emit no das/dad rows:\n%s", aaaExcerpt(resInert.Text))
	}
}

// TestAaaDASRowsGateOpen pins the das/dad row family on the gate-open
// shape (§12 row 1014 implemented — int offsets 176-299, 527-736):
// accounting_enabled && radius_das_enabled && hasCapability(0x100000).
// Case 1 pins the EXACT aaa.1 row order: dad.status → dad.port=3799 →
// das.status → das.port (3800 + the aaa index) → dad.status AGAIN (the
// duplicate is the jar's own byte shape) → then the acct rows → then
// das.client/das.secret (once) → dad.client.<i>.cidr (<ip>/32, the acct
// server bean's own ip field) / dad.client.<i>.secret. The cidr source
// is the EXACT field the admin API already configures — the reason the
// block dissolved.
func TestAaaDASRowsGateOpen(t *testing.T) {
	wls := acctEapEnvelope()
	wls[0].AccountingEnabled = true
	wls[0].RadiusDASEnabled = true
	wls[0].AcctServers = []wireless.RadiusAcctServer{{IP: "10.2.0.1"}}
	res := renderWithRecord(t, dasRecord(), wls)
	want := "aaa.1.auth_cache=enabled\n" +
		"aaa.1.radius.auth.1.ip=10.1.0.5\n" +
		"aaa.1.radius.auth.1.port=1812\n" +
		"aaa.1.radius.auth.1.secret=s3cr3t!\n" +
		"aaa.1.radius.dad.status=enabled\n" +
		"aaa.1.radius.dad.port=3799\n" +
		"aaa.1.radius.das.status=enabled\n" +
		"aaa.1.radius.das.port=3801\n" +
		"aaa.1.radius.dad.status=enabled\n" +
		"aaa.1.radius.acct.1.ip=10.2.0.1\n" +
		"aaa.1.radius.acct.1.port=1813\n" +
		"aaa.1.radius.acct.1.secret=s3cr3t!\n" +
		"aaa.1.radius.das.client=10.2.0.1\n" +
		"aaa.1.radius.das.secret=s3cr3t!\n" +
		"aaa.1.radius.dad.client.1.cidr=10.2.0.1/32\n" +
		"aaa.1.radius.dad.client.1.secret=s3cr3t!\n"
	if !strings.Contains(res.Text, want) {
		t.Fatalf("gate-open das/dad aaa.1 block mismatch:\n--- want ---\n%s--- got ---\n%s", want, aaaExcerpt(res.Text))
	}
	// Case 1's once per DEVICE RENDER shape spans the wlan's second band
	// too (the same wlan plans aaa.2 on na): dad.status/dad.port never
	// re-emit with the port.
	if strings.Contains(res.Text, "aaa.2.radius.dad.port=3799\n") {
		t.Fatalf("dad.port must emit once per device render, not per aaa index:\n%s", aaaExcerpt(res.Text))
	}
	if !strings.Contains(res.Text, "aaa.2.radius.das.status=enabled\n") ||
		!strings.Contains(res.Text, "aaa.2.radius.das.port=3802\n") ||
		!strings.Contains(res.Text, "aaa.2.radius.dad.status=enabled\n") {
		t.Fatalf("aaa.2 must carry its own das.status/port=3802/dad.status:\n%s", aaaExcerpt(res.Text))
	}
}

// TestAaaDASOnceFlagAcrossVaps is the cross-render once-flag test
// (jar local 19): TWO EAP wlans, both accounting+das, gate open. The
// dad.status/dad.port pair emits once — on the FIRST emitted aaa index
// only — while das.status/das.port/dad.status re-emit per index with
// das.port tracking the aaa index, and every emitted index gets its own
// das.client/das.secret pair once (jar local 8).
func TestAaaDASOnceFlagAcrossVaps(t *testing.T) {
	wl2 := func(name, server string) wireless.Wlan {
		return wireless.Wlan{
			Name: name, SSID: name, Security: "wpa-eap", Enabled: true,
			ID: "eap" + name, RadiusSecret: "s3cr3t!",
			RadiusServers:     []wireless.RadiusServer{{IP: "10.1.0.5"}},
			AccountingEnabled: true, RadiusDASEnabled: true,
			AcctServers: []wireless.RadiusAcctServer{{IP: server}},
		}
	}
	wls := []wireless.Wlan{wl2("corp", "10.2.0.1"), wl2("eng", "10.2.0.9")}
	res := renderWithRecord(t, dasRecord(), wls)
	if !strings.Contains(res.Text, "aaa.1.radius.dad.status=enabled\n") ||
		!strings.Contains(res.Text, "aaa.1.radius.dad.port=3799\n") ||
		!strings.Contains(res.Text, "aaa.1.radius.das.status=enabled\n") ||
		!strings.Contains(res.Text, "aaa.1.radius.das.port=3801\n") {
		t.Fatalf("aaa.1 must carry the first-emitted das/dad block:\n%s", aaaExcerpt(res.Text))
	}
	// aaa.2: NO dad.port, still das.status + das.port=3802 + dad.status.
	if strings.Contains(res.Text, "aaa.2.radius.dad.port=3799\n") {
		t.Fatalf("dad.port must not re-emit on aaa.2 (jar local 19):\n%s", aaaExcerpt(res.Text))
	}
	if !strings.Contains(res.Text, "aaa.2.radius.das.status=enabled\n") ||
		!strings.Contains(res.Text, "aaa.2.radius.das.port=3802\n") ||
		!strings.Contains(res.Text, "aaa.2.radius.dad.status=enabled\n") {
		t.Fatalf("aaa.2 must carry das.status/port=3802/dad.status:\n%s", aaaExcerpt(res.Text))
	}
	// The na band's indexes keep the same shape (3803/3804, no
	// dad.port re-emit).
	for _, x := range []struct{ idx, port string }{
		{"3", "3803"}, {"4", "3804"},
	} {
		if !strings.Contains(res.Text, "aaa."+x.idx+".radius.das.port="+x.port+"\n") ||
			!strings.Contains(res.Text, "aaa."+x.idx+".radius.das.status=enabled\n") ||
			!strings.Contains(res.Text, "aaa."+x.idx+".radius.dad.status=enabled\n") {
			t.Fatalf("aaa.%s must carry das.status/port=%s/dad.status:\n%s", x.idx, x.port, aaaExcerpt(res.Text))
		}
		if strings.Contains(res.Text, "aaa."+x.idx+".radius.dad.port=3799\n") {
			t.Fatalf("dad.port must not re-emit on aaa.%s:\n%s", x.idx, aaaExcerpt(res.Text))
		}
	}
	// dad.status/dad.port exactly once per device render (jar local 19);
	// one das.client pair per emitted index (two wlans × two bands ⇒ 4
	// emitted indexes).
	if got := strings.Count(res.Text, "radius.dad.port=3799\n"); got != 1 {
		t.Fatalf("dad.port must emit exactly once per render, got %d:\n%s", got, aaaExcerpt(res.Text))
	}
	// One das.client pair per emitted index, fed by each vap's own wlan:
	// vaps group by radio (both ng vaps first, then both na), so 1&3 =
	// corp (10.2.0.1) and 2&4 = eng (10.2.0.9).
	for _, x := range []struct {
		idxs   []string
		server string
	}{
		{[]string{"1", "3"}, "10.2.0.1"},
		{[]string{"2", "4"}, "10.2.0.9"},
	} {
		for _, idx := range x.idxs {
			if !strings.Contains(res.Text, "aaa."+idx+".radius.das.client="+x.server+"\n") ||
				!strings.Contains(res.Text, "aaa."+idx+".radius.das.secret=s3cr3t!\n") {
				t.Fatalf("aaa.%s must emit its own das.client pair once:\n%s", idx, aaaExcerpt(res.Text))
			}
		}
	}
	if got := strings.Count(res.Text, "radius.das.client="); got != 4 {
		t.Fatalf("exactly one das.client per emitted index expected, got %d:\n%s", got, aaaExcerpt(res.Text))
	}
}

// TestAaaDASGateClosedSilent pins the device capability arm of the gate:
// das on, accounting on, but the record lacks the DAS/DAD fw_caps bit
// (0x100000) — either way the jar's hasCapability evaluates to
// capability 0 — emits NO das/dad rows anywhere, carries no Alert
// (silent skip is the jar shape, the ledbar precedent), and leaves the
// acct rows byte-for-byte unchanged.
func TestAaaDASGateClosedSilent(t *testing.T) {
	wls := acctEapEnvelope()
	wls[0].AccountingEnabled = true
	wls[0].RadiusDASEnabled = true
	wls[0].AcctServers = []wireless.RadiusAcctServer{{IP: "10.2.0.1"}}

	// A record reporting fw_caps WITHOUT the DAS bit (the base fixture's
	// 0x400), and a record with no fw_caps field at all.
	noBit := renderRecord()
	noCaps := renderRecord()
	delete(noCaps.Extra, "fw_caps")
	for name, d := range map[string]store.Device{"fw_caps without the DAS bit": noBit, "no fw_caps": noCaps} {
		res := renderWithRecord(t, d, wls)
		if strings.Contains(res.Text, "radius.das.") || strings.Contains(res.Text, "radius.dad.") {
			t.Fatalf("%s: no das/dad rows may emit:\n%s", name, aaaExcerpt(res.Text))
		}
		if !strings.Contains(res.Text, "aaa.1.radius.acct.1.ip=10.2.0.1\n") ||
			!strings.Contains(res.Text, "aaa.1.radius.acct.1.port=1813\n") {
			t.Fatalf("%s: the gate must not disturb the acct rows:\n%s", name, aaaExcerpt(res.Text))
		}
		for _, a := range res.Alerts {
			if strings.Contains(a.Msg, "radius_das_enabled") {
				t.Fatalf("%s: gate-closed DAS must be a silent skip, got %+v", name, a)
			}
		}
	}
}

// TestAaaDASOnceFlagResetsPerRender pins the once-flag's scope: a FRESH
// render of the same gate-open envelope re-emits the dad.status/
// dad.port pair (rd.dasDadStatusDone starts at its zero value per
// render, jar local 19 initialized false per device render — int
// offsets 1435-1439).
func TestAaaDASOnceFlagResetsPerRender(t *testing.T) {
	wls := acctEapEnvelope()
	wls[0].AccountingEnabled = true
	wls[0].RadiusDASEnabled = true
	wls[0].AcctServers = []wireless.RadiusAcctServer{{IP: "10.2.0.1"}}
	for i := 0; i < 2; i++ {
		res := renderWithRecord(t, dasRecord(), wls)
		if !strings.Contains(res.Text, "aaa.1.radius.dad.status=enabled\n") ||
			!strings.Contains(res.Text, "aaa.1.radius.dad.port=3799\n") {
			t.Fatalf("render %d: the dad block must emit on a fresh device render:\n%s", i+1, aaaExcerpt(res.Text))
		}
	}
}

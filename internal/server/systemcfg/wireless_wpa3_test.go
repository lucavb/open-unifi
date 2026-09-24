package systemcfg

// WPA3-Personal emission tests (doc §4.3): the two WPA3 securities —
// wpa3-p (SAE-only) and wpa2-wpa3 (transition) — pinned against the
// committed jar-derived fixtures (fixture_wpa3_only_aaa.txt /
// fixture_wpa2_wpa3_aaa.txt: full aaa.1 blocks with per-row javap
// provenance), plus the regressions that keep the older securities
// byte-identical (wpa=3, pmf disabled/0, mgmt WPA-PSK — FID-4 must not
// flip for wpa-p), the SAE psk fallback shape, and the negative-shape
// pins (no sae.anti_clogging/sae.sync/sae.groups rows, no dynamic_vlan,
// no radius/auth_cache rows on WPA3 vaps).

import (
	_ "embed"
	"strconv"
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/wireless"
)

// The jar-derived byte contracts, fixture rows only (the '#' provenance
// header is stripped by fixtureRows before comparing).
//
//go:embed fixture_wpa3_only_aaa.txt
var fixtureWpa3OnlyAaa string

//go:embed fixture_wpa2_wpa3_aaa.txt
var fixtureWpa2Wpa3Aaa string

// wpa3Envelope is one enabled WPA3-family WLAN (both bands ⇒ aaa.1 on ng
// and aaa.2 on na); SSID/passphrase/id match the fixture headers.
func wpa3Envelope(security, ssid, psk, id string) []wireless.Wlan {
	return []wireless.Wlan{{
		Name: ssid, SSID: ssid, Security: security, Passphrase: psk,
		Enabled: true, ID: id,
	}}
}

// aaaBlock returns the ordered aaa.<n>.* rows of a render (the block is
// contiguous in the emitted text; the prefix scan keeps the comparison
// robust to surrounding sections).
func aaaBlock(sys string, n int) []string {
	prefix := "aaa." + strconv.Itoa(n) + "."
	var rows []string
	for _, l := range strings.Split(sys, "\n") {
		if strings.HasPrefix(l, prefix) {
			rows = append(rows, l)
		}
	}
	return rows
}

// fixtureRows strips the '#' provenance header from an embedded fixture,
// leaving the bare rows for the block comparison.
func fixtureRows(fix string) []string {
	var rows []string
	for _, l := range strings.Split(fix, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			rows = append(rows, l)
		}
	}
	return rows
}

// TestAaaWpa3OnlyFixture pins the FULL wpa3-p aaa.1 block (order and
// values) to the jar-derived fixture: pmf required (enabled/2), the
// B/F-forced wpa=2, the wpa3.support/transition/ft rows in position after
// id, the broadcast sae.psk.1 pair, mgmt=SAE, and the always-written
// wpa.psk row.
func TestAaaWpa3OnlyFixture(t *testing.T) {
	res := renderWith(t, wpa3Envelope("wpa3-p", "wpa3only", "correcthorse", "w3only"))
	if got, want := strings.Join(aaaBlock(res.Text, 1), "\n"),
		strings.Join(fixtureRows(fixtureWpa3OnlyAaa), "\n"); got != want {
		t.Fatalf("wpa3-p aaa.1 block mismatch:\n--- fixture ---\n%s\n--- got ---\n%s",
			want, got)
	}
}

// TestAaaWpa2Wpa3Fixture pins the FULL wpa2-wpa3 aaa.1 block to the
// fixture: pmf optional (enabled/1), wpa=2, wpa3.transition=enabled, and
// the transition DUPLICATE — the B/O0OO psk sub-writer's wpa.psk row
// ahead of the mgmt writer's own wpa.psk row (same value), with the
// sae.psk.1 pair absent.
func TestAaaWpa2Wpa3Fixture(t *testing.T) {
	res := renderWith(t, wpa3Envelope("wpa2-wpa3", "w23mix", "transition-psk", "w23mix"))
	if got, want := strings.Join(aaaBlock(res.Text, 1), "\n"),
		strings.Join(fixtureRows(fixtureWpa2Wpa3Aaa), "\n"); got != want {
		t.Fatalf("wpa2-wpa3 aaa.1 block mismatch:\n--- fixture ---\n%s\n--- got ---\n%s",
			want, got)
	}
}

// TestAaaWpa3BothBands mirrors the EAP pin: a both-band WLAN renders the
// same WPA3 row families on the second vap (aaa.2), index-shifted only.
func TestAaaWpa3BothBands(t *testing.T) {
	res := renderWith(t, wpa3Envelope("wpa2-wpa3", "w23mix", "transition-psk", "w23mix"))
	for _, want := range []string{
		"aaa.2.wpa3.support=enabled\n",
		"aaa.2.wpa3.transition=enabled\n",
		"aaa.2.wpa3.ft.status=disabled\n",
		"aaa.2.wpa.key.1.mgmt=SAE\n",
		"aaa.2.wpa.1.pairwise=CCMP\n",
		"aaa.2.pmf.status=enabled\n",
		"aaa.2.pmf.mode=1\n",
		"aaa.2.wpa=2\n",
	} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("missing %q on the na vap:\n%s", want, aaaExcerpt(res.Text))
		}
	}
}

// TestAaaWpa3FallbackPsk pins the SAE psk sub-writer's fallback shape:
// an empty passphrase rides the same getWpaPreSharedKey() fallback as
// the wpa.psk row ("letmeinnow" — §8), in the sae.psk.1 pair (wpa3-p)
// and in both transition wpa.psk rows. Only reachable via envelopes
// built outside the admin API (validateWlan enforces >= 8 chars).
func TestAaaWpa3FallbackPsk(t *testing.T) {
	res := renderWith(t, wpa3Envelope("wpa3-p", "wpa3only", "", "w3only"))
	for _, want := range []string{
		"aaa.1.sae.psk.1.psk=letmeinnow\n",
		"aaa.1.sae.psk.1.mac=ff:ff:ff:ff:ff:ff\n",
		"aaa.1.wpa.psk=letmeinnow\n",
	} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("fallback shape missing %q:\n%s", want, aaaExcerpt(res.Text))
		}
	}
	res = renderWith(t, wpa3Envelope("wpa2-wpa3", "w23mix", "", "w23mix"))
	if got := strings.Count(res.Text, "aaa.1.wpa.psk=letmeinnow\n"); got != 2 {
		t.Fatalf("transition fallback must keep the DUPLICATE wpa.psk pair, got %d:\n%s",
			got, aaaExcerpt(res.Text))
	}
}

// TestAaaWpa3NegativeShapes pins the unset-knob absences: the v1 admin
// API exposes no sae_anti_clogging/sae_sync/sae_groups/sae_psk/
// sae_psk_vlan_required knobs, so the jar emits none of those rows, and
// no EAP row family can appear on a WPA3 vap.
func TestAaaWpa3NegativeShapes(t *testing.T) {
	for _, env := range [][]wireless.Wlan{
		wpa3Envelope("wpa3-p", "wpa3only", "correcthorse", "w3only"),
		wpa3Envelope("wpa2-wpa3", "w23mix", "transition-psk", "w23mix"),
	} {
		res := renderWith(t, env)
		for _, absent := range []string{
			"sae.anti_clogging", "sae.sync", "sae.groups", "sae.has_groups",
			"sae.psk.2", "dynamic_vlan", "radius.auth.", "auth_cache",
			"interim_update", "radius.acct.", "radius.das.",
		} {
			if strings.Contains(res.Text, absent) {
				t.Fatalf("unset-knob row family %q must not emit:\n%s", absent, aaaExcerpt(res.Text))
			}
		}
	}
}

// TestAaaWpaPRegressions guards the FID-4 flip: plain wpa-p keeps
// wpa=3 (stored AUTO — the B/F forcing is WPA3-only), pmf disabled/0, the
// WPA-PSK mgmt row, and none of the WPA3/SAE row families.
func TestAaaWpaPRegressions(t *testing.T) {
	res := renderWith(t, []wireless.Wlan{{
		Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correcthorse",
		Enabled: true, ID: "corpwpa",
	}})
	for _, want := range []string{
		"aaa.1.wpa=3\n",
		"aaa.1.pmf.status=disabled\n",
		"aaa.1.pmf.mode=0\n",
		"aaa.1.wpa.key.1.mgmt=WPA-PSK\n",
		"aaa.1.wpa.psk=correcthorse\n",
	} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("wpa-p regression: missing %q:\n%s", want, aaaExcerpt(res.Text))
		}
	}
	for _, absent := range []string{
		"wpa3.support", "wpa3.transition", "wpa3.ft.status",
		"sae.", "wpa.key.1.mgmt=SAE",
	} {
		if strings.Contains(res.Text, absent) {
			t.Fatalf("wpa-p regression: %q must not emit:\n%s", absent, aaaExcerpt(res.Text))
		}
	}
}

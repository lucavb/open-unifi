package systemcfg

// radio.<n>.txpower_mode / radio.<n>.txpower echo pins (2026-09-19
// txpower lane; docs/PROTOCOL-systemcfg-wireless.md §9 resolved-as-echo).
//
// Jar evidence (the fleet parent's txpower packet — a verbatim
// transcription of the com__ubnt__service__config__int.txt javap dump,
// this lane's only javap access):
//   - int.txt 5687-5696: both values are READ from the device's
//     radio_table entry (local 19 = the per-radio X) via
//     X.getString(key, "auto") — default const #252 "auto" on BOTH reads
//     (tx_power_mode at javap offsets 396-403, tx_power at 405-414). No
//     setter, no admin lookup, no controller-side override participates.
//   - int.txt 5942-5958: the row emitter C.o00000 pairs key
//     `txpower_mode` (slot 40) with the tx_power_mode read (slot 41) and
//     key `txpower` (slot 42) with the tx_power read (slot 43) — the row
//     names DROP the underscore: tx_power_mode → txpower_mode,
//     tx_power → txpower.
//   - Packet pool-ref sweep (§1d): every constant-pool ref to the
//     tx_power_mode/tx_power strings (Utf8 #1695/#1697, row names
//     #1729/#1730) in config.int is consumed at those echo sites, and
//     config.String carries no tx_power/txpower refs at all — NO
//     controller-side writer for these rows exists in the config classes.
// The admin intent overlay (§3.2) therefore owns channel/txpower values
// only; these tests pin the no-intent byte-identity for BOTH tx rows and
// the never-intent-driven invariant of the mode row beside it.

import (
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

// txpowerEchoRecord returns the canonical record with a radio_table whose
// tx echoes are deliberately non-default, so echo, intent, and the jar
// default are distinguishable in every assertion: ra0 reports
// tx_power_mode "custom" + tx_power "17" (arbitrary sentinel strings —
// the jar applies NO transformation between read and row, int.txt
// 5687-5696 → 5942-5958, so any device-reported string proves verbatim
// passthrough; the packet settles the passthrough, not the value domain);
// rai0 omits both fields entirely, pinning the "auto" default of both
// reads.
func txpowerEchoRecord() store.Device {
	rec := renderRecord()
	rec.Extra["radio_table"] = []any{
		map[string]any{"name": "ra0", "radio": "ng", "channel": "6",
			"tx_power_mode": "custom", "tx_power": "17",
			"builtin_antenna": true, "builtin_ant_gain": 0.0},
		map[string]any{"name": "rai0", "radio": "na", "channel": 0.0,
			"builtin_antenna": true, "builtin_ant_gain": 0.0},
	}
	return rec
}

// TestTxpowerRowsArePureEcho pins the no-intent shape: with no
// radio_intent layer, both rows render byte-identical to the device's
// radio_table echo — radio.<n>.txpower_mode = tx_power_mode and
// radio.<n>.txpower = tx_power, each defaulting to "auto" when the device
// reports no value (both reads take default "auto", int.txt 5687-5696),
// under the underscore-less row names (int.txt 5942-5958).
func TestTxpowerRowsArePureEcho(t *testing.T) {
	res, err := Render(txpowerEchoRecord(), SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"radio.1.txpower_mode=custom\n", // sentinel echo passes through verbatim
		"radio.1.txpower=17\n",          // …and the tx_power echo beside it
		"radio.2.txpower_mode=auto\n",   // field absent ⇒ jar default "auto"
		"radio.2.txpower=auto\n",        // …on both reads, not just the mode
	} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("no-intent render must be the byte-identical echo, missing %q:\n%s", want, res.Text)
		}
	}

	// Numeric echo: tx_power decoded as a JSON number (float64 23) renders
	// in the number form JSONStr normalizes ("23") — the echo of a numeric
	// scalar, byte-identical like any other device-reported value.
	rec := txpowerEchoRecord()
	rec.Extra["radio_table"] = []any{
		map[string]any{"name": "ra0", "radio": "ng", "channel": "6",
			"tx_power_mode": "custom", "tx_power": 23.0,
			"builtin_antenna": true, "builtin_ant_gain": 0.0},
		map[string]any{"name": "rai0", "radio": "na"},
	}
	resNum, err := Render(rec, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resNum.Text, "radio.1.txpower=23\n") {
		t.Fatalf("numeric tx_power echo must render as 23:\n%s", resNum.Text)
	}
}

// TestTxpowerModeRowNeverIntentDriven pins the overlay boundary (§3.2):
// the radio_intent layer owns channel/txpower values ONLY. Even with
// intent set — and even with a hand-crafted txpower_mode key smuggled into
// the intent map, which RadioIntents structurally ignores — the
// txpower_mode row stays the device echo: the jar has no writer for the
// row (§9), so no intent may ever steer it.
func TestTxpowerModeRowNeverIntentDriven(t *testing.T) {
	rec := txpowerEchoRecord()
	rec.Extra["radio_intent"] = map[string]any{
		"ra0": map[string]any{"channel": 1.0, "txpower": 10.0,
			"txpower_mode": "hax"}, // smuggled key: never a real intent field
	}
	res, err := Render(rec, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"radio.1.txpower_mode=custom\n", // mode row: still the echo, intent cannot touch it
		"radio.1.txpower=10\n",          // txpower intent wins over the 17 echo (§3.2)
		"radio.1.channel=1\n",           // channel intent wins (§3.2, pinned here for contrast)
		"radio.2.txpower_mode=auto\n",   // no intent entry for rai0: echo defaults
		"radio.2.txpower=auto\n",
	} {
		if !strings.Contains(res.Text, want) {
			t.Fatalf("intent overlay boundary wrong, missing %q:\n%s", want, res.Text)
		}
	}
	// The smuggled value must never reach any row.
	if strings.Contains(res.Text, "hax") {
		t.Fatalf("radio_intent txpower_mode key leaked into system_cfg:\n%s", res.Text)
	}
}

// TestNoIntentVsEmptyIntentTxByteIdentity extends the §3.2 byte-identity
// contract to the tx rows: with the mode row carrying a NON-default echo,
// a record with an empty radio_intent map renders byte-identical to one
// with no layer at all — {} and absent are the same state for BOTH
// txpower rows. The ssh cache is seeded from the first render so the
// random salt cannot masquerade as a layer diff.
func TestNoIntentVsEmptyIntentTxByteIdentity(t *testing.T) {
	recNone := txpowerEchoRecord()
	resNone, err := Render(recNone, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	recEmpty := txpowerEchoRecord()
	recEmpty.Extra["radio_intent"] = map[string]any{}
	for _, seed := range []*store.Device{&recNone, &recEmpty} {
		for k, v := range resNone.CredentialDeltas {
			seed.Extra[k] = v
		}
	}
	resNone, err = Render(recNone, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	resEmpty, err := Render(recEmpty, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if resNone.Text != resEmpty.Text {
		t.Fatal("empty radio_intent map must render byte-identical to no intent layer (tx rows included)")
	}
	for _, want := range []string{"radio.1.txpower_mode=custom\n", "radio.1.txpower=17\n"} {
		if !strings.Contains(resNone.Text, want) {
			t.Fatalf("byte-identity render lost the non-default echo %q:\n%s", want, resNone.Text)
		}
	}
}

package systemcfg

// The ledbar block's unit gates (lane ledbar / WORKER-BRIEF-ledbar.md):
// golden pins of every emitted shape (enabled explicit, enabled defaults,
// short disabled block, absent block), the truncating brightness math,
// and the Color.decode port's parse table. Every expectation below cites
// the packet (tmpwork/javap/com__ubnt__service__config__String.txt
// lines 2566-2745, embedded in the lane brief) — change an expectation
// only with a new citation.

import (
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

// ledBarRecord is the canonical ledbar-capable record: renderRecord()'s
// U7PG2 with the LED knobs explicitly controllable per case.
func ledBarRecord() store.Device {
	return renderRecord()
}

// renderLedBar renders r with empty site facts and returns the text.
func renderLedBar(t *testing.T, r store.Device) string {
	t.Helper()
	res, err := Render(r, SiteFacts{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Text
}

// fullLedBarBlock is the enabled block's exact bytes (row order per
// String.txt:2604-2719).
func fullLedBarBlock(brightness, r, g, b_ string) string {
	return "ledbar.status=enabled\n" +
		"ledbar.persistent=true\n" +
		"ledbar.brightness=" + brightness + "\n" +
		"ledbar.active=3\n" +
		"ledbar.color.1.color=3\n" +
		"ledbar.color.1.r=" + r + "\n" +
		"ledbar.color.1.g=" + g + "\n" +
		"ledbar.color.1.b=" + b_ + "\n"
}

// TestRenderLedBarGolden pins every ledbar block shape and the block's
// headerless placement between `# users` and `# wlans (radio)`
// (int.txt:17221 / String.txt:2566-2745). The placement pin is a
// CONTIGUOUS segment: users.2.status + block + the wireless head — the
// block must sit exactly there with no invented section header.
func TestRenderLedBarGolden(t *testing.T) {
	bright := func(v int) *int { return &v }
	cases := []struct {
		name  string
		mut   func(*store.Device)
		block string // "" = the whole block must be ABSENT
	}{
		{
			name: "defaults enabled site default",
			// No knobs: led_override "" ≡ "default", site led_enabled
			// default true (String.txt:2580-2603) → enabled with the
			// jar defaults: brightness (255*100)/100=255 (String.txt:
			// 2627-2640), color #0000ff → (0,0,255) (String.txt:2661-2678).
			mut:   func(*store.Device) {},
			block: fullLedBarBlock("255", "0", "0", "255"),
		},
		{
			name: "explicit on brightness 50 color #FF8000",
			// (255*50)/100 = 127 — truncating imul/idiv (String.txt:
			// 2627-2640); Color.decode("#FF8000") = (255,128,0).
			mut: func(d *store.Device) {
				d.LEDOverride = "on"
				d.LEDOverrideColorBrightness = bright(50)
				d.LEDOverrideColor = "#FF8000"
			},
			block: fullLedBarBlock("127", "255", "128", "0"),
		},
		{
			name: "explicit on hex color 0x00ff00",
			// Integer.decode's 0x-prefixed form: decode("0x00ff00") =
			// (0,255,0).
			mut: func(d *store.Device) {
				d.LEDOverride = "on"
				d.LEDOverrideColor = "0x00ff00"
			},
			block: fullLedBarBlock("255", "0", "255", "0"),
		},
		{
			name: "explicit on garbage color falls back",
			// Color.decode("notacolor") throws NumberFormatException →
			// decode("#0000ff") (String.txt:2669-2678).
			mut: func(d *store.Device) {
				d.LEDOverride = "on"
				d.LEDOverrideColor = "notacolor"
			},
			block: fullLedBarBlock("255", "0", "0", "255"),
		},
		{
			name: "explicit on blank color falls back",
			// StringUtils.isBlank ⇒ "#0000ff" (String.txt:2666-2668).
			mut: func(d *store.Device) {
				d.LEDOverride = "on"
				d.LEDOverrideColor = "   "
			},
			block: fullLedBarBlock("255", "0", "0", "255"),
		},
		{
			name: "override off short block",
			// led_override=off ⇒ enabled=false ⇒ status+persistent only
			// (String.txt:2585-2626).
			mut: func(d *store.Device) { d.LEDOverride = "off" },
			block: "ledbar.status=disabled\n" +
				"ledbar.persistent=true\n",
		},
		{
			name: "admin disabled flag short block",
			// device.is("disabled") ⇒ enabled=false regardless of the
			// override (String.txt:2575-2603).
			mut: func(d *store.Device) {
				d.Disabled = true
				d.LEDOverride = "on"
			},
			block: "ledbar.status=disabled\n" +
				"ledbar.persistent=true\n",
		},
		{
			name: "unsupported model no block",
			// supportLedBar() false ⇒ the whole block ABSENT
			// (String.txt:2571-2574) — nothing, not even the short form.
			mut:   func(d *store.Device) { d.Model = "US24P250W" },
			block: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := ledBarRecord()
			tc.mut(&rec)
			sys := renderLedBar(t, rec)
			if tc.block == "" {
				if strings.Contains(sys, "ledbar.") {
					t.Fatalf("unsupported model must carry no ledbar rows:\n%s", sys)
				}
				return
			}
			// Placement: contiguous users tail + block + wireless head.
			segment := "users.2.status=enabled\n" + tc.block + "# wlans (radio)\n"
			if !strings.Contains(sys, segment) {
				t.Fatalf("ledbar block not pinned between users and wlans:\nwant segment:\n%s\n--- got ---\n%s", segment, sys)
			}
			// No invented section header wraps the block.
			if strings.Contains(sys, "# mgmt\n") || strings.Contains(sys, "# ledbar\n") {
				t.Fatalf("ledbar block must be headerless:\n%s", sys)
			}
		})
	}
}

// TestRenderLedBarBrightnessMath pins the truncating (255*b)/100 row for
// the knob's whole domain, including the explicit-zero knob (b=0 ⇒ row 0
// — the reason the record field is a pointer) and the unset knob
// (getInt default 100 ⇒ 255) (String.txt:2627-2640).
func TestRenderLedBarBrightnessMath(t *testing.T) {
	bright := func(v int) *int { return &v }
	cases := []struct {
		knob *int
		want string
	}{
		{nil, "255"}, // getInt(..., 100)
		{bright(100), "255"},
		{bright(0), "0"},    // explicit zero must survive (pointer field)
		{bright(1), "2"},    // 255/100 truncates: (255*1)/100 = 2
		{bright(33), "84"},  // 8415/100 = 84.15 → 84
		{bright(50), "127"}, // 12750/100 = 127.5 → 127
	}
	for _, tc := range cases {
		rec := ledBarRecord()
		rec.LEDOverride = "on"
		rec.LEDOverrideColorBrightness = tc.knob
		want := "ledbar.brightness=" + tc.want + "\n"
		if got := renderLedBar(t, rec); !strings.Contains(got, want) {
			t.Fatalf("knob %v: missing %q in:\n%s", tc.knob, want, got)
		}
	}
}

// TestDecodeLedColor pins the Color.decode port against Java semantics:
// Integer.decode grammar (sign, 0x/#/leading-0 forms, decimal), the
// 32-bit range rules (negative magnitudes up to 2^31 — parseInt's
// MIN_VALUE edge), and every fallback path landing on #0000ff.
func TestDecodeLedColor(t *testing.T) {
	cases := []struct {
		in      string
		r, g, b int
	}{
		// Hex forms (Integer.decode: "0x"/"0X"/"#" prefixes — a bare
		// hex literal with NO prefix is DECIMAL, so "ff0000" throws).
		{"#0000ff", 0, 0, 255},
		{"#FF8000", 255, 128, 0},
		{"0x00ff00", 0, 255, 0},
		{"0Xff0000", 255, 0, 0},
		// Decimal: "255" is the int 255 → (0, 0, 255) — the same
		// components as #0000ff but parsed as a plain decimal int.
		{"255", 0, 0, 255},
		{"16711680", 255, 0, 0},   // 0xFF0000 decimal
		{"16776960", 255, 255, 0}, // 0xFFFF00 decimal: (FF,FF,00)
		// Octal: leading-0 form (Integer.decode's second grammar rule).
		{"0377", 0, 0, 255},
		// Signed forms within the int range.
		{"-1", 255, 255, 255}, // 0xFFFFFFFF masked
		{"+64", 0, 0, 64},
		{"-0x10000", 255, 0, 0},  // -65536 = 0xFFFF0000 masked
		{"-0x80000000", 0, 0, 0}, // Integer.MIN_VALUE edge (neg mag ≤ 2^31)
	}
	for _, tc := range cases {
		r, g, b := decodeLedColor(tc.in)
		if r != tc.r || g != tc.g || b != tc.b {
			t.Fatalf("decodeLedColor(%q) = (%d,%d,%d), want (%d,%d,%d)",
				tc.in, r, g, b, tc.r, tc.g, tc.b)
		}
	}
	// Fallbacks: every NumberFormatException / blank lands on the jar's
	// #0000ff fallback (String.txt:2661-2678) — (0, 0, 255).
	for _, in := range []string{
		"", "   ", "\t\n", // blank (isBlank path)
		"notacolor", "#GGGGGG", // non-hex digits
		"ff0000",                              // bare hex digits = DECIMAL radix → throws
		"0x", "#", "0x1FFFFFFFF", "#FFFFFFFF", // empty/overflow hex
		"08",                // invalid octal digit
		"1_0", "1-2", "+-1", // separators / sign in wrong position
		" 255", "255 ", "#00ff00 extra", // stray whitespace / trailing garbage
	} {
		r, g, b := decodeLedColor(in)
		if r != 0 || g != 0 || b != 255 {
			t.Fatalf("decodeLedColor(%q) = (%d,%d,%d), want fallback (0,0,255)", in, r, g, b)
		}
	}
}

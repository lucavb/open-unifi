package systemcfg

// The headerless `# mgmt` ledbar block (docs/PROTOCOL-mgmt.md §3 item 4,
// docs/PROTOCOL-systemcfg-wireless.md §12 row 1007): the classic
// controller's config_String.Ò00000(StringBuilder, Device, Setting) —
// tmpwork/javap/com__ubnt__service__config__String.txt:2566-2745,
// transcribed verbatim in the ledbar lane's embedded citation packet
// (WORKER-BRIEF-ledbar.md) — re-derived here row for row. Every emitted
// row cites the packet below; nothing in this file may grow without a
// new bytecode citation.

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/lucavb/open-unifi/internal/store"
)

// defaultLedColor is the jar's default for the ledbar color in BOTH roles
// it plays: the Device.getString fallback (String.txt:2663) and the
// blank/decode-failure fallback (String.txt:2669-2678 — ldc "#0000ff"
// appears at all three sites). Color.decode("#0000ff") is (0, 0, 255).
// defaultLedBrightnessPercent is the jar's getInt default for the
// brightness knob (String.txt:2628-2630: bipush 100).
const defaultLedBrightnessPercent = 100

// ledbarModels is the in-repo device-model decision for the jar's
// Device.supportLedBar() gate: supportLedBar() == hasHardwareCapability(2)
// (config_Device.txt:7935-7943) — the controller-side device-class
// hardware-capability bit 0x2, whose record source the packet does not
// carry. The real builder emits the ledbar block for this device class
// (the bench U7PG2, fw 6.8.2.15592), so U7PG2 carries the bit here; every
// other model renders without the block (String.txt:2571-2574: the
// early return fires before any row). Extending the set needs the same
// evidence bar: a device class proven ledbar-capable, e.g. a captured
// full provisioning response carrying the block for that model.
var ledbarModels = map[string]bool{"U7PG2": true}

// emitLedBar emits the headerless ledbar block between `# users` and the
// wireless compound, exactly like config_String.Ò00000
// (String.txt:2566-2745):
//
//   - guard: supportLedBar() false ⇒ the whole block ABSENT
//     (String.txt:2571-2574);
//   - local5 = device.is("disabled", false) — the admin-owned typed
//     record flag (String.txt:2575-2579). NOTE: unlike the §2 B writer
//     there is no "uap".equals(type) gate in this emitter; every device
//     this controller manages is a uap-class AP, so the typed flag is the
//     whole read;
//   - local6 = device.getString("led_override", "default") — the typed
//     record field, "" ≡ the jar default (String.txt:2580-2584);
//   - enabled = !disabled && (led_override=="on" ||
//     (led_override=="default" && Setting.is("led_enabled", true)))
//     (String.txt:2585-2603) — the SAME device state the mgmt_cfg
//     led_enabled row follows (§2, adoption.ledEnabledValue); the jar
//     computes it independently in both emitters, and the server lane's
//     TestLEDStateMgmtCfgLedBarConsistency pins ours to agree;
//   - row 1, ALWAYS: ledbar.status=<statusword(enabled)>
//     (String.txt:2604-2614) — "enabled"/"disabled", the file-wide
//     status-word vocabulary corroborated at config_int.txt:5623-5626
//     (the mapper body itself — super:(Z)Ljava/lang/String; at
//     String.txt:2612 — is not in the packet; see the lane report's
//     citation note and §12 row 1007);
//   - row 2, ALWAYS: ledbar.persistent=true (String.txt:2615-2623);
//   - NOT enabled ⇒ the block ENDS after row 2 — status+persistent only
//     (String.txt:2624-2626);
//   - b = device.getInt("led_override_color_brightness", 100), then the
//     row value is (255*b)/100 — truncating integer math, imul/idiv
//     (String.txt:2627-2640);
//   - row 3: ledbar.brightness=<b> (String.txt:2641-2651);
//   - row 4: ledbar.active=3 (String.txt:2652-2660);
//   - c = device.getString("led_override_color", "#0000ff"); blank ⇒
//     "#0000ff"; Color.decode(c), NumberFormatException ⇒ decode(
//     "#0000ff") (String.txt:2661-2678);
//   - rows 5-8, in order: ledbar.color.1.color=3, then ledbar.color.1.r/
//     .g/.b = the decoded 0..255 components (String.txt:2679-2719).
//
// All rows go through the shared injection-guarded line writer.
func (rd *render) emitLedBar(line func(k, v string), d store.Device) {
	if !ledbarModels[d.Model] {
		return // String.txt:2571-2574: the whole block is absent
	}

	// siteLEDEnabledDefault is Setting.is("led_enabled", true) — the jar's
	// site default. No site settings table exists yet, so the site default
	// IS the jar default, the same policy mgmt_cfg's led_enabled and
	// selfrun_guest_mode follow (adoption/mgmtcfg.go). When a site table
	// lands, thread its mgmt.led_enabled value into BOTH emitters; the
	// consistency test catches a one-sided threading.
	const siteLEDEnabledDefault = true

	override := d.LEDOverride
	if override == "" {
		override = "default" // device.getString("led_override", "default")
	}
	enabled := !d.Disabled &&
		(override == "on" || (override == "default" && siteLEDEnabledDefault))

	statusWord := "disabled"
	if enabled {
		statusWord = "enabled"
	}
	line("ledbar.status", statusWord) // String.txt:2604-2614
	line("ledbar.persistent", "true") // String.txt:2615-2623
	if !enabled {
		return // String.txt:2624-2626: status+persistent only
	}

	b := defaultLedBrightnessPercent
	if d.LEDOverrideColorBrightness != nil {
		b = *d.LEDOverrideColorBrightness // String.txt:2627-2640
	}
	line("ledbar.brightness", strconv.Itoa((255*b)/100)) // imul/idiv, truncating
	line("ledbar.active", "3")                           // String.txt:2652-2660
	r, g, bl := decodeLedColor(d.LEDOverrideColor)       // String.txt:2661-2678
	line("ledbar.color.1.color", "3")                    // String.txt:2679-2687
	line("ledbar.color.1.r", strconv.Itoa(r))            // String.txt:2688-2698
	line("ledbar.color.1.g", strconv.Itoa(g))            // String.txt:2699-2709
	line("ledbar.color.1.b", strconv.Itoa(bl))           // String.txt:2710-2719
}

// decodeLedColor resolves the ledbar color exactly like the jar's render
// path (String.txt:2661-2678): the record's led_override_color, blank ⇒
// "#0000ff", then java.awt.Color.decode(c) with NumberFormatException ⇒
// Color.decode("#0000ff"). Color.decode(s) is Integer.decode(s) masked to
// the three 0..255 components — (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF — so
// only those components ever reach a config row: an unparseable or
// hostile value can never inject a row, it can only select the fallback
// color.
func decodeLedColor(raw string) (r, g, b int) {
	if isBlank(raw) { // StringUtils.isBlank (String.txt:2666-2668)
		return 0, 0, 255 // Color.decode("#0000ff")
	}
	rgb, ok := javaIntegerDecode(raw)
	if !ok {
		return 0, 0, 255 // NumberFormatException ⇒ Color.decode("#0000ff")
	}
	return (rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF
}

// javaIntegerDecode ports java.lang.Integer.decode for the color path:
// optional leading sign, then a "#"/"0x"/"0X"-prefixed hex form, a
// leading-0 octal form, or plain decimal digits; the signed result must
// fit the 32-bit int range (a negative sign admits a magnitude up to
// 2^31 — Integer.parseInt's MIN_VALUE edge). Any other shape is the Java
// NumberFormatException; the caller falls back to the default color.
//
// PORT CAVEAT (recorded in the lane report): the JDK's parseInt accepts
// non-ASCII Unicode digits via Character.digit; this port accepts ASCII
// digits only. Every rejected input lands on the proven #0000ff fallback,
// so no row can be mis-emitted — only the color CHOICE for such
// pathological inputs differs.
func javaIntegerDecode(nm string) (int, bool) {
	if nm == "" {
		return 0, false // NumberFormatException("Zero length string")
	}
	i := 0
	neg := false
	switch nm[0] {
	case '-':
		neg, i = true, 1
	case '+':
		i = 1
	}
	radix := 10
	rest := nm[i:]
	switch {
	case strings.HasPrefix(rest, "0x"), strings.HasPrefix(rest, "0X"):
		radix, rest = 16, rest[2:]
	case strings.HasPrefix(rest, "#"):
		radix, rest = 16, rest[1:]
	case len(rest) > 1 && rest[0] == '0':
		radix, rest = 8, rest[1:]
	}
	if rest == "" || rest[0] == '-' || rest[0] == '+' {
		// Empty digits after the prefix, or "Sign character in wrong
		// position" — both NumberFormatException in the JDK.
		return 0, false
	}
	v, err := strconv.ParseInt(rest, radix, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		if v > 1<<31 {
			return 0, false // below Integer.MIN_VALUE
		}
		return int(-v), true
	}
	if v > 1<<31-1 {
		return 0, false // above Integer.MAX_VALUE ("0x1FFFFFFFF"-class overflow)
	}
	return int(v), true
}

// isBlank mirrors org.apache.commons.lang3.StringUtils.isBlank for the
// color knob: empty or all-whitespace (String.txt:2666-2668).
func isBlank(s string) bool {
	return strings.TrimFunc(s, unicode.IsSpace) == ""
}

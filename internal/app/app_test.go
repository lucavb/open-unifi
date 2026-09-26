package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/server/systemcfg"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func testApp(t *testing.T) (*App, store.DeviceStore) {
	t.Helper()
	st := store.NewMemStore()
	a := New(st, quietLogger())
	return a, st
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// counterDefault returns the summed counter value of a metric family from
// the default Prometheus registry (metrics registers in init()).
func counterDefault(name string) float64 {
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return -1
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		var total float64
		for _, m := range f.Metric {
			if c := m.GetCounter(); c != nil {
				total += c.GetValue()
			}
		}
		return total
	}
	return 0 // family registered but no series yet / absent
}

// ---- device CRUD ---------------------------------------------------------

func TestDeviceCreateListGetRoundtrip(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()

	dv, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "F0:9F:C2:84:8F:2A", Name: "lobby", SiteID: "default"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if dv.MAC != "f0:9f:c2:84:8f:2a" || dv.State != store.StatePending {
		t.Fatalf("create view: %+v", dv)
	}

	// store record must be canonical bare 12-hex
	rec, err := st.Get("f09fc2848f2a")
	if err != nil || rec.State != store.StatePending || rec.Name != "lobby" {
		t.Fatalf("store record: %+v err=%v", rec, err)
	}

	got, err := a.GetDevice(ctx, "F0-9F-C2-84-8F-2A")
	if err != nil || got.Name != "lobby" || got.IP != "" {
		t.Fatalf("get: %+v err=%v", got, err)
	}
	list := a.ListDevices(ctx)
	if len(list) != 1 || list[0].MAC != "f0:9f:c2:84:8f:2a" || list[0].State != 1 {
		t.Fatalf("list: %+v", list)
	}
}

func TestDuplicateCreateIsIdempotentUpsert(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "aabbccddeeff", Name: "first"}); err != nil {
		t.Fatal(err)
	}
	dv, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "AA-BB-CC-DD-EE-FF", Name: "second"})
	if err != nil {
		t.Fatalf("duplicate create returned error (would become HTTP 500): %v", err)
	}
	if dv.Name != "second" || dv.State != store.StatePending {
		t.Fatalf("upsert result: %+v", dv)
	}
	if n := len(a.ListDevices(ctx)); n != 1 {
		t.Fatalf("duplicate created %d records", n)
	}
}

func deviceNamePtr(s string) *string { return &s }

func ledOverridePtr(s string) *string { return &s }

func brightPtr(v int) *int { return &v }

// TestPatchDeviceLEDOverride pins the real adapter's LED override write
// path: the three §2 states reach the typed record field, "default" is the
// explicit clear (record canonical unset ""), the view mirrors the record,
// and the backend-side enum fence rejects anything else WITHOUT touching
// the record.
func TestPatchDeviceLEDOverride(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()

	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "aabbccddeeff"}); err != nil {
		t.Fatal(err)
	}
	// set → record + view carry the override
	if dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverride: ledOverridePtr("on")}); err != nil || dv.LEDOverride != "on" {
		t.Fatalf("set on: %+v err=%v", dv, err)
	}
	rec, err := st.Get("aabbccddeeff")
	if err != nil || rec.LEDOverride != "on" {
		t.Fatalf("record after set on: %+v err=%v", rec.LEDOverride, err)
	}
	if dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverride: ledOverridePtr("off")}); err != nil || dv.LEDOverride != "off" {
		t.Fatalf("set off: %+v err=%v", dv, err)
	}
	// explicit clear: "default" maps to the record's canonical unset
	if dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverride: ledOverridePtr("default")}); err != nil || dv.LEDOverride != "" {
		t.Fatalf("clear: %+v err=%v", dv, err)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil || rec.LEDOverride != "" {
		t.Fatalf("record after clear: %q err=%v", rec.LEDOverride, err)
	}
	// backend-side enum fence: invalid value is ErrConflict and mutates nothing
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverride: ledOverridePtr("blink")}); !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("invalid override must be ErrConflict, got %v", err)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil || rec.LEDOverride != "" {
		t.Fatalf("rejected patch mutated the record: %q err=%v", rec.LEDOverride, err)
	}
}

// TestPatchDeviceLEDMintsCfgVersionOncePerChange pins the LED override's
// delivery trigger (putRadioIntent's operator-save discipline): an
// EFFECTIVE override change mints a fresh 16-hex cfgversion — without the
// mint, a settled device never re-provisions and led_enabled never reaches
// the mgmt_cfg it rides. Idempotent saves mint nothing.
func TestPatchDeviceLEDMintsCfgVersionOncePerChange(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	if err := st.Put(store.Device{
		MAC: "aabbccddeeff", Model: "U7PG2", State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
	}); err != nil {
		t.Fatal(err)
	}

	// Effective change (""): mint a fresh 16-hex cfgversion.
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverride: ledOverridePtr("off")}); err != nil {
		t.Fatal(err)
	}
	rec, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if rec.LEDOverride != "off" || rec.CfgVersion == "aaaa" || len(rec.CfgVersion) != 16 {
		t.Fatalf("effective LED change must mint a fresh 16-hex cfgversion: %+v", rec)
	}
	bumped := rec.CfgVersion

	// Idempotent re-save of the same value: no further mint.
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverride: ledOverridePtr("off")}); err != nil {
		t.Fatal(err)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil || rec.CfgVersion != bumped {
		t.Fatalf("idempotent LED save minted: %q -> %q", bumped, rec.CfgVersion)
	}

	// Explicit clear is an effective change again ("off" → ""): mint.
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverride: ledOverridePtr("default")}); err != nil {
		t.Fatal(err)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil || rec.LEDOverride != "" || rec.CfgVersion == bumped {
		t.Fatalf("effective clear must mint: %+v", rec)
	}
}

// TestPatchDeviceLEDBarKnobs pins the real adapter's §12 ledbar knob write
// path: the brightness knob's pointer semantics (explicit 0 survives the
// round-trip; 100 is the explicit clear to the record's nil unset), the
// backend-side domain fence (same fence style as LEDOverride), and the
// color knob's deliberate NO-fence verbatim storage — the §12 render owns
// the fallback (Color.decode; config_String.txt:2669-2678), so even a
// "garbage" value is stored, and "" is the explicit clear. The mint
// discipline follows TestPatchDeviceLEDMintsCfgVersionOncePerChange:
// effective change → fresh 16-hex cfgversion; idempotent save → nothing.
func TestPatchDeviceLEDBarKnobs(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	if err := st.Put(store.Device{
		MAC: "aabbccddeeff", Model: "U7PG2", State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
	}); err != nil {
		t.Fatal(err)
	}

	// Brightness: effective change mints; explicit 0 round-trips.
	if dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverrideColorBrightness: brightPtr(50)}); err != nil ||
		dv.LEDOverrideColorBrightness == nil || *dv.LEDOverrideColorBrightness != 50 {
		t.Fatalf("set 50: %+v err=%v", dv, err)
	}
	rec, err := st.Get("aabbccddeeff")
	if err != nil || rec.LEDOverrideColorBrightness == nil || *rec.LEDOverrideColorBrightness != 50 ||
		len(rec.CfgVersion) != 16 || rec.CfgVersion == "aaaa" {
		t.Fatalf("effective brightness change must mint: %+v", rec)
	}
	if dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverrideColorBrightness: brightPtr(0)}); err != nil ||
		dv.LEDOverrideColorBrightness == nil || *dv.LEDOverrideColorBrightness != 0 {
		t.Fatalf("explicit 0 must round-trip (not read as unset): %+v err=%v", dv, err)
	}
	// 50 → 0 was an effective change too: re-baseline before the
	// idempotent re-save check.
	if rec, err = st.Get("aabbccddeeff"); err != nil {
		t.Fatal(err)
	}
	bumped := rec.CfgVersion
	// Idempotent re-save of 0: no further mint.
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverrideColorBrightness: brightPtr(0)}); err != nil {
		t.Fatal(err)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil || rec.CfgVersion != bumped {
		t.Fatalf("idempotent brightness save minted: %q -> %q", bumped, rec.CfgVersion)
	}
	// 100 is the explicit clear: the record's canonical unset is nil.
	if dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverrideColorBrightness: brightPtr(100)}); err != nil ||
		dv.LEDOverrideColorBrightness != nil {
		t.Fatalf("clear brightness: %+v err=%v", dv, err)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil || rec.LEDOverrideColorBrightness != nil {
		t.Fatalf("record after clear must be nil-unset: %+v err=%v", rec.LEDOverrideColorBrightness, err)
	}
	// Backend-side domain fence: out-of-domain is ErrConflict and
	// mutates nothing.
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverrideColorBrightness: brightPtr(101)}); !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("out-of-domain brightness must be ErrConflict, got %v", err)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil || rec.LEDOverrideColorBrightness != nil {
		t.Fatalf("rejected patch mutated the record: %+v err=%v", rec.LEDOverrideColorBrightness, err)
	}

	// Color: verbatim storage, no fence by design — the §12 render owns
	// the fallback; "garbage" is stored exactly like a well-formed value.
	for _, c := range []string{"#ff8c00", "garbage"} {
		if dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverrideColor: ledOverridePtr(c)}); err != nil ||
			dv.LEDOverrideColor != c {
			t.Fatalf("set color %q: %+v err=%v", c, dv, err)
		}
		if rec, err = st.Get("aabbccddeeff"); err != nil || rec.LEDOverrideColor != c {
			t.Fatalf("record after color %q: %q err=%v", c, rec.LEDOverrideColor, err)
		}
	}
	// "" is the explicit clear.
	if dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverrideColor: ledOverridePtr("")}); err != nil || dv.LEDOverrideColor != "" {
		t.Fatalf("clear color: %+v err=%v", dv, err)
	}
	// Idempotent color save mints nothing (same value re-saved).
	rec, err = st.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	bumped = rec.CfgVersion
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverrideColor: ledOverridePtr("")}); err != nil {
		t.Fatal(err)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil || rec.CfgVersion != bumped {
		t.Fatalf("idempotent color save minted: %q -> %q", bumped, rec.CfgVersion)
	}
}

// TestPatchDeviceSSHPassword pins the real adapter's per-device SSH
// password write path (installed alongside the site-level password's
// removal): nil = untouched, a non-empty set = effective change (mints
// cfgversion, the view echoes the record), "" = the explicit clear = STOP
// MANAGING (also minting — the intent stamp flaps with the record value),
// and the render-after-clear contract: the renderer reuses the device's
// last controller-pushed cache row verbatim, so the AP's actual password
// never changes (locked per-device semantics, store.Device.SSHPassword
// docblock).
func TestPatchDeviceSSHPassword(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	// fw_caps 0x400: the real U7PG2 SHA-512 password capability bit
	// (supportsSha512Password, Default-0 semantics), so the
	// render-after-clear section exercises the sha512 family arm — the
	// family of the cache row it seeds below.
	if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StateAdopted, CfgVersion: "aaaa1111bbbb2222",
		Extra: store.JSONMap{"fw_caps": 1024.0}}); err != nil {
		t.Fatal(err)
	}

	// nil → no change, no mint.
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{Name: deviceNamePtr("renamed")}); err != nil {
		t.Fatal(err)
	}
	rec, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if rec.SSHPassword != "" || rec.CfgVersion != "aaaa1111bbbb2222" {
		t.Fatalf("nil-password patch changed the record: %+v", rec)
	}
	if dv := a.ListDevices(ctx)[0]; dv.SSHPassword != "" {
		t.Fatalf("nil-password patch echoed a password: %+v", dv)
	}

	// set → record updated + mint + view echo.
	dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{SSHPassword: deviceNamePtr("pw1")})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if dv.SSHPassword != "pw1" {
		t.Fatalf("set view echo: %+v", dv)
	}
	minted := dv.CfgVersion
	if rec, err = st.Get("aabbccddeeff"); err != nil || rec.SSHPassword != "pw1" || rec.CfgVersion != minted ||
		rec.CfgVersion == "aaaa1111bbbb2222" {
		t.Fatalf("set record: %+v err=%v", rec, err)
	}

	// Instructing the render with the same value mints nothing:
	// save-vs-save idempotence, the LED-knob rule.
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{SSHPassword: deviceNamePtr("pw1")}); err != nil {
		t.Fatal(err)
	}
	if rec, _ = st.Get("aabbccddeeff"); rec.CfgVersion != minted {
		t.Fatalf("idempotent password save minted: %q -> %q", minted, rec.CfgVersion)
	}

	// Seed the record cache as the SERVER's credential delta would (a
	// well-formed, deliberately non-ubnt $6$ row standing in for
	// sha512Crypt("pw1") — format-only; the render's cache reuse is
	// verbatim by contract): the device now runs pw1, whose hash row C the
	// controller pushed last.
	const cacheRow = "$6$0Vt2Ue1V$cZ7N8BjYvOhq2jbFLYMyiJC8t1j3QroXfPzolNy0KhHypWV4OQqLPTerxeYg4LjtLpHzdXH2QCxaOmB2Pup0cz"
	if err := st.UpdateExisting("aabbccddeeff", func(d *store.Device) error {
		if d.Extra == nil {
			d.Extra = store.JSONMap{}
		}
		d.Extra["ssh_sha512passwd"] = cacheRow
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// clear → "" + mint (stop managing: the AP keeps pw1).
	dv, err = a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{SSHPassword: deviceNamePtr("")})
	if err != nil {
		t.Fatal(err)
	}
	if dv.SSHPassword != "" {
		t.Fatalf("clear view echo: %+v", dv)
	}
	if rec, _ = st.Get("aabbccddeeff"); rec.SSHPassword != "" || rec.CfgVersion == minted {
		t.Fatalf("clear record: %+v (mint %q)", rec, minted)
	}

	// render-after-clear: the unset record reuses the last
	// controller-pushed row VERBATIM — the device stays on pw1; an
	// unchanged-device pin (the stop-managing semantics live here, not in
	// a warn).
	asserted, rerr := systemcfg.Render(rec, systemcfg.SiteFacts{})
	if rerr != nil {
		t.Fatal(rerr)
	}
	row := ""
	for _, ln := range strings.Split(asserted.Text, "\n") {
		if after, ok := strings.CutPrefix(ln, "users.1.password="); ok {
			row = after
		}
	}
	if row != cacheRow {
		t.Fatalf("render after clear must reuse the cached row verbatim: %q, want %q", row, cacheRow)
	}
}

func TestPatchDeviceCountryAndSSHKeys(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB test@ap"
	if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StateAdopted, CfgVersion: "v1"}); err != nil {
		t.Fatal(err)
	}
	cc := 276
	dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{
		RegulatoryCountryCode: chPtr(cc),
		SSHPublicKeys:         &[]string{key},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dv.RegulatoryCountryCode != cc || len(dv.SSHPublicKeys) != 1 || dv.SSHPublicKeys[0] != key {
		t.Fatalf("view: %+v", dv)
	}
	rec, err := st.Get("aabbccddeeff")
	if err != nil || rec.RegulatoryCountryCode != cc || len(rec.SSHPublicKeys) != 1 || rec.CfgVersion == "v1" {
		t.Fatalf("record: %+v err=%v", rec, err)
	}
	empty := []string{}
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{SSHPublicKeys: &empty}); err != nil {
		t.Fatal(err)
	}
	rec, _ = st.Get("aabbccddeeff")
	if len(rec.SSHPublicKeys) != 0 {
		t.Fatalf("clear keys: %+v", rec.SSHPublicKeys)
	}
}

// TestDeviceNameValidationBackstop pins the adapter-side fence for device
// names (mirror of the wlan flows: the adminapi handler 400s first, every
// Backend caller is fenced with ErrConflict). Empty stays legal: it is the
// "leave unset" value for DeviceUpsert and the explicit clear for
// DevicePatch.
func TestDeviceNameValidationBackstop(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()

	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "aabbccddeeff", Name: "ok"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{Name: deviceNamePtr("bad\nname")}); !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("control-char name patch must be ErrConflict, got %v", err)
	}
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{Name: deviceNamePtr(strings.Repeat("n", 65))}); !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("over-long name patch must be ErrConflict, got %v", err)
	}
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "112233445566", Name: "bad\rname"}); !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("control-char name create must be ErrConflict, got %v", err)
	}
	// A rejected patch must not have touched the record.
	dv, err := a.GetDevice(ctx, "aabbccddeeff")
	if err != nil || dv.Name != "ok" {
		t.Fatalf("rejected patch mutated the record: %+v err=%v", dv, err)
	}
	// Empty patch is the documented explicit clear — still legal.
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{Name: deviceNamePtr("")}); err != nil {
		t.Fatalf("explicit empty-name clear must stay legal: %v", err)
	}
	if dv, err = a.GetDevice(ctx, "aabbccddeeff"); err != nil || dv.Name != "" {
		t.Fatalf("empty clear: name=%q err=%v", dv.Name, err)
	}
}

func TestAdoptPendingFlow(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()

	if err := st.MarkPending("a040a0aabbcc", "discovery:platform=U7PG2"); err != nil {
		t.Fatal(err)
	}
	dv, err := a.AdoptPending(ctx, "A0:40:A0:AA:BB:CC")
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if dv.MAC != "a0:40:a0:aa:bb:cc" || dv.State != store.StatePending {
		t.Fatalf("adopt view: %+v", dv)
	}
	rec, err := st.Get("a040a0aabbcc")
	if err != nil || rec.State != store.StatePending {
		t.Fatalf("after adopt: %+v err=%v", rec, err)
	}

	// The promotion leaves the live note in the pending map (it is
	// consumed by the next inform, not by the promotion), so the record
	// is a state-1-with-note candidate: LISTED from now on, awaiting its
	// first inform — the console shape the factory reset round needs.
	pen := a.ListPending(ctx)
	if len(pen) != 1 {
		t.Fatalf("pending after adopt: %+v", pen)
	}
	if pen[0].MAC != "a0:40:a0:aa:bb:cc" || pen[0].Name != "" {
		t.Fatalf("pending after adopt: %+v", pen[0])
	}

	// adopting again: PENDING record is valid for re-adopt (idempotent)
	if dv, err := a.AdoptPending(ctx, "a0:40:a0:aa:bb:cc"); err != nil || dv.State != store.StatePending {
		t.Fatalf("re-adopt: %+v err=%v", dv, err)
	}
}

// TestListPendingShapes is the table over the four pending-row shapes
// the console's pending table can show:
//
//	(a) no record + live note   → listed, Name empty (stranger candidate)
//	(b) state-3 record + note   → skipped (adopted; note is stale)
//	(c) state-1 record + note   → listed, Name from the record (a KNOWN
//	    device demoted by factory reset, or promoted and awaiting its
//	    first inform) — this is the round that lets a factory reset be
//	    re-adopted from the console with one Accept click
//	(d) state-1 record, NO note → not listed (the pending map is the
//	    liveness source, not the record)
func TestListPendingShapes(t *testing.T) {
	cases := []struct {
		name     string
		seed     *store.Device
		note     string
		wantRows int
		wantName string
	}{
		{
			name: "stranger-no-record",
			note: "discovery:model=U7PG2,ip=10.10.10.20",
			// nothing in the store; the map alone lists it
			wantRows: 1,
		},
		{
			name:     "adopted-record-skipped",
			seed:     &store.Device{MAC: "112233445566", State: store.StateAdopted, Name: "ceiling-west"},
			note:     "discovery:model=U7PG2",
			wantRows: 0,
		},
		{
			name:     "pending-record-listed-named",
			seed:     &store.Device{MAC: "112233445566", State: store.StatePending, Name: "ceiling-west"},
			note:     "inform:factory",
			wantRows: 1,
			wantName: "ceiling-west",
		},
		{
			name:     "pending-record-without-note-hidden",
			seed:     &store.Device{MAC: "112233445566", State: store.StatePending, Name: "ceiling-west"},
			wantRows: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, st := testApp(t)
			if tc.seed != nil {
				if err := st.Put(*tc.seed); err != nil {
					t.Fatal(err)
				}
			}
			if tc.note != "" {
				if err := st.MarkPending("112233445566", tc.note); err != nil {
					t.Fatal(err)
				}
			}
			rows := a.ListPending(context.Background())
			if len(rows) != tc.wantRows {
				t.Fatalf("rows: %+v, want %d", rows, tc.wantRows)
			}
			if tc.wantRows == 1 && rows[0].Name != tc.wantName {
				t.Fatalf("row name: %q, want %q", rows[0].Name, tc.wantName)
			}
		})
	}
}

func TestAdoptUnknownMACErrors(t *testing.T) {
	a, _ := testApp(t)
	if _, err := a.AdoptPending(context.Background(), "ff:ff:ff:ff:ff:ff"); err == nil {
		t.Fatal("adopt of unknown mac must return an error")
	}
}

func TestGetDeleteUnknownMACErrors(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	_, err := a.GetDevice(ctx, "ff:ff:ff:ff:ff:ff")
	if !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("get unknown: want adminapi.ErrNotFound wrapped, got %v", err)
	}
	if err := a.DeleteDevice(ctx, "ff:ff:ff:ff:ff:ff"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("delete unknown: want adminapi.ErrNotFound wrapped, got %v", err)
	}
}

// ---- remote lifecycle arming (§6.5 reboot / §6.6 setdefault) -----------------

// TestLifecycleArmingArmsOnlyTheFlag pins the arming contract: an armed
// command changes ONLY the admin-owned flag — state, per-device key,
// cfgversion and applied cfgversion are untouched (no §6.2 mint site
// exists for either response), the record stays where it is, and the
// second arm is idempotent (flag already true).
func TestLifecycleArmingArmsOnlyTheFlag(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()

	seeded := store.Device{
		MAC: "f09fc2848f2a", State: store.StateAdopted, Model: "U7PG2",
		XAuthkey: "0123456789abcdef", CfgVersion: "aaaabbbbccccdddd", AppliedCfg: "aaaabbbbccccdddd",
	}
	if err := st.Put(seeded); err != nil {
		t.Fatal(err)
	}

	// Before arming: no pending command — the view's steady state.
	if get, gerr := a.GetDevice(ctx, "f0:9f:c2:84:8f:2a"); gerr != nil || get.PendingCommand != "" {
		t.Fatalf("pre-arm GET pending_command = %q (err=%v), want \"\"", get.PendingCommand, gerr)
	}

	dv, err := a.RebootDevice(ctx, "F0:9F:C2:84:8F:2A") // normalized on the way in
	if err != nil {
		t.Fatalf("reboot arm: %v", err)
	}
	if dv.MAC != "f0:9f:c2:84:8f:2a" || dv.State != store.StateAdopted {
		t.Fatalf("reboot view: %+v", dv)
	}
	if dv.PendingCommand != "reboot" {
		t.Fatalf("reboot-arm view pending_command = %q, want reboot", dv.PendingCommand)
	}
	if get, gerr := a.GetDevice(ctx, "f0:9f:c2:84:8f:2a"); gerr != nil || get.PendingCommand != "reboot" {
		t.Fatalf("post-arm GET pending_command = %q (err=%v), want reboot", get.PendingCommand, gerr)
	}
	d, err := st.Get("f09fc2848f2a")
	if err != nil {
		t.Fatal(err)
	}
	if !truthyFlag(d.Extra["reboot_on_connect"]) {
		t.Fatalf("reboot flag not armed: %+v", d.Extra)
	}
	if d.State != store.StateAdopted || d.XAuthkey != seeded.XAuthkey ||
		d.CfgVersion != seeded.CfgVersion || d.AppliedCfg != seeded.AppliedCfg {
		t.Fatalf("arming mutated the record: %+v", d)
	}

	// re-arm is idempotent; the setdefault arm coexists until the engine
	// fires (setdefault outranks reboot at emission).
	if _, err := a.RebootDevice(ctx, "f0:9f:c2:84:8f:2a"); err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	dv, err = a.FactoryResetDevice(ctx, "f0:9f:c2:84:8f:2a")
	if err != nil {
		t.Fatalf("factory-reset arm: %v", err)
	}
	// Both flags armed: factory-reset wins the view exactly as it wins
	// the engine's emission order.
	if dv.PendingCommand != "factory-reset" {
		t.Fatalf("both-armed view pending_command = %q, want factory-reset", dv.PendingCommand)
	}
	if get, gerr := a.GetDevice(ctx, "f0:9f:c2:84:8f:2a"); gerr != nil || get.PendingCommand != "factory-reset" {
		t.Fatalf("both-armed GET pending_command = %q (err=%v), want factory-reset", get.PendingCommand, gerr)
	}
	d, err = st.Get("f09fc2848f2a")
	if err != nil {
		t.Fatal(err)
	}
	if !truthyFlag(d.Extra["reboot_on_connect"]) || !truthyFlag(d.Extra["setdefault_armed"]) {
		t.Fatalf("both flags must be armed: %+v", d.Extra)
	}
	if d.State != store.StateAdopted || d.XAuthkey != seeded.XAuthkey ||
		d.CfgVersion != seeded.CfgVersion || d.AppliedCfg != seeded.AppliedCfg {
		t.Fatalf("arming mutated the record: %+v", d)
	}
}

// TestLifecycleArmingWorksOnNilExtra pins the nil-map arm path (a record
// created without Extra): UpdateExisting allocates the map, the flag
// lands, and nothing else changes.
func TestLifecycleArmingWorksOnNilExtra(t *testing.T) {
	a, st := testApp(t)
	if err := st.Put(store.Device{MAC: "a040a0aabbcc", State: store.StatePending}); err != nil {
		t.Fatal(err)
	}
	dv, err := a.FactoryResetDevice(context.Background(), "a0:40:a0:aa:bb:cc")
	if err != nil {
		t.Fatalf("arm on nil Extra: %v", err)
	}
	// Factory-reset armed ALONE (no reboot flag on this record): the view
	// must show it, so an operator can tell armed/pending from consumed.
	if dv.PendingCommand != "factory-reset" {
		t.Fatalf("nil-Extra arm view pending_command = %q, want factory-reset", dv.PendingCommand)
	}
	d, err := st.Get("a040a0aabbcc")
	if err != nil {
		t.Fatal(err)
	}
	if !truthyFlag(d.Extra["setdefault_armed"]) {
		t.Fatalf("flag not armed: %+v", d.Extra)
	}
	if d.State != store.StatePending {
		t.Fatalf("arming changed state: %+v", d)
	}
}

func TestLifecycleArmingUnknownMACIsWrappedNotFound(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	if _, err := a.RebootDevice(ctx, "ff:ff:ff:ff:ff:ff"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("reboot unknown: want adminapi.ErrNotFound wrapped, got %v", err)
	}
	if _, err := a.FactoryResetDevice(ctx, "ff:ff:ff:ff:ff:ff"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("factory-reset unknown: want adminapi.ErrNotFound wrapped, got %v", err)
	}
	if _, err := a.RebootDevice(ctx, "not-a-mac"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("reboot invalid mac: want adminapi.ErrNotFound wrapped, got %v", err)
	}
	if _, err := a.FactoryResetDevice(ctx, "not-a-mac"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("factory-reset invalid mac: want adminapi.ErrNotFound wrapped, got %v", err)
	}
}

// TestEnqueueCmdTaskArmsOnlyTheRow pins the §6.3 enqueue contract: the
// stored-task row lands as the ONLY record change (state, per-device key,
// cfgversion, applied cfgversion untouched — no §6.2 mint site exists for
// the replay), the view's PendingCommand reports "cmd" exactly while the
// task is armed, and a second enqueue REPLACES the armed task (at most
// one; §6.3 silent on enqueue, chosen: overwrite).
func TestEnqueueCmdTaskArmsOnlyTheRow(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()

	seeded := store.Device{
		MAC: "f09fc2848f2a", State: store.StateAdopted, Model: "U7PG2",
		XAuthkey: "0123456789abcdef", CfgVersion: "aaaabbbbccccdddd", AppliedCfg: "aaaabbbbccccdddd",
	}
	if err := st.Put(seeded); err != nil {
		t.Fatal(err)
	}

	// Before enqueue: no pending command.
	if get, gerr := a.GetDevice(ctx, "f0:9f:c2:84:8f:2a"); gerr != nil || get.PendingCommand != "" {
		t.Fatalf("pre-enqueue GET pending_command = %q (err=%v), want \"\"", get.PendingCommand, gerr)
	}

	dv, err := a.EnqueueDeviceCmd(ctx, "F0:9F:C2:84:8F:2A", "restart") // normalized on the way in
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if dv.PendingCommand != "cmd" {
		t.Fatalf("enqueue view pending_command = %q, want cmd", dv.PendingCommand)
	}
	d, err := st.Get("f09fc2848f2a")
	if err != nil {
		t.Fatal(err)
	}
	if got := store.CmdTaskCmd(d); got != "restart" {
		t.Fatalf("stored cmd = %q, want restart (row: %+v)", got, d.Extra[store.CmdTaskKey])
	}
	if row := store.ArmedCmdTask(d); row == nil || row["mac"] != "f09fc2848f2a" {
		t.Fatalf("stored row mac = %+v, want the canonical identity", row)
	}
	if d.State != store.StateAdopted || d.XAuthkey != seeded.XAuthkey ||
		d.CfgVersion != seeded.CfgVersion || d.AppliedCfg != seeded.AppliedCfg {
		t.Fatalf("enqueue mutated the record: %+v", d)
	}

	// Second enqueue REPLACES the armed task; the queue holds one slot.
	if _, err := a.EnqueueDeviceCmd(ctx, "f0:9f:c2:84:8f:2a", "spectrum-scan"); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	d, err = st.Get("f09fc2848f2a")
	if err != nil {
		t.Fatal(err)
	}
	if got := store.CmdTaskCmd(d); got != "spectrum-scan" {
		t.Fatalf("re-enqueue did not replace the task: cmd = %q", got)
	}
	if get, gerr := a.GetDevice(ctx, "f0:9f:c2:84:8f:2a"); gerr != nil || get.PendingCommand != "cmd" {
		t.Fatalf("post-re-enqueue GET pending_command = %q (err=%v), want cmd", get.PendingCommand, gerr)
	}
}

// TestEnqueueCmdTaskWorksOnNilExtra pins the nil-map enqueue path (a
// record created without Extra): UpdateExisting allocates the map, the
// row lands, nothing else changes.
func TestEnqueueCmdTaskWorksOnNilExtra(t *testing.T) {
	a, st := testApp(t)
	if err := st.Put(store.Device{MAC: "a040a0aabbcc", State: store.StatePending}); err != nil {
		t.Fatal(err)
	}
	dv, err := a.EnqueueDeviceCmd(context.Background(), "a0:40:a0:aa:bb:cc", "restart")
	if err != nil {
		t.Fatalf("enqueue on nil Extra: %v", err)
	}
	if dv.PendingCommand != "cmd" {
		t.Fatalf("nil-Extra enqueue view pending_command = %q, want cmd", dv.PendingCommand)
	}
	d, err := st.Get("a040a0aabbcc")
	if err != nil {
		t.Fatal(err)
	}
	if got := store.CmdTaskCmd(d); got != "restart" {
		t.Fatalf("stored cmd = %q, want restart", got)
	}
	if d.State != store.StatePending {
		t.Fatalf("enqueue changed state: %+v", d)
	}
}

// TestEnqueueCmdTaskUnknownMACIsWrappedNotFound: the enqueue seam maps
// unknown and unparseable MACs onto the wrapped ErrNotFound sentinel,
// like the arming routes.
func TestEnqueueCmdTaskUnknownMACIsWrappedNotFound(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	if _, err := a.EnqueueDeviceCmd(ctx, "ff:ff:ff:ff:ff:ff", "restart"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("enqueue unknown: want adminapi.ErrNotFound wrapped, got %v", err)
	}
	if _, err := a.EnqueueDeviceCmd(ctx, "not-a-mac", "restart"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("enqueue invalid mac: want adminapi.ErrNotFound wrapped, got %v", err)
	}
}

// TestEnqueueCmdTaskViewPrecedence: the view names the response _type the
// engine will actually fire — factory-reset and reboot outrank the queued
// task exactly like armedLifecycle's emission order.
func TestEnqueueCmdTaskViewPrecedence(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	if err := a.st.Put(store.Device{MAC: "f09fc2848f2a", State: store.StateAdopted}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.EnqueueDeviceCmd(ctx, "f0:9f:c2:84:8f:2a", "restart"); err != nil {
		t.Fatal(err)
	}
	if get, gerr := a.GetDevice(ctx, "f0:9f:c2:84:8f:2a"); gerr != nil || get.PendingCommand != "cmd" {
		t.Fatalf("task-only view pending_command = %q (err=%v), want cmd", get.PendingCommand, gerr)
	}
	if _, err := a.RebootDevice(ctx, "f0:9f:c2:84:8f:2a"); err != nil {
		t.Fatal(err)
	}
	if get, gerr := a.GetDevice(ctx, "f0:9f:c2:84:8f:2a"); gerr != nil || get.PendingCommand != "reboot" {
		t.Fatalf("reboot-outranks view pending_command = %q (err=%v), want reboot", get.PendingCommand, gerr)
	}
	if _, err := a.FactoryResetDevice(ctx, "f0:9f:c2:84:8f:2a"); err != nil {
		t.Fatal(err)
	}
	if get, gerr := a.GetDevice(ctx, "f0:9f:c2:84:8f:2a"); gerr != nil || get.PendingCommand != "factory-reset" {
		t.Fatalf("setdefault-outranks view pending_command = %q (err=%v), want factory-reset", get.PendingCommand, gerr)
	}
}

// truthyFlag mirrors the adoption engine's truthy() for the JSON map
// values an armed flag can carry (stored as bool true).
func truthyFlag(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != "" && t != "0" && t != "false"
	case float64:
		return t != 0
	case nil:
		return false
	}
	return v != nil
}

// ---- end-to-end wiring: real adapter behind the real adminapi handler ----

// TestHTTPNotFoundThroughRealAdapter composes App (real Backend) with a real
// adminapi handler and exercises unknown-MAC paths over httptest recorders —
// no sockets. Pins the wire contract: unknown device must be HTTP 404 with a
// JSON error body on GET/DELETE/adopt, never 500.
func TestHTTPNotFoundThroughRealAdapter(t *testing.T) {
	a, _ := testApp(t)
	h := adminapi.New(adminapi.Config{}, a) // App implements Backend

	for _, tc := range []struct {
		name, method, path string
	}{
		{"get unknown", "GET", "/api/v1/devices/ff:ff:ff:ff:ff:ff"},
		{"delete unknown", "DELETE", "/api/v1/devices/ff:ff:ff:ff:ff:ff"},
		{"adopt unknown", "POST", "/api/v1/pending/ff:ff:ff:ff:ff:ff/adopt"},
	} {
		req, err := http.NewRequest(tc.method, tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d (%s), want 404", tc.name, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body not JSON: %q", tc.name, rec.Body.String())
		}
		if s, _ := body["error"].(string); s == "" {
			t.Fatalf("%s: missing error key", tc.name)
		}
	}

	// known devices still work end to end (sanity of the composition)
	if _, err := a.CreateDevice(context.Background(), adminapi.DeviceUpsert{MAC: "F0:9F:C2:84:8F:2A"}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/v1/devices/f0:9f:c2:84:8f:2a", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get known through adapter: %d (%s)", rec.Code, rec.Body.String())
	}
}

// ---- per-device wireless persistence -------------------------------------

const testWLANDeviceMAC = "aabbccddeeff"

func seedWLANDevice(t *testing.T, a *App, st store.DeviceStore) {
	t.Helper()
	ctx := context.Background()
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: testWLANDeviceMAC, Name: "ap1"}); err != nil {
		t.Fatal(err)
	}
	_ = st
}

func TestDeviceWirelessRoundTripPersistence(t *testing.T) {
	a, st := testApp(t)
	seedWLANDevice(t, a, st)
	ctx := context.Background()

	got, err := a.GetDeviceWireless(ctx, testWLANDeviceMAC)
	if err != nil || len(got.Wlans) != 0 {
		t.Fatalf("default wireless: %+v err=%v", got, err)
	}

	env := adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{
		{ID: "w1", Name: "home", SSID: "home-net", Security: "wpa-p", Passphrase: "correct-horse", VLAN: 1, Enabled: true},
		{Name: "guest", SSID: "guests", Security: "open", VLAN: 20},
	}}
	if err := a.PutDeviceWireless(ctx, testWLANDeviceMAC, env); err != nil {
		t.Fatalf("put wireless: %v", err)
	}

	back, err := a.GetDeviceWireless(ctx, testWLANDeviceMAC)
	if err != nil || len(back.Wlans) != 2 || back.Wlans[0].SSID != "home-net" || back.Wlans[1].VLAN != 20 {
		t.Fatalf("readback: %+v err=%v", back, err)
	}

	rec, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if len(wireless.DeviceWLANs(rec)) != 2 {
		t.Fatalf("device_wlans on record: %+v", wireless.DeviceWLANs(rec))
	}
}

func TestPutDeviceWirelessFencesFullEnvelope(t *testing.T) {
	a, st := testApp(t)
	seedWLANDevice(t, a, st)
	ctx := context.Background()
	err := a.PutDeviceWireless(ctx, testWLANDeviceMAC, adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{
		{Name: "", SSID: "ssid-only", Security: "open", VLAN: 1},
	}})
	if !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("empty-name wlan must be ErrConflict, got %v", err)
	}
	env, err := a.GetDeviceWireless(ctx, testWLANDeviceMAC)
	if err != nil || len(env.Wlans) != 0 {
		t.Fatalf("fenced put must not leave wlans on device: %+v err=%v", env, err)
	}
}

func TestUpdateDeviceWlanDuplicateSSIDRejected(t *testing.T) {
	a, st := testApp(t)
	seedWLANDevice(t, a, st)
	ctx := context.Background()
	pre := adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{
		{Name: "a", SSID: "aa", Security: "open", VLAN: 1, Enabled: true},
		{Name: "b", SSID: "bb", Security: "open", VLAN: 2, Enabled: true},
	}}
	if err := a.PutDeviceWireless(ctx, testWLANDeviceMAC, pre); err != nil {
		t.Fatal(err)
	}
	_, err := a.UpdateDeviceWlan(ctx, testWLANDeviceMAC, "a", adminapi.Wlan{Name: "a", SSID: "bb", Security: "open", VLAN: 1, Enabled: true})
	if !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("duplicate SSID update must be rejected, got %v", err)
	}
	got, err := a.GetDeviceWireless(ctx, testWLANDeviceMAC)
	if err != nil || got.Wlans[0].SSID != "aa" {
		t.Fatalf("unchanged: %+v err=%v", got, err)
	}
}

func TestDeleteDeviceWlan(t *testing.T) {
	a, st := testApp(t)
	seedWLANDevice(t, a, st)
	ctx := context.Background()
	pre := adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{
		{Name: "a", SSID: "aa", Security: "open", VLAN: 1, Enabled: true},
		{Name: "b", SSID: "bb", Security: "open", VLAN: 2, Enabled: true},
	}}
	if err := a.PutDeviceWireless(ctx, testWLANDeviceMAC, pre); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteDeviceWlan(ctx, testWLANDeviceMAC, "nope"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("unknown delete: %v", err)
	}
	if err := a.DeleteDeviceWlan(ctx, testWLANDeviceMAC, "a"); err != nil {
		t.Fatal(err)
	}
	got, err := a.GetDeviceWireless(ctx, testWLANDeviceMAC)
	if err != nil || len(got.Wlans) != 1 || got.Wlans[0].Name != "b" {
		t.Fatalf("post-delete: %+v err=%v", got, err)
	}
}

// ---- metrics poller ------------------------------------------------------

func pollerSetup(t *testing.T) (*App, store.DeviceStore) {
	t.Helper()
	return testApp(t)
}

// ---- lost sweep (StateLost finally has a producer) ------------------------

func TestLostSweepMarksStaleAdoptedDeviceLost(t *testing.T) {
	a, st := pollerSetup(t)
	now := time.Now().Unix()

	mk := func(mac string) error {
		return st.Put(store.Device{MAC: mac, State: store.StateAdopted, LastSeen: now - lostAfterSeconds - 121})
	}
	if err := mk("f09fc2848f2a"); err != nil {
		t.Fatal(err)
	}
	// fresh adopted: must be untouched
	if err := st.Put(store.Device{MAC: "010203040506", State: store.StateAdopted, LastSeen: now - 15}); err != nil {
		t.Fatal(err)
	}
	// other states with ancient LastSeen: never swept
	if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StatePending, LastSeen: now - 9999}); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(store.Device{MAC: "112233445566", State: store.StateAdopting, LastSeen: now - 9999}); err != nil {
		t.Fatal(err)
	}

	bFail := counterDefault("openunifi_adopt_fail_total")
	a.PollOnce()

	if d, err := st.Get("f09fc2848f2a"); err != nil || d.State != store.StateLost {
		t.Fatalf("stale adopted must be StateLost, got %+v err=%v", d, err)
	}
	if d, err := st.Get("010203040506"); err != nil || d.State != store.StateAdopted {
		t.Fatalf("fresh adopted must stay Adopted, got %+v err=%v", d, err)
	}
	if d, err := st.Get("aabbccddeeff"); err != nil || d.State != store.StatePending {
		t.Fatalf("pending must never be swept, got %+v err=%v", d, err)
	}
	if d, err := st.Get("112233445566"); err != nil || d.State != store.StateAdopting {
		t.Fatalf("adopting must never be swept, got %+v err=%v", d, err)
	}
	if got := counterDefault("openunifi_adopt_fail_total"); got != bFail+1 {
		t.Fatalf("sweep transition must count exactly one adopt failure: %v -> %v", bFail, got)
	}
}

func TestLostSweepSkipsAdoptedWithZeroLastSeen(t *testing.T) {
	a, st := pollerSetup(t)
	if err := st.Put(store.Device{MAC: "f09fc2848f2a", State: store.StateAdopted, LastSeen: 0}); err != nil {
		t.Fatal(err)
	}
	bFail := counterDefault("openunifi_adopt_fail_total")
	a.PollOnce()
	if d, err := st.Get("f09fc2848f2a"); err != nil || d.State != store.StateAdopted {
		t.Fatalf("LastSeen==0 (never seen) must not be swept to Lost, got %+v err=%v", d, err)
	}
	if got := counterDefault("openunifi_adopt_fail_total"); got != bFail {
		t.Fatalf("no sweep transition, no fail count: %v -> %v", bFail, got)
	}
}

func TestPrevStatesPrunedForDeletedDevices(t *testing.T) {
	a, st := pollerSetup(t)
	if err := st.Put(store.Device{MAC: "f09fc2848f2a", State: store.StateAdopted, LastSeen: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	a.PollOnce() // seeds prevStates
	a.prevMu.Lock()
	seeded := len(a.prevStates)
	a.prevMu.Unlock()
	if seeded != 1 {
		t.Fatalf("expected exactly one prevStates entry, got %d", seeded)
	}

	if err := st.Delete("f09fc2848f2a"); err != nil {
		t.Fatal(err)
	}
	a.PollOnce() // device gone: prevStates entry must be pruned, not leak
	a.prevMu.Lock()
	left := len(a.prevStates)
	a.prevMu.Unlock()
	if left != 0 {
		t.Fatalf("prevStates entry for deleted device must be pruned, %d left", left)
	}
}

// Deleting a device must also remove its metric series (FID-38): per-device
// gauges keyed by MAC would otherwise survive inventory churn forever, with
// mac labels enumerating devices that are no longer ours to track.
func TestDeleteDevicePrunesMetricSeries(t *testing.T) {
	a, st := pollerSetup(t)
	ctx := context.Background()

	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "F0:9F:C2:84:8F:2A", Name: "lobby"}); err != nil {
		t.Fatal(err)
	}
	d, err := st.Get("f09fc2848f2a")
	if err != nil {
		t.Fatal(err)
	}
	d.State = store.StateAdopted
	d.Model = "U7PG2"
	d.LastSeen = time.Now().Unix()
	d.Extra = store.JSONMap{"uptime": 7231.0}
	d.LastUps = store.JSONMap{"user-num_sta": 12.0, "user-tx_bytes": 1048576.0, "user-rx_bytes": 2097152.0}
	if err := st.Put(d); err != nil {
		t.Fatal(err)
	}
	a.PollOnce() // seeds the per-device gauges

	if got := seriesForMAC(gatherDefault(t), "f0:9f:c2:84:8f:2a"); got < 6 {
		t.Fatalf("expected seeded series (state+last_seen+uptime+tx+rx), got %d", got)
	}

	if err := a.DeleteDevice(ctx, "f0:9f:c2:84:8f:2a"); err != nil {
		t.Fatal(err)
	}

	if got := seriesForMAC(gatherDefault(t), "f0:9f:c2:84:8f:2a"); got != 0 {
		t.Fatalf("deleted device still has %d metric series", got)
	}
}

// gatherDefault and seriesForMAC count exposition series for a MAC label,
// since the process-global registry accumulates series from earlier tests.

// gatherDefault collects one exposition snapshot from the default registry,
// keyed "<family>{label=value,...}".
func gatherDefault(t *testing.T) map[string]*dto.Metric {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*dto.Metric{}
	for _, f := range fams {
		for _, m := range f.Metric {
			labels := ""
			for _, l := range m.GetLabel() {
				labels += l.GetName() + "=" + l.GetValue() + ","
			}
			out[f.GetName()+"{"+labels+"}"] = m
		}
	}
	return out
}

// seriesForMAC counts gathered series whose mac label matches.
func seriesForMAC(g map[string]*dto.Metric, mac string) int {
	n := 0
	for k := range g {
		if strings.Contains(k, "mac="+mac+",") {
			n++
		}
	}
	return n
}

// ---- MAC consolidation (store.CanonicalMAC is the single normalizer) -----

func TestInvalidMACIsRejectedOrNotFound(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()

	for _, bad := range []string{"zz", "not a mac at all"} {
		if _, err := a.GetDevice(ctx, bad); !errors.Is(err, adminapi.ErrNotFound) {
			t.Fatalf("get %q: want not-found, got %v", bad, err)
		}
		if err := a.DeleteDevice(ctx, bad); !errors.Is(err, adminapi.ErrNotFound) {
			t.Fatalf("delete %q: want not-found, got %v", bad, err)
		}
		if _, err := a.AdoptPending(ctx, bad); err == nil {
			t.Fatalf("adopt %q: want error", bad)
		}
	}
	// After the saveIntent convergence the unparseable create maps to the
	// skeleton's canonical wrapped-404 sentinel (was: a plain "invalid mac"
	// error) — the route 400s first, so this is the direct-caller shape.
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "zz"}); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("create with unparseable mac must be wrapped-ErrNotFound, got %v", err)
	}
	// valid input is behavior-identical to the old private normalizer
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "A0.40.A0.AA.BB.CC"}); err != nil {
		t.Fatalf("dot-separated mac must normalize: %v", err)
	}
}

// ---- per-radio admin intent (admin-owned record state) ---------------------

// seedRadioDevice seeds an adopted device whose radio_table mirrors the
// live U7PG2 shape: ra0 (ng) + rai0 (na), device-reported txpower bounds
// 6..22 dBm, echo channel defaults.
func seedRadioDevice(t *testing.T, st store.DeviceStore) {
	t.Helper()
	if err := st.Put(store.Device{
		MAC: "aabbccddeeff", Model: "U7PG2", State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
		Extra: store.JSONMap{"radio_table": []any{
			map[string]any{"name": "ra0", "radio": "ng", "channel": "6",
				"min_txpower": 6.0, "max_txpower": 22.0},
			map[string]any{"name": "rai0", "radio": "na", "channel": 0.0,
				"min_txpower": 6.0, "max_txpower": 22.0},
		}},
	}); err != nil {
		t.Fatal(err)
	}
}

func chPtr(n int) *int { return &n }
func txPtr(auto bool, dbm int) *adminapi.RadioTxPower {
	return &adminapi.RadioTxPower{Auto: auto, DBm: dbm}
}

// TestRadioIntentPutBumpsCfgVersionOncePerChange pins the operator-save
// trigger: an EFFECTIVE intent change bumps the device's cfgversion
// (fresh 16-hex, the engine's operator-save shape); idempotent writes
// do not bump; wholesale replaces/clears behave the same.
func TestRadioIntentPutBumpsCfgVersionOncePerChange(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	seedRadioDevice(t, st)

	v, err := a.PutDeviceRadioIntent(ctx, "aabbccddeeff", "rai0",
		adminapi.RadioIntentUpsert{Channel: chPtr(36)})
	if err != nil {
		t.Fatal(err)
	}
	if v.Channel == nil || *v.Channel != "36" || v.Txpower != nil {
		t.Fatalf("put view: %+v", v)
	}
	rec, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if rec.CfgVersion == "aaaa" || len(rec.CfgVersion) != 16 {
		t.Fatalf("effective change must bump cfgversion (16 hex), got %q", rec.CfgVersion)
	}
	per, ok := rec.Extra["radio_intent"].(map[string]any)["rai0"].(map[string]any)
	if !ok || per["channel"] != 36.0 {
		t.Fatalf("stored intent: %v", rec.Extra["radio_intent"])
	}

	// Idempotent re-put of the same value: no further bump.
	bumped := rec.CfgVersion
	if _, err := a.PutDeviceRadioIntent(ctx, "aabbccddeeff", "rai0",
		adminapi.RadioIntentUpsert{Channel: chPtr(36)}); err != nil {
		t.Fatal(err)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil {
		t.Fatal(err)
	}
	if rec.CfgVersion != bumped {
		t.Fatalf("idempotent write bumped cfgversion: %q -> %q", bumped, rec.CfgVersion)
	}

	// Wholesale replace: txpower only — the channel intent is cleared.
	v, err = a.PutDeviceRadioIntent(ctx, "aabbccddeeff", "rai0",
		adminapi.RadioIntentUpsert{Txpower: txPtr(false, 10)})
	if err != nil {
		t.Fatal(err)
	}
	if v.Channel != nil || v.Txpower == nil || *v.Txpower != "10" {
		t.Fatalf("wholesale replace view: %+v", v)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil {
		t.Fatal(err)
	}
	if rec.CfgVersion == bumped {
		t.Fatal("effective change (channel cleared) must bump cfgversion")
	}
	per = rec.Extra["radio_intent"].(map[string]any)["rai0"].(map[string]any)
	if _, has := per["channel"]; has {
		t.Fatalf("wholesale replace must clear the channel field: %v", per)
	}
	if per["txpower"] != 10.0 {
		t.Fatalf("stored txpower: %v", per)
	}

	// DELETE clears the radio's layer entirely; the empty layer key is
	// dropped from Extra (absent == empty on disk).
	v, err = a.DeleteDeviceRadioIntent(ctx, "aabbccddeeff", "rai0")
	if err != nil {
		t.Fatal(err)
	}
	if v.Channel != nil || v.Txpower != nil {
		t.Fatalf("delete view must show echo-only: %+v", v)
	}
	if rec, err = st.Get("aabbccddeeff"); err != nil {
		t.Fatal(err)
	}
	if _, exists := rec.Extra["radio_intent"]; exists {
		t.Fatalf("empty intent layer must be dropped from Extra: %v", rec.Extra["radio_intent"])
	}
	if rec.CfgVersion == bumped {
		t.Fatal("effective clear must bump cfgversion")
	}
}

// TestRadioIntentValidation pins the band/bounds contract: ng/na channel
// ranges, device-reported txpower bounds, the "auto" forms, unknown-band
// rejection, missing-bounds rejection, and unknown MAC/radio 404s.
func TestRadioIntentValidation(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	seedRadioDevice(t, st)
	// An unknown-band radio and a bounds-less radio join the fixture.
	if err := st.Update("aabbccddeeff", func(d *store.Device) error {
		d.Extra["radio_table"] = append(d.Extra["radio_table"].([]any),
			map[string]any{"name": "rae0", "radio": "6e"},
			map[string]any{"name": "rax0", "radio": "ng"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	ok := func(radio string, up adminapi.RadioIntentUpsert) error {
		_, err := a.PutDeviceRadioIntent(ctx, "aabbccddeeff", radio, up)
		return err
	}
	conflict := func(err error) bool { return errors.Is(err, adminapi.ErrConflict) }
	notFound := func(err error) bool { return errors.Is(err, adminapi.ErrNotFound) }

	// Channel ranges per band.
	if err := ok("ra0", adminapi.RadioIntentUpsert{Channel: chPtr(15)}); !conflict(err) {
		t.Fatalf("ng channel 15 must conflict: %v", err)
	}
	if err := ok("ra0", adminapi.RadioIntentUpsert{Channel: chPtr(-1)}); !conflict(err) {
		t.Fatalf("ng channel -1 must conflict: %v", err)
	}
	if err := ok("ra0", adminapi.RadioIntentUpsert{Channel: chPtr(0)}); err != nil {
		t.Fatalf("ng channel 0 (explicit auto) must pass: %v", err)
	}
	if err := ok("rai0", adminapi.RadioIntentUpsert{Channel: chPtr(200)}); !conflict(err) {
		t.Fatalf("na channel 200 must conflict: %v", err)
	}
	if err := ok("rai0", adminapi.RadioIntentUpsert{Channel: chPtr(35)}); !conflict(err) {
		t.Fatalf("na channel 35 must conflict: %v", err)
	}
	if err := ok("rai0", adminapi.RadioIntentUpsert{Channel: chPtr(36)}); err != nil {
		t.Fatalf("na channel 36 must pass: %v", err)
	}
	// txpower bounds: device-reported [6, 22].
	if err := ok("ra0", adminapi.RadioIntentUpsert{Txpower: txPtr(false, 23)}); !conflict(err) {
		t.Fatalf("txpower 23 over max must conflict: %v", err)
	}
	if err := ok("ra0", adminapi.RadioIntentUpsert{Txpower: txPtr(false, 5)}); !conflict(err) {
		t.Fatalf("txpower 5 under min must conflict: %v", err)
	}
	if err := ok("ra0", adminapi.RadioIntentUpsert{Txpower: txPtr(false, 22)}); err != nil {
		t.Fatalf("txpower 22 at max must pass: %v", err)
	}
	if err := ok("ra0", adminapi.RadioIntentUpsert{Txpower: txPtr(true, 0)}); err != nil {
		t.Fatalf("txpower auto must pass: %v", err)
	}
	// Unknown band: any intent (even auto) is rejected — semantics for
	// non-na/ng tokens are unrecovered; never ship unvalidated rows.
	if err := ok("rae0", adminapi.RadioIntentUpsert{Channel: chPtr(36)}); !conflict(err) {
		t.Fatalf("unknown-band channel intent must conflict: %v", err)
	}
	if err := ok("rae0", adminapi.RadioIntentUpsert{Txpower: txPtr(true, 0)}); !conflict(err) {
		t.Fatalf("unknown-band txpower intent must conflict: %v", err)
	}
	// Bounds-less radio: fixed txpower rejected ("byte-exact or absent"),
	// auto passes.
	if err := ok("rax0", adminapi.RadioIntentUpsert{Txpower: txPtr(false, 10)}); !conflict(err) {
		t.Fatalf("txpower without device bounds must conflict: %v", err)
	}
	if err := ok("rax0", adminapi.RadioIntentUpsert{Txpower: txPtr(true, 0)}); err != nil {
		t.Fatalf("txpower auto without bounds must pass: %v", err)
	}
	// Unknown radio name and unknown MAC: not-found (404).
	if err := ok("nosuch", adminapi.RadioIntentUpsert{Channel: chPtr(36)}); !notFound(err) {
		t.Fatalf("unknown radio must be not-found: %v", err)
	}
	if _, err := a.PutDeviceRadioIntent(ctx, "deadbeef0000", "ra0",
		adminapi.RadioIntentUpsert{Channel: chPtr(36)}); !notFound(err) {
		t.Fatalf("unknown mac must be not-found: %v", err)
	}
	if _, err := a.ListDeviceRadios(ctx, "deadbeef0000"); !notFound(err) {
		t.Fatalf("list unknown mac must be not-found: %v", err)
	}
}

// TestRadioIntentListView pins the list read model: name order, the echo
// fields formatted exactly as the renderer emits them, and intent
// overlaying the echo.
func TestRadioIntentListView(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	seedRadioDevice(t, st)
	if _, err := a.PutDeviceRadioIntent(ctx, "aa:bb:cc:dd:ee:ff", "rai0",
		adminapi.RadioIntentUpsert{Channel: chPtr(36), Txpower: txPtr(false, 8)}); err != nil {
		t.Fatal(err)
	}
	radios, err := a.ListDeviceRadios(ctx, "AA-BB-CC-DD-EE-FF")
	if err != nil {
		t.Fatal(err)
	}
	if len(radios) != 2 {
		t.Fatalf("want 2 radios, got %+v", radios)
	}
	if radios[0].Name != "ra0" || radios[1].Name != "rai0" {
		t.Fatalf("radios must be in name order: %+v", radios)
	}
	ra0, rai0 := radios[0], radios[1]
	if ra0.Channel != nil || ra0.Txpower != nil ||
		ra0.EchoChannel != "6" || ra0.EchoTxPower != "auto" || ra0.EchoTxPowerMode != "auto" {
		t.Fatalf("ra0 view (echo only): %+v", ra0)
	}
	if rai0.Channel == nil || *rai0.Channel != "36" || rai0.Txpower == nil || *rai0.Txpower != "8" ||
		rai0.EchoChannel != "0" || rai0.EchoTxPower != "auto" {
		t.Fatalf("rai0 view (intent over echo): %+v", rai0)
	}
}

// ---- admin-intent fences at the Backend (the save skeleton's validate step) --
//
// The admin-intent save owns its domain fences — the essential
// domain-pinning cases that used to hang only on the adminapi helpers are
// pinned HERE at the Backend seam where the save skeleton validates. The
// adminapi boundary battery stays untouched on that lane; these are the
// Backend-surface equivalents (rejections are ErrConflict, sentinels are
// ErrNotFound, rejected saves mutate nothing).

// TestEnqueueCmdFenceRecordByteUntouched pins the cmd fence's no-mutation
// guarantee by full-DeepEqual comparison: a st.Put-seeded record (no
// timestamps anywhere — the fetched record is deterministic) fetched after
// five rejected enqueues must equal the seeded literal EXACTLY, not merely
// share the rows the earlier partial checks looked at.
func TestEnqueueCmdFenceRecordByteUntouched(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	seeded := store.Device{
		MAC: "f09fc2848f2a", State: store.StateAdopted, Model: "U7PG2",
		CfgVersion: "aaaabbbbccccdddd", AppliedCfg: "aaaabbbbccccdddd",
	}
	if err := st.Put(seeded); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"", strings.Repeat("x", 65), "re\nstart", " restart", "restart "} {
		if _, err := a.EnqueueDeviceCmd(ctx, "f0:9f:c2:84:8f:2a", cmd); !errors.Is(err, adminapi.ErrConflict) {
			t.Fatalf("cmd %q: want ErrConflict, got %v", cmd, err)
		}
	}
	got, err := st.Get("f09fc2848f2a")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, seeded) {
		t.Fatalf("rejected enqueue mutated the record:\n got %+v\nwant %+v", got, seeded)
	}
}

// TestEnqueueCmdStringBackendFence pins the §6.3 cmd fence at the
// Backend seam (mirror of the route's 400 battery, moved home with the
// save skeleton): empty, oversized, control-character and padded cmd
// strings are ErrConflict and arm nothing; a reject happens before the
// row write, so the record stays exactly as it was.
func TestEnqueueCmdStringBackendFence(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	seeded := store.Device{
		MAC: "f09fc2848f2a", State: store.StateAdopted, Model: "U7PG2",
		CfgVersion: "aaaabbbbccccdddd", AppliedCfg: "aaaabbbbccccdddd",
	}
	if err := st.Put(seeded); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, cmd string
	}{
		{"empty", ""},
		{"oversized", strings.Repeat("x", 65)},
		{"control char", "re\nstart"},
		{"leading whitespace", " restart"},
		{"trailing whitespace", "restart "},
	} {
		if _, err := a.EnqueueDeviceCmd(ctx, "f0:9f:c2:84:8f:2a", tc.cmd); !errors.Is(err, adminapi.ErrConflict) {
			t.Fatalf("%s cmd %q: want ErrConflict, got %v", tc.name, tc.cmd, err)
		}
		if _, err := st.Get("f09fc2848f2a"); err != nil {
			t.Fatalf("%s fence left no record: %v", tc.name, err)
		}
	}
	// A rejected enqueue must not have armed the row (second dollar: the
	// record carries no cmd task row).
	d, err := st.Get("f09fc2848f2a")
	if err != nil {
		t.Fatal(err)
	}
	if store.ArmedCmdTask(d) != nil {
		t.Fatalf("rejected enqueue armed a task row: %+v", d.Extra)
	}
	if d.State != store.StateAdopted || d.CfgVersion != seeded.CfgVersion {
		t.Fatalf("rejected enqueue mutated the record: %+v", d)
	}
	// A valid cmd still arms verbatim (the fence rejects, never trims).
	if _, err := a.EnqueueDeviceCmd(ctx, "f0:9f:c2:84:8f:2a", "restart"); err != nil {
		t.Fatalf("valid enqueue: %v", err)
	}
	if d, err = st.Get("f09fc2848f2a"); err != nil || store.CmdTaskCmd(d) != "restart" {
		t.Fatalf("valid enqueue row: %+v err=%v", d, err)
	}
}

// TestPatchSiteIDBackendFence pins the site_id fence at the Backend seam
// (mirror of the route's 400, via the same fence style as the name): an
// out-of-domain site_id is ErrConflict and mutates nothing; "" stays the
// documented explicit clear.
func TestPatchSiteIDBackendFence(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "aabbccddeeff", SiteID: "default"}); err != nil {
		t.Fatal(err)
	}
	before, err := a.GetDevice(ctx, "aabbccddeeff")
	if err != nil || before.SiteID != "default" {
		t.Fatalf("pre-state: %+v err=%v", before, err)
	}
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{SiteID: deviceNamePtr("bad site!")}); !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("invalid site_id must be ErrConflict, got %v", err)
	}
	if dv, err := a.GetDevice(ctx, "aabbccddeeff"); err != nil || dv.SiteID != "default" {
		t.Fatalf("rejected site patch mutated the record: %+v err=%v", dv, err)
	}
	// "" is the explicit clear and stays legal at the Backend.
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{SiteID: deviceNamePtr("")}); err != nil {
		t.Fatalf("explicit site clear must stay legal: %v", err)
	}
	if dv, err := a.GetDevice(ctx, "aabbccddeeff"); err != nil || dv.SiteID != "" {
		t.Fatalf("site clear: %+v err=%v", dv, err)
	}
}

// TestPatchLEDEffectiveChangeEchoesMintedCfgVersion pins the mint ECHO:
// an EFFECTIVE LED patch ships the fresh cfgversion in the same 200 body —
// the saveIntent project step runs AFTER the mint inside the same cycle, so
// the returned DeviceView can never carry the stale pre-mint value. No
// existing test read the returned CfgVersion (the mint pins read the store
// record instead), which is exactly the hole this closes.
func TestPatchLEDEffectiveChangeEchoesMintedCfgVersion(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	const seeded = "aaaabbbbccccdddd"
	if err := st.Put(store.Device{
		MAC: "aabbccddeeff", Model: "U7PG2", State: store.StateAdopted,
		CfgVersion: seeded, AppliedCfg: seeded,
	}); err != nil {
		t.Fatal(err)
	}
	dv, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{LEDOverride: ledOverridePtr("on")})
	if err != nil {
		t.Fatal(err)
	}
	if dv.CfgVersion == seeded || len(dv.CfgVersion) != 16 {
		t.Fatalf("200 body must echo the minted cfgversion (fresh 16-hex), got %q", dv.CfgVersion)
	}
	if dv.LEDOverride != "on" {
		t.Fatalf("echo view is the projected record state: %+v", dv)
	}
}

// TestCreateDeviceSiteIDBackendFence pins the site_id fence at the Backend
// seam of the create save (mirror of TestPatchSiteIDBackendFence): garbage
// site_id is ErrConflict and — the change step aborting inside the store's
// RMW cycle — mutates nothing: an unknown MAC is NOT seeded (absent), an
// existing record stays byte-identical (compared by DeepEqual between two
// st.Get snapshots, never against a constructed clone — CreateDevice
// stamps FirstSeen). A valid site_id creates normally.
func TestCreateDeviceSiteIDBackendFence(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()

	// Unknown MAC + garbage site_id: ErrConflict, and the aborted upsert
	// cycle must not leave a seeded record behind.
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "aabbccddeeff", SiteID: "bad site!"}); !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("invalid site_id must be ErrConflict, got %v", err)
	}
	if _, err := st.Get("aabbccddeeff"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rejected create must not seed a record, got %+v", err)
	}

	// Existing record + garbage site_id: ErrConflict, byte-identical record.
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "aabbccddeeff", Name: "lobby", SiteID: "s1"}); err != nil {
		t.Fatalf("valid create: %v", err)
	}
	before, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatalf("pre-fence fetch: %v", err)
	}
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "aabbccddeeff", SiteID: "bad site!"}); !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("invalid site_id on existing record must be ErrConflict, got %v", err)
	}
	after, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatalf("post-fence fetch: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected create mutated the record: %+v -> %+v", before, after)
	}
}

// TestPatchBookkeepingRowsMintNothing pins the save skeleton's mint
// condition end to end: name and site_id are bookkeeping rows the device
// is never provisioned from — saving them effectively changes NO
// provisioning input and therefore mints no cfgversion.
func TestPatchBookkeepingRowsMintNothing(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	if err := st.Put(store.Device{
		MAC: "aabbccddeeff", Model: "U7PG2", State: store.StateAdopted,
		CfgVersion: "aaaabbbbccccdddd", AppliedCfg: "aaaabbbbccccdddd",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PatchDevice(ctx, "aabbccddeeff", adminapi.DevicePatch{
		Name: deviceNamePtr("renamed"), SiteID: deviceNamePtr("lab"),
	}); err != nil {
		t.Fatal(err)
	}
	rec, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Name != "renamed" || rec.SiteID != "lab" {
		t.Fatalf("bookkeeping rows not saved: %+v", rec)
	}
	if rec.CfgVersion != "aaaabbbbccccdddd" {
		t.Fatalf("bookkeeping-only save minted a cfgversion: %q", rec.CfgVersion)
	}
}

// ---- devname-level device view (vaps_not_running) ----------------------------

// TestDeviceViewVAPsNotRunning pins the GET read model's devname-level
// runtime field: when a planned vap's devname is absent/not-RUN from the
// record's vap_table while the SSID still proves RUN on another radio
// (the 2026-09-26 split-band materialization gap), GET device JSON carries
// vaps_not_running with the missing devnames; when every planned devname is
// RUN (or the device reported no table — unknown), the field is omitted.
func TestDeviceViewVAPsNotRunning(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()

	env := []wireless.Wlan{{Name: "guest", SSID: "guest-net", Security: "wpa-p", Passphrase: "pw", VLAN: 2, Enabled: true}}
	envJSON, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	mac := "aabbccddeeff"
	seed := func(extra store.JSONMap) {
		t.Helper()
		if err := st.Put(store.Device{
			MAC: mac, State: store.StateAdopted, Model: "U7PG2",
			CfgVersion: "aaaa", AppliedCfg: "aaaa",
			Extra: store.JSONMap{
				"device_wlans": string(envJSON),
				"radio_table": []any{
					map[string]any{"name": "ra0", "radio": "ng"},
					map[string]any{"name": "ra1", "radio": "na"},
				},
			},
		}); err != nil {
			t.Fatal(err)
		}
		d, err := st.Get(mac)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range extra {
			d.Extra[k] = v
		}
		if err := st.Put(d); err != nil {
			t.Fatal(err)
		}
	}
	// 1. Split-band gap: ath0 RUN for the SSID, ath1 missing → surfaced.
	seed(store.JSONMap{
		"vap_table": []any{map[string]any{"essid": "guest-net", "state": "RUN", "radio_name": "ra0", "name": "ath0"}},
	})
	dv, err := a.GetDevice(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dv.VAPsNotRunning, []string{"ath1"}) {
		t.Fatalf("view vaps_not_running = %v, want [ath1]", dv.VAPsNotRunning)
	}
	body, err := json.Marshal(dv)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"vaps_not_running":["ath1"]`) {
		t.Fatalf("GET device JSON missing the field: %s", body)
	}
	if dv.InSync == nil || !*dv.InSync {
		t.Fatalf("in_sync with SSID RUN present = %v, want true (the gap is devname-invisible to the SSID bar, by design)", dv.InSync)
	}

	// 2. All planned devnames RUN → field omitted from the JSON.
	rec, err := st.Get(mac)
	if err != nil {
		t.Fatal(err)
	}
	rec.Extra["vap_table"] = []any{
		map[string]any{"essid": "guest-net", "state": "RUN", "radio_name": "ra0", "name": "ath0"},
		map[string]any{"essid": "guest-net", "state": "RUN", "radio_name": "ra1", "name": "ath1"},
	}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	dv, err = a.GetDevice(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if dv.VAPsNotRunning != nil {
		t.Fatalf("all-RUN vaps_not_running = %v, want nil", dv.VAPsNotRunning)
	}
	body, err = json.Marshal(dv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "vaps_not_running") {
		t.Fatalf("all-RUN GET device JSON carries the field: %s", body)
	}

	// 3. Sparse heartbeat (no vap_table at all) → unknown, field omitted.
	rec, err = st.Get(mac)
	if err != nil {
		t.Fatal(err)
	}
	delete(rec.Extra, "vap_table")
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	dv, err = a.GetDevice(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if dv.VAPsNotRunning != nil {
		t.Fatalf("absent-table vaps_not_running = %v, want nil (unknown is never a positive gap)", dv.VAPsNotRunning)
	}

	// 4. Present-but-EMPTY table → a DIFFERENT branch from absent: the
	// value passes the type assert and hits len==0, still unknown from the
	// view's side (the engine's nrRun gate screens the empty table off, so
	// the view is the only reachable call site for this branch).
	rec, err = st.Get(mac)
	if err != nil {
		t.Fatal(err)
	}
	rec.Extra["vap_table"] = []any{}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	dv, err = a.GetDevice(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if dv.VAPsNotRunning != nil {
		t.Fatalf("empty-table vaps_not_running = %v, want nil (unknown is never a positive gap)", dv.VAPsNotRunning)
	}
	body, err = json.Marshal(dv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "vaps_not_running") {
		t.Fatalf("empty-table GET device JSON carries the field: %s", body)
	}
}

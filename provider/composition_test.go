package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/lucabecker/open-unifi/internal/adminapi"
	"github.com/lucabecker/open-unifi/internal/app"
	"github.com/lucabecker/open-unifi/internal/store"
)

// composition_test.go is the missing contract test: it drives the REAL
// adminapi handler (app.New over store.NewMemStore) through the provider's
// own apiClient decode layer, asserting that the provider correctly decodes
// everything the real server emits — number-typed device states, unix
// last_seen values, the {"devices":[...]} envelope, {"error":"..."} JSON
// error bodies, and the passphrase-echoing wireless envelope. No TCP socket
// is opened: the handler runs in-process behind a RoundTripper (same seam
// as client_test.go).

// composeAPI builds an apiClient wired to a real adminapi handler plus the
// underlying store so tests can seed device records directly. The captured
// status map records status codes under "METHOD path".
func composeAPI(t *testing.T) (*apiClient, store.DeviceStore, map[string]int) {
	t.Helper()
	st := store.NewMemStore()
	ap := app.New(st, filepath.Join(t.TempDir(), "wireless.json"), nil) // slog default logger
	handler := adminapi.New(adminapi.Config{}, ap)

	status := map[string]int{}
	tripper := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		status[req.Method+" "+req.URL.Path] = rec.Code
		return rec.Result(), nil
	})
	c := (&apiClient{baseURL: "http://composition"}).
		withHTTPClient(&http.Client{Transport: tripper})
	return c, st, status
}

// TestProviderDecodesRealServerDevices walks the device flow against the
// real handler: POST /api/v1/devices (idempotent upsert, 201), the
// post-create Read GET, and the list GET. It proves the provider decodes
// the real DeviceView wire shape: numeric "state" (mapped through
// stateNames) and unix-secs "last_seen" — including a device the server
// never saw on the inform channel (no last_seen field, zero value).
func TestProviderDecodesRealServerDevices(t *testing.T) {
	c, st, status := composeAPI(t)
	ctx := context.Background()

	if err := c.checkConnectivity(ctx); err != nil {
		t.Fatalf("whoami probe against real server failed: %v", err)
	}
	if got := status["GET /api/v1/whoami"]; got != http.StatusOK {
		t.Fatalf("whoami status = %d, want 200", got)
	}

	mac := "78:8a:20:11:22:33"
	body := map[string]string{"mac": mac, "name": "ap-lobby", "site_id": "default"}
	if err := c.do(ctx, http.MethodPost, "/api/v1/devices", body, nil); err != nil {
		t.Fatalf("real POST /api/v1/devices: %v", err)
	}
	if got := status["POST /api/v1/devices"]; got != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", got)
	}

	// Duplicate POST: the real server is an upsert, NOT a 409.
	if err := c.do(ctx, http.MethodPost, "/api/v1/devices", body, nil); err != nil {
		t.Fatalf("duplicate create must be an idempotent upsert, got: %v", err)
	}

	// Post-create Read (GET): freshly registered => state 1 (pending), no
	// last_seen yet (the device never informed; last_seen omitted inline).
	dev, err := c.getDevice(ctx, mac)
	if err != nil {
		t.Fatalf("real GET /api/v1/devices/{mac}: %v", err)
	}
	if dev.State != store.StatePending || stateName(dev.State) != "pending" {
		t.Fatalf("pending decode: state=%d stateName=%q, want 1/pending", dev.State, stateName(dev.State))
	}
	if dev.LastSeen != 0 || dev.IP != "" {
		t.Fatalf("fresh device wire truth: last_seen=%d ip=%q, want 0/\"\"", dev.LastSeen, dev.IP)
	}

	// applyDevice renders the full TF model from this wire truth.
	m := &apModel{
		Mac:      types.StringValue(mac),
		Name:     types.StringValue("ap-lobby"),
		SiteID:   types.StringValue("default"),
		State:    types.StringNull(),
		IP:       types.StringNull(),
		Firmware: types.StringNull(),
		LastSeen: types.StringNull(),
	}
	applyDevice(m, dev, "default")
	if m.State.ValueString() != "pending" || m.LastSeen.ValueString() != "" || m.IP.ValueString() != "" {
		t.Fatalf("applyDevice fresh: state=%q last_seen=%q ip=%q",
			m.State.ValueString(), m.LastSeen.ValueString(), m.IP.ValueString())
	}
	// The wire never carries site_id; the model keeps the configured value.
	if m.SiteID.ValueString() != "default" {
		t.Fatalf("site_id must stay configured, got %q", m.SiteID.ValueString())
	}

	// Seed an adopted device directly through the store, then decode the
	// real view of it: state 3, last_seen present, actions attached.
	if err := st.Put(store.Device{
		MAC:      "788a20001122",
		Name:     "ap-attic",
		Model:    "UAP-AC-Pro-Gen2",
		Firmware: "6.6.55",
		IP:       "192.0.2.9",
		State:    store.StateAdopted,
		LastSeen: 1726432000,
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	dev2, err := c.getDevice(ctx, "78:8a:20:00:11:22")
	if err != nil {
		t.Fatalf("GET seeded device: %v", err)
	}
	if dev2.State != store.StateAdopted || dev2.LastSeen != 1726432000 {
		t.Fatalf("seeded decode: state=%d last_seen=%d, want 3/1726432000", dev2.State, dev2.LastSeen)
	}
	if got := stateName(dev2.State); got != "adopted" {
		t.Fatalf("stateName(adopted) = %q", got)
	}

	// List: the {"devices":[...]} envelope decodes both records.
	devs, err := c.listDevices(ctx)
	if err != nil {
		t.Fatalf("real GET /api/v1/devices: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("listDevices decoded %d devices, want 2: %+v", len(devs), devs)
	}
	seen := map[string]int{}
	for _, d := range devs {
		seen[stateName(d.State)]++
	}
	if seen["pending"] != 1 || seen["adopted"] != 1 {
		t.Fatalf("envelope state vocabulary mismatch: %v", seen)
	}
}

// TestProviderDecodesRealServerWireless walks the wlan flow against the
// real handler: GET empty envelope, PUT (server validates + echoes), the
// provider's read-back decode (server echoes the passphrase), server-side
// rejection of open-with-passphrase, and provider-side validation parity.
func TestProviderDecodesRealServerWireless(t *testing.T) {
	c, _, status := composeAPI(t)
	ctx := context.Background()

	// Empty envelope decode.
	env, err := c.getWireless(ctx)
	if err != nil {
		t.Fatalf("real GET /api/v1/wireless: %v", err)
	}
	if len(env.Wlans) != 0 {
		t.Fatalf("fresh envelope should be empty, got %+v", env.Wlans)
	}

	// Build a provider-shaped entry and PUT the whole document.
	plan := &wlanModel{
		Name:       types.StringValue("home"),
		SSID:       types.StringValue("home"),
		Security:   types.StringValue("wpa-p"),
		Passphrase: types.StringValue("sup3rsecret"),
		VLAN:       types.Int64Value(42),
		Enabled:    types.BoolValue(true),
	}
	var d diag.Diagnostics
	if !newWlan().validateWlan(plan, &d) || d.HasError() {
		t.Fatal("wpa-p plan must validate")
	}
	entry := wlanEntryFromModel(plan)
	if entry.Passphrase != "sup3rsecret" || entry.VLAN != 42 || !entry.Enabled {
		t.Fatalf("wlanEntryFromModel dropped wire fields: %+v", entry)
	}
	env.Wlans = append(env.Wlans, entry)
	if err := c.putWireless(ctx, env); err != nil {
		t.Fatalf("real PUT /api/v1/wireless: %v (server must 200 valid payloads)", err)
	}
	if got := status["PUT /api/v1/wireless"]; got != http.StatusOK {
		t.Fatalf("PUT wireless status = %d, want 200", got)
	}

	// Read-back: the REAL server echoes the stored document (including the
	// passphrase) — the provider decode must carry that truth into the
	// model.
	got, err := c.getWireless(ctx)
	if err != nil {
		t.Fatalf("read-back GET: %v", err)
	}
	if len(got.Wlans) != 1 || got.Wlans[0].Name != "home" || got.Wlans[0].VLAN != 42 ||
		got.Wlans[0].Passphrase != "sup3rsecret" || got.Wlans[0].Security != "wpa-p" {
		t.Fatalf("server echo mismatch: %+v", got.Wlans)
	}
	m2 := *plan
	entryToModel(&got.Wlans[0], &m2)
	if m2.Passphrase.ValueString() != "sup3rsecret" || !m2.Enabled.ValueBool() || m2.VLAN.ValueInt64() != 42 {
		t.Fatalf("entryToModel lost server truth: psk=%q enabled=%v vlan=%d",
			m2.Passphrase.ValueString(), m2.Enabled.ValueBool(), m2.VLAN.ValueInt64())
	}

	// Open security: provider must strip the passphrase before PUT (the
	// server rejects any passphrase on open) and validateWlan must reject
	// an open plan that carries one (mirrors the server 400).
	openPlan := &wlanModel{
		Name:       types.StringValue("guest"),
		SSID:       types.StringValue("guest"),
		Security:   types.StringValue("open"),
		Passphrase: types.StringValue("stale-psk"),
		VLAN:       types.Int64Value(1),
		Enabled:    types.BoolValue(true),
	}
	if newWlan().validateWlan(openPlan, &d) {
		t.Fatal("open plan with stale psk must fail validateWlan")
	}
	if e := wlanEntryFromModel(openPlan); e.Passphrase != "" {
		t.Fatalf("open entry must drop the passphrase, got %q", e.Passphrase)
	}
	openPlan.Passphrase = types.StringNull()
	openDiag := diag.Diagnostics{}
	if !newWlan().validateWlan(openPlan, &openDiag) || openDiag.HasError() {
		t.Fatal("open plan must validate once the passphrase is dropped")
	}
	// Server-side double-check: PUT open-with-passphrase must 400.
	badEnv := &wirelessEnvelope{Wlans: []wirelessEntry{{
		Name: "bad", SSID: "bad", Security: "open",
		Passphrase: "oops-oops", VLAN: 1, Enabled: true,
	}}}
	err = c.putWireless(ctx, badEnv)
	if err == nil {
		t.Fatal("open-with-passphrase PUT must be rejected by the server")
	}
	var ae *apiError
	if !errors.As(err, &ae) || ae.status != http.StatusBadRequest {
		t.Fatalf("expected typed 400 apiError, got %T (%v)", err, err)
	}
	if want := "http 400: wlan[0]: passphrase must be empty when security is open"; err.Error() != want {
		t.Fatalf("clean server diagnostic expected, got %q", err.Error())
	}

	// wpa-eap validation parity (fix 6a): same >=8 server rule.
	eapPlan := &wlanModel{
		Name:       types.StringValue("corp"),
		SSID:       types.StringValue("corp"),
		Security:   types.StringValue("wpa-eap"),
		Passphrase: types.StringValue("short"),
		VLAN:       types.Int64Value(10),
		Enabled:    types.BoolValue(true),
	}
	if newWlan().validateWlan(eapPlan, &d) {
		t.Fatal("wpa-eap with <8 char passphrase must fail validateWlan")
	}
	eapPlan.Passphrase = types.StringValue("radius-shared")
	eapDiag := diag.Diagnostics{}
	if !newWlan().validateWlan(eapPlan, &eapDiag) || eapDiag.HasError() {
		t.Fatal("wpa-eap with >=8 char passphrase must validate")
	}

	// Duplicate-SSID conflict detection (fix 6c), provider side.
	env2, _ := c.getWireless(ctx)
	var cd diag.Diagnostics
	if newWlan().checkWlanConflicts(env2, "copy", "home", -1, &cd) {
		t.Fatal("SSIDs must be unique: copy/home should conflict")
	}
	if !cd.HasError() {
		t.Fatal("conflict must surface as a diagnostic error")
	}
}

// TestRealServer404AndIDRoundTrip pins that a missing device produces a
// typed 404 through the REAL handler and that the envelope PUT/GET
// round trip preserves the server-assigned wlan ID (which Update must
// carry over).
func TestRealServer404AndIDRoundTrip(t *testing.T) {
	c, _, status := composeAPI(t)
	ctx := context.Background()

	_, err := c.getDevice(ctx, "aa:bb:cc:dd:ee:ff")
	if err == nil || !errNotFound(err) {
		t.Fatalf("typed 404 expected, got %T: %v", err, err)
	}
	var ae *apiError
	if !errors.As(err, &ae) || ae.status != http.StatusNotFound || !ae.NotFound() {
		t.Fatalf("apiError misclassified: %v", err)
	}
	if got := status["GET /api/v1/devices/aa:bb:cc:dd:ee:ff"]; got != http.StatusNotFound {
		t.Fatalf("wire status = %d, want 404", got)
	}
	// JSON error extraction happens against the real body: the server's
	// wrapped sentinel plus the MAC is surfaced cleanly, not as a raw body
	// blob.
	if want := "not found: device not found: aabbccddeeff"; err.Error() != want {
		t.Fatalf("error message = %q, want %q", err.Error(), want)
	}

	// Envelope PUT/GET round trip preserves the server-assigned wlan ID.
	env := &wirelessEnvelope{Wlans: []wirelessEntry{{
		ID: "srv-1", Name: "one", SSID: "one", Security: "wpa-p",
		Passphrase: "eight+chars", VLAN: 2, Enabled: true,
	}}}
	if err := c.putWireless(ctx, env); err != nil {
		t.Fatalf("PUT: %v", err)
	}
	got, err := c.getWireless(ctx)
	if err != nil {
		t.Fatalf("GET after PUT: %v", err)
	}
	if len(got.Wlans) != 1 || got.Wlans[0].ID != "srv-1" {
		t.Fatalf("round trip lost server ID: %+v", got.Wlans)
	}
}

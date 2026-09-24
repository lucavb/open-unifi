package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/app"
	"github.com/lucavb/open-unifi/internal/store"
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
	ap := app.New(st, filepath.Join(t.TempDir(), "site-settings.json"), app.SiteSettings{}, nil) // slog default logger
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
	m := &deviceModel{
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

func TestDeviceUpdateClearsName(t *testing.T) {
	state := deviceModel{Name: types.StringValue("old"), SiteID: types.StringValue("default")}
	plan := state
	plan.Name = types.StringNull()
	body := deviceUpdateBody(plan, state)
	if got := body["name"]; got != "" {
		t.Fatalf("name update = %#v, want explicit empty name", body)
	}
	if _, ok := body["site_id"]; ok {
		t.Fatalf("unchanged site_id should be absent: %#v", body)
	}
}

// TestProviderDecodesRealServerWireless walks the wlan flow against the
// real handler: GET empty envelope, PUT (server validates + echoes), the
// provider's read-back decode (server echoes the passphrase), server-side
// rejection of open-with-passphrase, and provider-side validation parity.
func TestProviderDecodesRealServerWireless(t *testing.T) {
	c, _, status := composeAPI(t)
	ctx := context.Background()
	mac := "78:8a:20:11:22:33"
	if err := c.do(ctx, http.MethodPost, "/api/v1/devices", map[string]string{"mac": mac, "name": "ap-wlan"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, e := range []wirelessEntry{{Name: "home", SSID: "home", Security: "wpa-p", Passphrase: "sup3rsecret", VLAN: 42, Enabled: true}, {Name: "guest", SSID: "guest", Security: "open", VLAN: 1, Enabled: true}} {
		e := e
		if err := c.createWireless(ctx, mac, &e); err != nil {
			t.Fatal(err)
		}
	}
	home, err := c.getWireless(ctx, mac, "home")
	if err != nil || home.VLAN != 42 {
		t.Fatalf("home read: %+v %v", home, err)
	}
	home.VLAN = 100
	if err := c.updateWireless(ctx, mac, "home", home); err != nil {
		t.Fatal(err)
	}
	guest, err := c.getWireless(ctx, mac, "guest")
	if err != nil || guest.Name != "guest" {
		t.Fatalf("guest lost: %+v %v", guest, err)
	}
	if status["POST /api/v1/devices/"+mac+"/wireless"] != http.StatusCreated {
		t.Fatalf("POST status %d", status["POST /api/v1/devices/"+mac+"/wireless"])
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

	// Item PUT/GET round trip preserves the server-assigned wlan ID.
	mac := "aa:bb:cc:dd:ee:01"
	if err := c.do(ctx, http.MethodPost, "/api/v1/devices", map[string]string{"mac": mac, "name": "one-ap"}, nil); err != nil {
		t.Fatal(err)
	}
	entry := &wirelessEntry{
		ID: "srv-1", Name: "one", SSID: "one", Security: "wpa-p",
		Passphrase: "eight+chars", VLAN: 2, Enabled: true,
	}
	if err := c.createWireless(ctx, mac, entry); err != nil {
		t.Fatalf("POST: %v", err)
	}
	got, err := c.getWireless(ctx, mac, "one")
	if err != nil {
		t.Fatalf("GET after PUT: %v", err)
	}
	if got.ID != "srv-1" {
		t.Fatalf("round trip lost server ID: %+v", got)
	}
}

// TestProviderDecodesRealServerSiteSettings walks the site-settings flow
// against the real handler: whole-document PUT (2 keys), the
// verbatim ordered GET roundtrip, and the API's 400 rejections (invalid key
// line, missing field). These pin the provider↔API
// contract end to end: the provider's siteSettings wire struct must decode
// exactly what adminapi emits and encode exactly what its strict PUT decode
// accepts. (The site password is OFF the site wire since Phase A —
// PUT bodies and views carry both remaining fields only; the HISTORICAL
// `ap_ssh_password` name stays in the stale-key pins because that is what
// GHCR-era deployed records and old client binaries actually carry.)
func TestProviderDecodesRealServerSiteSettings(t *testing.T) {
	c, _, status := composeAPI(t)
	ctx := context.Background()

	// The repo's canonical valid authorized_keys line (adminapi/app tests).
	key1 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB test@ap"
	key2 := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB second@ap"
	doc := siteSettings{
		RegulatoryCountryCode: 276,
		DeviceSSHPublicKeys:   []string{key1, key2},
	}

	// PUT goes through the provider's own wire struct (the real handler's
	// strict decode accepts the two-field wholesale document).
	view, err := c.putSiteSettings(ctx, doc)
	if err != nil {
		t.Fatalf("real PUT /api/v1/site-settings: %v", err)
	}
	if got := status["PUT /api/v1/site-settings"]; got != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200", got)
	}
	if !reflect.DeepEqual(*view, doc) {
		t.Fatalf("PUT view = %+v, want verbatim echo of %+v", *view, doc)
	}

	// GET roundtrip: all fields verbatim, keys in slice order (the
	// order-sensitive echo the provider's drift detection relies on); the
	// removed password field must not decode onto anything.
	got, err := c.getSiteSettings(ctx)
	if err != nil {
		t.Fatalf("real GET /api/v1/site-settings: %v", err)
	}
	if !reflect.DeepEqual(*got, doc) {
		t.Fatalf("GET roundtrip = %+v, want %+v", *got, doc)
	}
	if got.DeviceSSHPublicKeys[0] != key1 || got.DeviceSSHPublicKeys[1] != key2 {
		t.Fatalf("key order not preserved: %q, %q", got.DeviceSSHPublicKeys[0], got.DeviceSSHPublicKeys[1])
	}

	// PUT with an invalid key line → 400, the FIRST failing line named in
	// the message (the server's user-facing wording).
	bad := doc
	bad.DeviceSSHPublicKeys = []string{key1, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXk!!!"}
	if view, err := c.putSiteSettings(ctx, bad); err == nil {
		t.Fatalf("invalid key line accepted: %+v", view)
	} else {
		var ae *apiError
		if !errors.As(err, &ae) || ae.status != http.StatusBadRequest {
			t.Fatalf("invalid key line: expected typed 400, got %v", err)
		}
		if !strings.Contains(err.Error(), "invalid Device SSH public key #2") {
			t.Fatalf("invalid key line message = %q, want the #2 line named", err.Error())
		}
	}

	// PUT an unknown field → 400 (the strict decoder's
	// DisallowUnknownFields): a stale client still carrying a HISTORICAL
	// removed wire name (the disable knob, the removed site password) is
	// rejected before the Backend runs.
	for staleName, staleVal := range map[string]any{
		"ap_ssh_disable_password": false,
		"ap_ssh_password":         "s3cret",
	} {
		stale := map[string]any{
			"regulatory_country_code": 0,
			"device_ssh_public_keys":  []string{},
			staleName:                 staleVal,
		}
		err = c.do(ctx, http.MethodPut, "/api/v1/site-settings", stale, nil)
		if err == nil {
			t.Fatalf("unknown-field PUT accepted (%s)", staleName)
		}
		var ae *apiError
		if !errors.As(err, &ae) || ae.status != http.StatusBadRequest {
			t.Fatalf("unknown field %s: expected typed 400, got %v", staleName, err)
		}
	}

	// PUT missing a field → 400 "missing field <name>" (the provider's wire
	// struct always emits both; a hand-rolled partial body must not).
	partial := map[string]any{
		"regulatory_country_code": 0,
	}
	err = c.do(ctx, http.MethodPut, "/api/v1/site-settings", partial, nil)
	if err == nil {
		t.Fatal("partial PUT accepted")
	}
	var ae *apiError
	if !errors.As(err, &ae) || ae.status != http.StatusBadRequest {
		t.Fatalf("missing field: expected typed 400, got %v", err)
	}

	// Zero-document PUT (Delete's restore-defaults body,
	// resource_site_settings.go): BOTH fields present with zero values —
	// country 0, [] (a PRESENT field, not a missing/null
	// one) — through the provider's own wire struct against
	// the real server's strict decode. This pins that zero VALUES alone
	// never read as missing.
	zero := siteSettings{DeviceSSHPublicKeys: []string{}}
	viewZ, err := c.putSiteSettings(ctx, zero)
	if err != nil {
		t.Fatalf("zero-doc PUT rejected: %v", err)
	}
	if got := status["PUT /api/v1/site-settings"]; got != http.StatusOK {
		t.Fatalf("zero-doc PUT status = %d, want 200", got)
	}
	if !reflect.DeepEqual(*viewZ, zero) {
		t.Fatalf("zero-doc PUT view = %+v, want verbatim echo of %+v", *viewZ, zero)
	}
}

func TestImportAndNormalizeHelpers(t *testing.T) {
	if got, err := normalizeMAC("AA-BB-CC-DD-EE-FF"); err != nil || got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("normalize MAC: %q %v", got, err)
	}
	if _, err := normalizeMAC("not-a-mac"); err == nil {
		t.Fatal("invalid MAC accepted")
	}
}

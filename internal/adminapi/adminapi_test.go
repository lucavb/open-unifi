package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/server"
)

// fakeBackend implements Backend with fixed fixtures; it records calls so
// tests can assert behavior (adopt routing, whole-doc wireless upsert).
type fakeBackend struct {
	devices  []DeviceView
	pending  []PendingView
	wireless WlansEnvelope

	lastPut           WlansEnvelope
	created           []DeviceUpsert
	adopted           []string
	deleted           []string
	rebootArmed       []string
	factoryResetArmed []string
	cmdEnqueued       []cmdEnqueue
	byMAC             map[string]DeviceView
	// Site-settings fixture: the fixed GET view plus the last PUT body
	// recorded for routing/decode assertions (backend-not-called pins).
	siteSettings        SiteSettingsView
	lastSiteSettingsPut SiteSettingsDocument
	// Blocked-set state (device MAC -> clients in the boundary-normalized
	// colon-hex spelling) plus call recording for routing assertions.
	blocked        map[string][]string
	blockedAdded   []string
	blockedRemoved []string
	// Client-session fixture (device MAC -> rows, colon-hex).
	clients   map[string][]ClientView
	radios    []RadioView
	radioPuts []radioPutCall
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		devices: []DeviceView{
			{MAC: "f0:9f:c2:84:8f:2a", Name: "office-ceiling", Model: "U7PG2", Firmware: "6.6.55", IP: "192.168.1.20", State: 3, LastSeen: 1700000000, Actions: []string{"delete"}},
			{MAC: "00:11:22:33:44:55", State: 1},
		},
		byMAC: map[string]DeviceView{
			"f0:9f:c2:84:8f:2a": {MAC: "f0:9f:c2:84:8f:2a", Name: "office-ceiling", Model: "U7PG2", State: 3, LastSeen: 1700000000},
		},
		pending: []PendingView{
			{MAC: "a0:40:a0:aa:bb:cc", Source: "discovery-beacon"},
		},
		wireless: WlansEnvelope{Wlans: []Wlan{
			{ID: "wlan-1", Name: "home", SSID: "home-net", Security: "wpa-p", Passphrase: "correct-horse", VLAN: 1, Enabled: true},
		}},
		siteSettings: SiteSettingsView{
			RegulatoryCountryCode: 840,
			DeviceSSHPublicKeys:   []string{testKeyEd25519Line},
		},
	}
}

func (f *fakeBackend) ListDevices(context.Context) []DeviceView { return f.devices }

func (f *fakeBackend) GetDevice(_ context.Context, mac string) (DeviceView, error) {
	if dv, ok := f.byMAC[mac]; ok {
		return dv, nil
	}
	return DeviceView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
}
func (f *fakeBackend) PatchDevice(_ context.Context, mac string, p DevicePatch) (DeviceView, error) {
	d, err := f.GetDevice(context.Background(), mac)
	if err != nil {
		return d, err
	}
	if p.Name != nil {
		d.Name = *p.Name
	}
	if p.SiteID != nil {
		d.SiteID = *p.SiteID
	}
	if p.LEDOverride != nil {
		if *p.LEDOverride == "default" {
			d.LEDOverride = "" // the explicit clear, mirroring the real adapter
		} else {
			d.LEDOverride = *p.LEDOverride
		}
	}
	if p.LEDOverrideColorBrightness != nil {
		if *p.LEDOverrideColorBrightness == 100 {
			d.LEDOverrideColorBrightness = nil // the explicit clear, mirroring the real adapter
		} else {
			v := *p.LEDOverrideColorBrightness
			d.LEDOverrideColorBrightness = &v
		}
	}
	if p.LEDOverrideColor != nil {
		d.LEDOverrideColor = *p.LEDOverrideColor // verbatim, "" clears — mirroring the real adapter
	}
	if p.SSHPassword != nil {
		d.SSHPassword = *p.SSHPassword // "", non-empty both ride through — mirroring the real adapter
	}
	f.byMAC[mac] = d
	return d, nil
}
func (f *fakeBackend) CreateWlan(context.Context, Wlan) (Wlan, error) { return Wlan{}, nil }
func (f *fakeBackend) GetWlan(context.Context, string) (Wlan, error) {
	return Wlan{}, fmt.Errorf("%w", ErrNotFound)
}
func (f *fakeBackend) UpdateWlan(context.Context, string, Wlan) (Wlan, error) { return Wlan{}, nil }
func (f *fakeBackend) DeleteWlan(context.Context, string) error               { return nil }

func (f *fakeBackend) CreateDevice(_ context.Context, up DeviceUpsert) (DeviceView, error) {
	f.created = append(f.created, up)
	dv := DeviceView{MAC: up.MAC, Name: up.Name, State: 1}
	f.byMAC[up.MAC] = dv
	return dv, nil
}

func (f *fakeBackend) DeleteDevice(_ context.Context, mac string) error {
	if _, ok := f.byMAC[mac]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, mac) // deliberately wrapped
	}
	f.deleted = append(f.deleted, mac)
	delete(f.byMAC, mac)
	return nil
}

// ---- blocked-set fake -----------------------------------------------------

// blockedView renders the fake's set with the same never-nil, canonical-
// order contract the real adapter exposes: sorted colon-hex, like the
// store-backed adapter, so route tests pin the ordering too.
func (f *fakeBackend) blockedView(mac string) BlockedClientsView {
	set := append([]string{}, f.blocked[mac]...)
	sort.Strings(set)
	if set == nil {
		set = []string{}
	}
	return BlockedClientsView{MAC: mac, Blocked: set}
}

func (f *fakeBackend) ListBlockedClients(_ context.Context, mac string) (BlockedClientsView, error) {
	if _, ok := f.byMAC[mac]; !ok {
		return BlockedClientsView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
	}
	return f.blockedView(mac), nil
}

func (f *fakeBackend) BlockClient(_ context.Context, mac, client string) (BlockedClientsView, error) {
	if _, ok := f.byMAC[mac]; !ok {
		return BlockedClientsView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
	}
	f.blockedAdded = append(f.blockedAdded, mac+"/"+client)
	for _, c := range f.blocked[mac] {
		if strings.EqualFold(c, client) {
			return f.blockedView(mac), nil // idempotent
		}
	}
	if f.blocked == nil {
		f.blocked = map[string][]string{}
	}
	f.blocked[mac] = append(f.blocked[mac], client)
	return f.blockedView(mac), nil
}

func (f *fakeBackend) UnblockClient(_ context.Context, mac, client string) (BlockedClientsView, error) {
	if _, ok := f.byMAC[mac]; !ok {
		return BlockedClientsView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
	}
	set := f.blocked[mac]
	kept := set[:0:0] // fresh slice; never alias the stored one
	found := false
	for _, c := range set {
		if strings.EqualFold(c, client) {
			found = true
			continue
		}
		kept = append(kept, c)
	}
	if !found {
		return BlockedClientsView{}, fmt.Errorf("%w: client not blocked: %s", ErrNotFound, client)
	}
	f.blocked[mac] = kept
	f.blockedRemoved = append(f.blockedRemoved, mac+"/"+client)
	return f.blockedView(mac), nil
}

func (f *fakeBackend) ListPending(context.Context) []PendingView { return f.pending }

// ListDeviceClients mirrors the read-only projection: fixed fixture rows
// (never nil — the wire contract is a list, never null) for known devices,
// ErrNotFound for unknown MACs.
func (f *fakeBackend) ListDeviceClients(_ context.Context, mac string) ([]ClientView, error) {
	if _, ok := f.byMAC[mac]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, mac)
	}
	rows := append([]ClientView{}, f.clients[mac]...)
	if rows == nil {
		rows = []ClientView{}
	}
	return rows, nil
}

func (f *fakeBackend) RebootDevice(_ context.Context, mac string) (DeviceView, error) {
	f.rebootArmed = append(f.rebootArmed, mac)
	if dv, ok := f.byMAC[mac]; ok {
		return dv, nil
	}
	return DeviceView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
}

func (f *fakeBackend) FactoryResetDevice(_ context.Context, mac string) (DeviceView, error) {
	f.factoryResetArmed = append(f.factoryResetArmed, mac)
	if dv, ok := f.byMAC[mac]; ok {
		return dv, nil
	}
	return DeviceView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
}

// cmdEnqueue records one §6.3 EnqueueDeviceCmd call.
type cmdEnqueue struct {
	mac string
	cmd string
}

func (f *fakeBackend) EnqueueDeviceCmd(_ context.Context, mac, cmd string) (DeviceView, error) {
	f.cmdEnqueued = append(f.cmdEnqueued, cmdEnqueue{mac: mac, cmd: cmd})
	if dv, ok := f.byMAC[mac]; ok {
		return dv, nil
	}
	return DeviceView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
}

func (f *fakeBackend) AdoptPending(_ context.Context, mac string) (DeviceView, error) {
	f.adopted = append(f.adopted, mac)
	for _, p := range f.pending {
		if strings.EqualFold(p.MAC, mac) {
			// Wire contract (see Backend.AdoptPending): a successful adopt
			// response carries State 1 (pending) — the unsigned-promotion
			// state — NOT 2 (adopting); adopting is entered later by the
			// inform handshake. State: 2 here once contradicted the real
			// adapter (internal/app returns 1).
			dv := DeviceView{MAC: mac, State: 1, Actions: []string{"delete"}}
			f.byMAC[mac] = dv
			return dv, nil
		}
	}
	return DeviceView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
}

func (f *fakeBackend) GetWireless(context.Context) WlansEnvelope { return f.wireless }

func (f *fakeBackend) PutWireless(_ context.Context, env WlansEnvelope) error {
	f.lastPut = env
	f.wireless = env
	return nil
}

// Site-settings fixtures: the fake carries the fixed GET view and records
// the last PUT body so route tests can pin the decoded document verbatim
// and that rejected requests never reach the Backend.
const testKeyEd25519Line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB test@ap"

func (f *fakeBackend) GetSiteSettings(context.Context) (SiteSettingsView, error) {
	return f.siteSettings, nil
}

func (f *fakeBackend) PutSiteSettings(_ context.Context, doc SiteSettingsDocument) (SiteSettingsView, error) {
	f.lastSiteSettingsPut = doc
	f.siteSettings = SiteSettingsView(doc)
	return f.siteSettings, nil
}

// radioPutCall records one per-radio intent mutation for assertions.
type radioPutCall struct {
	mac, radio string
	up         RadioIntentUpsert
	clear      bool // DELETE route
}

func (f *fakeBackend) ListDeviceRadios(_ context.Context, mac string) ([]RadioView, error) {
	if _, ok := f.byMAC[mac]; !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, mac)
	}
	if len(f.radios) == 0 {
		return []RadioView{}, nil
	}
	return f.radios, nil
}

func (f *fakeBackend) PutDeviceRadioIntent(_ context.Context, mac, radio string, up RadioIntentUpsert) (RadioView, error) {
	f.radioPuts = append(f.radioPuts, radioPutCall{mac: mac, radio: radio, up: up})
	if _, ok := f.byMAC[mac]; !ok {
		return RadioView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
	}
	return fakeRadioView(radio, up), nil
}

func (f *fakeBackend) DeleteDeviceRadioIntent(_ context.Context, mac, radio string) (RadioView, error) {
	f.radioPuts = append(f.radioPuts, radioPutCall{mac: mac, radio: radio, clear: true})
	if _, ok := f.byMAC[mac]; !ok {
		return RadioView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
	}
	return fakeRadioView(radio, RadioIntentUpsert{}), nil
}

// fakeRadioView echoes the request into the view shape the real backend
// returns after applying it.
func fakeRadioView(radio string, up RadioIntentUpsert) RadioView {
	v := RadioView{Name: radio, Band: "na", EchoChannel: "0", EchoTxPower: "auto", EchoTxPowerMode: "auto"}
	if up.Channel != nil {
		c := strconv.Itoa(*up.Channel)
		v.Channel = &c
	}
	if up.Txpower != nil {
		p := up.Txpower.String()
		v.Txpower = &p
	}
	return v
}

// ---- harness -------------------------------------------------------------

type testCase struct {
	name   string
	method string
	path   string
	token  string
	body   string
	want   int
	checks func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder)
}

func run(t *testing.T, tc testCase) {
	t.Helper()
	be := newFakeBackend()
	h := New(Config{AdminToken: tc.token}, be)

	req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != tc.want {
		t.Fatalf("%s: got HTTP %d (%s), want %d", tc.name, rec.Code, rec.Body.String(), tc.want)
	}
	if tc.checks != nil {
		tc.checks(t, be, rec)
	}
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body not JSON: %v (%q)", err, rec.Body.String())
	}
	return m
}

// ---- auth ----------------------------------------------------------------

func TestUnauthorizedPostWhenTokenSet(t *testing.T) {
	for _, tc := range []struct {
		method, path string
	}{
		{"POST", "/api/v1/devices"},
		{"DELETE", "/api/v1/devices/f0:9f:c2:84:8f:2a"},
		{"POST", "/api/v1/devices/f0:9f:c2:84:8f:2a/reboot"},
		{"POST", "/api/v1/devices/f0:9f:c2:84:8f:2a/factory-reset"},
		{"POST", "/api/v1/pending/a0:40:a0:aa:bb:cc/adopt"},
		{"PUT", "/api/v1/wireless"},
		// GETs require the token too when auth is on:
		{"GET", "/api/v1/devices"},
		{"GET", "/api/v1/wireless"},
		{"GET", "/api/v1/whoami"},
	} {
		run(t, testCase{
			name: tc.method + " " + tc.path, method: tc.method, path: tc.path,
			token: "s3cret",
			body:  "{}",
			want:  http.StatusUnauthorized,
			checks: func(t *testing.T, _ *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				m := decodeJSON(t, rec)
				if m["error"] != "unauthorized" {
					t.Fatalf("error key = %v, want unauthorized", m["error"])
				}
				if rec.Header().Get("WWW-Authenticate") == "" {
					t.Fatalf("missing WWW-Authenticate header")
				}
			},
		})
	}
}

func TestAuthAcceptedAndHealthzOpen(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{AdminToken: "s3cret"}, be)

	// whoami with correct Bearer prefix on header token.
	req := httptest.NewRequest("GET", "/api/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("whoami: got %d", rec.Code)
	}
	var me whoAmI
	if err := json.Unmarshal(rec.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if me.AuthConfigured != true || me.Server != "open-unifi" || me.Version == "" {
		t.Fatalf("whoami shape: %+v", me)
	}

	// healthz stays open even with auth configured.
	req = httptest.NewRequest("GET", "/healthz", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("healthz: %d %q", rec.Code, rec.Body.String())
	}

	// root page is open.
	req = httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "open-unifi controller") {
		t.Fatalf("root: %d", rec.Code)
	}
}

func TestWrongTokenRejected(t *testing.T) {
	// A SAME-LENGTH wrong token must still be rejected: this is the case
	// that proves the constant-time compare actually compares content, not
	// just length (length-mismatch cases 401 trivially).
	req := httptest.NewRequest("GET", "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer s3cerx") // same length as "s3cret"
	h := New(Config{AdminToken: "s3cret"}, newFakeBackend())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("same-length wrong token accepted: %d (%s)", rec.Code, rec.Body.String())
	}
	if m := decodeJSON(t, rec); m["error"] != "unauthorized" {
		t.Fatalf("error shape: %v", m["error"])
	}

	// The correct token still opens the same endpoint with the same handler.
	req = httptest.NewRequest("GET", "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	h = New(Config{AdminToken: "s3cret"}, newFakeBackend())
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("correct same-length token rejected: %d", rec.Code)
	}
}

// ---- full authenticated flow ----------------------------------------------

func TestAuthorizedFullFlow(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{}, be) // auth disabled

	// 1. list devices
	req := httptest.NewRequest("GET", "/api/v1/devices", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("devices: %d %q", rec.Code, rec.Body.String())
	}
	var env devicesEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Devices) != 2 || env.Devices[0].MAC != "f0:9f:c2:84:8f:2a" || env.Devices[0].State != 3 {
		t.Fatalf("devices envelope: %+v", env)
	}

	// 2. get single device
	req = httptest.NewRequest("GET", "/api/v1/devices/f0:9f:c2:84:8f:2a", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("device get: %d", rec.Code)
	}
	var dv DeviceView
	if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil || dv.Name != "office-ceiling" {
		t.Fatalf("device get: %+v err=%v", dv, err)
	}

	// 3. unknown device -> 404 JSON
	req = httptest.NewRequest("GET", "/api/v1/devices/ff:ff:ff:ff:ff:ff", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown device: %d", rec.Code)
	}
	if m := decodeJSON(t, rec); !strings.Contains(m["error"].(string), "not found") {
		t.Fatalf("404 shape: %v", m["error"])
	}

	// 4. list pending
	req = httptest.NewRequest("GET", "/api/v1/pending", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var penv pendingEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &penv); err != nil {
		t.Fatal(err)
	}
	if len(penv.Pending) != 1 || penv.Pending[0].Source != "discovery-beacon" {
		t.Fatalf("pending envelope: %+v", penv)
	}

	// 5. adopt routes into AdoptPending
	req = httptest.NewRequest("POST", "/api/v1/pending/a0:40:a0:aa:bb:cc/adopt", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("adopt: %d %q", rec.Code, rec.Body.String())
	}
	if len(be.adopted) != 1 || be.adopted[0] != "a0:40:a0:aa:bb:cc" {
		t.Fatalf("backend adopt calls: %v", be.adopted)
	}
	var dv2 DeviceView
	if err := json.Unmarshal(rec.Body.Bytes(), &dv2); err != nil || dv2.State != 1 {
		t.Fatalf("adopt body (contract: State 1 = pending): %+v err=%v", dv2, err)
	}
}

// TestPendingJSONCarriesNameWhenSet pins the PendingView.Name wire shape:
// the GET /pending body carries "name" for rows backed by a StatePending
// record (the KNOWN device the factory reset round re-adopts) and omits
// the key entirely for stranger candidates — no empty-string noise on the
// wire.
func TestPendingJSONCarriesNameWhenSet(t *testing.T) {
	be := newFakeBackend()
	be.pending = []PendingView{
		{MAC: "a0:40:a0:aa:bb:cc", Source: "inform:factory", Name: "ceiling-west"},
		{MAC: "de:ad:be:ef:00:01", Source: "discovery:model=U7PG2,ip=10.10.10.20"},
	}
	h := New(Config{}, be)
	req := httptest.NewRequest("GET", "/api/v1/pending", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pending: %d %q", rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &struct {
		Pending *[]map[string]any `json:"pending"`
	}{Pending: &rows}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows: %d", len(rows))
	}
	if rows[0]["name"] != "ceiling-west" {
		t.Fatalf("row 0: %v (want name=ceiling-west)", rows[0])
	}
	// omitempty must keep the key OFF the wire for records without a name.
	if _, ok := rows[1]["name"]; ok {
		t.Fatalf("row 1 must omit name, got %v", rows[1])
	}
}

// TestWrappedErrNotFoundMapsTo404 pins the errors.Is-based mapping: the fake
// returns the sentinel WRAPPED with the MAC (as real adapters like
// internal/app do); GET/DELETE/adopt of an unknown MAC must all be 404 with
// the canonical JSON error shape — never 500.
func TestWrappedErrNotFoundMapsTo404(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{}, be)

	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"get unknown", "GET", "/api/v1/devices/aa:bb:cc:dd:ee:66", ""},
		{"delete unknown", "DELETE", "/api/v1/devices/aa:bb:cc:dd:ee:66", ""},
		{"adopt unknown", "POST", "/api/v1/pending/aa:bb:cc:dd:ee:66/adopt", ""},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d (%s), want 404", tc.name, rec.Code, rec.Body.String())
		}
		m := decodeJSON(t, rec)
		if s, ok := m["error"].(string); !ok || s == "" {
			t.Fatalf("%s: no error string in %q", tc.name, rec.Body.String())
		}
		if !strings.Contains(m["error"].(string), "device not found") {
			t.Fatalf("%s: error text %q does not carry the sentinel message", tc.name, m["error"])
		}
	}
}

// TestLifecycleRoutes pins the §6.5/§6.6 admin arming surface: route in,
// backend method called with the normalized MAC, 200 carries the backend
// DeviceView, unknown MAC is the wrapped-404 shape, malformed MAC is 400,
// and neither route is reachable under a foreign method (Go 1.22 mux: no
// registered POST under GET falls through to 405).
func TestLifecycleRoutes(t *testing.T) {
	const known = "f0:9f:c2:84:8f:2a"
	for _, tc := range []testCase{
		{
			name: "reboot arms via RebootDevice", method: "POST",
			path: "/api/v1/devices/" + known + "/reboot", want: http.StatusOK,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.rebootArmed) != 1 || be.rebootArmed[0] != known {
					t.Fatalf("RebootDevice calls: %v", be.rebootArmed)
				}
				if len(be.factoryResetArmed) != 0 {
					t.Fatalf("factory reset armed by reboot route: %v", be.factoryResetArmed)
				}
				var dv DeviceView
				if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil || dv.Name != "office-ceiling" {
					t.Fatalf("200 body should be the DeviceView: %+v err=%v", dv, err)
				}
			},
		},
		{
			name: "reboot MAC is normalized (upper-case in, lower-case out)", method: "POST",
			path: "/api/v1/devices/F0:9F:C2:84:8F:2A/reboot", want: http.StatusOK,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.rebootArmed) != 1 || be.rebootArmed[0] != known {
					t.Fatalf("RebootDevice calls: %v", be.rebootArmed)
				}
			},
		},
		{
			name: "factory-reset arms via FactoryResetDevice", method: "POST",
			path: "/api/v1/devices/" + known + "/factory-reset", want: http.StatusOK,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.factoryResetArmed) != 1 || be.factoryResetArmed[0] != known {
					t.Fatalf("FactoryResetDevice calls: %v", be.factoryResetArmed)
				}
				if len(be.rebootArmed) != 0 {
					t.Fatalf("reboot armed by factory-reset route: %v", be.rebootArmed)
				}
				var dv DeviceView
				if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil || dv.Name != "office-ceiling" {
					t.Fatalf("200 body should be the DeviceView: %+v err=%v", dv, err)
				}
			},
		},
		{
			name: "reboot unknown MAC is 404", method: "POST",
			path: "/api/v1/devices/aa:bb:cc:dd:ee:66/reboot", want: http.StatusNotFound,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if !strings.Contains(rec.Body.String(), "device not found") {
					t.Fatalf("404 shape: %q", rec.Body.String())
				}
			},
		},
		{
			name: "factory-reset unknown MAC is 404", method: "POST",
			path: "/api/v1/devices/aa:bb:cc:dd:ee:66/factory-reset", want: http.StatusNotFound,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if !strings.Contains(rec.Body.String(), "device not found") {
					t.Fatalf("404 shape: %q", rec.Body.String())
				}
			},
		},
		{
			name: "reboot malformed MAC is 400", method: "POST",
			path: "/api/v1/devices/not-a-mac/reboot", want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if !strings.Contains(rec.Body.String(), "invalid mac") {
					t.Fatalf("400 shape: %q", rec.Body.String())
				}
				if len(be.rebootArmed) != 0 {
					t.Fatalf("backend called with malformed MAC: %v", be.rebootArmed)
				}
			},
		},
		{
			name: "factory-reset malformed MAC is 400", method: "POST",
			path: "/api/v1/devices/not-a-mac/factory-reset", want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if !strings.Contains(rec.Body.String(), "invalid mac") {
					t.Fatalf("400 shape: %q", rec.Body.String())
				}
				if len(be.factoryResetArmed) != 0 {
					t.Fatalf("backend called with malformed MAC: %v", be.factoryResetArmed)
				}
			},
		},
		{
			// Only POST is registered; the project's unmatched-route
			// wrapper answers with the JSON 404 (Go 1.22 mux 405 never
			// surfaces through it). Either way the backend must NOT run.
			name: "GET reboot does not arm (only POST registered)", method: "GET",
			path: "/api/v1/devices/" + known + "/reboot", want: http.StatusNotFound,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.rebootArmed) != 0 {
					t.Fatalf("backend reached via GET: %v", be.rebootArmed)
				}
			},
		},
		{
			name: "GET factory-reset does not arm (only POST registered)", method: "GET",
			path: "/api/v1/devices/" + known + "/factory-reset", want: http.StatusNotFound,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.factoryResetArmed) != 0 {
					t.Fatalf("backend reached via GET: %v", be.factoryResetArmed)
				}
			},
		},
	} {
		run(t, tc)
	}
}

// TestCmdTaskRoutes pins the §6.3 stored-task enqueue surface: route in,
// EnqueueDeviceCmd called with the normalized MAC and the VALIDATED cmd
// string, 200 carries the backend DeviceView, unknown MAC is the
// wrapped-404 shape, malformed MAC is 400, cmd-string violations are 400
// before the backend runs, and the route is not reachable under a
// foreign method.
func TestCmdTaskRoutes(t *testing.T) {
	const known = "f0:9f:c2:84:8f:2a"
	for _, tc := range []testCase{
		{
			name: "cmd enqueues via EnqueueDeviceCmd", method: "POST",
			path: "/api/v1/devices/" + known + "/cmd", body: `{"cmd":"restart"}`, want: http.StatusOK,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.cmdEnqueued) != 1 || be.cmdEnqueued[0].mac != known || be.cmdEnqueued[0].cmd != "restart" {
					t.Fatalf("EnqueueDeviceCmd calls: %+v", be.cmdEnqueued)
				}
				var dv DeviceView
				if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil || dv.Name != "office-ceiling" {
					t.Fatalf("200 body should be the DeviceView: %+v err=%v", dv, err)
				}
			},
		},
		{
			name: "cmd MAC is normalized (upper-case in, lower-case out)", method: "POST",
			path: "/api/v1/devices/F0:9F:C2:84:8F:2A/cmd", body: `{"cmd":"restart"}`, want: http.StatusOK,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.cmdEnqueued) != 1 || be.cmdEnqueued[0].mac != known {
					t.Fatalf("EnqueueDeviceCmd calls: %+v", be.cmdEnqueued)
				}
			},
		},
		{
			name: "cmd task replaces enqueue (no error path)", method: "POST",
			path: "/api/v1/devices/" + known + "/cmd", body: `{"cmd":"spectrum-scan"}`, want: http.StatusOK,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.cmdEnqueued) != 1 || be.cmdEnqueued[0].cmd != "spectrum-scan" {
					t.Fatalf("EnqueueDeviceCmd calls: %+v", be.cmdEnqueued)
				}
			},
		},
		{
			name: "unknown MAC is 404", method: "POST",
			path: "/api/v1/devices/aa:bb:cc:dd:ee:66/cmd", body: `{"cmd":"restart"}`, want: http.StatusNotFound,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if !strings.Contains(rec.Body.String(), "device not found") {
					t.Fatalf("404 shape: %q", rec.Body.String())
				}
			},
		},
		{
			name: "malformed MAC is 400", method: "POST",
			path: "/api/v1/devices/not-a-mac/cmd", body: `{"cmd":"restart"}`, want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if !strings.Contains(rec.Body.String(), "invalid mac") {
					t.Fatalf("400 shape: %q", rec.Body.String())
				}
				if len(be.cmdEnqueued) != 0 {
					t.Fatalf("backend called with malformed MAC: %+v", be.cmdEnqueued)
				}
			},
		},
		{
			name: "invalid JSON body is 400", method: "POST",
			path: "/api/v1/devices/" + known + "/cmd", body: `{"cmd":`, want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.cmdEnqueued) != 0 {
					t.Fatalf("backend called on invalid JSON: %+v", be.cmdEnqueued)
				}
			},
		},
		{
			name: "empty cmd is 400", method: "POST",
			path: "/api/v1/devices/" + known + "/cmd", body: `{"cmd":""}`, want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				if !strings.Contains(rec.Body.String(), "invalid cmd") {
					t.Fatalf("400 shape: %q", rec.Body.String())
				}
				if len(be.cmdEnqueued) != 0 {
					t.Fatalf("backend called with empty cmd: %+v", be.cmdEnqueued)
				}
			},
		},
		{
			name: "missing cmd key is 400", method: "POST",
			path: "/api/v1/devices/" + known + "/cmd", body: `{}`, want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.cmdEnqueued) != 0 {
					t.Fatalf("backend called with missing cmd: %+v", be.cmdEnqueued)
				}
			},
		},
		{
			name: "cmd over 64 characters is 400", method: "POST",
			path: "/api/v1/devices/" + known + "/cmd", body: `{"cmd":"` + strings.Repeat("x", 65) + `"}`, want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.cmdEnqueued) != 0 {
					t.Fatalf("backend called with oversized cmd: %+v", be.cmdEnqueued)
				}
			},
		},
		{
			name: "cmd with control character is 400", method: "POST",
			path: "/api/v1/devices/" + known + "/cmd", body: "{\"cmd\":\"re\nstart\"}", want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.cmdEnqueued) != 0 {
					t.Fatalf("backend called with control-char cmd: %+v", be.cmdEnqueued)
				}
			},
		},
		{
			name: "cmd with leading whitespace is 400 (no silent trim — verbatim replay)", method: "POST",
			path: "/api/v1/devices/" + known + "/cmd", body: `{"cmd":" restart"}`, want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.cmdEnqueued) != 0 {
					t.Fatalf("backend called with padded cmd: %+v", be.cmdEnqueued)
				}
			},
		},
		{
			// Only POST is registered; the project's unmatched-route
			// wrapper answers with the JSON 404. Either way the backend
			// must NOT run.
			name: "GET cmd does not enqueue (only POST registered)", method: "GET",
			path: "/api/v1/devices/" + known + "/cmd", want: http.StatusNotFound,
			checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
				t.Helper()
				if len(be.cmdEnqueued) != 0 {
					t.Fatalf("backend reached via GET: %+v", be.cmdEnqueued)
				}
			},
		},
	} {
		run(t, tc)
	}
}

func TestCreateDeleteDevice(t *testing.T) {
	run(t, testCase{
		name: "create device hyphen mac", method: "POST", path: "/api/v1/devices",
		body: `{"mac":"F0-9F-C2-84-8F-2A","name":"lobby","site_id":"default"}`,
		want: http.StatusCreated,
		checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
			t.Helper()
			if len(be.created) != 1 || be.created[0].MAC != "f0:9f:c2:84:8f:2a" {
				t.Fatalf("created: %+v", be.created)
			}
			var dv DeviceView
			if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil {
				t.Fatal(err)
			}
			if dv.MAC != "f0:9f:c2:84:8f:2a" || dv.State != 1 {
				t.Fatalf("create response: %+v", dv)
			}

			// delete it
			req := httptest.NewRequest("DELETE", "/api/v1/devices/f0:9f:c2:84:8f:2a", nil)
			h := New(Config{}, be)
			rec2 := httptest.NewRecorder()
			h.ServeHTTP(rec2, req)
			if rec2.Code != http.StatusOK {
				t.Fatalf("delete: %d", rec2.Code)
			}
			if len(be.deleted) != 1 || be.deleted[0] != "f0:9f:c2:84:8f:2a" {
				t.Fatalf("backend deletes: %v", be.deleted)
			}

			// delete unknown mac -> 404
			req = httptest.NewRequest("DELETE", "/api/v1/devices/aa:aa:aa:aa:aa:aa", nil)
			rec3 := httptest.NewRecorder()
			h.ServeHTTP(rec3, req)
			if rec3.Code != http.StatusNotFound {
				t.Fatalf("delete unknown: %d", rec3.Code)
			}
		},
	})
}

// ---- mac normalization -----------------------------------------------------

func TestMACNormalization(t *testing.T) {
	// accepted variants normalize to lowercase colon-hex
	for _, in := range []string{
		"F0-9F-C2-84-8F-2A",
		"F0:9F:C2:84:8F:2A",
		"f09fc2848f2a",
		"F09F.C284.8F2A",
		"F0 9F C2 84 8F 2A",
	} {
		req := httptest.NewRequest("POST", "/api/v1/devices", strings.NewReader(`{"mac":"`+in+`"}`))
		h := New(Config{}, newFakeBackend())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("mac %q: got %d body=%s", in, rec.Code, rec.Body.String())
		}
		var dv DeviceView
		if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil || dv.MAC != "f0:9f:c2:84:8f:2a" {
			t.Fatalf("mac %q: normalized to %+v", in, dv.MAC)
		}
	}

	// garbage -> 400 JSON
	for _, in := range []string{"FOO", "", "aa:bb:cc:dd:ee", "zz:zz:zz:zz:zz:zz", "aabbccddeefff"} {
		req := httptest.NewRequest("POST", "/api/v1/devices", strings.NewReader(`{"mac":"`+in+`"}`))
		h := New(Config{}, newFakeBackend())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("mac %q: got %d, want 400 (body=%s)", in, rec.Code, rec.Body.String())
		}
		if m := decodeJSON(t, rec); m["error"] == nil {
			t.Fatalf("mac %q: no error key", in)
		}
	}
}

// TestMACInputBoundary pins the narrow end of the MAC spelling boundary —
// the REJECTION side; the acceptance side (five separator spellings,
// colon/hyphen/dot/space/bare) is the battery in TestMACNormalization above.
// Control characters (tab/newline) are NOT in the stripping set: a padded
// spelling fails the 12-hex count and is rejected BEFORE the Backend, at
// both the body field and a percent-escaped path segment (ServeMux
// unescapes per segment, so %09AA:BB:... reaches normalizeMAC as a
// tab-prefixed spelling).
func TestMACInputBoundary(t *testing.T) {
	// Padded body MAC: 400, fake Backend never reached.
	run(t, testCase{
		name: "tab/newline-padded body mac is 400", method: "POST", path: "/api/v1/devices",
		body: `{"mac":"\taabbccddeeff\n"}`,
		want: http.StatusBadRequest,
		checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
			t.Helper()
			if len(be.created) != 0 {
				t.Fatalf("padded mac create must not reach the backend: %+v", be.created)
			}
		},
	})
	// Percent-escaped path segment: unescape happens per segment in
	// ServeMux, so a tab-prefixed spelling is reachable via GET and 400s.
	req := httptest.NewRequest("GET", "/api/v1/devices/%09AA%3ABB%3ACC%3ADD%3AEE%3AFF", nil)
	h := New(Config{}, newFakeBackend())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("escaped padded mac: got %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	// Blank MAC: the exact canonical error body (json.Encoder appends a
	// trailing newline).
	req = httptest.NewRequest("POST", "/api/v1/devices", strings.NewReader(`{"mac":""}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("blank mac: got %d, want 400", rec.Code)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"invalid mac: want 12 hex chars, got 0"}` {
		t.Fatalf("blank mac body = %q, want the exact normalized-error shape", got)
	}
}

// ---- wireless validation + round trip ----------------------------------------

func putWireless(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("PUT", "/api/v1/wireless", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWirelessValidation(t *testing.T) {
	h := New(Config{}, newFakeBackend())

	// open + passphrase -> 400
	rec := putWireless(t, h, `{"wlans":[{"ssid":"guest","security":"open","passphrase":"secret12","vlan":1}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("open+passphrase: %d", rec.Code)
	}
	if m := decodeJSON(t, rec); !strings.Contains(m["error"].(string), "open") {
		t.Fatalf("open+passphrase error text: %v", m["error"])
	}

	// vlan 5000 -> 400
	rec = putWireless(t, h, `{"wlans":[{"ssid":"x","security":"wpa-p","passphrase":"longenough","vlan":5000}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("vlan 5000: %d", rec.Code)
	}

	// vlan 0 -> 400
	rec = putWireless(t, h, `{"wlans":[{"ssid":"x","security":"wpa-p","passphrase":"longenough","vlan":0}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("vlan 0: %d", rec.Code)
	}

	// short passphrase -> 400
	rec = putWireless(t, h, `{"wlans":[{"ssid":"x","security":"wpa-p","passphrase":"short","vlan":1}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short passphrase: %d", rec.Code)
	}

	// bad security enum -> 400
	rec = putWireless(t, h, `{"wlans":[{"ssid":"x","security":"wpa2","passphrase":"longenough","vlan":1}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad security: %d", rec.Code)
	}

	// 33-char ssid -> 400
	rec = putWireless(t, h, `{"wlans":[{"ssid":"`+strings.Repeat("a", 33)+`","security":"open","vlan":1}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("33-char ssid: %d", rec.Code)
	}

	// open without passphrase is fine
	rec = putWireless(t, h, `{"wlans":[{"ssid":"guest","security":"open","vlan":20,"enabled":true}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("open without passphrase: %d %q", rec.Code, rec.Body.String())
	}
}

func TestWPAEAPRadiusValidation(t *testing.T) {
	// Bytecode rationale in validateWlan: the reference controller only
	// emits functional EAP vaps with a valid radiusprofile
	// (requireRadiusProfile, int §13492+). wpa-eap is now ACCEPTED with an
	// inline RADIUS profile (radius_servers + radius_secret) and stays
	// rejected without one.
	h := New(Config{}, newFakeBackend())

	// Without a profile: still rejected, new wording.
	rec := putWireless(t, h, `{"wlans":[{"ssid":"corp","security":"wpa-eap","vlan":1}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("profile-less wpa-eap: %d, want 400", rec.Code)
	}
	if m := decodeJSON(t, rec); !strings.Contains(m["error"].(string), "wpa-eap requires at least one RADIUS server") {
		t.Fatalf("profile-less wpa-eap error text: %v", m["error"])
	}

	// With a minimal profile: accepted.
	rec = putWireless(t, h, `{"wlans":[{"ssid":"corp","security":"wpa-eap","vlan":1,`+
		`"radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s3cr3t!"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("wpa-eap with profile: %d %q, want 200", rec.Code, rec.Body.String())
	}

	// Profile shape failures, each with its precise wording.
	for _, tc := range []struct {
		name, extra, wantErr string
	}{
		{"empty ip",
			`"security":"wpa-eap","radius_servers":[{"ip":""}],"radius_secret":"s"`,
			"radius_servers[0].ip must not be empty"},
		{"five servers",
			`"security":"wpa-eap","radius_servers":[` + strings.Repeat(`{"ip":"10.0.0.1"},`, 4) + `{"ip":"10.0.0.5"}],"radius_secret":"s"`,
			"radius_servers supports at most 4 entries"},
		{"port out of range",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.0.0.1","port":65536}],"radius_secret":"s"`,
			"radius_servers[0].port must be 1..65535"},
		{"missing secret",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.1.0.5"}]`,
			"wpa-eap requires a RADIUS shared secret"},
		{"control char secret",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s\nevil=1"`,
			"radius_secret must not contain control characters"},
		{"bad vlan mode",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s","radius_vlan_mode":"sometimes"`,
			"radius_vlan_mode must be one of disabled, optional, required"},
		{"short passphrase",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s","passphrase":"short"`,
			"passphrase must be at least 8 characters"},
		{"acct empty ip",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s",` +
				`"accounting_enabled":true,"acct_servers":[{"ip":""}]`,
			"acct_servers[0].ip must not be empty"},
		{"acct five servers",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s",` +
				`"accounting_enabled":true,"acct_servers":[` + strings.Repeat(`{"ip":"10.2.0.1"},`, 4) + `{"ip":"10.2.0.5"}]`,
			"acct_servers supports at most 4 entries"},
		{"acct port out of range",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s",` +
				`"accounting_enabled":true,"acct_servers":[{"ip":"10.2.0.1","port":65536}]`,
			"acct_servers[0].port must be 1..65535"},
		{"interim without accounting",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s","interim_update_enabled":true`,
			"interim_update_enabled requires accounting_enabled"},
		{"das without accounting",
			`"security":"wpa-eap","radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s","radius_das_enabled":true`,
			"radius_das_enabled requires accounting_enabled"},
		{"acct on wpa-p",
			`"security":"wpa-p","passphrase":"correcthorse","accounting_enabled":true`,
			"require security wpa-eap"},
		{"acct on open",
			`"security":"open","acct_servers":[{"ip":"10.2.0.1"}]`,
			"require security wpa-eap"},
		{"radius on wpa-p",
			`"security":"wpa-p","passphrase":"correcthorse","radius_secret":"s"`,
			"require security wpa-eap"},
		{"radius on open",
			`"security":"open","radius_servers":[{"ip":"10.1.0.5"}]`,
			"require security wpa-eap"},
	} {
		rec := putWireless(t, h, `{"wlans":[{"ssid":"corp","name":"corp","vlan":1,`+tc.extra+`}]}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %q, want 400", tc.name, rec.Code, rec.Body.String())
		}
		if m := decodeJSON(t, rec); !strings.Contains(m["error"].(string), tc.wantErr) {
			t.Fatalf("%s: error %q, want it to contain %q", tc.name, m["error"], tc.wantErr)
		}
	}

	// The full accepted shape round-trips through the 200 echo body,
	// including the optional port and vlan mode.
	rec = putWireless(t, h, `{"wlans":[{"ssid":"corp","security":"wpa-eap","vlan":1,`+
		`"radius_servers":[{"ip":"10.1.0.5","port":1812},{"ip":"10.1.0.6"}],`+
		`"radius_secret":"s3cr3t!","radius_vlan_mode":"required"}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("full profile wpa-eap: %d %q, want 200", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"radius_vlan_mode":"required"`) {
		t.Fatalf("radius_vlan_mode missing from the echo: %s", body)
	}
}

// TestWPAEAPAccountingAcceptance pins the accepted accounting shape
// (§12 rows 1013-1014): accounting_enabled + acct_servers (port 0 kept
// as the 1813 default client-side) + interim_update_enabled round-trip
// through the 200 echo body, stored acct_servers stay acceptable with
// accounting OFF (radiusprofile shape: server list and toggle are
// independent; the inert list renders byte-identically to none), and
// radius_das_enabled is accepted under the requires-accounting gate
// (§12 row 1014 implemented — the renderer emits its das/dad rows).
func TestWPAEAPAccountingAcceptance(t *testing.T) {
	h := New(Config{}, newFakeBackend())
	profile := `"radius_servers":[{"ip":"10.1.0.5"}],"radius_secret":"s3cr3t!"`

	// Full accounting shape: accepted and echoed.
	rec := putWireless(t, h, `{"wlans":[{"ssid":"corp","security":"wpa-eap","vlan":1,`+profile+`,`+
		`"accounting_enabled":true,`+
		`"acct_servers":[{"ip":"10.2.0.1"},{"ip":"10.2.0.2","port":18131}],`+
		`"interim_update_enabled":true}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("accounting wpa-eap: %d %q, want 200", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`"accounting_enabled":true`,
		`"acct_servers":[{"ip":"10.2.0.1"},{"ip":"10.2.0.2","port":18131}]`,
		`"interim_update_enabled":true`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("accounting echo missing %q: %s", want, body)
		}
	}

	// radius_das_enabled with accounting and a valid acct server:
	// accepted and echoed (the judge's acct_servers precheck applies —
	// das adds only the requires-accounting rule).
	rec = putWireless(t, h, `{"wlans":[{"ssid":"corp","security":"wpa-eap","vlan":1,`+profile+`,`+
		`"accounting_enabled":true,"acct_servers":[{"ip":"10.2.0.1"}],`+
		`"radius_das_enabled":true}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("das wpa-eap: %d %q, want 200", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"radius_das_enabled":true`) {
		t.Fatalf("das echo missing the toggle: %s", body)
	}

	// Stored acct servers with accounting off: accepted (inert list —
	// the renderer goldens pin the byte-identity).
	rec = putWireless(t, h, `{"wlans":[{"ssid":"corp","security":"wpa-eap","vlan":1,`+profile+`,`+
		`"acct_servers":[{"ip":"10.2.0.1"}]}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("inert acct_servers wpa-eap: %d %q, want 200", rec.Code, rec.Body.String())
	}

	// accounting_enabled alone (zero acct servers): accepted — the
	// radiusprofile stores toggle and server list independently.
	rec = putWireless(t, h, `{"wlans":[{"ssid":"corp","security":"wpa-eap","vlan":1,`+profile+`,`+
		`"accounting_enabled":true}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("accounting without servers: %d %q, want 200", rec.Code, rec.Body.String())
	}
}

func TestWirelessNameCapAndBodyStrictness(t *testing.T) {
	h := New(Config{}, newFakeBackend())

	// 65-byte name -> 400 (same cap style as the ID).
	rec := putWireless(t, h, `{"wlans":[{"name":"`+strings.Repeat("a", 65)+`","ssid":"x","security":"open","vlan":1}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("65-byte name: %d, want 400", rec.Code)
	}
	// exactly 64 bytes is fine
	rec = putWireless(t, h, `{"wlans":[{"name":"`+strings.Repeat("a", 64)+`","ssid":"x","security":"open","vlan":1}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("64-byte name: %d %q, want 200", rec.Code, rec.Body.String())
	}

	// Unknown fields must be rejected (DisallowUnknownFields).
	rec = putWireless(t, h, `{"wlans":[{"ssid":"x","security":"open","vlan":1,"typo_field":true}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d %q, want 400", rec.Code, rec.Body.String())
	}
	rec = putWireless(t, h, `{"wlans":[],"extra_field":1}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown envelope field: %d, want 400", rec.Code)
	}

	// Trailing data after the JSON value must be rejected.
	rec = putWireless(t, h, `{"wlans":[]} trail`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("trailing data: %d, want 400", rec.Code)
	}
	// ...including trailing JSON values (smuggling attempts).
	rec = putWireless(t, h, `{"wlans":[]} {"wlans":[]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("trailing value: %d, want 400", rec.Code)
	}

	// The same strictness applies to the devices endpoint body.
	req := httptest.NewRequest("POST", "/api/v1/devices", strings.NewReader(`{"mac":"aabbccddeeff","bogus":1}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("devices unknown field: %d, want 400", rec.Code)
	}
}

func TestWirelessGetPutRoundTrip(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{}, be)

	rec := putWireless(t, h, `{"wlans":[
		{"name":"home","ssid":"home-net","security":"wpa-p","passphrase":"correct-horse","vlan":1,"enabled":true},
		{"name":"guest","ssid":"guests","security":"open","vlan":20,"enabled":false}
	]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %q", rec.Code, rec.Body.String())
	}
	var saved WlansEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &saved); err != nil {
		t.Fatal(err)
	}
	if len(saved.Wlans) != 2 || saved.Wlans[1].VLAN != 20 {
		t.Fatalf("put response: %+v", saved)
	}
	if be.lastPut.Wlans[0].SSID != "home-net" || be.lastPut.Wlans[1].Passphrase != "" {
		t.Fatalf("backend received: %+v", be.lastPut)
	}

	// GET echoes what was PUT
	req := httptest.NewRequest("GET", "/api/v1/wireless", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	var got WlansEnvelope
	if err := json.Unmarshal(rec2.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Wlans) != 2 || got.Wlans[0].Name != "home" || got.Wlans[1].SSID != "guests" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

// ---- device name validation (device-name hardening) -------------------------

func TestValidateDeviceName(t *testing.T) {
	if msg := ValidateDeviceName("office-ceiling"); msg != "" {
		t.Fatalf("valid name rejected: %q", msg)
	}
	// exactly 64 bytes is the cap
	if msg := ValidateDeviceName(strings.Repeat("n", 64)); msg != "" {
		t.Fatalf("64-byte name rejected: %q", msg)
	}
	for _, bad := range []string{
		strings.Repeat("n", 65), // over the cap
		"row1\nfake row",        // \n is the system_cfg row separator
		"bad\rname",
		"del\x7f",
	} {
		if msg := ValidateDeviceName(bad); msg == "" {
			t.Fatalf("invalid device name %q accepted", bad)
		}
	}
	// Empty is legal: DeviceUpsert treats "" as leave-unset and DevicePatch
	// treats it as a documented explicit clear.
	if msg := ValidateDeviceName(""); msg != "" {
		t.Fatalf("empty device name must stay legal: %q", msg)
	}
}

// TestPatchDeviceRoute covers PATCH /api/v1/devices/{mac} against the real
// handler (the provider's resource_access_point uses it): name+site_id happy
// path, invalid-name rejection, unknown MAC 404.
func TestPatchDeviceRoute(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{}, be)

	// Happy path: name + site_id patch reaches the backend.
	req := httptest.NewRequest("PATCH", "/api/v1/devices/f0:9f:c2:84:8f:2a",
		strings.NewReader(`{"name":"renamed","site_id":"lab"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %q", rec.Code, rec.Body.String())
	}
	var dv DeviceView
	if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil || dv.Name != "renamed" || dv.SiteID != "lab" {
		t.Fatalf("patch response: %+v err=%v", dv, err)
	}
	if got := be.byMAC["f0:9f:c2:84:8f:2a"]; got.Name != "renamed" || got.SiteID != "lab" {
		t.Fatalf("backend state after patch: %+v", got)
	}

	// Control-char name -> 400 (matches the site_id 400 style).
	req = httptest.NewRequest("PATCH", "/api/v1/devices/f0:9f:c2:84:8f:2a",
		strings.NewReader(`{"name":"row1\nfake"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid name patch: %d %q, want 400", rec.Code, rec.Body.String())
	}

	// Unknown MAC -> 404 (wrapped ErrNotFound from the backend).
	req = httptest.NewRequest("PATCH", "/api/v1/devices/aa:bb:cc:dd:ee:66",
		strings.NewReader(`{"name":"x"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("patch unknown mac: %d, want 404", rec.Code)
	}
}

// TestPatchDeviceLEDOverrideRoute covers the per-device LED override on
// PATCH /api/v1/devices/{mac}: the three §2 states round-trip ("default" is
// the explicit clear → the view omits the field), an invalid enum value is
// a 400, and an omitted field leaves the record untouched (pointer
// semantics — only an explicit value changes state).
func TestPatchDeviceLEDOverrideRoute(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{}, be)

	patch := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PATCH", "/api/v1/devices/f0:9f:c2:84:8f:2a", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// on
	if rec := patch(`{"led_override":"on"}`); rec.Code != http.StatusOK {
		t.Fatalf("set on: %d %q", rec.Code, rec.Body.String())
	}
	var dv DeviceView
	if err := json.Unmarshal(patch(`{"led_override":"off"}`).Body.Bytes(), &dv); err != nil || dv.LEDOverride != "off" {
		t.Fatalf("set off round-trip: %+v err=%v", dv, err)
	}
	// "default" clears back to the jar default; the view omits the field.
	clearRec := patch(`{"led_override":"default"}`)
	if clearRec.Code != http.StatusOK {
		t.Fatalf("clear: %d %q", clearRec.Code, clearRec.Body.String())
	}
	dv = DeviceView{}
	if err := json.Unmarshal(clearRec.Body.Bytes(), &dv); err != nil || dv.LEDOverride != "" {
		t.Fatalf("clear round-trip: %+v err=%v", dv, err)
	}
	if strings.Contains(clearRec.Body.String(), "led_override") {
		t.Fatalf("cleared override must be omitted from the view: %q", clearRec.Body.String())
	}
	// invalid enum -> 400 with the validator message
	if rec := patch(`{"led_override":"blink"}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "led_override must be one of default, on, off") {
		t.Fatalf("invalid enum: %d %q, want 400", rec.Code, rec.Body.String())
	}
	// empty string is not one of the three states -> 400 too
	if rec := patch(`{"led_override":""}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty override: %d, want 400", rec.Code)
	}
}

// TestPatchDeviceLEDBarKnobsRoute covers the two §12 ledbar knobs on
// PATCH /api/v1/devices/{mac}: the brightness knob's 0..100 domain
// (explicit 0 is valid and must round-trip — the pointer semantics; 100
// is the explicit clear back to the jar default, omitted from the view;
// out-of-domain is a 400), and the color knob's verbatim storage (no
// format validation — the §12 render owns the Color.decode fallback per
// the packet, so even a "garbage" value is accepted and stored; "" is
// the explicit clear). Pointer semantics: an omitted field leaves the
// record untouched.
func TestPatchDeviceLEDBarKnobsRoute(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{}, be)

	patch := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("PATCH", "/api/v1/devices/f0:9f:c2:84:8f:2a", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Brightness: explicit 0 is VALID and must round-trip (not omitted).
	rec := patch(`{"led_override_color_brightness":0}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set explicit 0: %d %q", rec.Code, rec.Body.String())
	}
	var dv DeviceView
	if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil ||
		dv.LEDOverrideColorBrightness == nil || *dv.LEDOverrideColorBrightness != 0 {
		t.Fatalf("explicit 0 round-trip: %+v err=%v", dv, err)
	}
	// Mid-domain value round-trips.
	if err := json.Unmarshal(patch(`{"led_override_color_brightness":50}`).Body.Bytes(), &dv); err != nil ||
		dv.LEDOverrideColorBrightness == nil || *dv.LEDOverrideColorBrightness != 50 {
		t.Fatalf("set 50 round-trip: %+v err=%v", dv, err)
	}
	// 100 is the explicit clear back to the jar default: omitted from view.
	clearRec := patch(`{"led_override_color_brightness":100}`)
	if clearRec.Code != http.StatusOK {
		t.Fatalf("clear brightness: %d %q", clearRec.Code, clearRec.Body.String())
	}
	if strings.Contains(clearRec.Body.String(), "led_override_color_brightness") {
		t.Fatalf("cleared brightness must be omitted from the view: %q", clearRec.Body.String())
	}
	// Out-of-domain: 400 with the validator message.
	for _, bad := range []string{`{"led_override_color_brightness":101}`, `{"led_override_color_brightness":-1}`} {
		if rec := patch(bad); rec.Code != http.StatusBadRequest ||
			!strings.Contains(rec.Body.String(), "led_override_color_brightness must be 0..100") {
			t.Fatalf("out-of-domain %q: %d %q, want 400", bad, rec.Code, rec.Body.String())
		}
	}

	// Color: verbatim storage — a well-formed hex, and a "garbage" value
	// the jar itself would fall back on, both round-trip unchanged (the
	// §12 render owns the fallback; the API does not second-guess it).
	for _, c := range []string{"#ff8c00", "garbage", "  "} {
		if err := json.Unmarshal(patch(`{"led_override_color":"`+c+`"}`).Body.Bytes(), &dv); err != nil ||
			dv.LEDOverrideColor != c {
			t.Fatalf("verbatim color %q round-trip: %+v err=%v", c, dv, err)
		}
	}
	// "" is the explicit clear: omitted from the view.
	clearColor := patch(`{"led_override_color":""}`)
	if clearColor.Code != http.StatusOK || strings.Contains(clearColor.Body.String(), "led_override_color") {
		t.Fatalf("clear color: %d %q, want 200 with the field omitted", clearColor.Code, clearColor.Body.String())
	}
	// A JSON string into the int knob (and a fractional number) is a
	// body-decode 400, not a stored value.
	for _, bad := range []string{`{"led_override_color_brightness":"42"}`, `{"led_override_color_brightness":42.5}`} {
		if rec := patch(bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("type-confused %q: %d %q, want 400", bad, rec.Code, rec.Body.String())
		}
	}
}

// TestDeviceRadiosRoutes covers the per-radio admin-intent endpoints:
// list shape, wholesale-replace PUT semantics (absent/null = clear),
// strict body decoding (fractional/string/unknown-field rejection), the
// DELETE sugar, and 404/400/401 mapping.
func TestDeviceRadiosRoutes(t *testing.T) {
	const known = "/api/v1/devices/f0:9f:c2:84:8f:2a/radios"
	intPtr := func(n int) *int { return &n }

	// Happy path + response/view shape.
	run(t, testCase{
		name: "radios list", method: "GET", path: known, want: http.StatusOK,
		checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
			var env radiosEnvelope
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("list body: %v", err)
			}
			if len(env.Radios) != 0 {
				t.Fatalf("fake radios fixture should be empty, got %+v", env.Radios)
			}
		},
	})
	run(t, testCase{
		name: "radio put channel+txpower", method: "PUT", path: known + "/wifi1",
		body: `{"channel":36,"txpower":10}`, want: http.StatusOK,
		checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
			if len(be.radioPuts) != 1 {
				t.Fatalf("backend saw %d puts", len(be.radioPuts))
			}
			call := be.radioPuts[0]
			if call.radio != "wifi1" || call.clear {
				t.Fatalf("call routed wrong: %+v", call)
			}
			if call.up.Channel == nil || *call.up.Channel != 36 ||
				call.up.Txpower == nil || call.up.Txpower.Auto || call.up.Txpower.DBm != 10 {
				t.Fatalf("call upsert decoded wrong: %+v", call.up)
			}
			var v RadioView
			if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil ||
				v.Channel == nil || *v.Channel != "36" || v.Txpower == nil || *v.Txpower != "10" {
				t.Fatalf("put response view: %+v err=%v", v, err)
			}
		},
	})
	run(t, testCase{
		name: "radio put txpower auto", method: "PUT", path: known + "/wifi1",
		body: `{"txpower":"auto"}`, want: http.StatusOK,
		checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
			call := be.radioPuts[len(be.radioPuts)-1]
			if call.up.Txpower == nil || !call.up.Txpower.Auto || call.up.Channel != nil {
				t.Fatalf("txpower auto decode: %+v", call.up)
			}
		},
	})
	run(t, testCase{
		name: "radio put empty body clears all", method: "PUT", path: known + "/wifi1",
		body: `{}`, want: http.StatusOK,
		checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
			call := be.radioPuts[len(be.radioPuts)-1]
			if call.up.Channel != nil || call.up.Txpower != nil {
				t.Fatalf("empty put must clear wholesale: %+v", call.up)
			}
		},
	})
	run(t, testCase{
		name: "radio put null field clears", method: "PUT", path: known + "/wifi1",
		body: `{"channel":null}`, want: http.StatusOK,
		checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
			call := be.radioPuts[len(be.radioPuts)-1]
			if call.up.Channel != nil || call.up.Txpower != nil {
				t.Fatalf("null put must equal absent (wholesale clear): %+v", call.up)
			}
		},
	})
	run(t, testCase{
		name: "radio delete", method: "DELETE", path: known + "/wifi1", want: http.StatusOK,
		checks: func(t *testing.T, be *fakeBackend, _ *httptest.ResponseRecorder) {
			call := be.radioPuts[len(be.radioPuts)-1]
			if !call.clear || call.up.Channel != nil || call.up.Txpower != nil {
				t.Fatalf("delete must be the wholesale clear: %+v", call)
			}
		},
	})

	// Strict decoding: 400 for every malformed shape (typo'd clients must
	// fail loud, never silently drop inputs).
	for _, tc := range []testCase{
		{name: "fractional channel", method: "PUT", path: known + "/wifi1", body: `{"channel":36.5}`, want: http.StatusBadRequest},
		{name: "fractional txpower", method: "PUT", path: known + "/wifi1", body: `{"txpower":10.5}`, want: http.StatusBadRequest},
		{name: "txpower string number", method: "PUT", path: known + "/wifi1", body: `{"txpower":"10"}`, want: http.StatusBadRequest},
		{name: "txpower boolean", method: "PUT", path: known + "/wifi1", body: `{"txpower":true}`, want: http.StatusBadRequest},
		{name: "unknown field", method: "PUT", path: known + "/wifi1", body: `{"chan":36}`, want: http.StatusBadRequest},
		{name: "trailing data", method: "PUT", path: known + "/wifi1", body: `{"channel":36} x`, want: http.StatusBadRequest},
		{name: "malformed json", method: "PUT", path: known + "/wifi1", body: `{`, want: http.StatusBadRequest},
		{name: "unknown mac list", method: "GET", path: "/api/v1/devices/de:ad:be:ef:00:00/radios", want: http.StatusNotFound},
		{name: "unknown mac put", method: "PUT", path: "/api/v1/devices/de:ad:be:ef:00:00/radios/wifi1", body: `{"channel":36}`, want: http.StatusNotFound},
		{name: "unknown mac delete", method: "DELETE", path: "/api/v1/devices/de:ad:be:ef:00:00/radios/wifi1", want: http.StatusNotFound},
		{name: "invalid mac", method: "GET", path: "/api/v1/devices/zz/radios", want: http.StatusBadRequest},
	} {
		run(t, tc)
	}

	// Auth: the routes sit behind the admin token like every /api route.
	run(t, testCase{
		name: "radios require token", method: "GET", path: known, token: "secret", want: http.StatusUnauthorized,
	})

	// PUT int-pointer plumbing sanity (the request struct is decoded by
	// the handler, not by these literals — this guards the helper).
	if *intPtr(36) != 36 {
		t.Fatal("intPtr helper broken")
	}
}

// TestCreateDeviceRejectsInvalidName pins the 400 on POST /api/v1/devices
// for a non-empty invalid name.
func TestCreateDeviceRejectsInvalidName(t *testing.T) {
	run(t, testCase{
		name: "create device with control-char name", method: "POST", path: "/api/v1/devices",
		body: `{"mac":"f0:9f:c2:84:8f:2a","name":"row1\nfake"}`,
		want: http.StatusBadRequest,
		checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
			t.Helper()
			if len(be.created) != 0 {
				t.Fatalf("invalid create must not reach the backend: %+v", be.created)
			}
		},
	})
}

// TestCreateDeviceRejectsBadgeSiteIDRoute pins the POST /api/v1/devices
// site gate (mirror of the PATCH route's gate, backend-create edition):
// garbage site_id 400s at the route and never reaches the Backend — before
// this gate the Backend's create accepted any site_id spelling and
// 201-created it.
func TestCreateDeviceRejectsInvalidSiteID(t *testing.T) {
	run(t, testCase{
		name: "create device with garbage site_id is 400", method: "POST", path: "/api/v1/devices",
		body: `{"mac":"f0:9f:c2:84:8f:2a","site_id":"bad site!"}`,
		want: http.StatusBadRequest,
		checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
			t.Helper()
			if len(be.created) != 0 {
				t.Fatalf("invalid site_id create must not reach the backend: %+v", be.created)
			}
		},
	})
	run(t, testCase{
		name: "empty site_id create stays legal (unset)", method: "POST", path: "/api/v1/devices",
		body: `{"mac":"f0:9f:c2:84:8f:2a"}`,
		want: http.StatusCreated,
	})
}

// ---- web console / fallbacks --------------------------------------------------

func TestRootServesEmbeddedConsole(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	h := New(Config{}, newFakeBackend())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("root: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type: %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{"open-unifi controller", "api/v1/devices", "Adopt"} {
		if !strings.Contains(body, want) {
			t.Fatalf("console missing %q", want)
		}
	}
}

func TestUnknownAPIPathJSON404(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/inform_preview", nil)
	h := New(Config{}, newFakeBackend())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown api path: %d", rec.Code)
	}
	if m := decodeJSON(t, rec); m["error"] == nil {
		t.Fatalf("unknown api path: not JSON-shaped")
	}
}

func TestMetricsInstrumented(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{}, be)

	req := httptest.NewRequest("GET", "/api/v1/devices", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	req = httptest.NewRequest("GET", "/metrics", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("metrics: %d", rec2.Code)
	}
	if !strings.Contains(rec2.Body.String(), "openunifi_api_requests_total") {
		t.Fatalf("metrics missing api requests counter")
	}
	for _, series := range []string{`{code="200",path="GET /api/v1/devices"}`} {
		if !strings.Contains(rec2.Body.String(), series) {
			t.Fatalf("metrics missing api request series %q; instrumented suffix:\n%s", series, bodyExcerpt(rec2.Body.String()))
		}
	}
}

func bodyExcerpt(body string) string {
	if i := strings.Index(body, "openunifi_api_requests_total"); i >= 0 {
		if i+600 < len(body) {
			return body[i : i+600]
		}
		return body[i:]
	}
	return body
}

// ---- error-injecting backend (opaque-500 / adopt-counter tests) ------------

// failingBackend decorates fakeBackend with forced errors for selected
// methods, bypassing the fixtures' happy/404 paths.
type failingBackend struct {
	*fakeBackend
	getErr   error
	adoptErr error
}

func (f *failingBackend) GetDevice(_ context.Context, mac string) (DeviceView, error) {
	return DeviceView{}, f.getErr
}

func (f *failingBackend) AdoptPending(_ context.Context, mac string) (DeviceView, error) {
	// Inject ONLY the generic failure; an unknown MAC still surfaces the
	// wrapped ErrNotFound exactly like the real adapter (404 semantics).
	for _, p := range f.pending {
		if strings.EqualFold(p.MAC, mac) {
			return DeviceView{}, f.adoptErr
		}
	}
	return DeviceView{}, fmt.Errorf("%w: %s", ErrNotFound, mac)
}

// ---- /metrics under auth (item 1) ------------------------------------------

func TestMetricsRequiresTokenWhenAuthConfigured(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{AdminToken: "s3cret"}, be)

	// No header -> 401 with the canonical JSON error shape.
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics without header: got %d, want 401", rec.Code)
	}
	if m := decodeJSON(t, rec); m["error"] != "unauthorized" {
		t.Fatalf("metrics 401 shape: %v", m["error"])
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("metrics 401 missing WWW-Authenticate")
	}

	// Wrong token ([same length as valid) -> still 401.
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cerx")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics wrong token: got %d, want 401", rec.Code)
	}

	// Valid Bearer -> 200 with the Prometheus exposition.
	req = httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics with token: got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "openunifi_api_requests_total") {
		t.Fatalf("metrics body missing exposition")
	}
}

func TestMetricsOpenWhenNoToken(t *testing.T) {
	h := New(Config{}, newFakeBackend())
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics without auth configured: got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "# TYPE openunifi_informs_total") {
		t.Fatalf("metrics body missing informs series")
	}
}

// ---- opaque 500s (item 2) ---------------------------------------------------

func TestOpaque500LogsAndHidesInternalError(t *testing.T) {
	var logBuf bytes.Buffer
	lg := slog.New(slog.NewJSONHandler(&logBuf, nil))

	internalMsg := "db file corrupted at /var/lib/openunifi/state/xxx.db"
	be := &failingBackend{
		fakeBackend: newFakeBackend(),
		getErr:      fmt.Errorf("secret-internal: %s", internalMsg),
	}
	h := New(Config{Logger: lg}, be)

	req := httptest.NewRequest("GET", "/api/v1/devices/f0:9f:c2:84:8f:2a", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("backend error: got %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), internalMsg) {
		t.Fatalf("500 body leaks internal detail: %q", rec.Body.String())
	}
	if m := decodeJSON(t, rec); m["error"] != "internal error" {
		t.Fatalf("500 body: %v, want \"internal error\"", m["error"])
	}
	// ...but the configured logger DID receive the full error server-side.
	if !strings.Contains(logBuf.String(), internalMsg) {
		t.Fatalf("internal detail missing from server-side log: %q", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "admin api backend error") {
		t.Fatalf("log record missing: %q", logBuf.String())
	}
}

func Test404PathKeepsErrorTextAndDefaultLoggerWorks(t *testing.T) {
	// Config{} (Logger nil ⇒ slog.Default) must keep compiling and working.
	be := &failingBackend{
		fakeBackend: newFakeBackend(),
		getErr:      fmt.Errorf("%w: aa:bb:cc:dd:ee:66", ErrNotFound),
	}
	h := New(Config{}, be)

	req := httptest.NewRequest("GET", "/api/v1/devices/aa:bb:cc:dd:ee:66", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", rec.Code)
	}
	if m := decodeJSON(t, rec); !strings.Contains(m["error"].(string), "device not found") {
		t.Fatalf("404 body must keep the MAC context: %v", m["error"])
	}
}

// ---- set-inform push failures are HTTP 502 ---------------------------------

// TestAdoptSetInformPushFailedMapsTo502 pins the lab-only set-inform push
// contract at the route level: a backend AdoptPending error wrapping
// ErrSetInformPushFailed (the SSH leg failed AFTER the whitelist
// promotion committed) must surface status 502 with the refinement-
// diagnostics-style extendable error text in the {"error":...} body — a
// re-click simply re-attempts the push (one click = one attempt).
func TestAdoptSetInformPushFailedMapsTo502(t *testing.T) {
	be := &failingBackend{
		fakeBackend: newFakeBackend(),
		adoptErr: fmt.Errorf("%w: mca-cli-op set-inform: exit status 1: refused",
			ErrSetInformPushFailed),
	}
	h := New(Config{}, be)
	req := httptest.NewRequest("POST", "/api/v1/pending/a0:40:a0:aa:bb:cc/adopt", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("set-inform push failure: got %d, want 502", rec.Code)
	}
	m := decodeJSON(t, rec)
	if em, ok := m["error"].(string); !ok ||
		strings.Contains(em, "internal error") ||
		!strings.Contains(em, "set-inform push failed") {
		t.Fatalf("502 body must carry the sentinel text: %v", m["error"])
	}
}

// ---- adopt counters are poller-only (item 3) --------------------------------

// adoptCounterValues reads openunifi_adopt_total / _adopt_fail_total through
// the handler's own /metrics endpoint (in-process exposition parse; no
// sockets).
func adoptCounterValues(t *testing.T, h http.Handler) (adopt, fail float64) {
	t.Helper()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics fetch: %d", rec.Code)
	}
	parse := func(name string) float64 {
		re := regexp.MustCompile(`(?m)^` + name + `\s+([0-9.eE+-]+)$`)
		m := re.FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("no %s series in exposition:\n%s", name, rec.Body.String())
		}
		v, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			t.Fatalf("parse %s value %q: %v", name, m[1], err)
		}
		return v
	}
	return parse("openunifi_adopt_total"), parse("openunifi_adopt_fail_total")
}

// TestAdoptCountersArePollerOnly pins the DECIDED metric semantics: the
// admin API NEVER bumps openunifi_adopt_total / _adopt_fail_total — those
// count state transitions observed by the app poller (internal/app
// PollOnce / sweepLost). Endpoint adopt success, genuine endpoint failure
// and 404 caller errors must all leave the counters untouched; otherwise
// real transitions would be double-counted (the poller observes the very
// transitions an adopt request kicks off) and API noise would look like
// adoption outcomes.
func TestAdoptCountersArePollerOnly(t *testing.T) {
	be := &failingBackend{
		fakeBackend: newFakeBackend(),
		adoptErr:    errors.New("fake adopt blowup: radius socket refused"),
	}
	h := New(Config{}, be)
	before, beforeFail := adoptCounterValues(t, h)

	// Unknown MAC -> 404 (caller error) → NO movement.
	req := httptest.NewRequest("POST", "/api/v1/pending/aa:bb:cc:dd:ee:66/adopt", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("adopt unknown: %d, want 404", rec.Code)
	}
	if a, f := adoptCounterValues(t, h); a != before || f != beforeFail {
		t.Fatalf("404 adopt moved counters: adopt %v->%v fail %v->%v", before, a, beforeFail, f)
	}

	// Genuine backend failure -> 500 → NO movement.
	req = httptest.NewRequest("POST", "/api/v1/pending/a0:40:a0:aa:bb:cc/adopt", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("adopt failure: %d, want 500", rec.Code)
	}
	if a, f := adoptCounterValues(t, h); a != before || f != beforeFail {
		t.Fatalf("failed adopt endpoint moved counters: adopt %v->%v fail %v->%v", before, a, beforeFail, f)
	}

	// Successful adoption -> 200 → NO movement (the backend was reached;
	// its later state transition will be counted by the app poller).
	be2 := newFakeBackend()
	h2 := New(Config{}, be2)
	req = httptest.NewRequest("POST", "/api/v1/pending/a0:40:a0:aa:bb:cc/adopt", nil)
	rec = httptest.NewRecorder()
	h2.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthy adopt: %d", rec.Code)
	}
	if len(be2.adopted) != 1 {
		t.Fatalf("healthy adopt did not reach backend: %v", be2.adopted)
	}
	if a, f := adoptCounterValues(t, h2); a != before || f != beforeFail {
		t.Fatalf("successful adopt endpoint moved counters: adopt %v->%v fail %v->%v", before, a, beforeFail, f)
	}
}

// ---- wlan input hardening (item 4) -----------------------------------------

func TestWirelessRejectsControlCharsAndBadID(t *testing.T) {
	h := New(Config{}, newFakeBackend())

	// A raw newline inside a value is the system_cfg row separator: any of
	// ssid / name / passphrase carrying \n or \r must be rejected; JSON
	// escapes \n/\r decode to real control chars before validation.
	for _, tc := range []struct {
		name, body, wantMsg string
	}{
		{"ssid newline", `{"wlans":[{"ssid":"evil\nline","security":"open","vlan":1}]}`, "ssid"},
		{"ssid carriage return", `{"wlans":[{"ssid":"bad\rcarriage","security":"open","vlan":1}]}`, "ssid"},
		{"name newline", `{"wlans":[{"name":"row1\nfake row","ssid":"ok","security":"open","vlan":1}]}`, "name"},
		{"passphrase newline", `{"wlans":[{"ssid":"x","security":"wpa-p","passphrase":"pass\nw0rd","vlan":1}]}`, "passphrase"},
		{"passphrase carriage return", `{"wlans":[{"ssid":"x","security":"wpa-p","passphrase":"a\rb7cd789","vlan":1}]}`, "passphrase"},
		{"id with space", `{"wlans":[{"id":"wlan 1","ssid":"x","security":"open","vlan":1}]}`, "id"},
		{"id with equals", `{"wlans":[{"id":"a=b","ssid":"x","security":"open","vlan":1}]}`, "id"},
		{"id with comma", `{"wlans":[{"id":"a,b","ssid":"x","security":"open","vlan":1}]}`, "id"},
		{"id with newline", `{"wlans":[{"id":"row1\nrow2","ssid":"x","security":"open","vlan":1}]}`, "id"},
		{"id too long", `{"wlans":[{"id":"` + strings.Repeat("a", 65) + `","ssid":"x","security":"open","vlan":1}]}`, "id"},
	} {
		rec := putWireless(t, h, tc.body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: got %d (%s), want 400", tc.name, rec.Code, rec.Body.String())
		}
		if m := decodeJSON(t, rec); !strings.Contains(m["error"].(string), tc.wantMsg) {
			t.Fatalf("%s: error %v does not mention %q", tc.name, m["error"], tc.wantMsg)
		}
	}

	// Clean values — including a hex-style ID — still pass.
	rec := putWireless(t, h, `{"wlans":[
		{"id":"wlan-1","name":"home","ssid":"home-net","security":"wpa-p","passphrase":"correct-horse","vlan":1,"enabled":true},
		{"name":"guest","ssid":"guests","security":"open","vlan":20}
	]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("clean wlans rejected: %d %q", rec.Code, rec.Body.String())
	}
}

// ---- web console: embedded esc() + CSP (item 5) -----------------------------
// These are mechanical tripwires on the embedded page: they prove the fix
// ships (quote-escaping chain present, DOM-based esc absent) and that page()
// serves the CSP header. Real JS behavior (whether esc() survives a u001F
// edge case, event-handler breakout attempt at runtime etc.) is browser
// behavior and NOT unit-testable from Go.

func TestEmbeddedConsoleHasQuoteEscapingAndCSP(t *testing.T) {
	src := string(indexHTML)

	if !strings.Contains(src, `.replace(/"/g, "&quot;")`) {
		t.Fatalf("esc() does not escape double quotes (required: output lands inside value=\"...\")")
	}
	if !strings.Contains(src, `.replace(/&/g, "&amp;")`) {
		t.Fatalf("esc() must escape & first so later entities are not double-escaped")
	}
	if !strings.Contains(src, `&apos;`) && !strings.Contains(src, `&#39;`) {
		t.Fatalf("esc() does not escape single quotes")
	}
	// The old textContent->innerHTML trick has no legitimate remaining user.
	if strings.Contains(src, "d.innerHTML") {
		t.Fatalf("old DOM-based esc remnant present")
	}

	// page() must set the CSP defense-in-depth header.
	h := New(Config{}, newFakeBackend())
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'", "object-src 'none'", "base-uri 'none'",
		"frame-ancestors 'none'", "connect-src 'self'",
	} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP header missing %q; got %q", want, csp)
		}
	}
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "open-unifi controller") {
		t.Fatalf("console page broken: %d %q", rec.Code, rec.Body.String()[:80])
	}
}

// ---- Wlan struct parity (item 7) --------------------------------------------
//
// adminapi.Wlan and server.Wlan are mirrored structs: the cmd/openunifi
//converter and server's wlanListHash replicate the field list by hand.
// ANY new field must be added to BOTH structs, the converter, AND
// wlanListHash's map — or provisioning silently drops it. This reflect test
// catches STRUCT drift (field name+type sets); converter/hash drift needs
// review attention — its test lives with the server lane. Nested mirror
// types (adminapi.RadiusServer vs wireless.RadiusServer) compare by
// STRUCTURAL shape, not nominal identity — the packages are deliberately
// decoupled.

// sameShape reports structural type identity: builtin kinds must match
// exactly; slices/pointers recurse into their elements; struct types
// (the two packages' mirrored RadiusServer) match when their field
// compositions match.
func sameShape(a, b reflect.Type) bool {
	if a == b {
		return true
	}
	if a.Kind() != b.Kind() {
		return false
	}
	switch a.Kind() {
	case reflect.Slice, reflect.Pointer, reflect.Array:
		return sameShape(a.Elem(), b.Elem())
	case reflect.Struct:
		if a.NumField() != b.NumField() {
			return false
		}
		for i := 0; i < a.NumField(); i++ {
			af, bf := a.Field(i), b.Field(i)
			if af.Name != bf.Name || !sameShape(af.Type, bf.Type) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func TestWlanStructParityWithServer(t *testing.T) {
	a := reflect.TypeOf(Wlan{})
	s := reflect.TypeOf(server.Wlan{})

	if a.NumField() != s.NumField() {
		t.Fatalf("field count drift: adminapi.Wlan has %d, server.Wlan has %d", a.NumField(), s.NumField())
	}
	afields := map[string]reflect.Type{}
	for i := 0; i < a.NumField(); i++ {
		f := a.Field(i)
		afields[f.Name] = f.Type
	}
	for i := 0; i < s.NumField(); i++ {
		sf := s.Field(i)
		at, ok := afields[sf.Name]
		if !ok {
			t.Fatalf("server.Wlan field %q missing in adminapi.Wlan — add to BOTH structs, the cmd/openunifi converter AND server's wlanListHash", sf.Name)
		}
		if !sameShape(at, sf.Type) {
			t.Fatalf("field %q type drift: adminapi %v vs server %v", sf.Name, at, sf.Type)
		}
		delete(afields, sf.Name)
	}
	for name := range afields {
		t.Fatalf("adminapi.Wlan field %q missing in server.Wlan — add to BOTH structs, the cmd/openunifi converter AND server's wlanListHash", name)
	}
}

// ---- blocked-client routes --------------------------------------------------

// TestBlockedClientRoutes walks the three blocked-set endpoints end-to-end:
// never-null listing, boundary MAC normalization, idempotent blocking, 404
// on not-blocked unblock and unknown devices, 400 on invalid MACs and
// strict/ malformed bodies, and token enforcement.
func TestBlockedClientRoutes(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{AdminToken: "s3cret"}, be)
	const dev = "f0:9f:c2:84:8f:2a" // fixture device from newFakeBackend
	do := func(method, path, body string) *httptest.ResponseRecorder {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Authorization", "Bearer s3cret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	decode := func(t *testing.T, rec *httptest.ResponseRecorder) BlockedClientsView {
		t.Helper()
		var v BlockedClientsView
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}

	// Fresh listing: 200 with an EMPTY LIST (never null).
	rec := do("GET", "/api/v1/devices/"+dev+"/blocked", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list fresh: %d %q", rec.Code, rec.Body.String())
	}
	v := decode(t, rec)
	if v.Blocked == nil || len(v.Blocked) != 0 || v.MAC != dev {
		t.Fatalf("fresh view = %+v, want empty non-nil list", v)
	}

	// Block a client in a non-normalized spelling: the boundary normalizes
	// before the backend sees it.
	rec = do("POST", "/api/v1/devices/"+dev+"/blocked", `{"mac":"AA-BB-CC-DD-EE-FF"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("block: %d %q", rec.Code, rec.Body.String())
	}
	if v = decode(t, rec); len(v.Blocked) != 1 || v.Blocked[0] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("block view = %+v, want normalized colon-hex", v)
	}

	// Idempotent re-block (other spelling): 200 with the SAME set.
	rec = do("POST", "/api/v1/devices/"+dev+"/blocked", `{"mac":"aabbccddeeff"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-block: %d %q", rec.Code, rec.Body.String())
	}
	if v = decode(t, rec); len(v.Blocked) != 1 {
		t.Fatalf("re-block must be idempotent: %+v", v)
	}

	// Second client, then list both.
	rec = do("POST", "/api/v1/devices/"+dev+"/blocked", `{"mac":"00:11:22:33:44:55"}`)
	if rec.Code != http.StatusOK || len(decode(t, rec).Blocked) != 2 {
		t.Fatalf("second block: %d %q", rec.Code, rec.Body.String())
	}
	rec = do("GET", "/api/v1/devices/"+dev+"/blocked", "")
	if v = decode(t, rec); len(v.Blocked) != 2 ||
		v.Blocked[0] != "00:11:22:33:44:55" || v.Blocked[1] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("list after two blocks = %+v, want canonical (sorted) order", v)
	}

	// Unblock one (dotted spelling in the path): 200 with the remainder.
	rec = do("DELETE", "/api/v1/devices/"+dev+"/blocked/AA.BB.CC.DD.EE.FF", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("unblock: %d %q", rec.Code, rec.Body.String())
	}
	if v = decode(t, rec); len(v.Blocked) != 1 || v.Blocked[0] != "00:11:22:33:44:55" {
		t.Fatalf("post-unblock view = %+v", v)
	}

	// Unblock a client that is not blocked: 404.
	rec = do("DELETE", "/api/v1/devices/"+dev+"/blocked/ff:ee:dd:cc:bb:aa", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unblock not-blocked: %d %q, want 404", rec.Code, rec.Body.String())
	}

	// Unknown device: 404 on all three.
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/v1/devices/aa:bb:cc:dd:ee:ff/blocked", ""},
		{"POST", "/api/v1/devices/aa:bb:cc:dd:ee:ff/blocked", `{"mac":"00:11:22:33:44:55"}`},
		{"DELETE", "/api/v1/devices/aa:bb:cc:dd:ee:ff/blocked/00:11:22:33:44:55", ""},
	} {
		rec = do(c.method, c.path, c.body)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s unknown device: %d %q, want 404", c.method, rec.Code, rec.Body.String())
		}
	}

	// Invalid MACs are boundary 400s, never backend calls.
	if rec = do("GET", "/api/v1/devices/zz/blocked", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad device mac: %d, want 400", rec.Code)
	}
	if rec = do("POST", "/api/v1/devices/"+dev+"/blocked", `{"mac":"not-a-mac"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad client body: %d, want 400", rec.Code)
	}
	if rec = do("DELETE", "/api/v1/devices/"+dev+"/blocked/zz", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad client path: %d, want 400", rec.Code)
	}

	// Strict body validation and malformed JSON.
	if rec = do("POST", "/api/v1/devices/"+dev+"/blocked", `{"mac":"00:11:22:33:44:55","extra":true}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d, want 400", rec.Code)
	}
	if rec = do("POST", "/api/v1/devices/"+dev+"/blocked", `{`); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: %d, want 400", rec.Code)
	}
	if rec = do("POST", "/api/v1/devices/"+dev+"/blocked", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body: %d, want 400", rec.Code)
	}

	// Token required, same as every other route.
	req := httptest.NewRequest("GET", "/api/v1/devices/"+dev+"/blocked", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", rec2.Code)
	}

	// The routes reached the backend (recorded calls, normalized spellings).
	if len(be.blockedAdded) != 3 || be.blockedAdded[0] != dev+"/aa:bb:cc:dd:ee:ff" {
		t.Fatalf("block calls recorded = %v", be.blockedAdded)
	}
	if len(be.blockedRemoved) != 1 || be.blockedRemoved[0] != dev+"/aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unblock calls recorded = %v", be.blockedRemoved)
	}
}

// ---- client-session route ---------------------------------------------------

// TestDeviceClientsRoute pins the read-only client-session listing: fixture
// rows pass through verbatim (sorted colon-hex + connected state), a device
// with no sessions lists EMPTY (never null), unknown devices are 404,
// invalid MACs are boundary 400s, and the token gate applies.
func TestDeviceClientsRoute(t *testing.T) {
	be := newFakeBackend()
	h := New(Config{AdminToken: "s3cret"}, be)
	const dev = "f0:9f:c2:84:8f:2a" // fixture device from newFakeBackend
	do := func(method, path, body string) *httptest.ResponseRecorder {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req := httptest.NewRequest(method, path, rdr)
		req.Header.Set("Authorization", "Bearer s3cret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	var env struct {
		Clients []ClientView `json:"clients"`
	}

	// A device with no recorded sessions lists EMPTY (never null).
	rec := do("GET", "/api/v1/devices/"+dev+"/clients", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("empty device: %d %q", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.Clients == nil || len(env.Clients) != 0 {
		t.Fatalf("empty device clients = %+v, want empty non-nil list", env.Clients)
	}

	// Seeded rows pass through verbatim in stored order (sorted
	// colon-hex + connected state + last_seen).
	be.clients = map[string][]ClientView{
		dev: {
			{MAC: "00:11:22:33:44:55", Connected: true, LastSeen: 1700000001},
			{MAC: "aa:bb:cc:dd:ee:ff", Connected: false, LastSeen: 1700000000},
		},
	}
	rec = do("GET", "/api/v1/devices/"+dev+"/clients", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %q", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if len(env.Clients) != 2 ||
		env.Clients[0].MAC != "00:11:22:33:44:55" || !env.Clients[0].Connected || env.Clients[0].LastSeen != 1700000001 ||
		env.Clients[1].MAC != "aa:bb:cc:dd:ee:ff" || env.Clients[1].Connected || env.Clients[1].LastSeen != 1700000000 {
		t.Fatalf("clients = %+v, want the fixture rows with connected state", env.Clients)
	}

	// Boundary MAC normalization: the hyphen spelling reaches the backend
	// as colon-hex.
	if rec = do("GET", "/api/v1/devices/F0-9F-C2-84-8F-2A/clients", ""); rec.Code != http.StatusOK {
		t.Fatalf("normalized mac: %d %q", rec.Code, rec.Body.String())
	}

	// Unknown device: 404.
	if rec = do("GET", "/api/v1/devices/aa:bb:cc:dd:ee:ff/clients", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown device: %d %q, want 404", rec.Code, rec.Body.String())
	}

	// Invalid MAC: boundary 400, never a backend call.
	if rec = do("GET", "/api/v1/devices/zz/clients", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad device mac: %d, want 400", rec.Code)
	}

	// Token required, same as every other route.
	req := httptest.NewRequest("GET", "/api/v1/devices/"+dev+"/clients", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", rec2.Code)
	}
}

// ---- site settings routes ---------------------------------------------------

const testKeyRSALine = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB second@ap"

// siteSettingsBody renders a strict whole-document PUT body; a nil field
// name drops that key (the missing-field decode cases use that).
func siteSettingsBody(missing string) string {
	m := map[string]any{
		"regulatory_country_code": 840,
		"device_ssh_public_keys":  []string{testKeyEd25519Line, testKeyRSALine},
	}
	if missing != "" {
		delete(m, missing)
	}
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestSiteSettingsGetHappy pins the GET wire shape: 200 with the exact
// snake_case view body the Backend's read model defines (the provider's
// drift detection decodes this document).
func TestSiteSettingsGetHappy(t *testing.T) {
	run(t, testCase{
		name: "GET site settings", method: "GET", path: "/api/v1/site-settings",
		want: http.StatusOK,
		checks: func(t *testing.T, _ *fakeBackend, rec *httptest.ResponseRecorder) {
			t.Helper()
			want := `{"regulatory_country_code":840,"device_ssh_public_keys":["` +
				testKeyEd25519Line + `"]}` + "\n"
			if rec.Body.String() != want {
				t.Fatalf("body = %q, want %q", rec.Body.String(), want)
			}
		},
	})
}

// TestSiteSettingsPutHappy pins the whole-document PUT: all three fields
// decode verbatim into the Backend document and the response echoes the
// projected view.
func TestSiteSettingsPutHappy(t *testing.T) {
	run(t, testCase{
		name: "PUT site settings", method: "PUT", path: "/api/v1/site-settings",
		body: siteSettingsBody(""),
		want: http.StatusOK,
		checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
			t.Helper()
			got := be.lastSiteSettingsPut
			if got.RegulatoryCountryCode != 840 ||
				len(got.DeviceSSHPublicKeys) != 2 || got.DeviceSSHPublicKeys[0] != testKeyEd25519Line ||
				got.DeviceSSHPublicKeys[1] != testKeyRSALine {
				t.Fatalf("backend document: %+v", got)
			}
			m := decodeJSON(t, rec)
			if m["regulatory_country_code"] != float64(840) {
				t.Fatalf("view body: %v", m)
			}
			if _, stale := m["ap_ssh_password"]; stale {
				t.Fatalf("removed site password field echoed back: %v", m)
			}
			keys, ok := m["device_ssh_public_keys"].([]any)
			if !ok || len(keys) != 2 || keys[0] != testKeyEd25519Line {
				t.Fatalf("view keys: %v", m["device_ssh_public_keys"])
			}
		},
	})
}

// TestSiteSettingsPutMissingField pins the whole-document decode: EVERY
// field is required; a partial body 400s with "missing field <name>"
// BEFORE the Backend runs (never an implicit zero write).
func TestSiteSettingsPutMissingField(t *testing.T) {
	for _, missing := range []string{"regulatory_country_code", "device_ssh_public_keys"} {
		run(t, testCase{
			name: "PUT site settings missing " + missing, method: "PUT", path: "/api/v1/site-settings",
			body: siteSettingsBody(missing),
			want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				m := decodeJSON(t, rec)
				if m["error"] != "missing field "+missing {
					t.Fatalf("error = %v, want missing field %s", m["error"], missing)
				}
				if !siteSettingsDocZero(be.lastSiteSettingsPut) {
					t.Fatalf("backend called on missing field: %+v", be.lastSiteSettingsPut)
				}
			},
		})
	}
}

// TestSiteSettingsPutValidation pins the pre-backend fence: the same rule
// set the app verb enforces 400s here BEFORE the Backend is called.
func TestSiteSettingsPutValidation(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantMsg string
	}{
		{
			name:    "invalid key line",
			body:    `{"regulatory_country_code":840,"device_ssh_public_keys":["not-a-key-line"]}`,
			wantMsg: "invalid Device SSH public key #1",
		},
		{
			name:    "country out of range high",
			body:    `{"regulatory_country_code":1000,"device_ssh_public_keys":[]}`,
			wantMsg: "regulatory country code must be an ISO 3166-1 numeric code from 001 to 999",
		},
		{
			name:    "country out of range low",
			body:    `{"regulatory_country_code":-7,"device_ssh_public_keys":[]}`,
			wantMsg: "regulatory country code must be an ISO 3166-1 numeric code from 001 to 999",
		},
		{
			// The removed knob's wire name must now be rejected as an
			// unknown field (DisallowUnknownFields) — the strict decoder
			// never lets a stale client send it.
			name:    "removed disable knob is an unknown field",
			body:    `{"regulatory_country_code":840,"device_ssh_public_keys":[],"ap_ssh_disable_password":false}`,
			wantMsg: "invalid JSON body",
		},
		{
			// The REMOVED SITE PASSWORD's HISTORICAL wire name must
			// likewise be an unknown field 400 (Phase A wire removal):
			// old provider binaries still PUTting `ap_ssh_password` (the
			// GHCR-era site wire key; `device_ssh_password` never
			// existed) are rejected before the Backend runs, mirroring
			// the removed-disable-field pin at its side.
			name:    "removed site password field is an unknown field",
			body:    `{"regulatory_country_code":840,"device_ssh_public_keys":[],"ap_ssh_password":"s3cret"}`,
			wantMsg: "invalid JSON body",
		},
	}
	for _, tc := range cases {
		run(t, testCase{
			name: tc.name, method: "PUT", path: "/api/v1/site-settings",
			body: tc.body,
			want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				m := decodeJSON(t, rec)
				msg, _ := m["error"].(string)
				if !strings.Contains(msg, tc.wantMsg) {
					t.Fatalf("error = %q, want containing %q", msg, tc.wantMsg)
				}
				if !siteSettingsDocZero(be.lastSiteSettingsPut) {
					t.Fatalf("backend called on invalid document: %+v", be.lastSiteSettingsPut)
				}
			},
		})
	}
}

// TestSiteSettingsPutBadBody pins the strict decode behavior: malformed
// JSON, unknown fields, and trailing data all 400 with the same body error
// the other routes emit (readJSON: DisallowUnknownFields + size cap).
func TestSiteSettingsPutBadBody(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{"regulatory_country_code": 840`},
		{name: "unknown field", body: `{"regulatory_country_code":840,"device_ssh_public_keys":[],"extra":1}`},
		{name: "removed disable knob is now unknown", body: `{"regulatory_country_code":840,"device_ssh_public_keys":[],"ap_ssh_disable_password":false}`},
		{name: "removed site password field is still unknown", body: `{"regulatory_country_code":840,"device_ssh_public_keys":[],"ap_ssh_password":""}`},
		{name: "trailing data", body: siteSettingsBody("") + ` {}`},
		{name: "null field counts as missing", body: `{"regulatory_country_code":null,"device_ssh_public_keys":[]}`},
	}
	for _, tc := range cases {
		run(t, testCase{
			name: tc.name, method: "PUT", path: "/api/v1/site-settings",
			body: tc.body,
			want: http.StatusBadRequest,
			checks: func(t *testing.T, be *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				m := decodeJSON(t, rec)
				if m["error"] != "invalid JSON body" && m["error"] != "missing field regulatory_country_code" {
					t.Fatalf("error = %v", m["error"])
				}
				if !siteSettingsDocZero(be.lastSiteSettingsPut) {
					t.Fatalf("backend called on bad body: %+v", be.lastSiteSettingsPut)
				}
			},
		})
	}
}

// TestSiteSettingsRoutesRequireToken pins the auth posture: both site
// settings routes sit behind requireToken like every other /api route
// (GETs are NOT exempt).
func TestSiteSettingsRoutesRequireToken(t *testing.T) {
	for _, tc := range []struct {
		method, path, body string
	}{
		{"GET", "/api/v1/site-settings", ""},
		{"PUT", "/api/v1/site-settings", siteSettingsBody("")},
	} {
		run(t, testCase{
			name: tc.method + " " + tc.path, method: tc.method, path: tc.path,
			token: "s3cret",
			body:  tc.body,
			want:  http.StatusUnauthorized,
			checks: func(t *testing.T, _ *fakeBackend, rec *httptest.ResponseRecorder) {
				t.Helper()
				m := decodeJSON(t, rec)
				if m["error"] != "unauthorized" {
					t.Fatalf("error = %v, want unauthorized", m["error"])
				}
				if rec.Header().Get("WWW-Authenticate") == "" {
					t.Fatalf("missing WWW-Authenticate header")
				}
			},
		})
	}
}

// siteSettingsDocZero reports the untouched fakeBackend PUT record (the
// default zero document) — the "backend NOT called" pin of the rejection
// tests.
func siteSettingsDocZero(d SiteSettingsDocument) bool {
	return d.RegulatoryCountryCode == 0 && d.DeviceSSHPublicKeys == nil
}

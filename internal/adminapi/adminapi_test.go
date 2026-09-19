package adminapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
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
	byMAC             map[string]DeviceView
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

func (f *fakeBackend) ListPending(context.Context) []PendingView { return f.pending }

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

func TestWPAEAPRejected(t *testing.T) {
	// Bytecode rationale in validateWlan: the reference controller only
	// emits functional EAP vaps with a valid radiusprofile; without RADIUS
	// support we must never accept wpa-eap.
	h := New(Config{}, newFakeBackend())
	rec := putWireless(t, h, `{"wlans":[{"ssid":"corp","security":"wpa-eap","vlan":1}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wpa-eap: %d, want 400", rec.Code)
	}
	if m := decodeJSON(t, rec); !strings.Contains(m["error"].(string), "wpa-eap requires RADIUS profiles, which open-unifi does not support") {
		t.Fatalf("wpa-eap error text: %v", m["error"])
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
// review attention — its test lives with the server lane.

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
		if at != sf.Type {
			t.Fatalf("field %q type drift: adminapi %v vs server %v", sf.Name, at, sf.Type)
		}
		delete(afields, sf.Name)
	}
	for name := range afields {
		t.Fatalf("adminapi.Wlan field %q missing in server.Wlan — add to BOTH structs, the cmd/openunifi converter AND server's wlanListHash", name)
	}
}

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The tests in this file run without opening any TCP socket: the sandbox
// used for CI forbids loopback connections, so instead of
// httptest.NewServer we wrap the fake backend's http.Handler in a
// RoundTripper that pipes each *http.Request through it in-process. The
// resulting coverage (routing, bearer auth, status codes, JSON bodies,
// method semantics) is identical to loopback httptest; only the TCP layer
// itself differs.

// fakeBackend is an in-memory stand-in for the admin API. Its shapes mirror
// internal/adminapi (DeviceView wire shape, {"devices":[...]} envelope,
// {"error":"..."} error bodies, idempotent-upsert POST /api/v1/devices):
//
//	GET/POST     /api/v1/devices
//	GET/DELETE   /api/v1/devices/{mac}
//	GET/PUT      /api/v1/wireless   (whole-document envelope)
//	GET          /api/v1/whoami
type fakeBackend struct {
	token    string            // required bearer token; "" means anonymous allowed
	devices  map[string]string // mac -> raw device JSON (DeviceView shape)
	wireless string            // raw wireless envelope JSON
	lastAuth string            // observed Authorization header of the last request
}

// lastSeenFixture is a fixed unix timestamp used in device fixtures.
const lastSeenFixture = int64(1726432000)

func newFakeBackend(token string) *fakeBackend {
	fb := &fakeBackend{
		token:    token,
		devices:  map[string]string{},
		wireless: `{"wlans":[]}`,
	}
	return fb
}

// handler returns the fb's http.Handler.
func (fb *fakeBackend) handler() http.Handler {
	mux := http.NewServeMux()

	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			fb.lastAuth = r.Header.Get("Authorization")
			if fb.token != "" && fb.lastAuth != "Bearer "+fb.token {
				// Canonical adminapi error shape: {"error":"..."}.
				writeFakeErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/api/v1/whoami", auth(func(w http.ResponseWriter, _ *http.Request) {
		// adminapi.whoAmI wire shape.
		_, _ = w.Write([]byte(`{"server":"open-unifi","version":"0.1.0-dev","authConfigured":` +
			boolJSON(fb.token != "") + "}\n"))
	}))

	mux.HandleFunc("/api/v1/devices", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// adminapi returns a {"devices":[...]} (devicesEnvelope).
			vals := mapValuesSorted(fb.devices)
			_, _ = w.Write([]byte(`{"devices":[` + strings.Join(vals, ",") + "]}\n"))
		case http.MethodPost:
			// DeviceUpsert: {mac, name?, site_id?}; idempotent upsert —
			// duplicates are overwritten (name refreshed) and still 201.
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeFakeErr(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			mac := strings.ToLower(strings.ReplaceAll(body["mac"], ":", ""))
			if len(mac) != 12 {
				writeFakeErr(w, http.StatusBadRequest, "invalid mac")
				return
			}
			w.WriteHeader(http.StatusCreated)
			fb.devices[mac] = deviceJSON(mac, body["name"])
			_, _ = w.Write([]byte(fb.devices[mac] + "\n"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/v1/devices/", auth(func(w http.ResponseWriter, r *http.Request) {
		mac := strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(r.URL.Path, "/api/v1/devices/"), ":", ""))
		dev, ok := fb.devices[mac]
		switch r.Method {
		case http.MethodGet:
			if !ok {
				writeFakeErr(w, http.StatusNotFound, "device not found")
				return
			}
			_, _ = w.Write([]byte(dev + "\n"))
		case http.MethodDelete:
			if !ok {
				writeFakeErr(w, http.StatusNotFound, "device not found")
				return
			}
			delete(fb.devices, mac)
			_, _ = w.Write([]byte(`{"status":"deleted","mac":"` + mac + `"}` + "\n"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/v1/wireless", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(fb.wireless + "\n"))
		case http.MethodPut:
			var env struct {
				Wlans []map[string]any `json:"wlans"`
			}
			if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
				writeFakeErr(w, http.StatusBadRequest, "invalid JSON body")
				return
			}
			buf, _ := json.Marshal(env)
			fb.wireless = string(buf)
			// adminapi echoes the accepted envelope.
			_, _ = w.Write([]byte(fb.wireless + "\n"))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	return mux
}

// writeFakeErr writes the adminapi canonical error shape {"error":"..."}.
func writeFakeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc, _ := json.Marshal(map[string]string{"error": msg})
	_, _ = w.Write(append(enc, '\n'))
}

// clientFor returns an apiClient against fb using an in-process transport.
func clientFor(fb *fakeBackend, token string) *apiClient {
	h := fb.handler()
	tripper := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		// The handler mutates nothing that needs the original URL, but keep
		// the URL intact so path-based routing inside the mux works.
		h.ServeHTTP(rec, req)
		return rec.Result(), nil
	})
	return (&apiClient{baseURL: "http://fake", token: token}).
		withHTTPClient(&http.Client{Transport: tripper})
}

// clientForURL behaves like clientFor but lets tests assert base-url
// joining with a configurable (fake) base URL.
func clientForURL(fb *fakeBackend, rawURL, token string) *apiClient {
	c := clientFor(fb, token)
	u, err := url.Parse(rawURL)
	if err == nil && u.Host == "fake" {
		c.baseURL = strings.TrimRight(rawURL, "/")
	}
	return c
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func boolJSON(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// deviceJSON renders the adminapi.DeviceView wire shape. State is a JSON
// NUMBER (state 1 = pending: registered via the adopt whitelist but not yet
// seen on the inform channel) and last_seen is a unix-seconds int64.
func deviceJSON(mac, name string) string {
	return `{"mac":"` + mac + `","name":"` + name + `","model":"UAP-AC-Pro-Gen2","firmware":"6.6.55","ip":"192.168.1.50","state":1,"last_seen":` +
		strconv.FormatInt(lastSeenFixture, 10) + `,"actions":["delete"]}`
}

func mapValuesSorted(m map[string]string) []string {
	vals := make([]string, 0, len(m))
	for _, k := range sortedKeys(m) {
		vals = append(vals, m[k])
	}
	return vals
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestClientAuthHeader(t *testing.T) {
	cases := []struct {
		name        string
		serverToken string
		clientToken string
		wantOK      bool
	}{
		{name: "server anonymous, client anonymous", serverToken: "", clientToken: "", wantOK: true},
		{name: "server token, client token mismatch", serverToken: "secret", clientToken: "wrong", wantOK: false},
		{name: "server token, client matches", serverToken: "secret", clientToken: "secret", wantOK: true},
		{name: "server token, client anonymous", serverToken: "secret", clientToken: "", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fb := newFakeBackend(tc.serverToken)
			c := clientFor(fb, tc.clientToken)
			err := c.do(context.Background(), http.MethodGet, "/api/v1/whoami", nil, nil)
			if tc.wantOK && err != nil {
				t.Fatalf("expected ok, got err: %v", err)
			}
			if !tc.wantOK && (err == nil || !strings.Contains(err.Error(), "unauthorized: check token")) {
				t.Fatalf("expected unauthorized: check token, got: %v", err)
			}
			if tc.clientToken != "" && fb.lastAuth != "Bearer "+tc.clientToken {
				t.Fatalf("expected Bearer auth header, got %q", fb.lastAuth)
			}
			if tc.clientToken == "" && fb.lastAuth != "" {
				t.Fatalf("expected no auth header, got %q", fb.lastAuth)
			}
		})
	}
}

func TestURLTrailingSlashTrimmed(t *testing.T) {
	c := newAPIClient("https://controller.example///", "", false)
	// baseURL must be free of trailing slashes so c.baseURL+path cannot
	// produce double slashes on the wire.
	if strings.HasSuffix(c.baseURL, "/") {
		t.Fatalf("baseURL should have trailing slashes trimmed: %q", c.baseURL)
	}
	// Path joining: base + path is exactly one slash between host and path.
	if want := "https://controller.example/api/v1/x"; c.baseURL+"/api/v1/x" != want {
		t.Fatalf("path join mismatch: %q", c.baseURL+"/api/v1/x")
	}
}

func TestInsecureSkipVerifyConfig(t *testing.T) {
	c := newAPIClient("https://example.invalid", "t", true)
	if !c.http.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure_skip_verify=true must disable TLS verification")
	}
	c2 := newAPIClient("https://example.invalid", "t", false)
	if c2.http.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure_skip_verify=false must keep TLS verification on")
	}
}

func TestWlanEnvelopeRoundTrip(t *testing.T) {
	fb := newFakeBackend("")
	ctx := context.Background()
	c := clientFor(fb, "")

	// Create: append a wpa-p wlan, PUT.
	env, err := c.getWireless(ctx)
	if err != nil {
		t.Fatalf("getWireless: %v", err)
	}
	env.Wlans = append(env.Wlans, wirelessEntry{
		Name: "main", SSID: "main", Security: "wpa-p",
		Passphrase: "sup3rsecret", VLAN: 42, Enabled: true,
	})
	if err := c.putWireless(ctx, env); err != nil {
		t.Fatalf("putWireless create: %v", err)
	}

	// Read-back: server has the entry with its fields intact.
	got, err := c.getWireless(ctx)
	if err != nil {
		t.Fatalf("getWireless read-back: %v", err)
	}
	if len(got.Wlans) != 1 || got.Wlans[0].Name != "main" || got.Wlans[0].VLAN != 42 {
		t.Fatalf("read-back mismatch: %+v", got.Wlans)
	}
	if got.Wlans[0].Passphrase != "sup3rsecret" {
		t.Fatal("passphrase not persisted server-side")
	}

	// Update: change vlan in place.
	got.Wlans[0].VLAN = 100
	if err := c.putWireless(ctx, got); err != nil {
		t.Fatalf("putWireless update: %v", err)
	}
	got, _ = c.getWireless(ctx)
	if got.Wlans[0].VLAN != 100 {
		t.Fatalf("update not visible: %+v", got.Wlans)
	}

	// Delete: drop and PUT.
	env, _ = c.getWireless(ctx)
	env.Wlans = env.Wlans[:0]
	if err := c.putWireless(ctx, env); err != nil {
		t.Fatalf("putWireless delete: %v", err)
	}
	got, _ = c.getWireless(ctx)
	if len(got.Wlans) != 0 {
		t.Fatalf("expected empty wlans, got %+v", got.Wlans)
	}
}

// TestWhoamiProbe pins fix 4: checkConnectivity (Configure-time probe) must
// succeed against a real whoami route and fail — typed 404 — when the route
// is missing (wrong server, wrong port, older build).
func TestWhoamiProbe(t *testing.T) {
	ctx := context.Background()

	// Probe against the fake full backend: nil error expected.
	if err := clientFor(newFakeBackend("secret"), "secret").checkConnectivity(ctx); err != nil {
		t.Fatalf("whoami probe against known-good backend: %v", err)
	}

	// Probe against a server WITHOUT the whoami route: typed 404.
	bare := http.NewServeMux()
	bare.HandleFunc("/api/v1/devices", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"devices":[]}`))
	})
	tripper := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		bare.ServeHTTP(rec, req)
		return rec.Result(), nil
	})
	c := (&apiClient{baseURL: "http://bare"}).withHTTPClient(&http.Client{Transport: tripper})
	err := c.checkConnectivity(ctx)
	if err == nil || !errNotFound(err) {
		t.Fatalf("missing whoami route must fail the probe with a typed 404, got %v", err)
	}

	// whoami also reports whether the server expects a token.
	authConfigured, err := clientFor(newFakeBackend("secret"), "secret").whoami(ctx)
	if err != nil || !authConfigured {
		t.Fatalf("whoami authConfigured: got (%v, %v)", authConfigured, err)
	}
}

func TestDeviceLifecycleErrors(t *testing.T) {
	fb := newFakeBackend("")
	ctx := context.Background()
	c := clientFor(fb, "")

	// Missing device GET -> not found.
	if _, err := c.getDevice(ctx, "00:00:00:00:00:01"); !errNotFound(err) {
		t.Fatalf("expected not-found error, got %v", err)
	}
	// Missing device DELETE -> not found (resource Delete treats as success).
	if err := c.do(ctx, http.MethodDelete, "/api/v1/devices/00:00:00:00:00:01", nil, nil); !errNotFound(err) {
		t.Fatalf("expected not-found error on delete, got %v", err)
	}
	// Create a device and read it back.
	if err := c.do(ctx, http.MethodPost, "/api/v1/devices", map[string]string{"mac": "aa:bb:cc:dd:ee:ff", "site_id": "default"}, nil); err != nil {
		t.Fatalf("create device: %v", err)
	}
	dev, err := c.getDevice(ctx, "aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if dev.State != 1 { // store.StatePending
		t.Fatalf("expected numeric pending state 1, got %+v", dev)
	}
	if dev.LastSeen != lastSeenFixture {
		t.Fatalf("expected last_seen %d (unix seconds), got %d", lastSeenFixture, dev.LastSeen)
	}
	// Duplicate POST is an idempotent upsert (200/201 family), never a 409.
	if err := c.do(ctx, http.MethodPost, "/api/v1/devices", map[string]string{"mac": "aa:bb:cc:dd:ee:ff", "name": "renamed-ap"}, nil); err != nil {
		t.Fatalf("duplicate create should be an idempotent upsert, got err: %v", err)
	}
	// listDevices now contains exactly one device.
	if devs, err := c.listDevices(ctx); err != nil || len(devs) != 1 {
		t.Fatalf("listDevices: err=%v want 1 device, got %v", err, devs)
	}
	// Delete and confirm absence.
	if err := c.do(ctx, http.MethodDelete, "/api/v1/devices/aa:bb:cc:dd:ee:ff", nil, nil); err != nil {
		t.Fatalf("delete device: %v", err)
	}
	if _, err := c.getDevice(ctx, "aa:bb:cc:dd:ee:ff"); !errNotFound(err) {
		t.Fatalf("expected gone device, got %v", err)
	}
}

// TestDeviceDecodeNumbers pins the BLOCKER wire contract: the server sends
// the DeviceView numeric vocabulary (state JSON number, last_seen unix
// seconds int64), and the provider decodes both plus maps state names,
// including the unknown(n) fallback.
func TestDeviceDecodeNumbers(t *testing.T) {
	fb := newFakeBackend("")
	fb.devices["aabbccddeeff"] = `{"mac":"aa:bb:cc:dd:ee:ff","name":"adopted-ap","model":"UAP-AC-Pro-Gen2","firmware":"6.6.55","ip":"192.168.1.60","state":3,"last_seen":1726432000,"actions":["delete"]}`
	fb.devices["112233445566"] = `{"mac":"11:22:33:44:55:66","state":9}`
	fb.devices["778899aabbcc"] = `{"mac":"77:88:99:aa:bb:cc","name":"gone","state":4}`
	c := clientFor(fb, "")
	ctx := context.Background()

	dev, err := c.getDevice(ctx, "aabbccddeeff")
	if err != nil {
		t.Fatalf("getDevice: %v", err)
	}
	if dev.State != 3 || dev.LastSeen != 1726432000 {
		t.Fatalf("wire decode mismatch: got state=%d last_seen=%d, want 3/1726432000", dev.State, dev.LastSeen)
	}
	if got := stateName(dev.State); got != "adopted" {
		t.Fatalf("stateName(3) = %q, want adopted", got)
	}

	lost, err := c.getDevice(ctx, "778899aabbcc")
	if err != nil {
		t.Fatalf("getDevice lost: %v", err)
	}
	if got := stateName(lost.State); got != "lost" {
		t.Fatalf("stateName(4) = %q, want lost", got)
	}

	unknown, err := c.getDevice(ctx, "112233445566")
	if err != nil {
		t.Fatalf("getDevice unknown: %v", err)
	}
	if got := stateName(unknown.State); got != "unknown(9)" {
		t.Fatalf("stateName(9) = %q, want unknown(9)", got)
	}

	for n, want := range map[int]string{1: "pending", 2: "adopting", 3: "adopted", 4: "lost"} {
		if got := stateName(n); got != want {
			t.Fatalf("stateName(%d) = %q, want %q", n, got, want)
		}
	}
}

// TestAPIErrorTyped404 pins fix 3: non-2xx responses yield a typed
// *apiError whose NotFound() is probeable via errors.As, and whose message
// extracts the server's {"error":"..."} JSON field.
func TestAPIErrorTyped404(t *testing.T) {
	fb := newFakeBackend("")
	c := clientFor(fb, "")
	_, err := c.getDevice(context.Background(), "00:11:22:33:44:55")
	if err == nil {
		t.Fatal("expected error for unknown device")
	}
	var ae *apiError
	if !errors.As(err, &ae) {
		t.Fatalf("expected typed *apiError, got %T: %v", err, err)
	}
	if !ae.NotFound() {
		t.Fatalf("expected NotFound() for status 404, got %d", ae.status)
	}
	if ae.status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", ae.status)
	}
	// Message must be the clean extracted error text, not the raw body.
	if want := "not found: device not found"; err.Error() != want {
		t.Fatalf("error message = %q, want %q", err.Error(), want)
	}

	// Non-JSON bodies keep their trimmed text as the diagnostic.
	e := doErr(http.StatusInternalServerError, []byte("  boom  \n"))
	ae2 := e.(*apiError)
	if ae2.status != 500 || ae2.message != "boom" || ae2.NotFound() {
		t.Fatalf("5xx apiError mismatch: %#v", ae2)
	}

	// 401s still render the checkpoint-token message.
	e401 := doErr(http.StatusUnauthorized, []byte(`{"error":"unauthorized"}`))
	if got := e401.Error(); got != "unauthorized: check token" {
		t.Fatalf("401 message = %q", got)
	}
}

// TODO(morning): acceptance tests via terraform-plugin-framework's
// resource.TestCase scaffolding need the terraform CLI to spawn the
// provider; skipped tonight on purpose.
func TestAcceptanceStubbedOut(t *testing.T) {
	t.Skip("TODO(morning): acceptance tests (require terraform CLI)")
}

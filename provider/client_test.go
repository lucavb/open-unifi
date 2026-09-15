package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
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

// fakeBackend is an in-memory stand-in for the admin API. It implements:
//
//	GET/POST     /api/v1/devices
//	GET/DELETE   /api/v1/devices/{mac}
//	GET/PUT      /api/v1/wireless   (whole-document envelope)
//	GET          /api/v1/whoami
type fakeBackend struct {
	token    string            // required bearer token; "" means anonymous allowed
	devices  map[string]string // mac -> raw device JSON
	wireless string            // raw wireless envelope JSON
	lastAuth string            // observed Authorization header of the last request
}

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
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("bad token"))
				return
			}
			next(w, r)
		}
	}

	mux.HandleFunc("/api/v1/whoami", auth(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"server":"open-unifi","authConfigured":` + boolJSON(fb.token != "") + `}`))
	}))

	mux.HandleFunc("/api/v1/devices", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			vals := mapValuesSorted(fb.devices)
			_, _ = w.Write([]byte(`{"devices":[` + strings.Join(vals, ",") + `]}`))
		case http.MethodPost:
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mac := body["mac"]
			if mac == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if _, ok := fb.devices[mac]; ok {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte("device exists"))
				return
			}
			fb.devices[mac] = deviceJSON(mac, body["name"], "pending")
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/v1/devices/", auth(func(w http.ResponseWriter, r *http.Request) {
		mac := strings.TrimPrefix(r.URL.Path, "/api/v1/devices/")
		dev, ok := fb.devices[mac]
		switch r.Method {
		case http.MethodGet:
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("device not found"))
				return
			}
			_, _ = w.Write([]byte(dev))
		case http.MethodDelete:
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte("device not found"))
				return
			}
			delete(fb.devices, mac)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	mux.HandleFunc("/api/v1/wireless", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(fb.wireless))
		case http.MethodPut:
			var env struct {
				Wlans []map[string]any `json:"wlans"`
			}
			if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			buf, _ := json.Marshal(env)
			fb.wireless = string(buf)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	return mux
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

func deviceJSON(mac, name, state string) string {
	return `{"mac":"` + mac + `","name":"` + name + `","state":"` + state + `","ip":"192.168.1.50","firmware":"6.6.55","last_seen":"now"}`
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
	if dev.State != "pending" {
		t.Fatalf("expected pending device, got %+v", dev)
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

// TODO(morning): acceptance tests via terraform-plugin-framework's
// resource.TestCase scaffolding need the terraform CLI to spawn the
// provider; skipped tonight on purpose.
func TestAcceptanceStubbedOut(t *testing.T) {
	t.Skip("TODO(morning): acceptance tests (require terraform CLI)")
}

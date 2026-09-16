package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// apiClient is a tiny HTTP client for the open-unifi admin API
// (docs/PROTOCOL.md §6 "internal/adminapi (lane D)").
//
// Semantics:
//   - Base URL is stored with NO trailing slash; paths are joined with a
//     single "/" so callers pass paths that start with "/".
//   - When a token is configured, every request carries
//     "Authorization: Bearer <token>". Otherwise the request is anonymous
//     (the server allows that when it was started without --admin-token).
//   - Default timeout is 2 seconds per request.
//   - Retries: NONE for POST/PUT/DELETE. These are non-idempotent on this
//     server (PUT of the whole wireless envelope is an upsert, POST creates
//     devices). If you need reliability around them, use create-then-check
//     polling: issue the call once, then GET until the expected state shows
//     up. GET requests would be safe to retry, but for uniformity we retry
//     nothing here; the framework's Terraform plan/apply loop is the retry
//     mechanism.
type apiClient struct {
	baseURL string
	token   string
	http    *http.Client
}

// maxRespBodySize caps how many response-body bytes the client will read
// into memory (4 MB; responses are small JSON documents).
const maxRespBodySize = 4 << 20

// newAPIClient builds a client. url has trailing slashes trimmed. If
// insecureSkipVerify is true, TLS certificate verification is disabled
// (use only against development controllers).
func newAPIClient(url string, token string, insecureSkipVerify bool) *apiClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig.InsecureSkipVerify = insecureSkipVerify
	c := &apiClient{
		baseURL: strings.TrimRight(url, "/"),
		token:   token,
	}
	c.http = &http.Client{
		Timeout:   2 * time.Second,
		Transport: transport,
	}
	return c
}

// withHTTPClient replaces the internal HTTP client (test seam: lets unit
// tests inject a RoundTripper that never touches the network, which is
// required in sandboxed CI where loopback TCP is forbidden).
func (c *apiClient) withHTTPClient(hc *http.Client) *apiClient {
	c.http = hc
	return c
}

// do performs an HTTP request against the controller and decodes the JSON
// response body into out (if out is non-nil). It turns non-2xx statuses
// into errors via doErr.
func (c *apiClient) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Read at most 4 MB: a server is never expected to return more, and a
	// hostile/broken peer handing us an unbounded stream must not balloon
	// memory. A truncated oversized body fails later at JSON decode time.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBodySize))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return doErr(resp.StatusCode, respBody)
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// doErr converts a non-2xx HTTP response into a typed *apiError. When the
// body carries the server's canonical JSON error shape ({"error":"..."})
// that message is extracted for a clean diagnostic instead of embedding the
// raw body; plain-text bodies are passed through trimmed.
func doErr(status int, body []byte) error {
	a := &apiError{status: status, body: strings.TrimSpace(string(body))}
	a.message = a.body
	var jerr struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &jerr); err == nil && jerr.Error != "" {
		a.message = jerr.Error
	}
	return a
}

// apiError is the typed error for non-2xx API responses, so call sites can
// branch on status via errors.As instead of string matching.
type apiError struct {
	status  int    // HTTP status code
	body    string // raw response body
	message string // clean diagnostic: JSON "error" field when present, else trimmed body
}

func (e *apiError) Error() string {
	switch e.status {
	case http.StatusUnauthorized:
		// Line the message up with the server's anonymous-vs-token auth
		// model; the canonical body ("unauthorized") adds nothing.
		if e.message == "" || e.message == "unauthorized" {
			return "unauthorized: check token"
		}
		return "unauthorized: check token (" + e.message + ")"
	case http.StatusNotFound:
		if e.message == "" {
			return "not found"
		}
		return "not found: " + e.message
	default:
		if e.message != "" {
			return fmt.Sprintf("http %d: %s", e.status, e.message)
		}
		return fmt.Sprintf("http %d", e.status)
	}
}

// NotFound reports whether the error came from an HTTP 404 response.
func (e *apiError) NotFound() bool { return e.status == http.StatusNotFound }

// errNotFound reports whether err came from a 404 response.
func errNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.NotFound()
}

// device is the wire shape of /api/v1/devices objects
// (adminapi.DeviceView). The server encodes `state` as a JSON number
// (store.StatePending..StateLost) and `last_seen` as unix-seconds int64.
// site_id is request-only on device creation and never appears in a
// response body, so it is deliberately absent here.
type device struct {
	Mac      string `json:"mac"`
	Name     string `json:"name"`
	Model    string `json:"model,omitempty"`
	State    int    `json:"state"`
	IP       string `json:"ip,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	LastSeen int64  `json:"last_seen,omitempty"`
}

// stateNames maps the server's numeric device states (internal/store
// StatePending..StateLost, the raw UniFi inform vocabulary) to the
// Terraform provider's string vocabulary.
var stateNames = map[int]string{
	1: "pending",
	2: "adopting",
	3: "adopted",
	4: "lost",
}

// stateName renders a numeric server state as the TF schema vocabulary.
// Unknown numbers degrade to a readable "unknown(<n>)" placeholder instead
// of silently colliding with a known state.
func stateName(n int) string {
	if name, ok := stateNames[n]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", n)
}

// listDevices GETs /api/v1/devices. The endpoint may return either a bare
// JSON array or a {"devices":[...]} envelope depending on the server lane's
// final shape; both are accepted here so the provider does not churn when
// that lands.
func (c *apiClient) listDevices(ctx context.Context) ([]device, error) {
	var raw json.RawMessage
	if err := c.do(ctx, http.MethodGet, "/api/v1/devices", nil, &raw); err != nil {
		return nil, err
	}
	var devices []device
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &devices); err != nil {
			return nil, fmt.Errorf("decode device list: %w", err)
		}
		return devices, nil
	}
	var env struct {
		Devices []device `json:"devices"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode device envelope: %w", err)
	}
	return env.Devices, nil
}

// getDevice GETs /api/v1/devices/{mac}. The MAC is path-escaped here (the
// single place all GET-read MACs flow into a URL path) so an unvalidated
// state value cannot add path segments.
func (c *apiClient) getDevice(ctx context.Context, mac string) (*apDevice, error) {
	var dev apDevice
	if err := c.do(ctx, http.MethodGet, "/api/v1/devices/"+url.PathEscape(mac), nil, &dev); err != nil {
		return nil, err
	}
	return &dev, nil
}

// wirelessEntry is one wlan inside the /api/v1/wireless envelope.
type wirelessEntry struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name"`
	SSID       string `json:"ssid"`
	Security   string `json:"security"`
	Passphrase string `json:"passphrase,omitempty"`
	VLAN       int    `json:"vlan,omitempty"`
	Enabled    bool   `json:"enabled"`
}

// wirelessEnvelope is the WHOLE-document payload of /api/v1/wireless.
// The server upserts this document on PUT; all per-wlan operations build on
// read-modify-write of this envelope (single-source-of-truth strategy).
type wirelessEnvelope struct {
	Wlans []wirelessEntry `json:"wlans"`
}

// getWireless GETs the wireless envelope.
func (c *apiClient) getWireless(ctx context.Context) (*wirelessEnvelope, error) {
	var env wirelessEnvelope
	if err := c.do(ctx, http.MethodGet, "/api/v1/wireless", nil, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// putWireless PUTs the (whole) wireless envelope. No retry: a lost PUT can
// clobber a concurrent editor's changes if blindly replayed.
func (c *apiClient) putWireless(ctx context.Context, env *wirelessEnvelope) error {
	return c.do(ctx, http.MethodPut, "/api/v1/wireless", env, nil)
}

// whoami is a cheap health/auth probe: GET /api/v1/whoami. It always
// exists on an open-unifi admin API (any /api/v1 route), so it doubles as
// the provider's Configure-time connection check: a connection failure,
// auth rejection, or decode error surfaces here before any resource call.
func (c *apiClient) whoami(ctx context.Context) (authConfigured bool, err error) {
	var out struct {
		Server         string `json:"server"`
		Version        string `json:"version"`
		AuthConfigured bool   `json:"authConfigured"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/whoami", nil, &out); err != nil {
		return false, err
	}
	return out.AuthConfigured, nil
}

// checkConnectivity verifies the controller is reachable and speaking the
// admin API by probing GET /api/v1/whoami. It returns a ready-to-render
// error on any failure (connection, HTTP status — including a missing
// whoami route (404) — auth rejection, or protocol/decode error).
func (c *apiClient) checkConnectivity(ctx context.Context) error {
	_, err := c.whoami(ctx)
	return err
}

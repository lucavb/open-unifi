package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	respBody, err := io.ReadAll(resp.Body)
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

// doErr converts a non-2xx HTTP response into a Go error.
//
// 401 is rendered as "unauthorized: check token" so the message lines up
// with the server's anonymous-vs-token auth model.
func doErr(status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	switch status {
	case http.StatusUnauthorized:
		if msg != "" {
			return fmt.Errorf("unauthorized: check token (%s)", msg)
		}
		return fmt.Errorf("unauthorized: check token")
	case http.StatusNotFound:
		if msg != "" {
			return fmt.Errorf("not found: %s", msg)
		}
		return fmt.Errorf("not found")
	default:
		if msg != "" {
			return fmt.Errorf("http %d: %s", status, msg)
		}
		return fmt.Errorf("http %d", status)
	}
}

// errNotFound reports whether err came from a 404 response.
func errNotFound(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "not found:")
}

// device is the wire shape of /api/v1/devices objects.
type device struct {
	Mac      string `json:"mac"`
	Name     string `json:"name"`
	Model    string `json:"model,omitempty"`
	State    string `json:"state,omitempty"`
	IP       string `json:"ip,omitempty"`
	SiteID   string `json:"site_id,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	LastSeen string `json:"last_seen,omitempty"`
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

// getDevice GETs /api/v1/devices/{mac}.
func (c *apiClient) getDevice(ctx context.Context, mac string) (*apDevice, error) {
	var dev apDevice
	if err := c.do(ctx, http.MethodGet, "/api/v1/devices/"+mac, nil, &dev); err != nil {
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

// whoami is a cheap health/auth probe: GET /api/v1/whoami.
func (c *apiClient) whoami(ctx context.Context) (bool, error) {
	var out struct {
		Server         string `json:"server"`
		AuthConfigured bool   `json:"authConfigured"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/whoami", nil, &out); err != nil {
		return false, err
	}
	return out.AuthConfigured, nil
}

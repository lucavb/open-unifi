package adminapi

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrNotFound is the sentinel backend error mapped to HTTP 404. External
// Backend implementations should return it (possibly wrapped — the mapping
// uses errors.Is) wherever a referenced device/MAC does not exist.
var ErrNotFound = errors.New("device not found")

// ---- response helpers ---------------------------------------------------

// writeErr emits the canonical JSON error shape: {"error":"..."}.
func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeJSON emits a JSON body with the given status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// readJSON decodes a request body strictly (no unknown-field tolerance would
// be gratuitous strictness here; we simply require well-formed JSON).
func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

type devicesEnvelope struct {
	Devices []DeviceView `json:"devices"`
}

type pendingEnvelope struct {
	Pending []PendingView `json:"pending"`
}

type whoAmI struct {
	Server         string `json:"server"`
	Version        string `json:"version"`
	AuthConfigured bool   `json:"authConfigured"`
}

// ---- auth middleware -----------------------------------------------------

// requireToken enforces Bearer-token auth when the token is configured.
// GET requests are NOT exempt — every /api route requires the token
// (only /healthz and / are open).
func requireToken(cfg DegenerateConfig, next http.HandlerFunc) http.HandlerFunc {
	if cfg.AdminToken == "" {
		return next
	}
	want := []byte("Bearer " + cfg.AdminToken)
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="open-unifi"`)
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// ---- MAC normalization ---------------------------------------------------

// normalizeMAC accepts common MAC spellings — colon/hyphen/dot/space
// separated, or bare "aabbccddeeff" — and returns canonical
// lowercase colon-hex ("aa:bb:cc:dd:ee:ff"). Garbage is rejected.
func normalizeMAC(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty")
	}
	// Strip common separators; dots come in pairs (aabb.ccdd.eeff).
	replaced := strings.NewReplacer(":", "", "-", "", " ", "", ".", "").Replace(s)
	if len(replaced) != 12 {
		return "", fmt.Errorf("want 12 hex chars, got %d", len(replaced))
	}
	raw, err := hex.DecodeString(strings.ToLower(replaced))
	if err != nil {
		return "", errors.New("not hexadecimal")
	}
	const nibble = 2 // hex chars per byte: shapes the colon-hex output loop
	out := make([]byte, 0, len(raw)*3-nibble)
	for i, b := range raw {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexDigit(b>>4), hexDigit(b&0x0f))
	}
	return string(out), nil
}

func hexDigit(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'a' + v - 10
}

// ---- wireless config validation -----------------------------------------

// validSecurities is the allowed Security enum for a Wlan.
var validSecurities = map[string]bool{
	"open":    true,
	"wpa-p":   true,
	"wpa-eap": true,
}

// validateWlan enforces server-side rules; the web console mirrors them.
// Returns "" when valid, or a short human message for the 400 body.
func validateWlan(wl *Wlan) string {
	if !validSecurities[wl.Security] {
		return "security must be one of open, wpa-p, wpa-eap"
	}
	if n := len(wl.SSID); n < 1 || n > 32 {
		return "ssid length must be 1..32"
	}
	if wl.VLAN < 1 || wl.VLAN > 4094 {
		return "vlan must be 1..4094"
	}
	if wl.Security == "open" {
		if wl.Passphrase != "" {
			return "passphrase must be empty when security is open"
		}
		return ""
	}
	if len(wl.Passphrase) < 8 {
		return "passphrase must be at least 8 characters when security is " + wl.Security
	}
	return ""
}

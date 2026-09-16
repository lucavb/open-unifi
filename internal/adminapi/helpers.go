package adminapi

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// readJSON decodes a request body strictly: JSON well-formedness, a
// bounded size, NO unknown fields (typo'd or tampered clients must not
// silently drop inputs — fail loud), and NO trailing data after the top
// level value (trailing bytes are never accidental).
func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Exactly one value must remain: a second decode must hit clean EOF.
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected trailing data after JSON value: %w", err)
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
func requireToken(cfg Config, next http.HandlerFunc) http.HandlerFunc {
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

// validSecurities is the allowed Security enum for a Wlan. wpa-eap is
// deliberately ABSENT: see ValidateWlan.
var validSecurities = map[string]bool{
	"open":  true,
	"wpa-p": true,
}

// ValidateWlan is the exported form of validateWlan: the SAME server-side
// rules apply at the admin API boundary AND at wireless.json load time
// (internal/app refuses startup with a precisely-named per-wlan error), so
// a document can never exist on disk that the API would reject. Returns ""
// when valid, else a short human message.
func ValidateWlan(wl *Wlan) string { return validateWlan(wl) }

// validateWlan enforces server-side rules. The web console mirrors the
// length/security rules client-side (see static/index.html validateWlan);
// the control-character and ID-charset checks are deliberately
// server-side-only defense-in-depth: control chars in SSID/Name/Passphrase
// (or separators in an ID) could inject extra system_cfg rows at emission
// time even if a client bypasses the console. Returns "" when valid, or a
// short human message for the 400 body.
//
// Bytecode evidence for the wpa-eap rejection (decompiled ace.jar, ground
// truth): com/ubnt/service/config/int only emits FUNCTIONAL EAP vaps when
// WlanConf.requireRadiusProfile() is backed by a valid radiusprofile_id
// lookup (tmpwork/javap/com__ubnt__service__config__int.txt:13492+) — and
// its invalid-profile warn path still emits the same non-functional config
// we would have been emitting (no radius servers → dead vaps on devices).
// open-unifi has no RADIUS support, so any wpa-eap we accept would ship a
// dead vap configuration to hardware. Fail loud instead.
func validateWlan(wl *Wlan) string {
	if wl.Security == "wpa-eap" {
		return "wpa-eap requires RADIUS profiles, which open-unifi does not support"
	}
	if !validSecurities[wl.Security] {
		return "security must be one of open, wpa-p"
	}
	if hasControlChar(wl.SSID) {
		return "ssid must not contain control characters"
	}
	if hasControlChar(wl.Name) {
		return "name must not contain control characters"
	}
	if hasControlChar(wl.Passphrase) {
		return "passphrase must not contain control characters"
	}
	// Name gets the same 64-byte cap as the supplied ID: both land in
	// system_cfg rows where length inflation is never legitimate.
	if n := len(wl.Name); n > 64 {
		return "name must be at most 64 characters"
	}
	if err := validateWlanID(wl.ID); err != "" {
		return err
	}
	if n := len(wl.SSID); n < 1 || n > 32 {
		return "ssid length must be 1..32"
	}
	if wl.VLAN < 1 || wl.VLAN > 4094 {
		// Rejecting here closes the "silently wraps to untagged/garbage"
		// hole downstream (the emission path's VLAN guard maps off-range
		// vids to 0/1); out-of-range VLANs can never reach it anymore.
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

// hasControlChar reports any character below 0x20 (includes \n and \r — the
// newline IS the system_cfg row separator, so a \n inside an emitted value
// would inject a forged row) or 0x7F (DEL).
func hasControlChar(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7F {
			return true
		}
	}
	return false
}

// validateWlanID checks the wlans[].id field when the client supplies one.
// Empty ID is fine (server derives sha256(nameSSID)[:24]); a supplied ID
// lands verbatim in WlanConf/WirelessConf `id` rows, so it must be a safe
// token: visible printable ASCII minus value separators (no whitespace, no
// = , ; " '), max 64 chars. Hex-style IDs like "wlan-1" pass.
func validateWlanID(id string) string {
	if id == "" {
		return ""
	}
	if len(id) > 64 {
		return "id must be at most 64 characters"
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c <= 0x20 || c > 0x7E { // 0x7F included by c > 0x7E
			return "id may only contain visible printable ASCII (no spaces or separators)"
		}
		switch c {
		case '=', ',', ';', '"', '\'':
			return "id must not contain = , ; or quote characters"
		}
	}
	return ""
}

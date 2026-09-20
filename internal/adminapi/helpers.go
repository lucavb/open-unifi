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
var ErrConflict = errors.New("conflict")

// ErrSetInformPushFailed is the sentinel backend error mapped to HTTP 502:
// the console Adopt action's set-inform push (the delivery lane for
// never-informed factory pending candidates, docs/PROTOCOL-mgmt.md §7)
// failed after the whitelist promotion was already committed. The
// promotion stands — the operator can simply click Adopt again.
var ErrSetInformPushFailed = errors.New("set-inform push failed")

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
	defer func() { _ = r.Body.Close() }()
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

type radiosEnvelope struct {
	Radios []RadioView `json:"radios"`
}

type pendingEnvelope struct {
	Pending []PendingView `json:"pending"`
}

// clientsEnvelope wraps the device-clients listing; Clients is never nil
// so the JSON is always a list, never null.
type clientsEnvelope struct {
	Clients []ClientView `json:"clients"`
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

// validSecurities is the allowed Security enum for a Wlan.
var validSecurities = map[string]bool{
	"open":    true,
	"wpa-p":   true,
	"wpa-eap": true,
}

// ValidateWlan is the exported form of validateWlan: the SAME server-side
// rules apply at the admin API boundary AND at wireless.json load time
// (internal/app refuses startup with a precisely-named per-wlan error), so
// a document can never exist on disk that the API would reject. Returns ""
// when valid, else a short human message.
func ValidateWlan(wl *Wlan) string { return validateWlan(wl) }

func ValidateWlanName(name string) string {
	if name == "" || len(name) > 64 {
		return "name must be 1..64 characters"
	}
	if hasControlChar(name) {
		return "name must not contain control characters"
	}
	return ""
}

// ValidateDeviceName enforces the same defense-in-depth rules as WLAN
// names for device names: control characters rejected (a \n is the
// system_cfg row separator, so a \n inside a device name could inject a
// forged row) and a 64-byte cap matching the WLAN name cap. Empty is
// ALLOWED here — DeviceUpsert treats "" as "leave unset" and DevicePatch's
// nil-vs-empty pointer semantics treat "" as a documented explicit clear —
// so the callers skip validation for empty values; only non-empty names
// carry injection risk. Returns "" when valid, else a short human message
// for the 400/409 body.
func ValidateDeviceName(name string) string {
	if name == "" {
		return ""
	}
	if len(name) > 64 {
		return "name must be at most 64 characters"
	}
	if hasControlChar(name) {
		return "name must not contain control characters"
	}
	return ""
}

func ValidateSiteID(id string) string {
	if len(id) < 1 || len(id) > 64 {
		return "site_id must be 1..64 characters"
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		valid := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
		first := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		if valid && (i != 0 || first) {
			continue
		}
		return "invalid site_id"
	}
	return ""
}

// ValidateLEDOverride enforces the per-device LED override enum. The classic
// controller's device record field is device.getString("led_override",
// "default") (docs/PROTOCOL-mgmt.md §2, config/B writer) — exactly these
// three strings; anything else would never round-trip through the §2
// led_enabled computation. "default" is the explicit clear (the record
// stores ""; an omitted patch field means "leave unchanged" instead).
// Returns "" when valid, else a short human message for the 400 body.
func ValidateLEDOverride(v string) string {
	switch v {
	case "default", "on", "off":
		return ""
	}
	return "led_override must be one of default, on, off"
}

// ValidateLEDOverrideColorBrightness enforces the ledbar brightness
// knob's 0..100 domain. The classic controller's §12 render reads
// device.getInt("led_override_color_brightness", 100) and scales it by
// the truncating (255*b)/100 (config_String.txt:2627-2640); the admin API
// keeps the knob's contract explicit instead of letting out-of-domain
// values ride to a render that was never cited for them. 0 is a VALID
// explicit choice (LED bar dark); 100 is the jar default (and the
// record's explicit-clear value). Returns "" when valid, else a short
// human message for the 400 body.
func ValidateLEDOverrideColorBrightness(v int) string {
	if v < 0 || v > 100 {
		return "led_override_color_brightness must be 0..100"
	}
	return ""
}

// ValidateRadioName enforces the path radio name for the per-radio intent
// routes: 1..64 characters, no control characters. The name is a LOOKUP
// KEY against the device-reported radio_table names (never emitted into
// system_cfg), so the injection surface is nil — the bounds are hygiene.
// The backend's not-found mapping answers unknown names with 404.
func ValidateRadioName(name string) string {
	if name == "" {
		return "empty"
	}
	if len(name) > 64 {
		return "must be at most 64 characters"
	}
	if hasControlChar(name) {
		return "must not contain control characters"
	}
	return ""
}

// maxCmdRunes caps the §6.3 stored-task cmd string. The jar's real cmds
// are short identifiers ("restart", "clear-all-dpi-counters", …); 64 runes
// bounds the replayed response payload while leaving generous headroom.
const maxCmdRunes = 64

// ValidateCmdString enforces the cmd string of a §6.3 stored-task
// enqueue (docs/PROTOCOL-mgmt.md §6.3): non-empty, at most 64 runes, no
// control characters, and no leading/trailing whitespace. §6.3 is silent
// on cmd validation (the classic UI only queued fixed cmd values, and the
// passthrough replays the stored row verbatim), so this is the boundary
// shape open-unifi chose: the shortest gate that keeps the replayed
// payload well-formed. It deliberately does NOT whitelist cmd names —
// the §6.3 built-in list is explicitly "implemented NOT as tasks", so no
// task-queue membership can be cited, and an invented whitelist would be
// drift. Rejected values 400 at the route; the stored value is replayed
// EXACTLY as validated (no silent trimming). Returns "" when valid, else
// a short human message for the 400 body.
func ValidateCmdString(cmd string) string {
	if cmd == "" {
		return "cmd is required"
	}
	if len([]rune(cmd)) > maxCmdRunes {
		return "cmd must be at most 64 characters"
	}
	if cmd != strings.TrimSpace(cmd) {
		return "cmd must not begin or end with whitespace"
	}
	if hasControlChar(cmd) {
		return "cmd must not contain control characters"
	}
	return ""
}

// validateWlan enforces server-side rules. The web console mirrors the
// length/security rules client-side (see static/index.html validateWlan);
// the control-character and ID-charset checks are deliberately
// server-side-only defense-in-depth: control chars in SSID/Name/Passphrase
// (or separators in an ID) could inject extra system_cfg rows at emission
// time even if a client bypasses the console. Returns "" when valid, or a
// short human message for the 400 body.
//
// WPA-EAP acceptance (decompiled ace.jar, ground truth): the reference
// controller emits FUNCTIONAL EAP vaps only when
// WlanConf.requireRadiusProfile() is backed by a valid radiusprofile_id
// lookup (tmpwork/javap/com__ubnt__service__config__int.txt:13492+); its
// invalid-profile warn path still emits a non-functional config (no radius
// servers → dead vaps on devices). open-unifi now models the profile
// inline on the Wlan (radius_servers/radius_secret, doc §4.3): wpa-eap is
// accepted ONLY with a usable profile (≥1 auth server + shared secret),
// which the renderer emits as the aaa.<n>.radius.auth.<i>.* rows.
func validateWlan(wl *Wlan) string {
	if wl.Band != "" && wl.Band != "2g" && wl.Band != "5g" && wl.Band != "both" {
		return "band must be one of 2g, 5g, both"
	}
	if !validSecurities[wl.Security] {
		return "security must be one of open, wpa-p, wpa-eap"
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
		if wl.hasRadiusFields() {
			return "radius_servers/radius_secret/radius_vlan_mode require security wpa-eap"
		}
		if wl.hasAcctFields() {
			return "accounting_enabled/acct_servers/interim_update_enabled/radius_das_enabled require security wpa-eap"
		}
		if wl.Passphrase != "" {
			return "passphrase must be empty when security is open"
		}
		return ""
	}
	if wl.Security == "wpa-eap" {
		return validateWlanEap(wl)
	}
	// wpa-p: radius fields are EAP-only; a non-EAP row carrying them is a
	// client bug the renderer would silently drop — fail loud instead.
	if wl.hasRadiusFields() {
		return "radius_servers/radius_secret/radius_vlan_mode require security wpa-eap"
	}
	if wl.hasAcctFields() {
		return "accounting_enabled/acct_servers/interim_update_enabled/radius_das_enabled require security wpa-eap"
	}
	if len(wl.Passphrase) < 8 {
		return "passphrase must be at least 8 characters when security is " + wl.Security
	}
	return ""
}

// hasRadiusFields reports whether any inline RADIUS profile field is set.
func (wl *Wlan) hasRadiusFields() bool {
	return len(wl.RadiusServers) > 0 || wl.RadiusSecret != "" || wl.RadiusVLANMode != ""
}

// hasAcctFields reports whether any inline RADIUS profile accounting
// field is set (§12 rows 1013-1014).
func (wl *Wlan) hasAcctFields() bool {
	return wl.AccountingEnabled || len(wl.AcctServers) > 0 || wl.InterimUpdateEnabled || wl.RadiusDASEnabled
}

// validateWlanEap enforces the wpa-eap-only rules: a usable inline RADIUS
// profile (the requireRadiusProfile gate) and the optional-passphrase
// relaxation (the jar still emits wpa.psk on the EAP branch via the same
// getWpaPreSharedKey() fallback, so an explicitly supplied passphrase keeps
// the wpa-p >= 8 rule; an absent one falls back at emission).
func validateWlanEap(wl *Wlan) string {
	if len(wl.RadiusServers) == 0 {
		return "wpa-eap requires at least one RADIUS server (radius_servers)"
	}
	if len(wl.RadiusServers) > 4 {
		// The system_cfg writer has exactly four auth slots (radius.auth.1..4,
		// int §791-840); a 5th server could never reach the device.
		return "radius_servers supports at most 4 entries"
	}
	for i, srv := range wl.RadiusServers {
		if srv.IP == "" {
			return fmt.Sprintf("radius_servers[%d].ip must not be empty", i)
		}
		if hasControlChar(srv.IP) {
			return fmt.Sprintf("radius_servers[%d].ip must not contain control characters", i)
		}
		if srv.Port < 0 || srv.Port > 65535 {
			return fmt.Sprintf("radius_servers[%d].port must be 1..65535 (0 = the 1812 default)", i)
		}
	}
	if wl.RadiusSecret == "" {
		return "wpa-eap requires a RADIUS shared secret (radius_secret)"
	}
	if hasControlChar(wl.RadiusSecret) {
		return "radius_secret must not contain control characters"
	}
	switch wl.RadiusVLANMode {
	case "", "disabled", "optional", "required":
		// "" and "disabled" are the same knob (vlan_wlan_mode jar default);
		// both emit dynamic_vlan=0.
	default:
		return "radius_vlan_mode must be one of disabled, optional, required"
	}
	// Accounting fields (§12 rows 1013-1014). acct_servers mirror the
	// auth-server rules exactly — ≤4 entries (the system_cfg writer's
	// slot count, mirrored from the auth writer's radius.acct.1..4
	// slots), non-empty IP, no control characters, port 0..65535 with
	// 0 meaning the 1813 emission default. acct_servers may be stored
	// with accounting_enabled false: the radiusprofile shape keeps the
	// server list and the toggle independent, and the inert list
	// renders byte-identically to none (pinned by the renderer goldens).
	if len(wl.AcctServers) > 4 {
		return "acct_servers supports at most 4 entries"
	}
	for i, srv := range wl.AcctServers {
		if srv.IP == "" {
			return fmt.Sprintf("acct_servers[%d].ip must not be empty", i)
		}
		if hasControlChar(srv.IP) {
			return fmt.Sprintf("acct_servers[%d].ip must not contain control characters", i)
		}
		if srv.Port < 0 || srv.Port > 65535 {
			return fmt.Sprintf("acct_servers[%d].port must be 1..65535 (0 = the 1813 default)", i)
		}
	}
	// interim_update_enabled needs accounting_enabled: the jar's own
	// gates make the interim rows unreachable without accounting
	// (§12 row 1014 rationale), so a stored interim toggle without
	// accounting would be admin intent the renderer can never honor.
	if wl.InterimUpdateEnabled && !wl.AccountingEnabled {
		return "interim_update_enabled requires accounting_enabled"
	}
	// radius_das_enabled needs accounting_enabled: every das/dad row
	// lives under the jar's accounting_enabled gate (int offsets 176-184),
	// so a stored das toggle without accounting would be admin intent the
	// renderer can never honor. The client rows' <ip> source is recovered
	// (the acct server beans' ip fields — §12 row 1014 implemented), so
	// the knob is accepted behind this gate.
	if wl.RadiusDASEnabled && !wl.AccountingEnabled {
		return "radius_das_enabled requires accounting_enabled"
	}
	if wl.Passphrase != "" && len(wl.Passphrase) < 8 {
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

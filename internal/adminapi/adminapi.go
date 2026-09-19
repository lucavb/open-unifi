// Package adminapi provides the human-facing admin HTTP API of open-unifi:
// JSON REST endpoints under /api/v1, the embedded single-page web console
// at /, and a plain /healthz probe.
//
// adminapi defines the Backend CONTRACT in this file; the server/store lane
// implements it at wire-up time. adminapi deliberately does NOT import
// internal/store (that contract evolves in a parallel lane).
package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lucavb/open-unifi/internal/metrics"
)

// Config is the minimal wiring input for New.
type Config struct {
	// AdminToken: when non-empty, ALL /api requests (GET included) AND
	// /metrics must carry "Authorization: Bearer <token>"; only /healthz and
	// / (web console) stay open.
	// Empty string disables authentication entirely.
	AdminToken string

	// Logger receives server-side diagnostics for events that are
	// deliberately NOT echoed to the client (opaque 500 bodies — see
	// handleBackendErr). Optional: nil ⇒ slog.Default(), so callers that
	// construct Config{} unchanged keep compiling.
	Logger *slog.Logger
}

// DeviceView is the read model for one managed device.
// Actions mirrors what this device/record currently allows (e.g. "delete").
type DeviceView struct {
	MAC      string `json:"mac"`
	Name     string `json:"name,omitempty"`
	Model    string `json:"model,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	IP       string `json:"ip,omitempty"`
	State    int    `json:"state"`
	LastSeen int64  `json:"last_seen,omitempty"`
	// CfgVersion is the desired configuration version last sent by the
	// controller. It is omitted when the store has no desired version.
	CfgVersion string `json:"cfg_version,omitempty"`
	// AppliedCfg is the configuration version last reported by the device.
	// It is omitted when the device has not reported one.
	AppliedCfg string `json:"applied_cfg,omitempty"`
	// InSync reports runtime WLAN delivery, not cfgversion echo equality. It
	// is true only after the latest vap_table shows every enabled desired
	// SSID RUNNING (SSID-presence check). It does NOT verify per-radio
	// placement or that deleted WLANs have disappeared — that strict check
	// lives in the server lane's settlePendingWLAN, which runs before this
	// view is served on every inform. nil means runtime evidence is absent.
	InSync *bool `json:"in_sync,omitempty"`
	// WLAN delivery is controller-side bookkeeping. It is independent of
	// cfgversion, which is not proof that the AP applied system_cfg.
	WLANDeliveryStatus string `json:"wlan_delivery_status,omitempty"`
	WLANDeliveryCount  int    `json:"wlan_delivery_count,omitempty"`
	WLANLastAttempt    int64  `json:"wlan_last_attempt,omitempty"`
	SiteID             string `json:"site_id,omitempty"`
	// PendingCommand is the read-only armed remote-command state: "reboot"
	// when the armed §6.5 reboot flag is set, "factory-reset" when the armed
	// §6.6 setdefault flag is set (outranking reboot, matching the engine's
	// emission precedence), "" (omitted) when no command is armed. The
	// engine consumes the flag one-shot on the device's next inform; the
	// value returning to "" is the operator's consumed/done signal.
	PendingCommand string   `json:"pending_command,omitempty"`
	Actions        []string `json:"actions,omitempty"`
}

// DevicePatch contains the mutable administrative device fields. Pointers
// distinguish an omitted field from an explicit clear.
type DevicePatch struct {
	Name   *string `json:"name,omitempty"`
	SiteID *string `json:"site_id,omitempty"`
}

// DeviceUpsert is the request body for manual device registration ("adopt
// whitelist"); the backend records it in state PENDING.
type DeviceUpsert struct {
	MAC    string `json:"mac"`
	Name   string `json:"name,omitempty"`
	SiteID string `json:"site_id,omitempty"`
}

// PendingView is a discovery-beacon candidate waiting for adoption.
type PendingView struct {
	MAC    string `json:"mac"`
	Source string `json:"source,omitempty"`
}

// Wlan is one wireless network entry in the whole-doc wireless config.
type Wlan struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	SSID       string `json:"ssid"`
	Security   string `json:"security"` // "open" | "wpa-p" | "wpa-eap"
	Passphrase string `json:"passphrase,omitempty"`
	VLAN       int    `json:"vlan"`
	Enabled    bool   `json:"enabled"`
	Band       string `json:"band,omitempty"`
}

// WlansEnvelope is the whole-document wireless config. PUT replaces it
// wholesale (terraform-reconcilable); future refinements may apply subsets.
type WlansEnvelope struct {
	Wlans []Wlan `json:"wlans"`
}

// Backend is the storage/service contract implemented by the server lane.
type Backend interface {
	ListDevices(ctx context.Context) []DeviceView
	GetDevice(ctx context.Context, mac string) (DeviceView, error)
	PatchDevice(ctx context.Context, mac string, patch DevicePatch) (DeviceView, error)
	// CreateDevice registers a device manually (state PENDING = adopt whitelist).
	CreateDevice(ctx context.Context, up DeviceUpsert) (DeviceView, error)
	DeleteDevice(ctx context.Context, mac string) error
	// ListPending returns discovery-beacon candidates.
	ListPending(ctx context.Context) []PendingView
	// AdoptPending attempts adoption of a pending candidate.
	//
	// Wire contract: on success the response DeviceView carries
	// State 1 (pending) — adoption here only puts the MAC on the inform
	// adopt whitelist; the native PENDING state is what the device record
	// holds until the inform handshake completes.
	AdoptPending(ctx context.Context, mac string) (DeviceView, error)
	// RebootDevice arms the remote reboot (docs/PROTOCOL-mgmt.md §6.5):
	// the device's NEXT decoded inform answers
	// {"_type":"reboot","reboot_type":"soft"} and the arming is consumed.
	// Arming is idempotent and one-shot; it leaves the record's state,
	// per-device key and cfgversion untouched (no §6.2 mint site exists
	// for the reboot response). Unknown MACs are a wrapped ErrNotFound.
	RebootDevice(ctx context.Context, mac string) (DeviceView, error)
	// FactoryResetDevice arms the factory reset
	// (docs/PROTOCOL-mgmt.md §6.6): the device's NEXT decoded inform
	// answers {"_type":"setdefault"}, then the record returns to a
	// pending-candidate shape — the device factory-resets, re-informs on
	// the factory default key, and is re-adopted by the existing
	// adoption flow. Like RebootDevice, arming changes only the flag.
	FactoryResetDevice(ctx context.Context, mac string) (DeviceView, error)
	// GetWireless returns the whole wireless config document.
	GetWireless(ctx context.Context) WlansEnvelope
	// PutWireless replaces the whole wireless config document.
	PutWireless(ctx context.Context, env WlansEnvelope) error
	CreateWlan(ctx context.Context, wlan Wlan) (Wlan, error)
	GetWlan(ctx context.Context, name string) (Wlan, error)
	UpdateWlan(ctx context.Context, name string, wlan Wlan) (Wlan, error)
	DeleteWlan(ctx context.Context, name string) error
}

// version reports the module version for /api/v1/whoami.
const version = "0.1.0-dev"

// ---- Low-cardinality metrics route labels ------------------------------

const (
	routeDevicesList        = "/api/v1/devices"
	routeDeviceItem         = "/api/v1/devices/{mac}"
	routeDeviceReboot       = "/api/v1/devices/{mac}/reboot"
	routeDeviceFactoryReset = "/api/v1/devices/{mac}/factory-reset"
	routePendingList        = "/api/v1/pending"
	routePendingAdopt       = "/api/v1/pending/{mac}/adopt"
	routeWireless           = "/api/v1/wireless"
	routeWhoAmI             = "/api/v1/whoami"
	routeOther              = "/api/other"
	apiPrefix               = "/api/"
)

// classifyRoute turns the ServeMux pattern into a bounded-cardinality
// metrics label. Method-based mux patterns already include the method
// (e.g. "GET /api/v1/devices/{mac}"), so no extra prefixing is needed.
func classifyRoute(method, pattern, path string) string {
	if pattern != "" {
		return pattern
	}
	if strings.HasPrefix(path, apiPrefix) {
		return method + " " + routeOther
	}
	return ""
}

// New returns the root HTTP handler for the admin API.
func New(cfg Config, be Backend) http.Handler {
	// Logger is optional: nil ⇒ process default (callers constructing
	// Config{} keep working).
	lg := cfg.Logger
	if lg == nil {
		lg = slog.Default()
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/devices", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, devicesEnvelope{be.ListDevices(r.Context())})
	}))
	mux.HandleFunc("POST /api/v1/devices", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		var up DeviceUpsert
		if err := readJSON(r, &up); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		mac, err := normalizeMAC(up.MAC)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid mac: "+err.Error())
			return
		}
		up.MAC = mac
		if up.Name != "" {
			if msg := ValidateDeviceName(up.Name); msg != "" {
				writeErr(w, http.StatusBadRequest, msg)
				return
			}
		}
		dv, err := be.CreateDevice(r.Context(), up)
		if err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusCreated, dv)
	}))
	mux.HandleFunc("GET /api/v1/devices/{mac}", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		mac, err := normalizeMAC(r.PathValue("mac"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid mac: "+err.Error())
			return
		}
		dv, err := be.GetDevice(r.Context(), mac)
		if err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, dv)
	}))
	mux.HandleFunc("PATCH /api/v1/devices/{mac}", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		mac, err := normalizeMAC(r.PathValue("mac"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid mac: "+err.Error())
			return
		}
		var patch DevicePatch
		if err := readJSON(r, &patch); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if patch.SiteID != nil {
			if msg := ValidateSiteID(*patch.SiteID); msg != "" {
				writeErr(w, http.StatusBadRequest, msg)
				return
			}
		}
		if patch.Name != nil {
			if msg := ValidateDeviceName(*patch.Name); msg != "" {
				writeErr(w, http.StatusBadRequest, msg)
				return
			}
		}
		dv, err := be.PatchDevice(r.Context(), mac, patch)
		if err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, dv)
	}))
	mux.HandleFunc("DELETE /api/v1/devices/{mac}", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		mac, err := normalizeMAC(r.PathValue("mac"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid mac: "+err.Error())
			return
		}
		if err := be.DeleteDevice(r.Context(), mac); err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "mac": mac})
	}))
	// Remote lifecycle commands (§6.5/§6.6): both only ARM the record —
	// the response the device sees rides its next inform, not this HTTP
	// reply. The 200 body is the (unchanged) device view.
	mux.HandleFunc("POST /api/v1/devices/{mac}/reboot", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		mac, err := normalizeMAC(r.PathValue("mac"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid mac: "+err.Error())
			return
		}
		dv, err := be.RebootDevice(r.Context(), mac)
		if err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, dv)
	}))
	mux.HandleFunc("POST /api/v1/devices/{mac}/factory-reset", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		mac, err := normalizeMAC(r.PathValue("mac"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid mac: "+err.Error())
			return
		}
		dv, err := be.FactoryResetDevice(r.Context(), mac)
		if err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, dv)
	}))
	mux.HandleFunc("GET /api/v1/pending", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, pendingEnvelope{be.ListPending(r.Context())})
	}))
	mux.HandleFunc("POST /api/v1/pending/{mac}/adopt", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		mac, err := normalizeMAC(r.PathValue("mac"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid mac: "+err.Error())
			return
		}
		dv, err := be.AdoptPending(r.Context(), mac)
		if err != nil {
			// Metric semantics (DECIDED): openunifi_adopt_total and
			// openunifi_adopt_fail_total count state transitions observed
			// by the app poller ONLY (see internal/metrics and
			// internal/app PollOnce). This endpoint deliberately bumps
			// NEITHER: an endpoint-driven count would double-count real
			// transitions (the poller sees the same adopting→...→adopted
			// state changes moments later) and would let API error churn
			// masquerade as adoption outcomes. A "device not found" 404 is
			// a caller error (bad MAC, stale pending list), never an
			// adoption failure; a genuine backend 500 is logged and
			// returned, not counter-bumped.
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, dv)
	}))
	mux.HandleFunc("GET /api/v1/wireless", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, be.GetWireless(r.Context()))
	}))
	mux.HandleFunc("PUT /api/v1/wireless", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		var env WlansEnvelope
		if err := readJSON(r, &env); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		// Backend performs the authoritative duplicate/ID checks.
		for i := range env.Wlans {
			if msg := ValidateWlan(&env.Wlans[i]); msg != "" {
				writeErr(w, http.StatusBadRequest, "wlan["+strconv.Itoa(i)+"]: "+msg)
				return
			}
		}
		if err := be.PutWireless(r.Context(), env); err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, env)
	}))
	mux.HandleFunc("POST /api/v1/wireless", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		var wlan Wlan
		if err := readJSON(r, &wlan); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if msg := ValidateWlanName(wlan.Name); msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		if msg := ValidateWlan(&wlan); msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		out, err := be.CreateWlan(r.Context(), wlan)
		if err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	}))
	mux.HandleFunc("GET /api/v1/wireless/{name}", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if msg := ValidateWlanName(name); msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		out, err := be.GetWlan(r.Context(), name)
		if err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("PUT /api/v1/wireless/{name}", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if msg := ValidateWlanName(name); msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		var wlan Wlan
		if err := readJSON(r, &wlan); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if wlan.Name != "" && wlan.Name != name {
			writeErr(w, http.StatusBadRequest, "name must match path")
			return
		}
		wlan.Name = name
		if msg := ValidateWlan(&wlan); msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		out, err := be.UpdateWlan(r.Context(), name, wlan)
		if err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("DELETE /api/v1/wireless/{name}", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if msg := ValidateWlanName(name); msg != "" {
			writeErr(w, http.StatusBadRequest, msg)
			return
		}
		if err := be.DeleteWlan(r.Context(), name); err != nil {
			handleBackendErr(w, lg, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "name": name})
	}))
	mux.HandleFunc("GET /api/v1/whoami", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, whoAmI{
			Server:         "open-unifi",
			Version:        version,
			AuthConfigured: cfg.AdminToken != "",
		})
	}))

	// /metrics sits BEHIND the token when one is configured: the exposition
	// enumerates every tracked device by MAC, which is exactly the
	// reconnaissance data a MAC-spoofing attacker wants (unexpected 200 with
	// no credentials would leak the whole inventory). /healthz and /
	// (web console) remain the only open paths.
	mux.Handle("GET /metrics", requireToken(cfg, metrics.Handler().ServeHTTP))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Root: embedded single-file web console. Any non-API path falls here
	// too (unknown /api/* paths below yield JSON 404 first).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			writeErr(w, http.StatusNotFound, "no such endpoint")
			return
		}
		page(w, r)
	})

	// Instrument every response: pattern-based route label keeps MACs out
	// of the label space. The completion log rides the request context, so
	// the wrapped logger injects trace_id/span_id when tracing is on.
	// /metrics and /healthz are skipped (scrape noise).
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		mux.ServeHTTP(sw, r)
		if route := classifyRoute(r.Method, r.Pattern, r.URL.Path); route != "" {
			metrics.ObserveAPIRequest(sw.code, route)
		}
		if r.URL.Path != "/metrics" && r.URL.Path != "/healthz" {
			lg.InfoContext(r.Context(), "admin: request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.code,
				"duration_ms", float64(time.Since(start).Microseconds())/1000,
			)
		}
	})
}

// handleBackendErr maps well-known backend errors to response codes:
// any error satisfying errors.Is(err, ErrNotFound) — the bare sentinel or a
// wrapped one — becomes 404. The 404 body carries err.Error() because those
// messages are user-facing MAC context ("device not found: aa:bb:…") and
// harmless. Everything else becomes an OPAQUE 500: the body is a fixed
// string, never err.Error(), and the full error is logged server-side via
// lg instead — internal messages can contain paths, addresses and store
// internals and must not be serialized into an HTTP response.
func handleBackendErr(w http.ResponseWriter, lg *slog.Logger, err error) {
	if errors.Is(err, ErrConflict) {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	lg.Error("admin api backend error", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// statusWriter captures the response code for instrumentation.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

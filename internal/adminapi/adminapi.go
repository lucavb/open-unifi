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
	"net/http"
	"strconv"
	"strings"

	"github.com/lucabecker/open-unifi/internal/metrics"
)

// DegenerateConfig is the minimal wiring input for New.
type DegenerateConfig struct {
	// AdminToken: when non-empty, ALL /api requests (GET included) must carry
	// "Authorization: Bearer <token>"; /healthz and / stay open.
	// Empty string disables authentication entirely.
	AdminToken string
}

// DeviceView is the read model for one managed device.
// Actions mirrors what this device/record currently allows (e.g. "delete").
type DeviceView struct {
	MAC      string   `json:"mac"`
	Name     string   `json:"name,omitempty"`
	Model    string   `json:"model,omitempty"`
	Firmware string   `json:"firmware,omitempty"`
	IP       string   `json:"ip,omitempty"`
	State    int      `json:"state"`
	LastSeen int64    `json:"last_seen,omitempty"`
	Actions  []string `json:"actions,omitempty"`
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
	// CreateDevice registers a device manually (state PENDING = adopt whitelist).
	CreateDevice(ctx context.Context, up DeviceUpsert) (DeviceView, error)
	DeleteDevice(ctx context.Context, mac string) error
	// ListPending returns discovery-beacon candidates.
	ListPending(ctx context.Context) []PendingView
	// AdoptPending attempts adoption of a pending candidate.
	AdoptPending(ctx context.Context, mac string) (DeviceView, error)
	// GetWireless returns the whole wireless config document.
	GetWireless(ctx context.Context) WlansEnvelope
	// PutWireless replaces the whole wireless config document.
	PutWireless(ctx context.Context, env WlansEnvelope) error
}

// version reports the module version for /api/v1/whoami.
const version = "0.1.0-dev"

// ---- Low-cardinality metrics route labels ------------------------------

const (
	routeDevicesList  = "/api/v1/devices"
	routeDeviceItem   = "/api/v1/devices/{mac}"
	routePendingList  = "/api/v1/pending"
	routePendingAdopt = "/api/v1/pending/{mac}/adopt"
	routeWireless     = "/api/v1/wireless"
	routeWhoAmI       = "/api/v1/whoami"
	routeOther        = "/api/other"
	apiPrefix         = "/api/"
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
func New(cfg DegenerateConfig, be Backend) http.Handler {
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
		dv, err := be.CreateDevice(r.Context(), up)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
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
			handleBackendErr(w, err)
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
			handleBackendErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "mac": mac})
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
			metrics.IncAdoptFail()
			handleBackendErr(w, err)
			return
		}
		metrics.IncAdopt()
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
		for i := range env.Wlans {
			if msg := validateWlan(&env.Wlans[i]); msg != "" {
				writeErr(w, http.StatusBadRequest, "wlan["+strconv.Itoa(i)+"]: "+msg)
				return
			}
		}
		if err := be.PutWireless(r.Context(), env); err != nil {
			handleBackendErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, env)
	}))
	mux.HandleFunc("GET /api/v1/whoami", requireToken(cfg, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, whoAmI{
			Server:         "open-unifi",
			Version:        version,
			AuthConfigured: cfg.AdminToken != "",
		})
	}))

	// /metrics is served directly from the metrics package; /healthz and /
	// (web console) are open even when a token is configured.
	mux.Handle("GET /metrics", metrics.Handler())
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
	// of the label space.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		mux.ServeHTTP(sw, r)
		if route := classifyRoute(r.Method, r.Pattern, r.URL.Path); route != "" {
			metrics.ObserveAPIRequest(sw.code, route)
		}
	})
}

// handleBackendErr maps well-known backend errors to response codes:
// any error satisfying errors.Is(err, ErrNotFound) — the bare sentinel or a
// wrapped one — becomes 404; everything else is a 500.
func handleBackendErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeErr(w, http.StatusInternalServerError, err.Error())
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

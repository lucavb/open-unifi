// Package app wires the store, admin API contract, and metrics together:
// it implements adminapi.Backend over internal/store and feeds
// internal/metrics on a poll loop.
//
// Ownership note: this package is the ADAPTER between lanes; unknown-device
// errors returned by every relevant Backend method wrap the exported
// adminapi.ErrNotFound sentinel, which adminapi maps to HTTP 404 via
// errors.Is (wrapped errors included).
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lucabecker/open-unifi/internal/adminapi"
	"github.com/lucabecker/open-unifi/internal/metrics"
	"github.com/lucabecker/open-unifi/internal/store"
)

// ErrUnknownDevice aliases the adminapi.ErrNotFound sentinel for backward
// compatibility. Errors returned by Backend methods for unknown MACs wrap
// this sentinel (adding the MAC as context): errors.Is(err, adminapi.ErrNotFound)
// holds, and adminapi.handleBackendErr maps them to HTTP 404 — for any
// Backend implementation, not just this adapter.
var ErrUnknownDevice = adminapi.ErrNotFound

// unknownDevice builds the canonical wrapped not-found error for a MAC.
func unknownDevice(mac string) error {
	return fmt.Errorf("%w: %s", ErrUnknownDevice, mac)
}

// App implements adminapi.Backend over the JSON device store and persists
// the wireless config document to its own JSON file.
type App struct {
	st store.DeviceStore
	lg *slog.Logger

	wirelessPath string
	wmu          sync.RWMutex // guards wireless load/save pairs

	prevMu     sync.Mutex
	prevStates map[string]int // MAC(file-free bare hex) -> last-observed state
}

// Compile-time proof that App satisfies the admin API storage contract.
var _ adminapi.Backend = (*App)(nil)

// New builds the application backend. wirelessPath is the JSON file holding
// the wireless config document (created atomically on first write; the
// document shape is {"wlans":[...]}).
func New(st store.DeviceStore, wirelessPath string, lg *slog.Logger) *App {
	if lg == nil {
		lg = slog.Default()
	}
	return &App{
		st:           st,
		lg:           lg,
		wirelessPath: wirelessPath,
		prevStates:   map[string]int{},
	}
}

// ---- MAC format helpers --------------------------------------------------
//
// Store/records use canonical lowercase 12-hex (no separators); the admin API
// uses lowercase colon-hex. These mirror store's canonicalization exactly.

// canonMAC normalizes any common MAC spelling to bare lowercase 12-hex.
func canonMAC(mac string) string {
	var b strings.Builder
	b.Grow(12)
	for _, r := range mac {
		switch r {
		case ':', '-', '.', ' ':
			continue
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

// colonMAC renders bare 12-hex as the admin API's lowercase colon-hex view.
func colonMAC(bare string) string {
	if len(bare) != 12 {
		return strings.ToLower(bare)
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		bare[0:2], bare[2:4], bare[4:6], bare[6:8], bare[8:10], bare[10:12])
}

// view maps a store record to the admin API read model. Actions is the
// minimal supported set (delete) and is omitted only if empty.
func view(d store.Device) adminapi.DeviceView {
	return adminapi.DeviceView{
		MAC:      colonMAC(d.MAC),
		Name:     d.Name,
		Model:    d.Model,
		Firmware: d.Firmware,
		IP:       d.IP,
		State:    d.State,
		LastSeen: d.LastSeen,
		Actions:  []string{"delete"},
	}
}

// ---- adminapi.Backend ----------------------------------------------------

// ListDevices returns all managed devices ordered by MAC.
func (a *App) ListDevices(_ context.Context) []adminapi.DeviceView {
	list, err := a.st.List()
	if err != nil {
		a.lg.Warn("list devices: store error", "err", err)
		return []adminapi.DeviceView{}
	}
	out := make([]adminapi.DeviceView, 0, len(list))
	for _, d := range list {
		out = append(out, view(d))
	}
	return out
}

// GetDevice returns one device by MAC.
func (a *App) GetDevice(_ context.Context, mac string) (adminapi.DeviceView, error) {
	d, err := a.st.Get(canonMAC(mac))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.DeviceView{}, unknownDevice(canonMAC(mac))
		}
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	return view(d), nil
}

// CreateDevice registers a device manually as the adopt whitelist (state
// PENDING). Duplicate posts are an idempotent upsert: the existing record is
// returned and its name/site updated, so provider re-applies never surface
// conflict errors.
func (a *App) CreateDevice(_ context.Context, up adminapi.DeviceUpsert) (adminapi.DeviceView, error) {
	mac := canonMAC(up.MAC)
	if mac == "" {
		return adminapi.DeviceView{}, errors.New("empty mac")
	}
	rec, err := a.st.Get(mac)
	switch {
	case errors.Is(err, store.ErrNotFound):
		rec = store.Device{
			MAC:       mac,
			Name:      up.Name,
			SiteID:    up.SiteID,
			State:     store.StatePending,
			FirstSeen: time.Now().Unix(),
		}
	case err != nil:
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	default:
		if up.Name != "" {
			rec.Name = up.Name
		}
		if up.SiteID != "" {
			rec.SiteID = up.SiteID
		}
	}
	if err := a.st.Put(rec); err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	a.lg.Debug("device created/updated via admin api", "mac", colonMAC(mac), "state", rec.State)
	return view(rec), nil
}

// DeleteDevice removes a device record. Unknown MACs wrap
// adminapi.ErrNotFound (HTTP 404, which the provider treats as success for
// idempotent deletes); real store faults map to plain errors (HTTP 500).
func (a *App) DeleteDevice(_ context.Context, mac string) error {
	if err := a.st.Delete(canonMAC(mac)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return unknownDevice(canonMAC(mac))
		}
		return fmt.Errorf("device store: %w", err)
	}
	return nil
}

// ListPending returns discovery/inform-reported candidates that do not have
// a device record yet.
func (a *App) ListPending(_ context.Context) []adminapi.PendingView {
	pend, err := a.st.Pending()
	if err != nil {
		a.lg.Warn("list pending: store error", "err", err)
		return []adminapi.PendingView{}
	}
	out := make([]adminapi.PendingView, 0, len(pend))
	for mac, note := range pend {
		if _, err := a.st.Get(mac); err == nil {
			continue // device record exists; no longer a candidate
		}
		out = append(out, adminapi.PendingView{MAC: colonMAC(mac), Source: note})
	}
	return out
}

// AdoptPending promotes a discovery/inform candidate (or an existing PENDING
// record) into the adopt whitelist so the inform handshake runs on next
// inform. Unknown MACs are an error.
func (a *App) AdoptPending(_ context.Context, mac string) (adminapi.DeviceView, error) {
	mac = canonMAC(mac)

	pend, err := a.st.Pending()
	if err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	inPending := false
	if _, ok := pend[mac]; ok {
		inPending = true
	}

	rec, gerr := a.st.Get(mac)
	switch {
	case errors.Is(gerr, store.ErrNotFound):
		if !inPending {
			return adminapi.DeviceView{}, unknownDevice(mac)
		}
		rec = store.Device{MAC: mac, State: store.StatePending, FirstSeen: time.Now().Unix()}
	case gerr != nil:
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", gerr)
	case rec.State != store.StatePending:
		return adminapi.DeviceView{}, fmt.Errorf("adopt: device %s is already in state %d", colonMAC(mac), rec.State)
	}
	// Existing records in any non-PENDING state already returned above; only
	// fresh candidates (pending map only) and PENDING records reach here.

	if err := a.st.Put(rec); err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	a.lg.Debug("device promoted to pending", "mac", colonMAC(mac))
	return view(rec), nil
}

// ---- wireless config file -------------------------------------------------

// GetWireless returns the persisted whole-document wireless config; a
// missing file yields the empty default {"wlans":[]}.
func (a *App) GetWireless(_ context.Context) adminapi.WlansEnvelope {
	a.wmu.RLock()
	defer a.wmu.RUnlock()
	return a.loadWireless()
}

// CurrentWireless exposes the persisted wireless envelope without the
// Backend context shape, for provisioning-side wiring (cmd/openunifi feeds
// it into server.Config.WirelessSource through an adminapi.Wlan →
// server.Wlan conversion). GetWireless never fails hard — unreadable or
// corrupt files degrade to the empty default and are logged — so the error
// is nil in all current cases and reserved for future backends.
func (a *App) CurrentWireless() (adminapi.WlansEnvelope, error) {
	return a.GetWireless(nil), nil
}

// loadWireless reads and decodes the wireless file (caller holds wmu at
// read level).
func (a *App) loadWireless() adminapi.WlansEnvelope {
	def := adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{}}
	raw, err := os.ReadFile(a.wirelessPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return def
	case err != nil:
		a.lg.Warn("wireless file unreadable; serving default", "path", a.wirelessPath, "err", err)
		return def
	}
	var env adminapi.WlansEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		a.lg.Warn("wireless file corrupt; serving default", "path", a.wirelessPath, "err", err)
		return def
	}
	if env.Wlans == nil {
		env.Wlans = []adminapi.Wlan{}
	}
	return env
}

// PutWireless replaces the whole wireless config document, persisted
// atomically (temp file + rename).
func (a *App) PutWireless(_ context.Context, env adminapi.WlansEnvelope) error {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	if env.Wlans == nil {
		env.Wlans = []adminapi.Wlan{}
	}
	blob, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("wireless marshal: %w", err)
	}
	dir := filepath.Dir(a.wirelessPath)
	tmp, err := os.CreateTemp(dir, filepath.Base(a.wirelessPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("wireless temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wireless chmod: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wireless write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("wireless fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("wireless close: %w", err)
	}
	if err := os.Rename(tmpName, a.wirelessPath); err != nil {
		return fmt.Errorf("wireless rename: %w", err)
	}
	tmpName = ""
	a.lg.Debug("wireless config replaced", "wlans", len(env.Wlans))
	return nil
}

// ---- metrics poller ------------------------------------------------------

// RunPoller pushes store snapshots into internal/metrics every interval.
// Each iteration is factored into PollOnce for testability.
func (a *App) RunPoller(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.PollOnce()
		}
	}
}

// PollOnce iterates every device record and reports it to metrics, tracking
// state transitions: entering Adopted counts a successful adopt, leaving
// Adopted counts an adopt failure. The first observation of a device only
// seeds prevStates (no spurious transition counters at startup).
func (a *App) PollOnce() {
	list, err := a.st.List()
	if err != nil {
		a.lg.Warn("poller: list failed", "err", err)
		return
	}
	for _, d := range list {
		mac := colonMAC(d.MAC)
		// LastUps is the device's "stat" object; Extra holds the full inform
		// passthrough (uptime lives there). Numeric JSON values are float64.
		uptime := numFloat(d.Extra, "uptime")
		sta := numFloat(d.LastUps, "user-num_sta")
		tx := numFloat(d.LastUps, "user-tx_bytes")
		rx := numFloat(d.LastUps, "user-rx_bytes")

		metrics.UpdateFromDevice(mac, d.Model, int64(d.State), d.LastSeen, uptime, sta, tx, rx)

		a.prevMu.Lock()
		prev, seen := a.prevStates[d.MAC]
		if seen && prev != d.State {
			switch {
			case d.State == store.StateAdopted:
				metrics.IncAdopt()
			case prev == store.StateAdopted:
				metrics.IncAdoptFail()
			}
		}
		a.prevStates[d.MAC] = d.State
		a.prevMu.Unlock()

		a.lg.Debug("poller: device snapshot", "mac", mac, "state", d.State)
	}
}

// numFloat extracts a numeric field as float64; missing/non-numeric values
// are reported as NaN so the metrics helpers skip (never fabricate) them.
func numFloat(m map[string]any, key string) float64 {
	if m == nil {
		return math.NaN()
	}
	if v, ok := m[key].(float64); ok {
		return v
	}
	return math.NaN()
}

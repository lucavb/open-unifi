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
	"sync"
	"time"

	"github.com/lucabecker/open-unifi/internal/adminapi"
	"github.com/lucabecker/open-unifi/internal/metrics"
	"github.com/lucabecker/open-unifi/internal/store"
)

// unknownDevice builds the canonical wrapped not-found error for a MAC.
// It wraps the adminapi.ErrNotFound sentinel (adding the MAC as context):
// errors.Is(err, adminapi.ErrNotFound) holds, and adminapi.handleBackendErr
// maps them to HTTP 404 — for any Backend implementation, not just this
// adapter.
func unknownDevice(mac string) error {
	return fmt.Errorf("%w: %s", adminapi.ErrNotFound, mac)
}

// App implements adminapi.Backend over the JSON device store and persists
// the wireless config document to its own JSON file.
type App struct {
	st store.DeviceStore
	lg *slog.Logger

	wirelessPath string
	wmu          sync.RWMutex // guards the wireless cache (Get/Put pairs)

	// cachedWireless is loaded EXACTLY ONCE by New; GetWireless and the
	// provisioning side serve the cache — there is no per-request file I/O.
	// PutWireless updates it in the same critical section that persists.
	cachedWireless adminapi.WlansEnvelope
	// loadErr is the error from that one eager load (unreadable/corrupt
	// file); missing file is NOT an error. It is fixed at New time and
	// surfaced by CurrentWireless so startup can refuse to launch.
	loadErr error

	prevMu     sync.Mutex
	prevStates map[string]int // MAC(file-free bare hex) -> last-observed state
}

// Compile-time proof that App satisfies the admin API storage contract.
var _ adminapi.Backend = (*App)(nil)

// New builds the application backend. wirelessPath is the JSON file holding
// the wireless config document (created atomically on first write; the
// document shape is {"wlans":[...]}). The wireless file is read EXACTLY ONCE
// here: a missing file yields the empty default (first boot), an unreadable
// or JSON-corrupt file is retained in loadErr — callers must check
// CurrentWireless at startup (cmd/openunifi refuses to launch) instead of
// silently provisioning APs with zero WLANs.
func New(st store.DeviceStore, wirelessPath string, lg *slog.Logger) *App {
	if lg == nil {
		lg = slog.Default()
	}
	env, err := loadWirelessFile(wirelessPath)
	return &App{
		st:             st,
		lg:             lg,
		wirelessPath:   wirelessPath,
		cachedWireless: env,
		loadErr:        err,
		prevStates:     map[string]int{},
	}
}

// ---- MAC format helpers --------------------------------------------------
//
// Store/records use canonical lowercase 12-hex (no separators); the admin API
// uses lowercase colon-hex. There is exactly ONE normalizer, in package
// store (store.CanonicalMAC / store.ColonMAC) — this package keeps no
// private copy of the normalization logic, so identity cannot drift
// between lanes. Where a validating error is possible (hand-written MACs),
// callers treat invalid input as reject/not-found, same as adminapi's own
// 400 edge validation.

// view maps a store record to the admin API read model. Actions is the
// minimal supported set (delete) and is omitted only if empty.
func view(d store.Device) adminapi.DeviceView {
	return adminapi.DeviceView{
		MAC:      store.ColonMAC(d.MAC),
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

// GetDevice returns one device by MAC. Unparseable MAC spellings are
// rejected as not-found (adminapi already 400s its own boundary; this is
// the adapter-side backstop).
func (a *App) GetDevice(_ context.Context, mac string) (adminapi.DeviceView, error) {
	canon, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return adminapi.DeviceView{}, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}
	d, err := a.st.Get(canon)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.DeviceView{}, unknownDevice(canon)
		}
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	return view(d), nil
}

// CreateDevice registers a device manually as the adopt whitelist (state
// PENDING). Duplicate posts are an idempotent upsert: the existing record is
// returned and its name/site updated, so provider re-applies never surface
// conflict errors. Invalid MACs are a hard reject (adminapi itself 400s at
// the edge; this adapter-side check is the backstop for other callers).
func (a *App) CreateDevice(_ context.Context, up adminapi.DeviceUpsert) (adminapi.DeviceView, error) {
	mac, err := store.CanonicalMAC(up.MAC)
	if err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("invalid mac %q: %w", up.MAC, err)
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
	a.lg.Debug("device created/updated via admin api", "mac", store.ColonMAC(mac), "state", rec.State)
	return view(rec), nil
}

// DeleteDevice removes a device record. Unknown MACs wrap
// adminapi.ErrNotFound (HTTP 404, which the provider treats as success for
// idempotent deletes); real store faults map to plain errors (HTTP 500).
func (a *App) DeleteDevice(_ context.Context, mac string) error {
	canon, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		// Invalid spelling cannot exist in the store: not-found semantics.
		return fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}
	if err := a.st.Delete(canon); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return unknownDevice(canon)
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
		out = append(out, adminapi.PendingView{MAC: store.ColonMAC(mac), Source: note})
	}
	return out
}

// AdoptPending promotes a discovery/inform candidate (or an existing PENDING
// record) into the adopt whitelist so the inform handshake runs on next
// inform. Unknown MACs are an error.
func (a *App) AdoptPending(_ context.Context, mac string) (adminapi.DeviceView, error) {
	mac, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return adminapi.DeviceView{}, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}

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
		return adminapi.DeviceView{}, fmt.Errorf("adopt: device %s is already in state %d", store.ColonMAC(mac), rec.State)
	}
	// Existing records in any non-PENDING state already returned above; only
	// fresh candidates (pending map only) and PENDING records reach here.

	if err := a.st.Put(rec); err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	a.lg.Debug("device promoted to pending", "mac", store.ColonMAC(mac))
	return view(rec), nil
}

// ---- wireless config file -------------------------------------------------

// GetWireless serves the cached whole-document wireless config. There is NO
// file I/O here: New loaded the document once, PutWireless keeps the cache
// in sync. A missing file was the empty default {"wlans":[]}; an unreadable
// or corrupt file was rejected at startup (CurrentWireless error, main
// refuses) — so serving empty-to-then-PUT-one-wlan (silent config wipes)
// cannot happen anymore.
func (a *App) GetWireless(_ context.Context) adminapi.WlansEnvelope {
	a.wmu.RLock()
	defer a.wmu.RUnlock()
	return a.cachedWireless
}

// CurrentWireless exposes the cached wireless envelope without the Backend
// context shape, for provisioning-side wiring (cmd/openunifi feeds it into
// server.Config.WirelessSource through an adminapi.Wlan → server.Wlan
// conversion). The error is REAL, not reserved: it is set at NEW time when
// the wireless file was unreadable or JSON-corrupt (missing file is not an
// error — first boot). cmd/openunifi checks it immediately after New and
// refuses to launch, so a corrupt wireless.json becomes a visible startup
// failure (matching store.NewJSONStore's corrupt-file behavior) instead of a
// silent future deconfiguration of adopted APs.
func (a *App) CurrentWireless() (adminapi.WlansEnvelope, error) {
	a.wmu.RLock()
	defer a.wmu.RUnlock()
	return a.cachedWireless, a.loadErr
}

// loadWirelessFile reads and decodes the wireless config document exactly
// once (called from New): a missing file yields the empty default with a nil
// error; an unreadable or corrupt file yields the empty default PLUS a real
// error that App retains until process exit.
func loadWirelessFile(path string) (adminapi.WlansEnvelope, error) {
	def := adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return def, nil
	}
	if err != nil {
		return def, fmt.Errorf("wireless file unreadable %s: %w", path, err)
	}
	var env adminapi.WlansEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return def, fmt.Errorf("wireless file corrupt %s: %w", path, err)
	}
	if env.Wlans == nil {
		env.Wlans = []adminapi.Wlan{}
	}
	return env, nil
}

// PutWireless replaces the whole wireless config document, persisted
// atomically (temp file + rename), and then swaps the in-memory cache in the
// SAME critical section. On any persist error the cache is left untouched
// and the error is returned — disk and memory can never disagree.
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
	a.cachedWireless = env // persist succeeded: swap the cache atomically
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

// lostAfterSeconds is how long an ADOPTED device may go without an inform
// before the poller marks it StateLost: 180s ≈ 12 missed 15s inform heartbeats.
const lostAfterSeconds int64 = 180

// PollOnce iterates every device record and reports it to metrics.
// Phase 1 sweeps stale heartbeats: an adopted device whose last_seen is
// older than lostAfterSeconds is transitioned to StateLost via store.Update
// (each sweep transition fires exactly one metrics.IncAdoptFail — losing an
// adopted device is an adopt failure — and the device's prevStates entry is
// pinned to the new state so the phase-2 loop cannot double count).
// Phase 2 reports every device snapshot, tracking state transitions:
// entering Adopted counts a successful adopt, leaving Adopted counts an
// adopt failure. The first observation of a device only seeds prevStates
// (no spurious transition counters at startup).
// prevStates entries for MACs that have since left the store are pruned so
// device churn cannot grow the map without bound.
func (a *App) PollOnce() {
	a.sweepLost()

	list, err := a.st.List()
	if err != nil {
		a.lg.Warn("poller: list failed", "err", err)
		return
	}
	inStore := make(map[string]struct{}, len(list))
	for _, d := range list {
		inStore[d.MAC] = struct{}{}
		mac := store.ColonMAC(d.MAC)
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

	// Prune prevStates for devices that no longer exist: the map is keyed by
	// bare canonical MAC and would otherwise grow with every adoption churn
	// cycle for the lifetime of the process.
	a.prevMu.Lock()
	for mac := range a.prevStates {
		if _, ok := inStore[mac]; !ok {
			delete(a.prevStates, mac)
		}
	}
	a.prevMu.Unlock()
}

// sweepLost transitions devices whose adopted heartbeats have gone stale
// (LastSeen > lostAfterSeconds ago) to StateLost. Pending/Adopting records
// and devices that have never been seen (LastSeen == 0) are never swept.
// Each successful transition is counted as an adopt failure and the
// prevStates entry is pinned to the new state, so PollOnce's phase-2 loop
// observes an unchanged state and the transition is counted exactly once.
func (a *App) sweepLost() {
	list, err := a.st.List()
	if err != nil {
		a.lg.Warn("lost sweep: list failed", "err", err)
		return
	}
	now := time.Now().Unix()
	for _, d := range list {
		if d.State != store.StateAdopted || d.LastSeen <= 0 {
			continue
		}
		if now-d.LastSeen <= lostAfterSeconds {
			continue // fresh heartbeat
		}
		err := a.st.Update(d.MAC, func(u *store.Device) error {
			u.State = store.StateLost
			return nil
		})
		if err != nil {
			a.lg.Warn("lost sweep: state transition failed", "mac", store.ColonMAC(d.MAC), "err", err)
			continue
		}
		metrics.IncAdoptFail()
		a.prevMu.Lock()
		a.prevStates[d.MAC] = store.StateLost
		a.prevMu.Unlock()
		a.lg.Info("device marked lost", "mac", store.ColonMAC(d.MAC),
			"last_seen_age_s", now-d.LastSeen)
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

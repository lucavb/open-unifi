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
	"crypto/sha256"
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

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/metrics"
	"github.com/lucavb/open-unifi/internal/store"
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
func (a *App) view(d store.Device) adminapi.DeviceView {
	a.wmu.RLock()
	desired := append([]adminapi.Wlan(nil), a.cachedWireless.Wlans...)
	a.wmu.RUnlock()
	inSync := runtimeInSync(d, desired)
	return adminapi.DeviceView{
		MAC:                store.ColonMAC(d.MAC),
		Name:               d.Name,
		Model:              d.Model,
		Firmware:           d.Firmware,
		IP:                 d.IP,
		State:              d.State,
		LastSeen:           d.LastSeen,
		CfgVersion:         d.CfgVersion,
		AppliedCfg:         d.AppliedCfg,
		InSync:             inSync,
		WLANDeliveryStatus: stringExtra(d.Extra, "wlan_cfg_delivery_status"),
		WLANDeliveryCount:  intExtra(d.Extra, "wlan_cfg_attempts"),
		WLANLastAttempt:    int64Extra(d.Extra, "wlan_cfg_last_attempt"),
		SiteID:             d.SiteID,
		Actions:            []string{"delete"},
	}
}

func stringExtra(m store.JSONMap, key string) string { v, _ := m[key].(string); return v }
func intExtra(m store.JSONMap, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	if v, ok := m[key].(int); ok {
		return v
	}
	return 0
}
func int64Extra(m store.JSONMap, key string) int64 {
	if v, ok := m[key].(float64); ok {
		return int64(v)
	}
	if v, ok := m[key].(int64); ok {
		return v
	}
	return 0
}

// runtimeInSync deliberately does not infer runtime WLAN health from the
// controller/device cfgversion pair.  Devices can echo a matching version
// before applying the WLAN, so that pair is only transport bookkeeping.
// This read-side predicate is SSID-PRESENCE-ONLY by design: a positive
// result requires a reported vap_table in which every enabled desired SSID
// is observed RUNNING. It does NOT verify per-radio placement or that a
// deleted WLAN has disappeared from the table — that strict check lives in
// the server lane's settlePendingWLAN, which runs before this view is
// served on every inform. Missing runtime evidence is unknown (nil), while
// an observed table that lacks a desired RUN SSID is false.
//
// The vap_table wire keys are firmware-verified: APs report "essid" (not
// "ssid") and "state" (not "status"). The alternate spellings are tolerated
// defensively, but "essid"/"state" are the primaries.
func runtimeInSync(d store.Device, desired []adminapi.Wlan) *bool {
	if d.Extra == nil {
		return nil
	}
	if _, pending := d.Extra["wlan_cfg_pending_sha"]; pending {
		v := false
		return &v
	}
	vaps, ok := d.Extra["vap_table"].([]any)
	if !ok || len(vaps) == 0 {
		return nil
	}
	// A vap_table with no RUN desired SSIDs is meaningful evidence of being out
	// of sync, but a missing/empty table is unknown rather than false.
	want := make(map[string]bool)
	for _, wlan := range desired {
		if wlan.Enabled {
			want[wlan.SSID] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	running := make(map[string]bool)
	for _, raw := range vaps {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		ssid, _ := m["essid"].(string)
		if ssid == "" {
			ssid, _ = m["ssid"].(string) // tolerated fallback spelling
		}
		state, _ := m["state"].(string)
		if state == "" {
			state, _ = m["status"].(string) // tolerated fallback spelling
		}
		if ssid != "" && strings.EqualFold(state, "RUN") && want[ssid] {
			running[ssid] = true
		}
	}
	v := len(running) == len(want)
	return &v
}

func (a *App) PatchDevice(_ context.Context, mac string, patch adminapi.DevicePatch) (adminapi.DeviceView, error) {
	canon, err := store.CanonicalMAC(mac)
	if err != nil {
		return adminapi.DeviceView{}, unknownDevice(mac)
	}
	var rec store.Device
	err = a.st.UpdateExisting(canon, func(d *store.Device) error {
		if patch.Name != nil {
			// Same backstop the wlan flows apply (CreateWlan): the handler
			// 400s first, but every Backend caller is still fenced in.
			if msg := adminapi.ValidateDeviceName(*patch.Name); msg != "" {
				return fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
			}
			d.Name = *patch.Name
		}
		if patch.SiteID != nil {
			d.SiteID = *patch.SiteID
		}
		rec = *d
		rec.LastUps = nil
		rec.Extra = nil
		rec.Authkeys = nil
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.DeviceView{}, unknownDevice(canon)
	}
	if err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	return a.view(rec), nil
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
		out = append(out, a.view(d))
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
	return a.view(d), nil
}

// CreateDevice registers a device manually as the adopt whitelist (state
// PENDING). Duplicate posts are an idempotent upsert: the existing record is
// returned and its name/site updated, so provider re-applies never surface
// conflict errors. Invalid MACs are a hard reject (adminapi itself 400s at
// the edge; this adapter-side check is the backstop for other callers).
//
// The whole cycle runs inside the store's per-MAC RMW closure: the previous
// Get→mutate→Put sequence could interleave with a concurrent inform handler
// and lose updates (e.g. resurrect an overwritten first-seen or clobber an
// inform-written field between the Get and the Put).
func (a *App) CreateDevice(_ context.Context, up adminapi.DeviceUpsert) (adminapi.DeviceView, error) {
	mac, err := store.CanonicalMAC(up.MAC)
	if err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("invalid mac %q: %w", up.MAC, err)
	}
	var rec store.Device
	created := false
	if err := a.st.Update(mac, func(d *store.Device) error {
		if d.State == 0 { // freshly seeded by the upsert: record did not exist
			created = true
			d.State = store.StatePending
			d.FirstSeen = time.Now().Unix()
		}
		if up.Name != "" {
			if msg := adminapi.ValidateDeviceName(up.Name); msg != "" {
				return fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
			}
			d.Name = up.Name
		}
		if up.SiteID != "" {
			d.SiteID = up.SiteID
		}
		// Detached snapshot for the returned view (view reads scalars only).
		rec = store.Device{
			MAC: d.MAC, Name: d.Name, Model: d.Model, Firmware: d.Firmware,
			IP: d.IP, State: d.State, LastSeen: d.LastSeen,
			CfgVersion: d.CfgVersion, AppliedCfg: d.AppliedCfg,
		}
		return nil
	}); err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	a.lg.Debug("device created/updated via admin api", "mac", store.ColonMAC(mac),
		"state", rec.State, "created", created)
	return a.view(rec), nil
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
	// Prune the deleted device's metric series: per-device gauges would
	// otherwise survive the removal forever (with the MAC label, an inventory
	// snapshot that has since been revoked).
	metrics.ForgetDevice(store.ColonMAC(canon))
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
// inform. Unknown MACs are an error. The decision AND the record write run
// inside the store's per-MAC RMW closure so a concurrent inform for the same
// device cannot interleave between the pending-existence check and the
// record upsert.
func (a *App) AdoptPending(_ context.Context, mac string) (adminapi.DeviceView, error) {
	mac, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return adminapi.DeviceView{}, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}

	var rec store.Device
	err := a.st.Update(mac, func(d *store.Device) error {
		if d.State == 0 { // freshly seeded by the upsert: no device record yet
			pend, perr := a.st.Pending()
			if perr != nil {
				return fmt.Errorf("device store: %w", perr)
			}
			if _, ok := pend[mac]; !ok {
				// Unknown AND never heard on discovery/inform: not-found.
				return fmt.Errorf("%w: %s", adminapi.ErrNotFound, mac)
			}
			d.State = store.StatePending
			d.FirstSeen = time.Now().Unix()
		} else if d.State != store.StatePending {
			return fmt.Errorf("adopt: device %s is already in state %d", store.ColonMAC(mac), d.State)
		}
		// Records in any non-PENDING state already returned above; only
		// fresh candidates (pending map only) and PENDING records persist.
		rec = store.Device{
			MAC: d.MAC, Name: d.Name, Model: d.Model, Firmware: d.Firmware,
			IP: d.IP, State: d.State, LastSeen: d.LastSeen,
		}
		return nil
	})
	if err != nil {
		return adminapi.DeviceView{}, err
	}
	a.lg.Debug("device promoted to pending", "mac", store.ColonMAC(mac))
	return a.view(rec), nil
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
	return cloneWireless(a.cachedWireless)
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
	return cloneWireless(a.cachedWireless), a.loadErr
}

// loadWirelessFile reads and decodes the wireless config document exactly
// once (called from New): a missing file yields the empty default with a nil
// error; an unreadable, corrupt, or INVALID file yields the empty default
// PLUS a real error that App retains until process exit.
//
// Validation runs the exact same rules as PUT /api/v1/wireless
// (adminapi.ValidateWlan): a document that would be rejected at the API must
// not be loaded silently and then provisioned to devices.
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
	for i := range env.Wlans {
		wl := &env.Wlans[i]
		if msg := adminapi.ValidateWlan(wl); msg != "" {
			return def, fmt.Errorf(
				"wireless file %s: invalid wlan[%d] (name=%q ssid=%q): %s; remove or convert it (e.g. via PUT /api/v1/wireless) and restart",
				path, i, wl.Name, wl.SSID, msg)
		}
	}
	if err := validateWlanUniqueness(env); err != nil {
		return def, err
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
	for i := range env.Wlans {
		env.Wlans[i].ID = wlanID(env.Wlans[i])
	}
	for _, w := range env.Wlans {
		if msg := adminapi.ValidateWlanName(w.Name); msg != "" {
			return fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
		}
	}
	if err := validateWlanUniqueness(env); err != nil {
		return err
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
	syncDir(dir)           // best effort: make the rename itself durable
	a.cachedWireless = env // persist succeeded: swap the cache atomically
	a.lg.Debug("wireless config replaced", "wlans", len(env.Wlans))
	return nil
}

func wlanID(w adminapi.Wlan) string {
	if w.ID != "" {
		return w.ID
	}
	sum := sha256.Sum256([]byte(w.Name + w.SSID))
	return fmt.Sprintf("%x", sum[:12])
}
func (a *App) validateWlans(env *adminapi.WlansEnvelope) error {
	names, ssids, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range env.Wlans {
		w := &env.Wlans[i]
		if msg := adminapi.ValidateWlanName(w.Name); msg != "" {
			return fmt.Errorf("%w: wlan[%d]: %s", adminapi.ErrConflict, i, msg)
		}
		if msg := adminapi.ValidateWlan(w); msg != "" {
			return fmt.Errorf("%w: wlan[%d]: %s", adminapi.ErrConflict, i, msg)
		}
		if names[w.Name] || ssids[w.SSID] || (w.ID != "" && ids[w.ID]) {
			return fmt.Errorf("%w: duplicate wlan", adminapi.ErrConflict)
		}
		names[w.Name], ssids[w.SSID], ids[w.ID] = true, true, w.ID != ""
	}
	return nil
}

func validateWlanUniqueness(env adminapi.WlansEnvelope) error {
	names, ssids, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, w := range env.Wlans {
		if names[w.Name] || ssids[w.SSID] || (w.ID != "" && ids[w.ID]) {
			return fmt.Errorf("%w: duplicate wlan", adminapi.ErrConflict)
		}
		names[w.Name], ssids[w.SSID], ids[w.ID] = true, true, w.ID != ""
	}
	return nil
}
func (a *App) CreateWlan(_ context.Context, wlan adminapi.Wlan) (adminapi.Wlan, error) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	env := a.cachedWireless
	if msg := adminapi.ValidateWlanName(wlan.Name); msg != "" {
		return adminapi.Wlan{}, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
	}
	wlan.ID = wlanID(wlan)
	env.Wlans = append(append([]adminapi.Wlan(nil), env.Wlans...), wlan)
	if err := a.validateWlans(&env); err != nil {
		return adminapi.Wlan{}, err
	}
	if err := a.persistWirelessLocked(env); err != nil {
		return adminapi.Wlan{}, err
	}
	return wlan, nil
}
func (a *App) GetWlan(_ context.Context, name string) (adminapi.Wlan, error) {
	a.wmu.RLock()
	defer a.wmu.RUnlock()
	for _, w := range a.cachedWireless.Wlans {
		if w.Name == name {
			return w, nil
		}
	}
	return adminapi.Wlan{}, fmt.Errorf("%w: wlan %s", adminapi.ErrNotFound, name)
}
func (a *App) UpdateWlan(_ context.Context, name string, wlan adminapi.Wlan) (adminapi.Wlan, error) {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	// Clone BEFORE any mutation: a shallow copy shares the backing array of
	// a.cachedWireless, so writing env.Wlans[i] here would leak the new
	// (possibly rejected) wlan into the live cache that CurrentWireless
	// serves to AP provisioning before validateWlans/persistWirelessLocked
	// have a say. persistWirelessLocked swaps the clone in on success.
	env := cloneWireless(a.cachedWireless)
	if msg := adminapi.ValidateWlanName(name); msg != "" {
		return adminapi.Wlan{}, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
	}
	if wlan.Name != "" && wlan.Name != name {
		return adminapi.Wlan{}, fmt.Errorf("%w: name must match path", adminapi.ErrConflict)
	}
	wlan.Name = name
	found := false
	for i := range env.Wlans {
		if env.Wlans[i].Name == name {
			wlan.ID = env.Wlans[i].ID
			env.Wlans[i] = wlan
			found = true
			break
		}
	}
	if !found {
		return adminapi.Wlan{}, fmt.Errorf("%w: wlan %s", adminapi.ErrNotFound, name)
	}
	if err := a.validateWlans(&env); err != nil {
		return adminapi.Wlan{}, err
	}
	if err := a.persistWirelessLocked(env); err != nil {
		return adminapi.Wlan{}, err
	}
	return wlan, nil
}

func cloneWireless(env adminapi.WlansEnvelope) adminapi.WlansEnvelope {
	env.Wlans = append([]adminapi.Wlan(nil), env.Wlans...)
	return env
}
func (a *App) DeleteWlan(_ context.Context, name string) error {
	a.wmu.Lock()
	defer a.wmu.Unlock()
	// Clone BEFORE any mutation (same discipline as UpdateWlan): the old
	// in-place compaction via Wlans[:0] wrote the filtered list into the
	// SHARED backing array of a.cachedWireless, so a failed persist left
	// the deleted state live in the cache while disk kept the old document.
	env := cloneWireless(a.cachedWireless)
	out := make([]adminapi.Wlan, 0, len(env.Wlans))
	found := false
	for _, w := range env.Wlans {
		if w.Name == name {
			found = true
		} else {
			out = append(out, w)
		}
	}
	if !found {
		return fmt.Errorf("%w: wlan %s", adminapi.ErrNotFound, name)
	}
	env.Wlans = out
	return a.persistWirelessLocked(env)
}
func (a *App) persistWirelessLocked(env adminapi.WlansEnvelope) error {
	blob, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.wirelessPath)
	tmp, err := os.CreateTemp(dir, filepath.Base(a.wirelessPath)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = tmp.Write(blob); err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, a.wirelessPath); err != nil {
		return err
	}
	// Same durability contract as PutWireless: flush the rename itself so
	// every wireless mutation path survives a crash identically.
	syncDir(dir)
	a.cachedWireless = env
	return nil
}

// syncDir fsyncs a directory so a just-renamed file entry survives a crash.
// Best effort by design: some platforms reject directory fsync, and a
// durability-flushing failure must not fail an otherwise-complete write.
// (The same helper exists in the store package; the wireless writer is a
// separate rename site, hence a tiny local copy rather than a dependency.)
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
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
// before the poller marks it StateLost. The reference controller sets
// considered_lost_at = now + 3*(interval+10) seconds
// (tmpwork/javap/com__ubnt__service__devmgr__voidsuper.txt:11398-11408,
// `considered_lost_at` put: (lload + 10) * 3 + interval); with our fixed
// 15s inform interval that is 3*25 = 75s. If the inform interval ever
// becomes dynamic this constant must be derived from the emitted interval,
// not hardcoded above it.
const lostAfterSeconds int64 = 75

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
// The sweep conditions are re-verified INSIDE the store RMW closure so a
// concurrent inform (fresh heartbeat, state change, or record mutation
// between the List snapshot above and this cycle) aborts the transition
// instead of racing it. Each actual transition is counted as an adopt
// failure exactly once and the prevStates entry is pinned to the new state,
// so PollOnce's phase-2 loop observes an unchanged state and cannot double
// count.
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
			continue // fresh heartbeat (as of the snapshot)
		}
		err := a.st.Update(d.MAC, func(u *store.Device) error {
			// TOCTOU re-check: the store List above is a snapshot; a
			// concurrent inform may have refreshed the heartbeat or moved
			// the device out of StateAdopted since. Only a record that is
			// STILL adopted and STILL stale at cycle time transitions.
			if u.State != store.StateAdopted || u.LastSeen <= 0 ||
				now-u.LastSeen <= lostAfterSeconds {
				return errSweepAborted
			}
			u.State = store.StateLost
			return nil
		})
		switch {
		case err == nil:
			// exactly one persisted transition happened
		case errors.Is(err, errSweepAborted):
			continue // concurrent mutation won; no transition, no count
		default:
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

// errSweepAborted aborts a sweep RMW cycle (no persist, no metric) when the
// pre-conditions re-verified inside the closure no longer hold.
var errSweepAborted = errors.New("lost sweep: device changed under us")

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

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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/lucavb/open-unifi/internal/server/adoption"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
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

	// informPush is the controller-side SSH set-inform push lane
	// (internal/app/setinform.go). nil = the --allow-ssh-set-inform-push
	// opt-in was not supplied: the lane never fires and AdoptPending keeps
	// its whitelist-arming-only semantics.
	informPush *setInformPush
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
		LEDOverride:        d.LEDOverride,
		// The two §12 ledbar knobs map straight through: the view keeps
		// the pointer semantics (explicit 0 survives; nil = jar default)
		// and the verbatim color string.
		LEDOverrideColorBrightness: d.LEDOverrideColorBrightness,
		LEDOverrideColor:           d.LEDOverrideColor,
		PendingCommand:             armedCommand(d),
		Actions:                    []string{"delete"},
	}
}

// armedCommand reads the admin-armed remote-command rows (§6.5 reboot /
// §6.6 setdefault / §6.3 stored cmd task) into the view's
// PendingCommand: the value names the _type the device's NEXT inform
// will carry. "reboot" when the reboot flag is armed, "factory-reset"
// when the setdefault arm is set (outranking reboot), "cmd" when a
// stored task is armed (last in the chain), "" when none. The order
// mirrors the engine's armedLifecycle emission precedence exactly, so
// the view can never name a response the engine would not fire.
func armedCommand(d store.Device) string {
	if flagArmed(d.Extra, adoption.FlagSetdefaultArmed) {
		return "factory-reset"
	}
	if flagArmed(d.Extra, adoption.FlagRebootOnConnect) {
		return "reboot"
	}
	if store.ArmedCmdTask(d) != nil {
		return "cmd"
	}
	return ""
}

// flagArmed reports whether an armed flag holds a truthy value. It applies
// the same acceptance as the adoption engine's truthy() (bool, or a
// non-empty string other than "false"/"0", or a non-zero number), so the
// view can never hide a command the engine would fire — the operator's
// armed/pending signal stays consistent with the emission path.
func flagArmed(m store.JSONMap, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v != "" && v != "false" && v != "0"
	case float64:
		return v != 0
	default:
		return v != nil
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
		if patch.LEDOverride != nil {
			// ValidateLEDOverride is enforced at the route; this is the
			// backend-side backstop (same fence style as Name). "default"
			// is the explicit clear: the record's canonical unset is ""
			// (the jar's getString default IS "default", so absence and
			// "default" mean the same wire value — §2 treats them alike).
			if msg := adminapi.ValidateLEDOverride(*patch.LEDOverride); msg != "" {
				return fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
			}
			next := ""
			if *patch.LEDOverride != "default" {
				next = *patch.LEDOverride
			}
			// Delivery trigger, putRadioIntent's idempotence discipline:
			// the LED override only reaches the device inside a full
			// provisioning's mgmt_cfg (BuildMgmtCfg's led_enabled row), so
			// an EFFECTIVE change mints a fresh cfgversion here — the
			// device's next inform still echoes the OLD applied stamp and
			// the engine's default arm full-provisions. A save that changes
			// nothing mints nothing.
			if next != d.LEDOverride {
				nv, merr := mintCfgVersion()
				if merr != nil {
					return merr
				}
				d.CfgVersion = nv
			}
			d.LEDOverride = next
		}
		if patch.LEDOverrideColorBrightness != nil {
			// ValidateLEDOverrideColorBrightness is enforced at the
			// route; this is the backend-side backstop (same fence
			// style as Name/LEDOverride). 100 is the explicit clear:
			// the record's canonical unset is nil, because the jar's
			// getInt default IS 100 (config_String.txt:2627-2630) — a
			// saved 100 and an absent knob render the same §12 row.
			// Every other in-domain value, including 0, is the admin's
			// explicit pick.
			if msg := adminapi.ValidateLEDOverrideColorBrightness(*patch.LEDOverrideColorBrightness); msg != "" {
				return fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
			}
			var next *int
			if *patch.LEDOverrideColorBrightness != 100 {
				v := *patch.LEDOverrideColorBrightness
				next = &v
			}
			// Same delivery trigger as the LED override: the knob only
			// reaches the device inside a full provisioning's
			// system_cfg ledbar block (§12), so an EFFECTIVE change
			// mints a fresh cfgversion here — the device's next inform
			// still echoes the OLD applied stamp and the engine full-
			// provisions. A save that changes nothing mints nothing.
			if !intPtrEq(next, d.LEDOverrideColorBrightness) {
				nv, merr := mintCfgVersion()
				if merr != nil {
					return merr
				}
				d.CfgVersion = nv
			}
			d.LEDOverrideColorBrightness = next
		}
		if patch.LEDOverrideColor != nil {
			// No format backstop for the color ON PURPOSE: the §12
			// render owns the fallback (Color.decode — unparseable
			// values land on #0000ff, config_String.txt:2669-2678);
			// the jar accepts any string in this knob and so does the
			// record. "" is the explicit clear (the jar's getString
			// default is "#0000ff"). Same delivery trigger as above:
			// an effective change mints cfgversion.
			if *patch.LEDOverrideColor != d.LEDOverrideColor {
				nv, merr := mintCfgVersion()
				if merr != nil {
					return merr
				}
				d.CfgVersion = nv
			}
			d.LEDOverrideColor = *patch.LEDOverrideColor
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

// intPtrEq is the nil-aware *int equality for the ledbar brightness knob:
// nil means "unset" (the jar default 100), never the number 0.
func intPtrEq(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
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

// ---- Blocked-client set (the admin-owned row behind blocked_sta) ---------

// blockedPair canonicalizes the device and client MACs — the shared prelude
// of the blocked-set endpoints. An unparseable DEVICE MAC cannot exist in
// the store (not-found semantics, mirroring GetDevice); an unparseable
// CLIENT MAC is a backstop conflict (adminapi already 400'd it at its
// boundary).
func blockedPair(mac, client string) (string, string, error) {
	canon, err := store.CanonicalMAC(mac)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, err)
	}
	cclient, err := store.CanonicalMAC(client)
	if err != nil {
		return "", "", fmt.Errorf("%w: invalid client mac: %s (%v)", adminapi.ErrConflict, client, err)
	}
	return canon, cclient, nil
}

// blockedClientsView renders the admin-facing projection: colon-hex in the
// set's canonical order, never a nil slice (the JSON is always a list).
func blockedClientsView(canon string, set []string) adminapi.BlockedClientsView {
	out := make([]string, len(set))
	for i, c := range set {
		out[i] = store.ColonMAC(c)
	}
	return adminapi.BlockedClientsView{MAC: store.ColonMAC(canon), Blocked: out}
}

// ListBlockedClients returns the device's blocked-client set.
func (a *App) ListBlockedClients(_ context.Context, mac string) (adminapi.BlockedClientsView, error) {
	canon, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return adminapi.BlockedClientsView{}, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}
	d, err := a.st.Get(canon)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.BlockedClientsView{}, unknownDevice(canon)
		}
		return adminapi.BlockedClientsView{}, fmt.Errorf("device store: %w", err)
	}
	return blockedClientsView(canon, store.BlockedClients(d)), nil
}

// ListDeviceClients returns the device's client sessions — the
// controller-owned rows the inform path derives from decoded station data
// — in canonical (sorted) MAC order. Read-only projection: the Backend
// never writes session state; the inform path owns it.
func (a *App) ListDeviceClients(_ context.Context, mac string) ([]adminapi.ClientView, error) {
	canon, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return nil, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}
	d, err := a.st.Get(canon)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, unknownDevice(canon)
		}
		return nil, fmt.Errorf("device store: %w", err)
	}
	sessions := store.ClientSessions(d)
	out := make([]adminapi.ClientView, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, adminapi.ClientView{
			MAC:       store.ColonMAC(s.MAC),
			Connected: s.Connected,
			LastSeen:  s.LastSeen,
		})
	}
	return out, nil
}

// BlockClient adds one client MAC to the device's blocked-client set.
// Idempotent: re-blocking returns the unchanged set, like the adopt route's
// state-change semantics. The set is an admin-owned record row; the engine
// delivers it inside full provisioning on the next inform via its
// blocked_sta drift — no admin-time cfgversion mint (exactly the WLAN
// envelope change machinery).
func (a *App) BlockClient(_ context.Context, mac, client string) (adminapi.BlockedClientsView, error) {
	canon, cclient, perr := blockedPair(mac, client)
	if perr != nil {
		return adminapi.BlockedClientsView{}, perr
	}
	var view adminapi.BlockedClientsView
	err := a.st.UpdateExisting(canon, func(d *store.Device) error {
		if _, err := store.AddBlockedClient(d, cclient); err != nil {
			return err
		}
		// Render INSIDE the closure: the clone is only authoritative within
		// the RMW cycle, and nothing aliases the record out of it.
		view = blockedClientsView(canon, store.BlockedClients(*d))
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.BlockedClientsView{}, unknownDevice(canon)
		}
		return adminapi.BlockedClientsView{}, fmt.Errorf("device store: %w", err)
	}
	return view, nil
}

// UnblockClient removes one client MAC from the device's blocked-client
// set. A client that is not currently blocked is ErrNotFound (the route
// maps it to 404, mirroring DeleteDevice/DeleteWlan semantics).
func (a *App) UnblockClient(_ context.Context, mac, client string) (adminapi.BlockedClientsView, error) {
	canon, cclient, perr := blockedPair(mac, client)
	if perr != nil {
		return adminapi.BlockedClientsView{}, perr
	}
	var view adminapi.BlockedClientsView
	err := a.st.UpdateExisting(canon, func(d *store.Device) error {
		removed, rerr := store.RemoveBlockedClient(d, cclient)
		if rerr != nil {
			return rerr
		}
		if !removed {
			return fmt.Errorf("%w: client not blocked: %s", adminapi.ErrNotFound, store.ColonMAC(cclient))
		}
		view = blockedClientsView(canon, store.BlockedClients(*d))
		return nil
	})
	if err != nil {
		// The not-blocked abort already carries the canonical 404 shape;
		// only store-level faults get wrapped opaque.
		if errors.Is(err, adminapi.ErrNotFound) {
			return adminapi.BlockedClientsView{}, err
		}
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.BlockedClientsView{}, unknownDevice(canon)
		}
		return adminapi.BlockedClientsView{}, fmt.Errorf("device store: %w", err)
	}
	return view, nil
}

// ---- per-radio admin intent (admin-owned record state) ---------------------

// radioRowOf finds the device's radio_table row by name; unknown names
// wrap adminapi.ErrNotFound (HTTP 404 — the radio key is a device-reported
// name, not admin-invented).
func radioRowOf(d *store.Device, radio string) (wireless.RadioRow, error) {
	for _, r := range wireless.StoredRadios(*d) {
		if r.Name == radio {
			return r, nil
		}
	}
	return wireless.RadioRow{}, fmt.Errorf("%w: radio %s", adminapi.ErrNotFound, radio)
}

// validateChannelIntent bounds a channel intent by the radio's band token.
// These are PHY-level NUMBER bounds only: country-specific legality
// (regulatory domain lists, DFS) lives in the jar's channel tables, which
// are not recovered in the tracked bytecode/docs — validating them would
// be guessing, so stricter checks are deliberately omitted (recorded as a
// bench obligation, docs/PROTOCOL-systemcfg-wireless.md §8).
func validateChannelIntent(r wireless.RadioRow, ch int) error {
	switch r.Band {
	case "ng": // 2.4 GHz: 0 (explicit auto) or 1..14
		if ch < 0 || ch > 14 {
			return fmt.Errorf("%w: channel %d out of range for band ng (0=auto, 1..14)", adminapi.ErrConflict, ch)
		}
	case "na": // 5 GHz: 0 (explicit auto) or 36..165
		if ch != 0 && (ch < 36 || ch > 165) {
			return fmt.Errorf("%w: channel %d out of range for band na (0=auto, 36..165)", adminapi.ErrConflict, ch)
		}
	default:
		// Real token set includes 6e/scan; intent semantics for those are
		// unrecovered — reject rather than ship unvalidated rows.
		return fmt.Errorf("%w: radio %s reports band %q; intent is only supported for the known provisioning bands (ng, na)",
			adminapi.ErrConflict, r.Name, r.Band)
	}
	return nil
}

// validateTxpowerIntent bounds a fixed dBm intent by the device-reported
// [min_txpower, max_txpower]; "auto" is always legal. Reading txpower as
// dBm follows those same radio_table fields' units (live-verified
// 6..22 on the U7PG2 6.8.2 record). A radio reporting no bounds cannot
// take a fixed value ("byte-exact or absent" — never guess a range).
func validateTxpowerIntent(r wireless.RadioRow, tx *adminapi.RadioTxPower) error {
	if tx.Auto {
		if r.Band != "ng" && r.Band != "na" {
			return fmt.Errorf("%w: radio %s reports band %q; intent is only supported for the known provisioning bands (ng, na)",
				adminapi.ErrConflict, r.Name, r.Band)
		}
		return nil
	}
	lo := wireless.JSONInt(r.Raw, "min_txpower")
	hi := wireless.JSONInt(r.Raw, "max_txpower")
	if lo == 0 && hi == 0 {
		return fmt.Errorf("%w: radio %s reports no txpower bounds (min_txpower/max_txpower); only \"auto\" is supported",
			adminapi.ErrConflict, r.Name)
	}
	if r.Band != "ng" && r.Band != "na" {
		return fmt.Errorf("%w: radio %s reports band %q; intent is only supported for the known provisioning bands (ng, na)",
			adminapi.ErrConflict, r.Name, r.Band)
	}
	if tx.DBm < lo || tx.DBm > hi {
		return fmt.Errorf("%w: txpower %d dBm outside the device-reported range [%d, %d]",
			adminapi.ErrConflict, tx.DBm, lo, hi)
	}
	return nil
}

// setRadioIntentExtra replaces the radio's entry in
// Extra["radio_intent"] wholesale (the admin API's PUT doctrine): absent
// fields drop from the entry, an empty entry removes the radio's key, and
// an empty map removes the whole layer (absent == empty on disk). Numbers
// are stored as float64 and "auto" as a string — exactly the scalars the
// JSON store round-trips and wireless.JSONStr formats back at render time.
// The copy into a fresh map never aliases store-owned values.
func setRadioIntentExtra(d *store.Device, radio string, up adminapi.RadioIntentUpsert) {
	if d.Extra == nil {
		d.Extra = store.JSONMap{}
	}
	cur, _ := d.Extra[wireless.RadioIntentExtraKey].(map[string]any)
	next := make(map[string]any, len(cur)+1)
	for k, v := range cur {
		next[k] = v
	}
	entry := map[string]any{}
	if up.Channel != nil {
		entry["channel"] = float64(*up.Channel)
	}
	if up.Txpower != nil {
		if up.Txpower.Auto {
			entry["txpower"] = "auto"
		} else {
			entry["txpower"] = float64(up.Txpower.DBm)
		}
	}
	if len(entry) == 0 {
		delete(next, radio)
	} else {
		next[radio] = entry
	}
	if len(next) == 0 {
		delete(d.Extra, wireless.RadioIntentExtraKey)
	} else {
		d.Extra[wireless.RadioIntentExtraKey] = next
	}
}

// intentChanged compares two parsed intent maps (Go maps are not
// ==-comparable; RadioIntent values are).
func intentChanged(before, after map[string]wireless.RadioIntent) bool {
	if len(before) != len(after) {
		return true
	}
	for k, v := range after {
		if before[k] != v {
			return true
		}
	}
	return false
}

// mintCfgVersion mints the 16-lowercase-hex cfgversion stamp
// (crypto/rand hex — the same shape and alphabet the server's
// randKeyChars(16) uses). The jar bumps device.cfgversion on operator
// config saves; the radio-intent save is open-unifi's operator-save path
// for these rows. The next inform still echoes the device's OLD applied
// version, so the engine's default arm full-provisions the new intent.
func mintCfgVersion() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cfgversion mint: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// radioView maps one radio_table row + its parsed intent to the read
// model; the echo fields use the exact formatting the renderer emits.
func radioView(r wireless.RadioRow, it wireless.RadioIntent) adminapi.RadioView {
	v := adminapi.RadioView{
		Name:            r.Name,
		Band:            r.Band,
		EchoChannel:     wireless.JSONStr(r.Raw, "channel", "0"),
		EchoTxPower:     wireless.JSONStr(r.Raw, "tx_power", "auto"),
		EchoTxPowerMode: wireless.JSONStr(r.Raw, "tx_power_mode", "auto"),
	}
	if it.Channel != "" {
		c := it.Channel
		v.Channel = &c
	}
	if it.Txpower != "" {
		p := it.Txpower
		v.Txpower = &p
	}
	return v
}

// ListDeviceRadios returns the per-radio view (device echo + admin
// intent) in radio_table name order.
func (a *App) ListDeviceRadios(_ context.Context, mac string) ([]adminapi.RadioView, error) {
	canon, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return nil, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}
	d, err := a.st.Get(canon)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, unknownDevice(canon)
		}
		return nil, fmt.Errorf("device store: %w", err)
	}
	intent := wireless.RadioIntents(d)
	rows := wireless.StoredRadios(d)
	out := make([]adminapi.RadioView, 0, len(rows))
	for _, r := range rows {
		out = append(out, radioView(r, intent[r.Name]))
	}
	return out, nil
}

// putRadioIntent is the shared PUT/DELETE core: validate against the
// device-reported radio row, replace the radio's intent wholesale, and
// bump the device's cfgversion ONLY on an effective change (idempotent
// writes never bump) — all inside the store's per-MAC RMW cycle so a
// concurrent inform cannot interleave.
func (a *App) putRadioIntent(canon, radio string, up adminapi.RadioIntentUpsert) (adminapi.RadioView, error) {
	var view adminapi.RadioView
	err := a.st.UpdateExisting(canon, func(d *store.Device) error {
		row, rerr := radioRowOf(d, radio)
		if rerr != nil {
			return rerr
		}
		if up.Channel != nil {
			if verr := validateChannelIntent(row, *up.Channel); verr != nil {
				return verr
			}
		}
		if up.Txpower != nil {
			if verr := validateTxpowerIntent(row, up.Txpower); verr != nil {
				return verr
			}
		}
		before := wireless.RadioIntents(*d)
		setRadioIntentExtra(d, radio, up)
		after := wireless.RadioIntents(*d)
		view = radioView(row, after[row.Name])
		if intentChanged(before, after) {
			nv, merr := mintCfgVersion()
			if merr != nil {
				return merr
			}
			d.CfgVersion = nv
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return adminapi.RadioView{}, unknownDevice(canon)
	}
	if err != nil {
		return adminapi.RadioView{}, err
	}
	return view, nil
}

// PutDeviceRadioIntent replaces the radio's admin intent wholesale and
// bumps cfgversion on effective changes (see putRadioIntent).
func (a *App) PutDeviceRadioIntent(_ context.Context, mac, radio string, up adminapi.RadioIntentUpsert) (adminapi.RadioView, error) {
	canon, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return adminapi.RadioView{}, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}
	return a.putRadioIntent(canon, radio, up)
}

// DeleteDeviceRadioIntent clears the radio's admin intent (wholesale
// clear == a PUT with every field absent).
func (a *App) DeleteDeviceRadioIntent(_ context.Context, mac, radio string) (adminapi.RadioView, error) {
	canon, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return adminapi.RadioView{}, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}
	return a.putRadioIntent(canon, radio, adminapi.RadioIntentUpsert{})
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
//
// Set-inform push contract (--allow-ssh-set-inform-push, lab-only):
// when the push lane is armed and the MAC's pending-candidate note is an
// announce-derived factory mark (a discovery note carrying factory=true,
// i.e. discovery TLV 23 present-and-true), a successful adopt ALSO means
// one SSH set-inform push was delivered to the candidate (the link a
// never-informed factory device needs to find this controller). A push
// failure is returned as a wrapped adminapi.ErrSetInformPushFailed (HTTP
// 502) with the whitelist promotion left standing — the operator can
// simply click Adopt again, one click = exactly one push attempt. Every
// other candidate shape (inform-noted, discovery note without a factory
// mark) keeps the whitelist-arming-only semantics above.
func (a *App) AdoptPending(ctx context.Context, mac string) (adminapi.DeviceView, error) {
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
	// The whitelist promotion is committed above; the push lane (when
	// armed) fires once here. A push failure surfaces wrapped
	// ErrSetInformPushFailed (HTTP 502) while the promotion stands.
	if perr := a.pushSetInform(ctx, mac); perr != nil {
		return adminapi.DeviceView{}, perr
	}
	return a.view(rec), nil
}

// ---- remote lifecycle commands (§6.5 reboot / §6.6 setdefault / §6.3 cmd) --

// RebootDevice arms the remote reboot: sets the admin-owned
// reboot_on_connect flag (the jar-verbatim §6.5 record field name), so
// the device's NEXT decoded inform answers
// {"_type":"reboot","reboot_type":"soft"} and the flag is consumed. The
// record's state, per-device key and cfgversion are untouched at arming
// time — the §6.2 mint-site list has no reboot entry.
func (a *App) RebootDevice(_ context.Context, mac string) (adminapi.DeviceView, error) {
	return a.armLifecycle(mac, adoption.FlagRebootOnConnect)
}

// FactoryResetDevice arms the factory reset: sets the admin-owned
// setdefault flag, so the device's NEXT decoded inform answers
// {"_type":"setdefault"} and the record then returns to the
// pending-candidate shape the existing default-key adoption path
// re-adopts (the demotion happens at emission, not at arming).
func (a *App) FactoryResetDevice(_ context.Context, mac string) (adminapi.DeviceView, error) {
	return a.armLifecycle(mac, adoption.FlagSetdefaultArmed)
}

// EnqueueDeviceCmd stores a §6.3 cmd task for the device
// (docs/PROTOCOL-mgmt.md §6.3): the record gains the admin-owned
// stored-task row (store.ArmCmdTask — at most one armed task, second
// enqueue REPLACES), and the device's NEXT decoded inform answers
// {"_type":"cmd", <stored task fields verbatim>} with the arming consumed
// one-shot by the adoption engine. Arming touches nothing else on the
// record — no §6.2 mint site exists for the replay. The cmd string is
// validated at the admin API boundary (ValidateCmdString) and stored
// verbatim; this Backend seam trusts the admin lane exactly like the
// blocked-client row helpers. Unknown MACs map to the wrapped ErrNotFound
// sentinel (HTTP 404).
func (a *App) EnqueueDeviceCmd(_ context.Context, mac, cmd string) (adminapi.DeviceView, error) {
	canon, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return adminapi.DeviceView{}, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}
	if err := a.st.UpdateExisting(canon, func(d *store.Device) error {
		store.ArmCmdTask(d, cmd)
		return nil
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.DeviceView{}, unknownDevice(canon)
		}
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	// Post-cycle read for the returned view: a detached deep copy, so the
	// response cannot alias store internals even transiently.
	d, err := a.st.Get(canon)
	if err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	return a.view(d), nil
}

// armLifecycle is the shared arming path for the admin remote-lifecycle
// commands: one admin-owned Extra flag set to true inside the store's
// per-MAC RMW cycle (a concurrent inform for the same device cannot
// interleave), everything else on the record untouched. The flag survives
// controller restarts (it is a persisted record row) and, being
// admin-owned, no inform body can introduce, forge or clear it — only
// the adoption engine consumes it (one-shot, on the next inform).
// Unknown MACs map to the wrapped ErrNotFound sentinel (HTTP 404).
func (a *App) armLifecycle(mac, flag string) (adminapi.DeviceView, error) {
	canon, cerr := store.CanonicalMAC(mac)
	if cerr != nil {
		return adminapi.DeviceView{}, fmt.Errorf("%w: %s (%v)", adminapi.ErrNotFound, mac, cerr)
	}
	if err := a.st.UpdateExisting(canon, func(d *store.Device) error {
		if d.Extra == nil {
			d.Extra = store.JSONMap{}
		}
		d.Extra[flag] = true
		return nil
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.DeviceView{}, unknownDevice(canon)
		}
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	// Post-cycle read for the returned view: a detached deep copy, so the
	// response cannot alias store internals even transiently.
	d, err := a.st.Get(canon)
	if err != nil {
		return adminapi.DeviceView{}, fmt.Errorf("device store: %w", err)
	}
	return a.view(d), nil
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

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
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/metrics"
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
// site settings to its own JSON file.
type App struct {
	st store.DeviceStore
	lg *slog.Logger

	// settingsPath is the JSON file holding the site-settings record
	// (site_settings.go), the wireless-envelope precedent for a
	// controller-level whole-document record.
	settingsPath string
	smu          sync.Mutex // guards the settings cache (Get/Put pairs)
	// cachedSettings is set EXACTLY ONCE by New (from the seed on first
	// boot, from the file otherwise); the site-settings verbs serve the
	// cache — no per-request file I/O.
	cachedSettings SiteSettings
	// settingsLoadErr is the error from that one eager load OR from the
	// first-boot seed persist; missing file is NOT an error (the seed
	// path is the happy path). Fixed at New time and surfaced by
	// CurrentSiteSettings so startup can refuse to launch.
	settingsLoadErr error
	// sweepFailed marks a site-settings mint sweep that failed mid-way
	// (site_settings.go): the record was already committed, but some
	// provisioned devices did not get their fresh cfgversion. A retry of
	// the SAME document must re-sweep instead of hitting the no-change
	// early return (which would answer 200 and leave the un-swept
	// devices nooping on stale intent until the next effective change).
	//
	// It is an atomic.Bool because PutSiteSettings is served
	// concurrently: one save's sweep can fail while another reads the
	// flag inside its smu section. An atomic read needs no lock, so the
	// leaf-lock doctrine is untouched (no thread holds smu while
	// acquiring a store lock, and the flag never participates in that
	// ordering). The flag is in-memory only: a crash — or a restart after
	// a failed sweep — loses it; the remaining recovery is the next
	// effective change, and a persisted marker is recorded as optional
	// future hardening (not implemented).
	sweepFailed atomic.Bool

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

// New builds the application backend. settingsPath + seed carry the
// site-settings record (site_settings.go): the file is read EXACTLY ONCE
// here, a present file wins over the seed (the startup flags are
// first-boot seeds only), and an absent file seeds, validates, and
// persists the seed immediately.
func New(st store.DeviceStore, settingsPath string, seed SiteSettings, lg *slog.Logger) *App {
	if lg == nil {
		lg = slog.Default()
	}
	// The logger is available before New returns: the loader warns once on
	// a stale removed key (the device_ssh_password peek) through it.
	settings, loaded, serr := loadSettingsFile(settingsPath, lg)
	settingsErr := serr
	if !loaded {
		// First boot: the seed (cmd/openunifi's startup flags, or the
		// zero record for tests/embedders) becomes the initial record.
		// Validation is the SAVE-verb rule (validateSiteSettingsChange):
		// the seed is admin intent — the same thing the save verb
		// validates — so an invalid seed is rejected exactly like an
		// equivalent API save (a rejected seed persists nothing and
		// produces the same settingsLoadErr → startup refusal as an
		// invalid disk file). The WEAK rule (validateSettingsSyntax)
		// stays at the disk-load site only: a hand-edited file must never
		// brick startup.
		if verr := validateSiteSettingsChange(seed); verr != nil {
			settingsErr = fmt.Errorf("first-boot site-settings seed: %w", verr)
		} else if perr := persistSettingsFile(settingsPath, seed); perr != nil {
			settingsErr = fmt.Errorf("site settings seed persist: %w", perr)
		}
		settings = seed
	}
	return &App{
		st:              st,
		lg:              lg,
		settingsPath:    settingsPath,
		cachedSettings:  settings,
		settingsLoadErr: settingsErr,
		prevStates:      map[string]int{},
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

// ---- admin-intent save skeleton -------------------------------------------
//
// Every admin-intent save — the admin verbs that change a device record —
// runs THE SAME sequence (CONTEXT.md "Admin intent"): canonicalize the MAC,
// validate and apply the change inside the device's RMW cycle, mint a fresh
// cfgversion when the change is EFFECTIVE, project the read view, and map a
// missing device to the canonical wrapped-404 error. saveIntent owns that
// sequence; a verb decodes its admin intent (the REST body spelled as a
// store change) and hands it over as two closures — no verb hand-rolls the
// pipeline, so mint conditions and 404/409 mapping cannot drift apart.
//
// The EIGHT routed save cores (the verbs riding the skeleton):
// CreateDevice (savePending mode — its seeding is its own change step and
// deliberately pending-map-INDEPENDENT, unlike AdoptPending whose change
// closure re-checks the pending map), AdoptPending, PatchDevice,
// BlockClient, UnblockClient, the per-radio intent core behind
// PutDeviceRadioIntent/DeleteDeviceRadioIntent, the lifecycle-arming core
// behind RebootDevice/FactoryResetDevice, and EnqueueDeviceCmd.
//
// Deliberate exclusions: DeleteDevice (a pure delete, not a save — the
// store's per-MAC delete owns its own cycle) and the per-device WLAN
// envelope verbs (Get/PutDeviceWireless and item CRUD persist device_wlans
// via saveIntent without cfgversion mint — drift-on-inform is the trigger).

// saveMode selects the RMW cycle the skeleton runs for a verb.
type saveMode int

const (
	// saveExisting is the plain device-record save: the record must
	// already exist (store.UpdateExisting), so the change can never
	// resurrect a deleted device.
	saveExisting saveMode = iota
	// savePending is the candidate promotion (AdoptPending): unknown MACs
	// are seeded empty (store.Update) and the change decides from the
	// pending map whether the promotion is legitimate.
	savePending
)

// saveIntent is the admin-intent save skeleton.
//
//	mac     — the admin-supplied MAC spelling; both an unparseable
//	          spelling and a missing record map to unknownDevice
//	          (errors.Is(err, adminapi.ErrNotFound) ⇒ HTTP 404).
//	change  — the verb's validate+apply step, run inside the store's
//	          per-MAC RMW closure: it consults and mutates ONLY the
//	          record handed to it, returns its ErrConflict/ErrNotFound
//	          wrapped rejections verbatim (the abort persists nothing),
//	          and reports whether the applied rows are EFFECTIVE —
//	          i.e. they change rows the device gets provisioned from
//	          (a save touching bookkeeping only passes false; a save
//	          that changes nothing mints nothing).
//	project — the read-model projection, run inside the same closure
//	          AFTER the optional mint so a bumped cfgversion is echoed
//	          in the same save; it runs on a record the store handed
//	          the cycle as a detached deep clone, so retaining the
//	          projection past the cycle aliases nothing.
//
// Errors other than store.ErrNotFound (unknown record) pass through
// verbatim — verbs own their sentinel wrapping; only the missing-device
// mapping is centralized.
//
// (A free function rather than an App method because the Go language
// version pins methods' type parameters to go1.27.)
func saveIntent[T any](a *App, mac string, mode saveMode, change func(d *store.Device) (bool, error), project func(d *store.Device) T) (T, error) {
	var zero T
	canon, err := store.CanonicalMAC(mac)
	if err != nil {
		return zero, unknownDevice(mac)
	}
	rmw := a.st.UpdateExisting
	if mode == savePending {
		rmw = a.st.Update
	}
	var out T
	err = rmw(canon, func(d *store.Device) error {
		effective, cerr := change(d)
		if cerr != nil {
			return cerr
		}
		if effective {
			// The single delivery trigger of the admin save: the jar
			// bumps device.cfgversion on operator config saves, so an
			// EFFECTIVE change mints a fresh stamp here — the device's
			// next inform still echoes the OLD applied stamp and the
			// engine's default arm full-provisions the new rows. A
			// save that changes nothing mints nothing (pinned by the
			// drift/noop suites).
			nv, merr := mintCfgVersion()
			if merr != nil {
				return merr
			}
			d.CfgVersion = nv
		}
		out = project(d)
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return zero, unknownDevice(canon)
		}
		return zero, err
	}
	return out, nil
}

// view maps a store record to the admin API read model. Actions is the
// minimal supported set (delete) and is omitted only if empty.
func (a *App) view(d store.Device) adminapi.DeviceView {
	desired := adminWlansFromDevice(d).Wlans
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
		SSHPassword:                d.SSHPassword,
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
	if flagArmed(d.Extra, store.FlagSetdefaultArmed) {
		return "factory-reset"
	}
	if flagArmed(d.Extra, store.FlagRebootOnConnect) {
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
// The vap_table wire keys are firmware-verified: devices report "essid" (not
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

// PatchDevice applies the admin's device-name/site/knob rows as one
// admin-intent save (see saveIntent): the fence validates every supplied
// row, the RMW cycle applies them, and an EFFECTIVE change — one of the
// provisioning-carried LED rows or the per-device SSH password — mints a
// fresh cfgversion; name/site_id
// are bookkeeping rows the device is never provisioned from, so they mint
// nothing.
func (a *App) PatchDevice(_ context.Context, mac string, patch adminapi.DevicePatch) (adminapi.DeviceView, error) {
	rec, err := saveIntent(a, mac, saveExisting,
		func(d *store.Device) (bool, error) {
			effective := false
			if patch.Name != nil {
				// Same fence the wlan flows apply (CreateWlan): the handler
				// 400s first, but every Backend caller is still fenced in.
				if msg := adminapi.ValidateDeviceName(*patch.Name); msg != "" {
					return false, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
				}
				d.Name = *patch.Name
			}
			if patch.SiteID != nil {
				// The site fence mirrors the name fence (route 400s
				// first; the Backend is the fence every direct caller
				// meets). "" is the explicit clear AT THE BACKEND door;
				// the route itself 400s "" (ValidateSiteID demands 1..64
				// characters), so site_id cannot be cleared via REST
				// today — a direct caller CAN clear it, which is the
				// deliberate asymmetry of the route-first/backend-fenced
				// split.
				if *patch.SiteID != "" {
					if msg := adminapi.ValidateSiteID(*patch.SiteID); msg != "" {
						return false, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
					}
				}
				d.SiteID = *patch.SiteID
			}
			if patch.LEDOverride != nil {
				// ValidateLEDOverride fence (same style as Name).
				// "default" is the explicit clear: the record's
				// canonical unset is "" (the jar's getString default
				// IS "default", so absence and "default" mean the same
				// wire value — §2 treats them alike).
				if msg := adminapi.ValidateLEDOverride(*patch.LEDOverride); msg != "" {
					return false, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
				}
				next := ""
				if *patch.LEDOverride != "default" {
					next = *patch.LEDOverride
				}
				if next != d.LEDOverride {
					effective = true
				}
				d.LEDOverride = next
			}
			if patch.LEDOverrideColorBrightness != nil {
				// ValidateLEDOverrideColorBrightness fence (same fence
				// style). 100 is the explicit clear: the record's
				// canonical unset is nil, because the jar's getInt
				// default IS 100 (config_String.txt:2627-2630) — a
				// saved 100 and an absent knob render the same §12 row.
				// Every other in-domain value, including 0, is the
				// admin's explicit pick.
				if msg := adminapi.ValidateLEDOverrideColorBrightness(*patch.LEDOverrideColorBrightness); msg != "" {
					return false, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
				}
				var next *int
				if *patch.LEDOverrideColorBrightness != 100 {
					v := *patch.LEDOverrideColorBrightness
					next = &v
				}
				if !intPtrEq(next, d.LEDOverrideColorBrightness) {
					effective = true
				}
				d.LEDOverrideColorBrightness = next
			}
			if patch.LEDOverrideColor != nil {
				// No format fence for the color ON PURPOSE: the §12
				// render owns the fallback (Color.decode — unparseable
				// values land on #0000ff, config_String.txt:2669-2678);
				// the jar accepts any string in this knob and so does
				// the record. "" is the explicit clear (the jar's
				// getString default is "#0000ff").
				if *patch.LEDOverrideColor != d.LEDOverrideColor {
					effective = true
				}
				d.LEDOverrideColor = *patch.LEDOverrideColor
			}
			if patch.SSHPassword != nil {
				// Pointer semantics mirror LEDOverrideColor: nil =
				// untouched; non-nil "" = STOP MANAGING (the render
				// reuses the last controller-pushed password hash, so
				// the device keeps its current password); non-empty = set.
				// "" is the explicit clear AT THE BACKEND door (the
				// route note rides adminapi.DevicePatch.SSHPassword).
				// Effective = the value differs: a set mints cfgversion
				// so the next deliverable provisioning carries the new
				// hashed row; a clear mints too (the pushed row changes
				// only when the keyed render would differ, but the
				// intent stamp flaps with the record value either way).
				if *patch.SSHPassword != d.SSHPassword {
					effective = true
				}
				d.SSHPassword = *patch.SSHPassword
			}
			return effective, nil
		},
		func(d *store.Device) store.Device {
			// Detached snapshot for the returned view: scalars only —
			// the inform passthrough (Extra), stats (LastUps) and key
			// history (Authkeys) never belong on a device-row echo,
			// and a save response must not leak the inform body it
			// merely raced.
			rec := *d
			rec.LastUps = nil
			rec.Extra = nil
			rec.Authkeys = nil
			return rec
		})
	if err != nil {
		return adminapi.DeviceView{}, err
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
// PENDING). The save routes through the admin-intent skeleton (saveIntent,
// savePending mode): the RMW cycle is the upsert — unknown MACs are seeded
// empty and the change step seeds the pending-candidate rows — so the
// previous Get→mutate→Put interleave loss is structurally impossible.
// Duplicate posts are an idempotent upsert: the existing record is returned
// and its name/site updated, so provider re-applies never surface conflict
// errors. Invalid MACs map to the skeleton's canonical wrapped-404 error
// (adminapi itself 400s at the edge; this adapter-side mapping is the
// backstop for other callers). The cycle reports never-effective: seeding
// is not a provisioning change, so no cfgversion is minted — the device
// gets everything it needs when its first inform reaches the adoption
// engine.
func (a *App) CreateDevice(_ context.Context, up adminapi.DeviceUpsert) (adminapi.DeviceView, error) {
	created := false
	rec, err := saveIntent(a, up.MAC, savePending,
		func(d *store.Device) (bool, error) {
			// Seed step (own step, pending-map-INDEPENDENT — unlike
			// AdoptPending, whose change closure re-checks the map): a
			// manually created device is by definition known to the admin
			// (CONTEXT.md: create is the manual whitelist entry).
			if d.State == 0 { // freshly seeded by the upsert: record did not exist
				created = true
				d.State = store.StatePending
				d.FirstSeen = time.Now().Unix()
			}
			if up.Name != "" {
				// Same fence the other admin verbs apply (route 400s
				// first; the Backend is the fence every direct caller
				// meets).
				if msg := adminapi.ValidateDeviceName(up.Name); msg != "" {
					return false, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
				}
				d.Name = up.Name
			}
			if up.SiteID != "" {
				// The site fence mirrors PatchDevice/PutWireless-adjacent
				// fences: never-effective bookkeeping rows, but domain-
				// validated on the way in.
				if msg := adminapi.ValidateSiteID(up.SiteID); msg != "" {
					return false, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
				}
				d.SiteID = up.SiteID
			}
			// Never effective: seeding + bookkeeping rows only — the save
			// mints no cfgversion (no §6.2 mint site for manual create).
			return false, nil
		},
		// Detached snapshot for the returned view (view reads scalars only).
		func(d *store.Device) store.Device {
			return store.Device{
				MAC: d.MAC, Name: d.Name, Model: d.Model, Firmware: d.Firmware,
				IP: d.IP, State: d.State, LastSeen: d.LastSeen,
				CfgVersion: d.CfgVersion, AppliedCfg: d.AppliedCfg,
			}
		})
	if err != nil {
		return adminapi.DeviceView{}, err
	}
	a.lg.Debug("device created/updated via admin api", "mac", store.ColonMAC(rec.MAC),
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

// BlockClient adds one client MAC to the device's blocked-client set
// (the store.BlockedStaExtraKey admin-owned Extra row). Idempotent:
// re-blocking returns the unchanged set, like the adopt route's
// state-change semantics. The set is delivered by the engine inside full
// provisioning on the next inform via its blocked_sta drift — no
// admin-time cfgversion mint (change reports never-effective, an
// instance of the saveIntent contract).
func (a *App) BlockClient(_ context.Context, mac, client string) (adminapi.BlockedClientsView, error) {
	canon, cclient, perr := blockedPair(mac, client)
	if perr != nil {
		return adminapi.BlockedClientsView{}, perr
	}
	return saveIntent(a, canon, saveExisting,
		func(d *store.Device) (bool, error) {
			if _, err := store.AddBlockedClient(d, cclient); err != nil {
				return false, err
			}
			return false, nil
		},
		// Render INSIDE the closure via the project step: the record the
		// cycle hands over is detached for the whole cycle anyway, but
		// the set view must reflect exactly the rows this save committed.
		func(d *store.Device) adminapi.BlockedClientsView {
			return blockedClientsView(canon, store.BlockedClients(*d))
		})
}

// UnblockClient removes one client MAC from the device's blocked-client
// set. A client that is not currently blocked is ErrNotFound (the route
// maps it to 404, mirroring DeleteDevice/DeleteWlan semantics). saveIntent
// passes the not-blocked sentinel error through verbatim — it already
// carries the canonical 404 shape — while a missing DEVICE record is
// mapped centrally.
func (a *App) UnblockClient(_ context.Context, mac, client string) (adminapi.BlockedClientsView, error) {
	canon, cclient, perr := blockedPair(mac, client)
	if perr != nil {
		return adminapi.BlockedClientsView{}, perr
	}
	return saveIntent(a, canon, saveExisting,
		func(d *store.Device) (bool, error) {
			removed, rerr := store.RemoveBlockedClient(d, cclient)
			if rerr != nil {
				return false, rerr
			}
			if !removed {
				return false, fmt.Errorf("%w: client not blocked: %s", adminapi.ErrNotFound, store.ColonMAC(cclient))
			}
			return false, nil
		},
		func(d *store.Device) adminapi.BlockedClientsView {
			return blockedClientsView(canon, store.BlockedClients(*d))
		})
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
	cur, _ := d.Extra[store.RadioIntentExtraKey].(map[string]any)
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
		delete(d.Extra, store.RadioIntentExtraKey)
	} else {
		d.Extra[store.RadioIntentExtraKey] = next
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

// putRadioIntent is the shared PUT/DELETE core: the admin intent (a
// channel/txpower replacement for one radio row) is validated against the
// device-reported radio_table row and applied as ONE admin-intent save
// (see saveIntent) — replacing the radio's intent wholesale inside the RMW
// cycle and bumping the device's cfgversion ONLY on an effective change
// (idempotent writes never bump). Unknown radio names are ErrNotFound from
// the change (HTTP 404 — the name is a device-reported key, not
// admin-invented); band/bounds violations are ErrConflict (HTTP 409).
func (a *App) putRadioIntent(mac, radio string, up adminapi.RadioIntentUpsert) (adminapi.RadioView, error) {
	var row wireless.RadioRow
	return saveIntent(a, mac, saveExisting,
		func(d *store.Device) (bool, error) {
			r, rerr := radioRowOf(d, radio)
			if rerr != nil {
				return false, rerr
			}
			row = r
			if up.Channel != nil {
				if verr := validateChannelIntent(r, *up.Channel); verr != nil {
					return false, verr
				}
			}
			if up.Txpower != nil {
				if verr := validateTxpowerIntent(r, up.Txpower); verr != nil {
					return false, verr
				}
			}
			before := wireless.RadioIntents(*d)
			setRadioIntentExtra(d, radio, up)
			return intentChanged(before, wireless.RadioIntents(*d)), nil
		},
		func(d *store.Device) adminapi.RadioView {
			return radioView(row, wireless.RadioIntents(*d)[row.Name])
		})
}

// PutDeviceRadioIntent replaces the radio's admin intent wholesale and
// bumps cfgversion on effective changes (see putRadioIntent).
func (a *App) PutDeviceRadioIntent(_ context.Context, mac, radio string, up adminapi.RadioIntentUpsert) (adminapi.RadioView, error) {
	return a.putRadioIntent(mac, radio, up)
}

// DeleteDeviceRadioIntent clears the radio's admin intent (wholesale
// clear == a PUT with every field absent).
func (a *App) DeleteDeviceRadioIntent(_ context.Context, mac, radio string) (adminapi.RadioView, error) {
	return a.putRadioIntent(mac, radio, adminapi.RadioIntentUpsert{})
}

// ListPending lists the console's pending rows from the pending map — the
// single liveness source for who is currently announce/inform-known.
//
// The listing includes TWO shapes:
//   - unheard candidates (no device record yet), and
//   - existing StatePending records that still carry a live map note —
//     a record demoted back to the pending-candidate shape by factory
//     reset (returning to state 1 until its next factory-key inform), or
//     one just promoted and awaiting its first inform. Surfacing the
//     latter lets the operator re-click Adopt on a factory-reset device
//     with NO Forget step: AdoptPending's existing-record branch re-
//     promotes state-1 records idempotently, one click = one push
//     attempt per its documented contract.
//
// Records in any other state (adopted/lost) are no longer candidates and
// are skipped even when a stale note lingers. The Name column is filled
// from the record; stranger candidates render empty.
func (a *App) ListPending(_ context.Context) []adminapi.PendingView {
	pend, err := a.st.Pending()
	if err != nil {
		a.lg.Warn("list pending: store error", "err", err)
		return []adminapi.PendingView{}
	}
	out := make([]adminapi.PendingView, 0, len(pend))
	for mac, note := range pend {
		d, err := a.st.Get(mac)
		if err == nil && d.State != store.StatePending {
			continue // record exists in a non-candidate state; not adoptable
		}
		pv := adminapi.PendingView{MAC: store.ColonMAC(mac), Source: note}
		if err == nil {
			// A state-1 record: surface its admin-assigned name so the
			// console shows a KNOWN device, not a stranger.
			pv.Name = d.Name
		}
		out = append(out, pv)
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
	rec, err := saveIntent(a, mac, savePending,
		func(d *store.Device) (bool, error) {
			// The RMW cycle seeds unknown MACs (savePending); a seeded
			// record (State 0) is only promotable if the pending map has
			// heard the candidate — the check and the write share THIS
			// cycle, so a concurrent inform cannot interleave.
			if d.State == 0 { // freshly seeded by the upsert: no device record yet
				pend, perr := a.st.Pending()
				if perr != nil {
					return false, fmt.Errorf("device store: %w", perr)
				}
				if _, ok := pend[d.MAC]; !ok {
					// Unknown AND never heard on discovery/inform: not-found.
					return false, fmt.Errorf("%w: %s", adminapi.ErrNotFound, d.MAC)
				}
				d.State = store.StatePending
				d.FirstSeen = time.Now().Unix()
			} else if d.State != store.StatePending {
				return false, fmt.Errorf("adopt: device %s is already in state %d", store.ColonMAC(d.MAC), d.State)
			}
			// Records in any non-PENDING state already returned above; only
			// fresh candidates (pending map only) and PENDING records persist.
			return false, nil
		},
		func(d *store.Device) store.Device {
			// The promotion response echoes the whitelist shape (the
			// record before any inform handshake key/heartbeat has
			// landed): scalars only, no cfgversion yet.
			return store.Device{
				MAC: d.MAC, Name: d.Name, Model: d.Model, Firmware: d.Firmware,
				IP: d.IP, State: d.State, LastSeen: d.LastSeen,
			}
		})
	if err != nil {
		return adminapi.DeviceView{}, err
	}
	a.lg.Debug("device promoted to pending", "mac", store.ColonMAC(rec.MAC))
	// The whitelist promotion is committed above; the push lane (when
	// armed) fires once here. A push failure surfaces wrapped
	// ErrSetInformPushFailed (HTTP 502) while the promotion stands.
	if perr := a.pushSetInform(ctx, rec.MAC); perr != nil {
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
	return a.armLifecycle(mac, store.FlagRebootOnConnect)
}

// FactoryResetDevice arms the factory reset: sets the admin-owned
// setdefault flag, so the device's NEXT decoded inform answers
// {"_type":"setdefault"} and the record then returns to the
// pending-candidate shape the existing default-key adoption path
// re-adopts (the demotion happens at emission, not at arming).
func (a *App) FactoryResetDevice(_ context.Context, mac string) (adminapi.DeviceView, error) {
	return a.armLifecycle(mac, store.FlagSetdefaultArmed)
}

// EnqueueDeviceCmd stores a §6.3 cmd task for the device
// (docs/PROTOCOL-mgmt.md §6.3): the record gains the admin-owned
// stored-task row (CmdTaskKey — at most one armed task, second enqueue
// REPLACES), and the device's NEXT decoded inform answers
// {"_type":"cmd", <stored task fields verbatim>} with the arming consumed
// one-shot by the adoption engine. Arming touches nothing else on the
// record — no §6.2 mint site exists for the replay, so the save never
// reports effective. The cmd string is fenced BY THE BACKEND (the same
// shape the route 400s with): the admin lane is decoded, then the
// skeleton's change step validates and applies the row. Unknown MACs map
// to the wrapped ErrNotFound sentinel (HTTP 404).
func (a *App) EnqueueDeviceCmd(_ context.Context, mac, cmd string) (adminapi.DeviceView, error) {
	rec, err := saveIntent(a, mac, saveExisting,
		func(d *store.Device) (bool, error) {
			if msg := adminapi.ValidateCmdString(cmd); msg != "" {
				return false, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
			}
			store.ArmCmdTask(d, cmd)
			return false, nil
		},
		// The whole record snapshot: the view's PendingCommand reads the
		// armed rows out of Extra, so this save echoes them (unlike the
		// device-row save above, which never drops passthrough state).
		func(d *store.Device) store.Device { return *d })
	if err != nil {
		return adminapi.DeviceView{}, err
	}
	return a.view(rec), nil
}

// armLifecycle is the shared arming path for the admin remote-lifecycle
// commands: the admin-owned Extra flag (FlagRebootOnConnect /
// FlagSetdefaultArmed) is set to true as ONE admin-intent save inside the
// device's RMW cycle (a concurrent inform for the same device cannot
// interleave), everything else on the record untouched — the save never
// reports effective (no §6.2 mint site exists for either response). The
// flag survives controller restarts (it is a persisted record row) and,
// being admin-owned, no inform body can introduce, forge or clear it —
// only the adoption engine consumes it (one-shot, on the next inform).
// Unknown MACs map to the wrapped ErrNotFound sentinel (HTTP 404).
func (a *App) armLifecycle(mac, flag string) (adminapi.DeviceView, error) {
	rec, err := saveIntent(a, mac, saveExisting,
		func(d *store.Device) (bool, error) {
			if d.Extra == nil {
				d.Extra = store.JSONMap{}
			}
			d.Extra[flag] = true
			return false, nil
		},
		// The whole record snapshot: the view's PendingCommand reads the
		// armed rows out of Extra, so an armed state is echoed immediately.
		func(d *store.Device) store.Device { return *d })
	if err != nil {
		return adminapi.DeviceView{}, err
	}
	return a.view(rec), nil
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

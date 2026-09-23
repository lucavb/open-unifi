// Site settings are the controller-level device-intent document: the two
// device-intent site facts that used to live only in startup flags — the
// regulatory country code and the ordered SSH authorized_keys lines. (The
// Device SSH password used to be the third: the site-wide concept is REMOVED —
// the per-device SSH password rides the device record itself,
// store.Device.SSHPassword, set via PATCH /api/v1/devices/{mac}.)
//
// It follows the wireless-envelope precedent exactly: an app-owned JSON
// file (`<data-dir>/site-settings.json`) loaded EXACTLY ONCE in New,
// cached, and replaced wholesale on change. The startup flags become
// first-boot seeds: a file already on disk wins, the seed is ignored.
// Record absorption (store trust policy) cannot touch this record — it
// sits outside the device record entirely, so no inform body can write
// it (pinned in site_settings_test.go).
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/server/systemcfg"
	"github.com/lucavb/open-unifi/internal/store"
)

// SiteSettings is the persisted controller-level device-intent record. The
// zero value carries exactly the semantics of the old flag defaults:
// CountryCode 0 renders as the 840 default at the server seam, and no keys
// render as no sshd.auth.key rows.
type SiteSettings struct {
	// CountryCode is the ISO 3166-1 numeric regulatory country code.
	// 0 = unset (renders as the default 840 at the server seam).
	CountryCode int
	// SSHPublicKeys are the ordered authorized_keys lines, each a
	// validated RFC 4253 line, stored VERBATIM (raw lines, not parsed
	// structs — parsing belongs to the render seam). The order is the
	// sshd.auth.key.<n> ordering, so an order-only diff is an effective
	// change (harmless re-provisioning, pinned by test).
	SSHPublicKeys []string
}

// toDocument converts the record to the admin-API wire shape (which is
// also the on-disk JSON shape of site-settings.json). The keys list is
// NEVER nil in the wire shape (a missing key list is an empty list, never
// null — the whole-document PUT semantics are reconcilable), matching the
// repo doctrine that JSON lists read by tooling are never null.
func (s SiteSettings) toDocument() adminapi.SiteSettingsDocument {
	keys := s.SSHPublicKeys
	if keys == nil {
		keys = []string{}
	}
	return adminapi.SiteSettingsDocument{
		RegulatoryCountryCode: s.CountryCode,
		DeviceSSHPublicKeys:   keys,
	}
}

// siteSettingsFromDoc converts an API/wire document into the record. A nil
// key list becomes an empty (never nil) list so cached records always hold
// usable slices.
func siteSettingsFromDoc(doc adminapi.SiteSettingsDocument) SiteSettings {
	keys := doc.DeviceSSHPublicKeys
	if keys == nil {
		keys = []string{}
	}
	return SiteSettings{
		CountryCode:   doc.RegulatoryCountryCode,
		SSHPublicKeys: keys,
	}
}

// projectSettingsView returns the read view of a record, detached: the key
// list is copied so a caller mutating the returned slice never aliases the
// cache (pinned in site_settings_test.go).
func projectSettingsView(s SiteSettings) adminapi.SiteSettingsView {
	keys := append([]string(nil), s.SSHPublicKeys...)
	if keys == nil {
		keys = []string{}
	}
	return adminapi.SiteSettingsView{
		RegulatoryCountryCode: s.CountryCode,
		DeviceSSHPublicKeys:   keys,
	}
}

// validateSiteSettingsChange is the SAVE verb's validation: CountryCode
// must be 0 (= unset, renders as the server-side 840 default) or an ISO
// 3166-1 numeric code 1..999; every key line must pass the single
// fail-closed RFC 4253 parser (systemcfg.ParsePublicKey — no other
// validator exists for this shape). All validation failures wrap the
// adminapi.ErrInvalid sentinel so handleBackendErr maps them to HTTP 400
// with the human message echoed.
func validateSiteSettingsChange(s SiteSettings) error {
	if code := s.CountryCode; code != 0 && (code < 1 || code > 999) {
		return fmt.Errorf("%w: regulatory country code must be an ISO 3166-1 numeric code from 001 to 999 (or 0 = unset), got %d",
			adminapi.ErrInvalid, code)
	}
	for i, line := range s.SSHPublicKeys {
		if _, err := systemcfg.ParsePublicKey(line); err != nil {
			return fmt.Errorf("%w: invalid Device SSH public key #%d: %v", adminapi.ErrInvalid, i+1, err)
		}
	}
	return nil
}

// validateSettingsSyntax is the DISK-LOAD rule, deliberately weaker than
// the save verb's; its ONLY caller is loadSettingsFile. It checks key-line
// syntax (same single parser, fail-closed) and the country range. The
// weaker rule exists so a hand-edited or foreign-written
// site-settings.json that is syntactically valid does not brick startup.
func validateSettingsSyntax(s SiteSettings) error {
	if code := s.CountryCode; code != 0 && (code < 1 || code > 999) {
		return fmt.Errorf("regulatory country code must be an ISO 3166-1 numeric code from 001 to 999 (or 0 = unset), got %d", code)
	}
	for i, line := range s.SSHPublicKeys {
		if _, err := systemcfg.ParsePublicKey(line); err != nil {
			return fmt.Errorf("invalid Device SSH public key #%d: %w", i+1, err)
		}
	}
	return nil
}

// loadSettingsFile reads and decodes the site-settings document exactly
// once (called from New); the same loader-discipline as loadWirelessFile:
// a missing file yields (zero, false, nil) — first boot, callers seed —
// while an unreadable, corrupt, or INVALID file yields (zero, true, a
// real error) that App retains as settingsLoadErr until the startup check
// refuses to launch (loaded=true: the file EXISTS, the seed must not
// silently overwrite it). A present file WINS over the seed: the startup
// flags are first-boot seeds only.
func loadSettingsFile(path string, lg *slog.Logger) (SiteSettings, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return SiteSettings{}, false, nil
	}
	if err != nil {
		return SiteSettings{}, true, fmt.Errorf("site settings file unreadable %s: %w", path, err)
	}
	// Stale-key peek: the struct decode below silently DROPs the removed
	// site password key (no field to land in), so a deployer-carrying
	// site-settings.json would fold it away with zero diagnostics. Peek
	// the RAW bytes and warn once when the HISTORICAL key is present —
	// the removed site-level field `ap_ssh_password` is what GHCR-era
	// deployed site-settings.json files actually carry ("device_ssh_password"
	// never existed on disk), and old-client names live only here, in
	// migration contexts. Ignored, with NO value migration (a migration
	// would resurrect site semantics under a per-device name: the
	// per-device password must be set explicitly per device instead).
	var peek map[string]any
	if jsonErr := json.Unmarshal(raw, &peek); jsonErr == nil {
		if _, stale := peek["ap_ssh_password"]; stale {
			lg.Warn("site settings: the removed \"ap_ssh_password\" key is ignored — no value migration; per-device SSH passwords are set via PATCH /api/v1/devices/{mac} (Terraform open-unifi_access_point)")
		}
	}
	var doc adminapi.SiteSettingsDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return SiteSettings{}, true, fmt.Errorf("site settings file corrupt %s: %w", path, err)
	}
	s := siteSettingsFromDoc(doc)
	if err := validateSettingsSyntax(s); err != nil {
		return SiteSettings{}, true, fmt.Errorf("site settings file %s: %w", path, err)
	}
	return s, true, nil
}

// persistSettingsFile atomically writes the settings document (temp file +
// fsync + rename + directory fsync — the same durability contract as the
// wireless persist). The temp file is created with 0600: the document is
// controller-level admin content, so it is never world-readable on disk,
// not even between rename and chmod-sweep.
func persistSettingsFile(path string, s SiteSettings) error {
	blob, err := json.MarshalIndent(s.toDocument(), "", "  ")
	if err != nil {
		return fmt.Errorf("site settings marshal: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("site settings temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("site settings chmod: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("site settings write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("site settings fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("site settings close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("site settings rename: %w", err)
	}
	tmpName = ""
	syncDir(dir) // best effort: make the rename itself durable
	return nil
}

// GetSiteSettings returns the site settings read view, read from the
// cache as a detached copy. The returned error is REAL, not reserved: it
// reports the New-time load problem of a present-but-unreadable/corrupt/
// invalid settings file (missing file is not an error — it was seeded).
func (a *App) GetSiteSettings(_ context.Context) (adminapi.SiteSettingsView, error) {
	s, err := a.currentSiteSettings()
	if err != nil {
		return adminapi.SiteSettingsView{}, err
	}
	return projectSettingsView(s), nil
}

// currentSiteSettings is the shared cache reader behind GetSiteSettings
// (admin API) and CurrentSiteSettings (wiring seam, below).
func (a *App) currentSiteSettings() (SiteSettings, error) {
	a.smu.Lock()
	defer a.smu.Unlock()
	if a.settingsLoadErr != nil {
		return SiteSettings{}, fmt.Errorf("site settings: %w", a.settingsLoadErr)
	}
	s := a.cachedSettings
	s.SSHPublicKeys = append([]string(nil), a.cachedSettings.SSHPublicKeys...)
	return s, nil
}

// CurrentSiteSettings exposes the cached record without the Backend
// shape, for wiring-side use (the server sources the device-intent site
// facts from here — including from inside the engine's decision
// path, which is exactly why smu must stay a leaf lock: this reader takes
// smu while the caller may already hold a per-MAC store lock). Mirrors
// CurrentWireless: the error is REAL — the New-time load/persist error —
// and cmd/openunifi checks it before launching.
func (a *App) CurrentSiteSettings() (SiteSettings, error) {
	return a.currentSiteSettings()
}

// siteSettingsChanged reports an EFFECTIVE change under the save verb's
// doctrine: any difference in the two facts. The key list comparison is
// ORDER-SENSITIVE — the list is provisioned as sshd.auth.key.<n> rows in
// order, so a reorder IS a different intended config. An order-only diff
// therefore mints one harmless re-provisioning (idempotent content, the
// device echoes the new cfgversion and noops thereafter; pinned by test).
func siteSettingsChanged(before, after SiteSettings) bool {
	return before.CountryCode != after.CountryCode ||
		!slices.Equal(before.SSHPublicKeys, after.SSHPublicKeys)
}

// PutSiteSettings is the site-settings admin-intent save — the same
// doctrine as the device-record saves (saveIntent, app.go): validate,
// apply inside the write cycle, MINT cfgversion on EFFECTIVE change,
// project the read view. It differs from saveIntent not just in target
// (a controller-level document, not a device record) but also in mint
// shape: cfgversion is PER-DEVICE, so an effective site change sweeps a
// fresh stamp across every provisioned device instead of stomping one
// record field (see the mint-site comment inside).
//
// LOCK SHAPE (the whole reason this verb is shaped the way it is): smu is
// held ONLY for the apply (no-change early return, wholesale replace,
// disk persist, cache swap) and is RELEASED before any store call. The
// sweep below runs with smu held nowhere. That makes smu a leaf lock by
// construction: Phase B wires CurrentSiteSettings (smu) into the engine's
// decision path, which runs inside the store's per-MAC RMW (macLock →
// smu) — a PUT that held smu across st.List/st.UpdateExisting (smu →
// macLock) would be a live AB-BA deadlock under concurrent inform
// traffic. No thread may hold smu while acquiring a store lock.
//
// Validation failures wrap adminapi.ErrInvalid (HTTP 400), mirroring the
// ErrConflict/409 arm of handleBackendErr. On a persist error the cache
// is left untouched and the error propagates — disk and memory can never
// disagree (the PutWireless discipline).
func (a *App) PutSiteSettings(_ context.Context, doc adminapi.SiteSettingsDocument) (adminapi.SiteSettingsView, error) {
	var zero adminapi.SiteSettingsView
	next := siteSettingsFromDoc(doc)
	if err := validateSiteSettingsChange(next); err != nil {
		return zero, err
	}

	// ---- the locked apply section (smu ONLY; no store calls inside) ----
	a.smu.Lock()
	if a.settingsLoadErr != nil {
		a.smu.Unlock()
		return zero, fmt.Errorf("site settings: %w", a.settingsLoadErr)
	}
	changed := siteSettingsChanged(a.cachedSettings, next)
	// A save that changes nothing mints nothing (the no-op save is pinned
	// by test) — EXCEPT when a previous sweep failed mid-way
	// (a.sweepFailed): then the same document is re-swept below instead
	// of being answered 200 with some devices still missing their mint.
	if !changed && !a.sweepFailed.Load() {
		view := projectSettingsView(a.cachedSettings)
		a.smu.Unlock()
		return view, nil
	}
	if changed {
		// Wholesale replace: persist FIRST (crash between persist and
		// sweep = the on-disk record is already the new intent), then
		// swap the cache, then sweep the mints below (outside this
		// section). On a sweepFailed retry there is nothing to persist
		// or swap — the record already holds exactly this document; only
		// the interrupted mints need re-delivery.
		if err := persistSettingsFile(a.settingsPath, next); err != nil {
			a.smu.Unlock()
			return zero, err
		}
		a.cachedSettings = next
	}
	a.smu.Unlock()
	// smu RELEASED: everything below is store work and must never re-take
	// smu (see the lock-shape comment above).

	minted, err := a.runSettingsMintSweep()
	if err != nil {
		// The record is already committed (persist + cache swap ran);
		// runSettingsMintSweep marked the sweep as failed so the next
		// PUT of this same document re-sweeps instead of returning a
		// silent 200.
		return zero, err
	}
	if changed && len(next.SSHPublicKeys) > 0 {
		// Mirrors the startup warn (cmd/openunifi, same document):
		// the app layer does not know whether the live gate was lifted
		// via --allow-gated-live-wlan, so the warn fires on the FACTS —
		// and it is honest either way: it says pushes stay gated BEHIND
		// the flag, not that they are blocked. One line per effective
		// save (not per device, and not on a sweepFailed retry — a
		// retry arms nothing new).
		a.lg.Warn("ssh site facts saved into the site-settings record: the sshd.auth.key rows are firmware-derived but NOT yet live-bench-validated — live pushes stay gated behind --allow-gated-live-wlan (docs/PROTOCOL-systemcfg-wireless.md §13, bench use only)")
	}
	a.lg.Debug("site settings replaced",
		"country_code", next.CountryCode,
		"keys", len(next.SSHPublicKeys),
		"devices_minted", minted)
	// Project from the LOCAL record, not the cache: `next` is exactly what
	// this save swapped in (or, on a sweepFailed retry, already equals the
	// cache), and re-reading the cache would mean re-taking smu after
	// store work (the lock-shape rule) — while a concurrent effective save
	// could have legitimately swapped a newer document in that is not
	// this save's read view.
	return projectSettingsView(next), nil
}

// runSettingsMintSweep runs ONE bounded mint-sweep attempt (the store
// method shape rides the device RMW cycle, see the sweep commentary below)
// and maintains a.sweepFailed: any error marks the sweep failed so the next
// PUT of the same document re-sweeps instead of silently no-oping, and only
// a sweep that completes without error clears the flag. It is called with
// NO lock held (smu is a leaf lock — never held across store calls) and
// never takes a lock itself; the flag is an atomic, so concurrent PUTs
// (each running at most this one bounded sweep attempt) cannot deadlock or
// corrupt it.
func (a *App) runSettingsMintSweep() (int, error) {
	minted, err := a.sweepSiteCfgVersionMints()
	if err != nil {
		a.sweepFailed.Store(true)
		return minted, err
	}
	a.sweepFailed.Store(false)
	return minted, nil
}

// sweepSiteCfgVersionMints is the sweep body proper (no flag bookkeeping —
// runSettingsMintSweep owns that).
func (a *App) sweepSiteCfgVersionMints() (int, error) {
	minted := 0
	devices, err := a.st.List()
	if err != nil {
		return minted, fmt.Errorf("site settings mint sweep list: %w", err)
	}
	// ---- the MINT SWEEP: one fresh cfgversion per provisioned device ----
	//
	// Site settings mint on save, not in the engine's drift arms. Reasons:
	// 1. cfgversion is the single per-device intent stamp and the sshd rows are not
	//    inform-observable, so an engine-side site-fact hash would need per-device
	//    offered-hash bookkeeping duplicating exactly what cfgversion already is.
	// 2. The engine stays blind to site facts — they enter only at render.
	// 3. The pending-delivery gate's operator-mint escape (engine.go:645) frees an
	//    externally minted cfgversion, the same shape as an operator device-save.
	//
	// Settings are persisted before the sweep; a CRASH mid-sweep leaves
	// the un-swept subset nooping until the next effective change
	// (self-healing, matches the single-process local-file persistence
	// posture of the rest of the store). A FAILED sweep (persist
	// succeeded, a store error mid-sweep) used to be a silent hole — the
	// no-change early return answered a retry with 200 and nothing
	// re-swept — but a.sweepFailed now carries the failure, so the next
	// PUT of the same document re-sweeps. The flag is in-memory only: a
	// restart (or a crash) after a failed sweep loses it and falls back
	// to the next-effective-change healing; a persisted marker is
	// recorded as optional future hardening, not implemented. A
	// persistently failing store cannot loop: each PUT runs at most this
	// one bounded sweep attempt.
	//
	// Concurrent sweeps may interleave (two effective saves back to back,
	// or a save racing a device-save mint): that is fine and expected —
	// the mints are opaque random stamps, and the CONTENT every device
	// eventually renders always comes from the newest cache, so an
	// interleaved sweep cannot land a stale intent.
	//
	// Devices with an empty CfgVersion are SKIPPED: they hold no
	// provisioning intent (never provisioned / pending candidates) — the
	// adoption flow and the engine's default arm render the CURRENT facts
	// into their first full provisioning, so a mint would be bookkeeping
	// noise. This is also why the sweep rides the device RMW cycle
	// (store.UpdateExisting — saveIntent's saveExisting shape) instead of
	// a plain Put: it cannot resurrect or race an inform handler.
	for _, d := range devices {
		if d.CfgVersion == "" {
			continue
		}
		nv, merr := mintCfgVersion()
		if merr != nil {
			return minted, merr
		}
		if err := a.st.UpdateExisting(d.MAC, func(rec *store.Device) error {
			rec.CfgVersion = nv
			return nil
		}); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				// Deleted between List and its RMW cycle: nothing left to
				// provision, not a sweep failure.
				continue
			}
			return minted, fmt.Errorf("site settings mint sweep %s: %w", d.MAC, err)
		}
		minted++
	}
	return minted, nil
}

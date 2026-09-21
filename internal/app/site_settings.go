// Site settings are the controller-level AP-intent document: the four
// AP-intent site facts that used to live only in startup flags — the
// regulatory country code, the AP SSH password, the ordered SSH
// authorized_keys lines, and the SSH password-login disable knob.
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
	"os"
	"path/filepath"
	"slices"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/server/systemcfg"
	"github.com/lucavb/open-unifi/internal/store"
)

// SiteSettings is the persisted controller-level AP-intent record. The
// zero value carries exactly the semantics of the old flag defaults:
// CountryCode 0 renders as the 840 default at the server seam, an empty
// SSHPassword renders as the site default ("ubnt", renderer semantics,
// unchanged), no keys render as no sshd.auth.key rows, and
// SSHDisablePassword false keeps password login enabled.
type SiteSettings struct {
	// CountryCode is the ISO 3166-1 numeric regulatory country code.
	// 0 = unset (renders as the default 840 at the server seam).
	CountryCode int
	// SSHPassword is the SSH password for adopted APs; "" = site default
	// "ubnt" (renderer semantics, unchanged).
	SSHPassword string
	// SSHPublicKeys are the ordered authorized_keys lines, each a
	// validated RFC 4253 line, stored VERBATIM (raw lines, not parsed
	// structs — parsing belongs to the render seam). The order is the
	// sshd.auth.key.<n> ordering, so an order-only diff is an effective
	// change (harmless re-provisioning, pinned by test).
	SSHPublicKeys []string
	// SSHDisablePassword renders sshd.auth.passwd=disabled (dropbear -s,
	// no remote password logins).
	SSHDisablePassword bool
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
		APSSHPassword:         s.SSHPassword,
		APSSHPublicKeys:       keys,
		APSSHDisablePassword:  s.SSHDisablePassword,
	}
}

// siteSettingsFromDoc converts an API/wire document into the record. A nil
// key list becomes an empty (never nil) list so cached records always hold
// usable slices.
func siteSettingsFromDoc(doc adminapi.SiteSettingsDocument) SiteSettings {
	keys := doc.APSSHPublicKeys
	if keys == nil {
		keys = []string{}
	}
	return SiteSettings{
		CountryCode:        doc.RegulatoryCountryCode,
		SSHPassword:        doc.APSSHPassword,
		SSHPublicKeys:      keys,
		SSHDisablePassword: doc.APSSHDisablePassword,
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
		APSSHPassword:         s.SSHPassword,
		APSSHPublicKeys:       keys,
		APSSHDisablePassword:  s.SSHDisablePassword,
	}
}

// validateSiteSettingsChange is the SAVE verb's validation: CountryCode
// must be 0 (= unset, renders as the server-side 840 default) or an ISO
// 3166-1 numeric code 1..999; every key line must pass the single
// fail-closed RFC 4253 parser (systemcfg.ParsePublicKey — no other
// validator exists for this shape); password auth disabled requires at
// least one provisioned key line, or the next cfg rebuild would lock SSH
// out. All validation failures wrap the adminapi.ErrInvalid sentinel so
// handleBackendErr maps them to HTTP 400 with the human message echoed.
func validateSiteSettingsChange(s SiteSettings) error {
	if code := s.CountryCode; code != 0 && (code < 1 || code > 999) {
		return fmt.Errorf("%w: regulatory country code must be an ISO 3166-1 numeric code from 001 to 999 (or 0 = unset), got %d",
			adminapi.ErrInvalid, code)
	}
	for i, line := range s.SSHPublicKeys {
		if _, err := systemcfg.ParsePublicKey(line); err != nil {
			return fmt.Errorf("%w: invalid AP SSH public key #%d: %v", adminapi.ErrInvalid, i+1, err)
		}
	}
	if s.SSHDisablePassword && len(s.SSHPublicKeys) == 0 {
		return fmt.Errorf("%w: AP SSH password auth cannot be disabled without a provisioned public key; add an authorized_keys line or SSH access will be locked out",
			adminapi.ErrInvalid)
	}
	return nil
}

// validateSettingsSyntax is the SEED/LOAD rule, deliberately weaker than
// the save verb's: it checks only key-line syntax (same single parser,
// fail-closed) and the country range. It does NOT enforce
// disable-without-keys, because the weaker rule exists so a hand-edited
// or foreign-written site-settings.json that is syntactically valid but
// semantically invalid does not brick startup — the file loads and the
// administrator fixes it through the API (the single validator going
// forward). Note the flag path can never seed the disable-without-keys
// combo: cmd's validateSSHDisableSeed guard rejects it at startup. A
// disable-without-keys value that DID reach disk is fail-closed where it
// matters: the adoption engine's live-provisioning gate (typed 501)
// blocks that combo's pushes. Zero
// seed (tests, first boot without flags) passes by construction.
func validateSettingsSyntax(s SiteSettings) error {
	if code := s.CountryCode; code != 0 && (code < 1 || code > 999) {
		return fmt.Errorf("regulatory country code must be an ISO 3166-1 numeric code from 001 to 999 (or 0 = unset), got %d", code)
	}
	for i, line := range s.SSHPublicKeys {
		if _, err := systemcfg.ParsePublicKey(line); err != nil {
			return fmt.Errorf("invalid AP SSH public key #%d: %w", i+1, err)
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
func loadSettingsFile(path string) (SiteSettings, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return SiteSettings{}, false, nil
	}
	if err != nil {
		return SiteSettings{}, true, fmt.Errorf("site settings file unreadable %s: %w", path, err)
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
// wireless persist). The temp file is created with 0600: unlike the
// wireless file the document carries an SSH password, so it is never
// world-readable on disk, not even between rename and chmod-sweep.
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
// shape, for wiring-side use (the server sources the four AP-intent site
// facts from here — including from inside the engine's decision
// path, which is exactly why smu must stay a leaf lock: this reader takes
// smu while the caller may already hold a per-MAC store lock). Mirrors
// CurrentWireless: the error is REAL — the New-time load/persist error —
// and cmd/openunifi checks it before launching.
func (a *App) CurrentSiteSettings() (SiteSettings, error) {
	return a.currentSiteSettings()
}

// siteSettingsChanged reports an EFFECTIVE change under the save verb's
// doctrine: any difference in the four facts. The key list comparison is
// ORDER-SENSITIVE — the list is provisioned as sshd.auth.key.<n> rows in
// order, so a reorder IS a different intended config. An order-only diff
// therefore mints one harmless re-provisioning (idempotent content, the
// device echoes the new cfgversion and noops thereafter; pinned by test).
func siteSettingsChanged(before, after SiteSettings) bool {
	return before.CountryCode != after.CountryCode ||
		before.SSHPassword != after.SSHPassword ||
		before.SSHDisablePassword != after.SSHDisablePassword ||
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
	if !siteSettingsChanged(a.cachedSettings, next) {
		// A save that changes nothing mints nothing (the no-op save is
		// pinned by test): project the read view and return.
		view := projectSettingsView(a.cachedSettings)
		a.smu.Unlock()
		return view, nil
	}
	// Wholesale replace: persist FIRST (crash between persist and sweep
	// = the on-disk record is already the new intent), then swap the
	// cache, then sweep the mints below (outside this section).
	if err := persistSettingsFile(a.settingsPath, next); err != nil {
		a.smu.Unlock()
		return zero, err
	}
	a.cachedSettings = next
	a.smu.Unlock()
	// smu RELEASED: everything below is store work and must never re-take
	// smu (see the lock-shape comment above).

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
	// Settings are persisted before the sweep; a crash mid-sweep leaves
	// the un-swept subset nooping until the next effective change
	// (self-healing, matches the single-process local-file persistence
	// posture of the rest of the store). A FAILED sweep (persist succeeded,
	// a store error mid-sweep) is NOT healed by retrying the same document:
	// the no-change early return turns a retry into a 200 without
	// sweeping — the next effective change of ANY mint kind (a later
	// site-settings save, an operator device save, wireless envelope
	// drift, a blocked-sta change) re-delivers to the un-swept devices.
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
	minted := 0
	devices, err := a.st.List()
	if err != nil {
		return zero, fmt.Errorf("site settings mint sweep list: %w", err)
	}
	for _, d := range devices {
		if d.CfgVersion == "" {
			continue
		}
		nv, merr := mintCfgVersion()
		if merr != nil {
			return zero, merr
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
			return zero, fmt.Errorf("site settings mint sweep %s: %w", d.MAC, err)
		}
		minted++
	}
	a.lg.Debug("site settings replaced",
		"country_code", next.CountryCode,
		"keys", len(next.SSHPublicKeys),
		"disable_password", next.SSHDisablePassword,
		"devices_minted", minted)
	// Project from the LOCAL record, not the cache: `next` is exactly what
	// this save swapped in, and re-reading the cache would mean re-taking
	// smu after store work (the lock-shape rule) — while a concurrent
	// effective save could have legitimately swapped a newer document in
	// that is not this save's read view.
	return projectSettingsView(next), nil
}

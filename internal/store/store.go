// Package store defines persistence for adopted/discovered UniFi devices.
//
// CONTRACT (lanes C=internal/server and D=internal/adminapi must program against
// exactly these exported names; lane C owns the implementation):
package store

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Device states: CONTROLLER-SIDE lifecycle enum (a per-device record field
// we own — NOT the device-reported state number that rides in the inform
// payload).
const (
	StatePending  = 1 // registered, not yet seen on the inform channel
	StateAdopting = 2 // inform received with default key; waiting for new key apply
	StateAdopted  = 3 // inform authenticated with device-specific key (x_authkey)
	StateLost     = 4 // heartbeats missed past LostAfter
)

// Device is a discovered/adopted UniFi device (U7PG2 et al).
type Device struct {
	MAC        string   `json:"mac"` // canonical lowercase 12-hex, no separators
	Name       string   `json:"name,omitempty"`
	Model      string   `json:"model,omitempty"` // e.g. U7PG2
	Firmware   string   `json:"firmware,omitempty"`
	Serial     string   `json:"serial,omitempty"`
	SiteID     string   `json:"site_id,omitempty"`
	State      int      `json:"state"`
	IP         string   `json:"ip,omitempty"`
	InformURL  string   `json:"inform_url,omitempty"`
	LastSeen   int64    `json:"last_seen,omitempty"` // unix seconds
	FirstSeen  int64    `json:"first_seen,omitempty"`
	CfgVersion string   `json:"cfg_version,omitempty"` // the version we TOLD the device
	AppliedCfg string   `json:"applied_cfg,omitempty"` // last cfgversion reported by device
	Authkeys   []string `json:"authkeys,omitempty"`    // per-device keys we assigned (newest last, capped to the newest two); the factory default key is NEVER stored here — keyCandidates appends it at use time
	XAuthkey   string   `json:"x_authkey,omitempty"`   // per-device key we assigned (>=32 hex)
	AESGCM     bool     `json:"aes_gcm,omitempty"`     // device advertised GCM support

	// KeyConfirmed is the controller-side key-confirmation marker (the
	// state machine's own words: "default key accepted only for a device
	// that has not yet authenticated its per-device key"): once an inform
	// was authenticated with ANY assigned per-device key (Authkeys), the
	// Engine stamps it so the factory default key is rejected for the
	// record no matter which lifecycle state it re-enters (the documented
	// mid-adoption double-rotation window stays open for records whose
	// assigned key was never proven used — docs/PROTOCOL.md §2/§3). The
	// encrypted factory-reset confirmation clears it with XAuthkey/Authkeys.
	KeyConfirmed bool `json:"key_confirmed,omitempty"`

	// FactoryResetInFlight marks a durable two-phase factory-reset handoff.
	// The initial setdefault emission retains assigned keys and this marker
	// until an encrypted factory-key status inform confirms the reset; this
	// makes a lost response/restart retryable without silently retiring the
	// only keys that can receive it.
	FactoryResetInFlight bool    `json:"factory_reset_in_flight,omitempty"`
	LastUps              JSONMap `json:"last_ups,omitempty"` // decoded stats snapshot from last inform
	Extra                JSONMap `json:"extra,omitempty"`    // raw passthrough of interesting inform fields

	// LEDOverride is the admin-set per-device LED override — the classic
	// controller's device record field "led_override"
	// (docs/PROTOCOL-mgmt.md §2: device.getString("led_override",
	// "default")). Values: "" (unset ≡ the jar's "default"), "on", "off".
	// ADMIN-OWNED (CONTEXT.md trust policy): the device can neither write
	// nor introduce it — Absorb never touches typed fields, and the trust
	// policy drops a device-supplied Extra["led_override"] copy (see the
	// adminOwnedKeys registry in trustpolicy.go).
	LEDOverride string `json:"led_override,omitempty"`

	// Disabled is the admin-set per-device disable flag — the classic
	// controller's controller-side record field "disabled" that §2's B
	// writer reads ("uap".equals(type) && device.is("disabled", false); all
	// devices this controller manages are uap-class APs). No admin route
	// sets it yet (reserved); the mgmt_cfg led_enabled computation consumes
	// it so the §2 semantics are complete the day one lands. ADMIN-OWNED:
	// a device body can neither write nor introduce it.
	Disabled bool `json:"disabled,omitempty"`

	// LEDOverrideColorBrightness is the admin-set per-device ledbar
	// brightness percent — the classic controller's device record field
	// "led_override_color_brightness" (the system_cfg ledbar emitter reads
	// device.getInt("led_override_color_brightness", 100),
	// config_String.txt:2627-2630). nil = unset (≡ the jar default 100).
	// It is a POINTER because 0 is a valid explicit value: a plain int
	// could not tell an explicit 0 from unset, and setting 100 ≡ clearing
	// (the renders are byte-identical). The admin API validates 0..100.
	// ADMIN-OWNED (CONTEXT.md trust policy): the device can neither write
	// nor introduce it — Absorb never touches typed fields, and the trust
	// policy drops device-supplied Extra["led_override_color_brightness"]
	// copies (the adminOwnedKeys registry in trustpolicy.go).
	LEDOverrideColorBrightness *int `json:"led_override_color_brightness,omitempty"`

	// LEDOverrideColor is the admin-set per-device ledbar color — the
	// classic controller's device record field "led_override_color" (the
	// ledbar emitter reads device.getString("led_override_color",
	// "#0000ff"), config_String.txt:2661-2663). "" ≡ unset (the jar
	// default "#0000ff"): blank or unparseable values fall back to
	// #0000ff at render time (config_String.txt:2666-2678) — stored
	// VERBATIM, not validated at the admin API, mirroring the jar's
	// record semantics. ADMIN-OWNED (CONTEXT.md trust policy): the
	// device can neither write nor introduce it.
	LEDOverrideColor string `json:"led_override_color,omitempty"`

	// SSHPassword is the admin-set per-device SSH login password — the
	// classic controller has NO per-device field for this (its §10 sink is
	// the site-wide mgmt setting x_ssh_password), so this is open-unifi's
	// extension over the official row mechanics. Values: "" (UNSET = STOP
	// MANAGING — the render reuses the last password hash the controller
	// pushed for this device, so the device's actual SSH password never
	// changes), or a non-empty password to set. Only an explicit non-empty
	// set ever changes the device's password; an unset render with no cache
	// falls back to the factory-default "ubnt" row. ADMIN-OWNED (CONTEXT.md
	// trust policy): the device can neither write nor introduce it —
	// Absorb never touches typed fields, and the trust policy drops a
	// device-supplied Extra["ssh_password"] copy (see the adminOwnedKeys
	// registry in trustpolicy.go). PLAINTEXT at rest is deliberate:
	// devices.json persists 0600 (store.go 0600 temp-file discipline), and
	// echo-based Terraform drift detection needs the plaintext read-back —
	// the same precedent as the removed site-level field before it and the
	// WLAN passphrase.
	SSHPassword string `json:"ssh_password,omitempty"`

	// RegulatoryCountryCode is the admin-set ISO 3166-1 numeric regulatory
	// country code for radio rows in system_cfg. 0 = unset (the server
	// renders the 840 default at the render seam). ADMIN-OWNED.
	RegulatoryCountryCode int `json:"regulatory_country_code,omitempty"`

	// SSHPublicKeys are the admin-set ordered authorized_keys lines
	// (sshd.auth.key.<n> row family). Stored verbatim; validated at the
	// admin API. ADMIN-OWNED.
	SSHPublicKeys []string `json:"ssh_public_keys,omitempty"`
}

// JSONMap is a loosely-typed JSON object (statistics passthrough etc.).
type JSONMap map[string]any

// DeviceStore persists UniFi devices across server restarts.
type DeviceStore interface {
	// Get returns the device with the given MAC (ErrNotFound if absent).
	// Every returned Device is a detached deep copy: mutating it never
	// aliases store internals.
	Get(mac string) (Device, error)
	// Put stores (upserts) a device record. The record is deep-copied on
	// the way in; the caller may keep mutating its own copy.
	Put(d Device) error
	// Delete removes the device with the given MAC.
	Delete(mac string) error
	// List returns all devices ordered by MAC.
	List() ([]Device, error)
	// Pending returns discovered-but-unadopted MACs heard on the
	// discovery beacon channel (MAC -> body/annotation map).
	Pending() (map[string]string, error)
	// MarkPending records a discovery beacon sighting for adoption UI.
	// The pending map is capped (100); inserting beyond the cap for a NEW
	// MAC is an error.
	MarkPending(mac, note string) error
	// Update serializes a per-MAC read-modify-write cycle: Promise-style
	// lookup-mutate-persist under a stable per-MAC lock, so concurrent inform
	// handling and admin mutations never interleave for the same device.
	// Unknown MACs receive &Device{MAC: canonical mac} (upsert semantics).
	// fn's error aborts the cycle without persisting. fn runs without the
	// store-wide commit or data lock, so Get/List/Pending are safe from fn;
	// callbacks must not invoke another mutation.
	Update(mac string, fn func(*Device) error) error
	// UpdateExisting is Update WITHOUT the upsert: an unknown MAC returns
	// ErrNotFound and fn runs zero times (the inform handler can therefore
	// never resurrect a deliberately deleted device). fn's error aborts the
	// cycle without persisting.
	UpdateExisting(mac string, fn func(*Device) error) error
}

// ErrNotFound is returned by Get/Delete for unknown MACs.
var ErrNotFound = errors.New("device not found")

// ---------------------------------------------------------------------------
// Implementation (JSON-file-backed + in-memory), owned by the server lane.
// ---------------------------------------------------------------------------

// PersistedFile is the on-disk shape of the JSON store file.
type PersistedFile struct {
	Version int               `json:"version"`  // schema version, currently 1
	SavedAt int64             `json:"saved_at"` // unix seconds, for forensic/debug
	Devices map[string]Device `json:"devices"`
	Pending map[string]string `json:"pending"`
}

// canonicalMAC normalizes a MAC to the store's canonical form:
// lowercase 12 hex chars, separators (':', '-', '.') removed.
func canonicalMAC(mac string) string {
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

// CanonicalMAC is the single source of truth for MAC identity across
// packages: it normalizes any common spelling (colon/hyphen/dot/space
// separated, or bare 12-hex) to the canonical lowercase 12-hex form AND
// validates the result is a well-formed 48-bit address. Unparseable input
// is an error. Packages must call this (and ColonMAC) instead of keeping
// private copies of the normalization logic — divergent copies silently
// split device identity.
func CanonicalMAC(mac string) (string, error) {
	c := canonicalMAC(mac)
	if len(c) != 12 {
		return "", fmt.Errorf("want 12 hex chars, got %d", len(c))
	}
	if _, err := hex.DecodeString(c); err != nil {
		return "", errors.New("not hexadecimal")
	}
	return c, nil
}

// ColonMAC renders a canonical 12-hex MAC in colon-hex ("aa:bb:cc:dd:ee:ff")
// for display and admin-wire formats. Input must already be canonical
// (see CanonicalMAC); anything else is returned lowercased as-is.
func ColonMAC(canonical string) string {
	low := strings.ToLower(canonical)
	if len(low) != 12 {
		return low
	}
	var b strings.Builder
	b.Grow(17)
	for i := 0; i+1 < len(low); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(low[i : i+2])
	}
	return b.String()
}

// db is the shared store core used by both implementations.
//
// Every mutation stages a private candidate under commitMu, persists that
// candidate (if this is a JSON store), then publishes it under mu. Callback
// execution is outside both locks. devices/pending are replaced as complete
// maps only after persistence succeeds.
type db struct {
	mu      sync.RWMutex
	devices map[string]Device
	pending map[string]pendingEntry

	// commitMu orders candidate snapshot → durable save → publication. It is
	// deliberately not held while an Update callback runs.
	commitMu sync.Mutex
	// stripes are permanent: deleting a device cannot split waiters that have
	// already resolved the lock for its MAC from later mutations of that MAC.
	stripes [macLockStripeCount]sync.Mutex
	// persistCandidate is nil for the in-memory store and writes a complete
	// candidate snapshot for JSON-backed stores. It runs under commitMu only.
	persistCandidate func(PersistedFile) error

	// now is the time source for pending TTL eviction; a test hook (nil ⇒
	// time.Now).
	now func() time.Time
}

const macLockStripeCount = 256

type dbCandidate struct {
	devices map[string]Device
	pending map[string]pendingEntry
}

// pendingEntry is one discovery-beacon sighting. seenAt is first-seen (in
// memory only — see PersistedFile); it drives TTL filtering and eviction.
type pendingEntry struct {
	note   string
	seenAt int64 // unix seconds
}

func newDB() *db {
	return &db{devices: map[string]Device{}, pending: map[string]pendingEntry{}}
}

func (m *db) clockNow() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// macLock returns the fixed stripe for a canonical MAC. Stripes are never
// removed, so callers that resolved a lock before a deletion cannot diverge
// from callers that arrive after it.
func (m *db) macLock(mac string) *sync.Mutex {
	var hash uint32 = 2166136261
	for i := 0; i < len(mac); i++ {
		hash ^= uint32(mac[i])
		hash *= 16777619
	}
	return &m.stripes[hash%macLockStripeCount]
}

// cloneValue deep-copies one JSON leaf container recursively (maps, JSONMap
// and []any may nest arbitrary radio_table-style structures).
func cloneValue(v any) any {
	switch t := v.(type) {
	case JSONMap:
		out := make(JSONMap, len(t))
		for k, val := range t {
			out[k] = cloneValue(val)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = cloneValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = cloneValue(val)
		}
		return out
	case []string:
		return append([]string(nil), t...)
	default:
		return v // scalars are values in Go
	}
}

// CloneDevice is the canonical deep copy of a Device record — every nested
// map, JSONMap and slice is duplicated, plus the LEDOverrideColorBrightness
// pointee, so no caller can mutate the source through a returned pointer.
// Other packages must use it instead of hand-rolling copies. nil Extra and
// nil LastUps are preserved as nil.
func CloneDevice(d Device) Device {
	out := d
	// The brightness knob is a pointer so explicit 0 survives the JSON
	// round-trip; the clone re-points it so the copy's aliasing matches
	// the map/slice deep-copy discipline below (no caller can mutate the
	// stored record through a returned pointer).
	if d.LEDOverrideColorBrightness != nil {
		v := *d.LEDOverrideColorBrightness
		out.LEDOverrideColorBrightness = &v
	}
	out.Authkeys = nil
	if d.Authkeys != nil {
		out.Authkeys = make([]string, len(d.Authkeys))
		copy(out.Authkeys, d.Authkeys)
	}
	out.SSHPublicKeys = nil
	if d.SSHPublicKeys != nil {
		out.SSHPublicKeys = make([]string, len(d.SSHPublicKeys))
		copy(out.SSHPublicKeys, d.SSHPublicKeys)
	}
	out.LastUps = nil
	if d.LastUps != nil {
		cloned := cloneValue(map[string]any(d.LastUps))
		out.LastUps = cloned.(map[string]any)
	}
	out.Extra = nil
	if d.Extra != nil {
		cloned := cloneValue(map[string]any(d.Extra))
		out.Extra = JSONMap(cloned.(map[string]any))
	}
	return out
}

func (m *db) Get(mac string) (Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.devices[canonicalMAC(mac)]
	if !ok {
		return Device{}, ErrNotFound
	}
	return CloneDevice(d), nil
}

// candidateLocked builds a private root-map candidate while the caller holds
// mu for reading. Unchanged Device values are immutable once published, so
// they may be shared between root maps: every mutator replaces or deletes a
// whole detached Device, while all public input/read/callback boundaries clone.
func (m *db) candidateLocked() dbCandidate {
	c := dbCandidate{
		devices: make(map[string]Device, len(m.devices)),
		pending: make(map[string]pendingEntry, len(m.pending)),
	}
	for mac, d := range m.devices {
		c.devices[mac] = d
	}
	for mac, entry := range m.pending {
		c.pending[mac] = entry
	}
	return c
}

// commit applies one internal edit to a detached latest-state candidate. The
// global commit lock preserves changes from distinct MACs: each candidate is
// based on the most recently published maps, persisted in full, then swapped
// into visibility only after persistence succeeds. A false changed result is
// a true no-op and skips both persistence and publication.
func (m *db) commit(edit func(*dbCandidate) (changed bool, err error)) error {
	m.commitMu.Lock()
	defer m.commitMu.Unlock()

	m.mu.RLock()
	candidate := m.candidateLocked()
	m.mu.RUnlock()

	changed, err := edit(&candidate)
	if err != nil || !changed {
		return err
	}
	// Pending reads intentionally remain pure. Reap expired sightings only
	// from a candidate that is already part of a real mutation, so unrelated
	// successful commits cannot persist stale rows and restart their TTL.
	cutoff := m.clockNow().Add(-pendingTTL).Unix()
	for mac, entry := range candidate.pending {
		if entry.seenAt < cutoff {
			delete(candidate.pending, mac)
		}
	}
	if m.persistCandidate != nil {
		if err := m.persistCandidate(m.persistedFile(candidate)); err != nil {
			return err
		}
	}
	m.mu.Lock()
	m.devices = candidate.devices
	m.pending = candidate.pending
	m.mu.Unlock()
	return nil
}

func (m *db) persistedFile(candidate dbCandidate) PersistedFile {
	pf := PersistedFile{
		Version: 1,
		SavedAt: m.clockNow().Unix(),
		Devices: make(map[string]Device, len(candidate.devices)),
		Pending: make(map[string]string, len(candidate.pending)),
	}
	for mac, d := range candidate.devices {
		// The candidate owns this root map, and its unchanged Device values
		// are immutable shared records. JSON encoding only reads them under
		// commitMu; do not deep-clone the full telemetry inventory here.
		pf.Devices[mac] = d
	}
	for mac, entry := range candidate.pending {
		// The v1 format remains map[string]string: first-seen stamps are
		// in-memory only and restart their TTL clock on load.
		pf.Pending[mac] = entry.note
	}
	return pf
}

func (m *db) Put(d Device) error {
	d.MAC = canonicalMAC(d.MAC)
	if d.MAC == "" {
		return errors.New("store: empty MAC")
	}
	mac := d.MAC
	clone := CloneDevice(d)
	lk := m.macLock(mac)
	lk.Lock()
	defer lk.Unlock()
	return m.commit(func(candidate *dbCandidate) (bool, error) {
		candidate.devices[mac] = clone
		return true, nil
	})
}

// Update serializes Get→mutate→commit under a stable per-MAC stripe. Unknown MACs
// start from the zero Device carrying the canonical MAC (upsert).
func (m *db) Update(mac string, fn func(*Device) error) error {
	return m.update(mac, fn, true)
}

// UpdateExisting is Update without the upsert seed: unknown MACs return
// ErrNotFound and fn never runs.
func (m *db) UpdateExisting(mac string, fn func(*Device) error) error {
	return m.update(mac, fn, false)
}

// update implements both flavors under one per-MAC cycle. fn runs with only
// the MAC stripe held: read methods are safe from the callback, but callbacks
// must not start nested mutations.
func (m *db) update(mac string, fn func(*Device) error, upsert bool) error {
	mac = canonicalMAC(mac)
	if mac == "" {
		return errors.New("store: empty MAC")
	}
	lk := m.macLock(mac)
	lk.Lock()
	defer lk.Unlock()

	m.mu.RLock()
	d, exists := m.devices[mac]
	if exists {
		d = CloneDevice(d)
	}
	m.mu.RUnlock()
	if !exists {
		if !upsert {
			return fmt.Errorf("%w: %s", ErrNotFound, mac)
		}
		d = Device{MAC: mac}
	}
	if ferr := fn(&d); ferr != nil {
		return ferr // abort without persisting
	}
	// MAC is the identity whose stripe is held for this cycle; callbacks may
	// change record fields but cannot move the candidate to another identity.
	d.MAC = mac
	clone := CloneDevice(d) // detach from a pointer the callback may retain
	return m.commit(func(candidate *dbCandidate) (bool, error) {
		candidate.devices[mac] = clone
		return true, nil
	})
}

// maxPending caps the unadopted-candidate map (discovery beacons can churn;
// the cap bounds memory on hostile/misconfigured networks). Jar default
// from the pending-adoption feed (voidsuper.txt:13925-13946): 100.
const maxPending = 100

// pendingTTL bounds how long an unpurged sighting may linger: beacons for
// MACs that never appear on the inform channel are evicted (lazily) after
// 24h. This keeps the map bounded for long-lived sightings even when the
// cap is never hit and the same beacons keep refreshing.
const pendingTTL = 24 * time.Hour

// errPendingFull is returned by MarkPending when the cap is hit for a
// NEW MAC (existing sightings still pass).
var errPendingFull = errors.New("store: pending map full")

func (m *db) Delete(mac string) error {
	mac = canonicalMAC(mac)
	lk := m.macLock(mac)
	lk.Lock()
	defer lk.Unlock()
	return m.commit(func(candidate *dbCandidate) (bool, error) {
		if _, ok := candidate.devices[mac]; !ok {
			return false, ErrNotFound
		}
		delete(candidate.devices, mac)
		return true, nil
	})
}

func (m *db) List() ([]Device, error) {
	m.mu.RLock()
	out := make([]Device, 0, len(m.devices))
	for _, d := range m.devices {
		out = append(out, CloneDevice(d))
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, nil
}

func (m *db) Pending() (map[string]string, error) {
	cutoff := m.clockNow().Add(-pendingTTL).Unix()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.pending))
	for k, e := range m.pending {
		if e.seenAt >= cutoff {
			out[k] = e.note
		}
	}
	return out, nil
}

// markPending stages expired-entry pruning and one sighting in the same
// candidate. Any error (including a full cap after pruning) leaves published
// memory and disk untouched.
func (m *db) markPending(mac, note string) error {
	mac = canonicalMAC(mac)
	if mac == "" {
		return errors.New("store: empty MAC")
	}
	return m.commit(func(candidate *dbCandidate) (bool, error) {
		now := m.clockNow()
		cutoff := now.Add(-pendingTTL).Unix()
		pruned := false
		for key, entry := range candidate.pending {
			if entry.seenAt < cutoff {
				delete(candidate.pending, key)
				pruned = true
			}
		}
		if existing, ok := candidate.pending[mac]; ok {
			if existing.note == note {
				// Repeats stay no-ops unless this operation also pruned stale
				// rows, which is a real persisted state change.
				return pruned, nil
			}
			candidate.pending[mac] = pendingEntry{note: note, seenAt: existing.seenAt}
			return true, nil
		}
		if len(candidate.pending) >= maxPending {
			return false, errPendingFull
		}
		candidate.pending[mac] = pendingEntry{note: note, seenAt: now.Unix()}
		return true, nil
	})
}

// MarkPending records a discovery beacon sighting for adoption UI.
func (m *db) MarkPending(mac, note string) error {
	return m.markPending(mac, note)
}

// memStore is the plain in-memory implementation (tests, ephemeral use).
type memStore struct {
	*db
}

// NewMemStore returns a non-persisting DeviceStore for tests.
func NewMemStore() DeviceStore { return &memStore{db: newDB()} }

type atomicTempFile interface {
	Name() string
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// atomicFileOps are narrow filesystem seams for deterministic pre-rename
// failure tests. Production uses the os functions below.
type atomicFileOps struct {
	createTemp func(dir, pattern string) (atomicTempFile, error)
	rename     func(oldPath, newPath string) error
	remove     func(path string) error
	syncDir    func(dir string) error
}

func defaultAtomicFileOps() atomicFileOps {
	return atomicFileOps{
		createTemp: func(dir, pattern string) (atomicTempFile, error) {
			return os.CreateTemp(dir, pattern)
		},
		rename:  os.Rename,
		remove:  os.Remove,
		syncDir: syncDir,
	}
}

// jsonStore wraps the shared candidate-commit core with durable JSON
// persistence. The commit mutex spans candidate snapshot, tempfile write,
// fsync, rename, and publication; readers only take db.mu and can continue
// to see the last committed state while a save is paused.
type jsonStore struct {
	*db
	path string
	ops  atomicFileOps
}

// NewJSONStore opens (or idempotently creates) a JSON-file-backed store at
// path. A missing file starts an empty store; a corrupt/unreadable file is an
// error. Callers must ensure the directory exists.
func NewJSONStore(path string) (DeviceStore, error) {
	if path == "" {
		return nil, errors.New("store: empty path")
	}
	core := newDB()
	s := &jsonStore{db: core, path: path, ops: defaultAtomicFileOps()}
	core.persistCandidate = s.persist

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var pf PersistedFile
		if jsonErr := json.Unmarshal(raw, &pf); jsonErr != nil {
			return nil, fmt.Errorf("store: corrupt store file %s: %w", path, jsonErr)
		}
		if pf.Devices != nil {
			for k, d := range pf.Devices {
				d.MAC = canonicalMAC(d.MAC)
				core.devices[canonicalMAC(k)] = CloneDevice(d)
			}
		}
		if pf.Pending != nil {
			// Reloaded sightings restart their TTL clock at load time: the
			// persisted format carries no timestamp (backward-compatible
			// map[string]string), and this keeps restarts from re-exposing
			// long-dead beacons for another full TTL.
			seenAt := time.Now().Unix()
			for k, v := range pf.Pending {
				core.pending[canonicalMAC(k)] = pendingEntry{note: v, seenAt: seenAt}
			}
		}
	case errors.Is(err, os.ErrNotExist):
		// idempotent fresh start
	default:
		return nil, fmt.Errorf("store: read %s: %w", path, err)
	}
	return s, nil
}

func (s *jsonStore) persist(pf PersistedFile) error {
	blob, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshal: %w", err)
	}
	dir := filepath.Dir(s.path)
	tmp, err := s.ops.createTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("store: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = s.ops.remove(tmpName)
		}
	}()
	// keep perms tight: the file contains per-device adoption keys
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: chmod: %w", err)
	}
	n, err := tmp.Write(blob)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: write: %w", err)
	}
	if n != len(blob) {
		_ = tmp.Close()
		return fmt.Errorf("store: write: short write: wrote %d of %d bytes", n, len(blob))
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	if err := s.ops.rename(tmpName, s.path); err != nil {
		return fmt.Errorf("store: rename: %w", err)
	}
	tmpName = ""           // renamed successfully; nothing to clean up
	_ = s.ops.syncDir(dir) // best effort: do not fail after the atomic commit
	return nil
}

// syncDir fsyncs a directory so a just-renamed file entry survives a crash.
// Best effort by design: some platforms reject directory fsync (macOS can
// return errors on dir fds), and a durability-flushing failure must not
// fail an otherwise-complete save.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

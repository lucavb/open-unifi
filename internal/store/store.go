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
	LastUps    JSONMap  `json:"last_ups,omitempty"`    // decoded stats snapshot from last inform
	Extra      JSONMap  `json:"extra,omitempty"`       // raw passthrough of interesting inform fields

	// LEDOverride is the admin-set per-device LED override — the classic
	// controller's device record field "led_override"
	// (docs/PROTOCOL-mgmt.md §2: device.getString("led_override",
	// "default")). Values: "" (unset ≡ the jar's "default"), "on", "off".
	// ADMIN-OWNED (CONTEXT.md trust policy): the device can neither write
	// nor introduce it — Absorb never touches typed fields, and the trust
	// policy drops a device-supplied Extra["led_override"] copy (see the
	// AdminOwnedKeys registry in trustpolicy.go).
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
	// copies (the AdminOwnedKeys registry in trustpolicy.go).
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
	// lookup-mutate-persist under a per-MAC mutex, so concurrent inform
	// handling and admin mutations never interleave for the same device.
	// Unknown MACs receive &Device{MAC: canonical mac} (upsert semantics).
	// fn's error aborts the cycle without persisting.
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

// db is the shared in-memory store core used by both implementations.
//
// INVARIANT: every Device handed to or returned by the core (Get, List,
// Put-copy, Update fn pointer) is a DETACHED deep clone; callers never hold
// references into m.devices' maps/slices.
//
// NOTE: jsonStore must override every MUTATING method of this core
// (Put/Delete/MarkPending/Update/UpdateExisting) so each mutation also
// calls save(); the read methods are shared as-is.
type db struct {
	mu      sync.RWMutex
	devices map[string]Device
	pending map[string]pendingEntry

	// upMu serializes read-modify-write cycles per canonical MAC (small
	// fixed-size map entry per known device; harmless at this scale).
	upMu    sync.Mutex
	upLocks map[string]*sync.Mutex

	// now is the time source for pending TTL eviction; a test hook (nil ⇒
	// time.Now).
	now func() time.Time
}

// pendingEntry is one discovery-beacon sighting. seenAt is first-seen (in
// memory only — see save); it drives TTL eviction.
type pendingEntry struct {
	note   string
	seenAt int64 // unix seconds
}

func newDB() *db {
	return &db{devices: map[string]Device{}, pending: map[string]pendingEntry{}, upLocks: map[string]*sync.Mutex{}}
}

func (m *db) clockNow() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// macLock returns the per-MAC serialization mutex (creating it lazily).
func (m *db) macLock(mac string) *sync.Mutex {
	m.upMu.Lock()
	defer m.upMu.Unlock()
	lk, ok := m.upLocks[mac]
	if !ok {
		lk = &sync.Mutex{}
		m.upLocks[mac] = lk
	}
	return lk
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

// cloneDevice deep-copies a Device record, including every nested map,
// JSONMap and slice that aliasing bugs could otherwise reach through.
func cloneDevice(d Device) Device {
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
	return cloneDevice(d), nil
}

func (m *db) Put(d Device) error {
	d.MAC = canonicalMAC(d.MAC)
	if d.MAC == "" {
		return errors.New("store: empty MAC")
	}
	clone := cloneDevice(d)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[d.MAC] = clone
	return nil
}

// Update serializes Get→mutate→Put under a per-MAC mutex. Unknown MACs
// start from the zero Device carrying the canonical MAC (upsert).
func (m *db) Update(mac string, fn func(*Device) error) error {
	return m.update(mac, fn, true)
}

// UpdateExisting is Update without the upsert seed: unknown MACs return
// ErrNotFound and fn never runs.
func (m *db) UpdateExisting(mac string, fn func(*Device) error) error {
	return m.update(mac, fn, false)
}

// update implements both flavors under one per-MAC cycle.
func (m *db) update(mac string, fn func(*Device) error, upsert bool) error {
	mac = canonicalMAC(mac)
	if mac == "" {
		return errors.New("store: empty MAC")
	}
	lk := m.macLock(mac)
	lk.Lock()
	defer lk.Unlock()

	d, err := m.Get(mac)
	switch {
	case errors.Is(err, ErrNotFound):
		if !upsert {
			return fmt.Errorf("%w: %s", ErrNotFound, mac)
		}
		d = Device{MAC: mac}
	case err != nil:
		return err
	}
	if ferr := fn(&d); ferr != nil {
		return ferr // abort without persisting
	}
	return m.Put(d)
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

// evictExpired drops TTL-expired sightings. Caller holds m.mu (write).
func (m *db) evictExpiredLocked() {
	if len(m.pending) == 0 {
		return
	}
	cutoff := m.clockNow().Add(-pendingTTL).Unix()
	for mac, e := range m.pending {
		if e.seenAt < cutoff {
			delete(m.pending, mac)
		}
	}
}

func (m *db) Delete(mac string) error {
	mac = canonicalMAC(mac)
	// Serialize under the same per-MAC lock as Update/UpdateExisting: a
	// concurrent RMW cycle must not resurrect a device that Delete is
	// removing (previously Delete only took m.mu, so a mid-cycle Update
	// could put the record right back after the delete observed emptiness).
	lk := m.macLock(mac)
	lk.Lock()
	defer lk.Unlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.devices[mac]; !ok {
		return ErrNotFound
	}
	delete(m.devices, mac)

	// Prune the per-MAC lock entry so churn cannot grow upLocks without
	// bound. Safe under upMu while we hold the lock ourselves: goroutines
	// that already resolved the pointer race with the prune only in the
	// pre-existing "Update upserts onto a just-deleted MAC" way, which this
	// locking deliberately permits (Delete is not a tombstone).
	m.upMu.Lock()
	delete(m.upLocks, mac)
	m.upMu.Unlock()
	return nil
}

func (m *db) List() ([]Device, error) {
	m.mu.RLock()
	out := make([]Device, 0, len(m.devices))
	for _, d := range m.devices {
		out = append(out, cloneDevice(d))
	}
	m.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out, nil
}

func (m *db) Pending() (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpiredLocked()
	out := make(map[string]string, len(m.pending))
	for k, e := range m.pending {
		out[k] = e.note
	}
	return out, nil
}

// markPending is the core mutation behind MarkPending. It reports whether
// the persisted state changed, so jsonStore can skip its full save+fsync
// when repeated sightings carry the same note.
func (m *db) markPending(mac, note string) (bool, error) {
	mac = canonicalMAC(mac)
	if mac == "" {
		return false, errors.New("store: empty MAC")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictExpiredLocked()
	if existing, ok := m.pending[mac]; ok {
		if existing.note == note {
			return false, nil // repeat sighting: nothing changed, nothing to persist
		}
		m.pending[mac] = pendingEntry{note: note, seenAt: existing.seenAt}
		return true, nil
	}
	if len(m.pending) >= maxPending {
		return false, errPendingFull
	}
	m.pending[mac] = pendingEntry{note: note, seenAt: m.clockNow().Unix()}
	return true, nil
}

// MarkPending records a discovery beacon sighting for adoption UI.
func (m *db) MarkPending(mac, note string) error {
	_, err := m.markPending(mac, note)
	return err
}

// memStore is the plain in-memory implementation (tests, ephemeral use).
type memStore struct {
	*db
}

// NewMemStore returns a non-persisting DeviceStore for tests.
func NewMemStore() DeviceStore { return &memStore{db: newDB()} }

// jsonStore wraps the in-memory core with durable JSON persistence to a single
// file. Saves are atomic (temp file + fsync + rename) AND ordered: saveMu is
// held across the whole save — snapshot marshaling under db.mu.RLock taken
// INSIDE saveMu, then tempfile/write/fsync/rename — so two concurrent savers
// can never rename out of order (a stale snapshot landing last). Get/List
// are not blocked by saveMu beyond the db.mu.RLock inside the snapshot.
type jsonStore struct {
	*db
	path   string
	saveMu sync.Mutex
}

// NewJSONStore opens (or idempotently creates) a JSON-file-backed store at
// path. A missing file starts an empty store; a corrupt/unreadable file is an
// error. Callers must ensure the directory exists.
func NewJSONStore(path string) (DeviceStore, error) {
	if path == "" {
		return nil, errors.New("store: empty path")
	}
	core := newDB()
	s := &jsonStore{db: core, path: path}

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
				core.devices[canonicalMAC(k)] = d
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

func (s *jsonStore) Put(d Device) error {
	if err := s.db.Put(d); err != nil {
		return err
	}
	return s.save()
}

func (s *jsonStore) Delete(mac string) error {
	if err := s.db.Delete(mac); err != nil {
		return err
	}
	return s.save()
}

// MarkPending persists the mutation ONLY when the core reports a change:
// discovery beacons re-announce every few seconds with an identical body,
// and each one previously cost a full snapshot marshal + fsync + rename on
// disk. Unchanged repeats now stop at the in-memory refresh.
func (s *jsonStore) MarkPending(mac, note string) error {
	changed, err := s.markPending(mac, note)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return s.save()
}

// Update runs the per-MAC cycle on the core, then persists on success.
func (s *jsonStore) Update(mac string, fn func(*Device) error) error {
	if err := s.db.Update(mac, fn); err != nil {
		return err
	}
	return s.save()
}

// UpdateExisting runs the per-MAC cycle on the core without the upsert
// seed, then persists on success. An unknown MAC is an error — nothing to
// persist, no save.
func (s *jsonStore) UpdateExisting(mac string, fn func(*Device) error) error {
	if err := s.db.UpdateExisting(mac, fn); err != nil {
		return err
	}
	return s.save()
}

// save persists the current snapshot atomically and ORDERED: saveMu spans
// the snapshot + tempfile + fsync + rename so rename order == snapshot
// order (two concurrent savers cannot invert).
func (s *jsonStore) save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	savedAt := s.db.clockNow().Unix()
	pf := PersistedFile{
		Version: 1,
		SavedAt: savedAt,
		Devices: make(map[string]Device, len(s.devices)),
		Pending: make(map[string]string, len(s.pending)),
	}
	for k, d := range s.devices {
		pf.Devices[k] = d
	}
	for k, e := range s.pending {
		// Persisted pending format stays map[string]string (v1): TTL
		// first-seen stamps are intentionally in-memory only; a reload
		// restarts the eviction clock, which is bounded by pendingTTL.
		pf.Pending[k] = e.note
	}
	blob, err := json.MarshalIndent(pf, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("store: marshal: %w", err)
	}

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("store: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	// keep perms tight: the file contains per-device adoption keys
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: chmod: %w", err)
	}
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("store: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("store: rename: %w", err)
	}
	tmpName = "" // renamed successfully; nothing to clean up
	syncDir(dir) // best effort: make the rename itself durable
	return nil
}

// syncDir fsyncs a directory so a just-renamed file entry survives a crash.
// Best effort by design: some platforms reject directory fsync (macOS can
// return errors on dir fds), and a durability-flushing failure must not
// fail an otherwise-complete save.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

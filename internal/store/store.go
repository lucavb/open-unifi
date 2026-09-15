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
	// The pending map is capped (512); inserting beyond the cap for a NEW
	// MAC is an error.
	MarkPending(mac, note string) error
	// Update serializes a per-MAC read-modify-write cycle: Promise-style
	// lookup-mutate-persist under a per-MAC mutex, so concurrent inform
	// handling and admin mutations never interleave for the same device.
	// Unknown MACs receive &Device{MAC: canonical mac} (upsert semantics).
	// fn's error aborts the cycle without persisting.
	Update(mac string, fn func(*Device) error) error
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
// (Put/Delete/MarkPending/Update) so each mutation also calls save();
// the read methods are shared as-is.
type db struct {
	mu      sync.RWMutex
	devices map[string]Device
	pending map[string]string

	// upMu serializes read-modify-write cycles per canonical MAC (small
	// fixed-size map entry per known device; harmless at this scale).
	upMu    sync.Mutex
	upLocks map[string]*sync.Mutex
}

func newDB() *db {
	return &db{devices: map[string]Device{}, pending: map[string]string{}, upLocks: map[string]*sync.Mutex{}}
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
// the cap bounds memory on hostile/misconfigured networks).
const maxPending = 512

// errPendingFull is returned by MarkPending when the cap is hit for a
// NEW MAC (existing sightings still pass).
var errPendingFull = errors.New("store: pending map full")

func (m *db) Delete(mac string) error {
	mac = canonicalMAC(mac)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.devices[mac]; !ok {
		return ErrNotFound
	}
	delete(m.devices, mac)
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]string, len(m.pending))
	for k, v := range m.pending {
		out[k] = v
	}
	return out, nil
}

func (m *db) MarkPending(mac, note string) error {
	mac = canonicalMAC(mac)
	if mac == "" {
		return errors.New("store: empty MAC")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pending[mac]; !ok && len(m.pending) >= maxPending {
		return errPendingFull
	}
	m.pending[mac] = note
	return nil
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
			for k, v := range pf.Pending {
				core.pending[canonicalMAC(k)] = v
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

func (s *jsonStore) MarkPending(mac, note string) error {
	if err := s.db.MarkPending(mac, note); err != nil {
		return err
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

// save persists the current snapshot atomically and ORDERED: saveMu spans
// the snapshot + tempfile + fsync + rename so rename order == snapshot
// order (two concurrent savers cannot invert).
func (s *jsonStore) save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	now := time.Now().Unix()
	pf := PersistedFile{
		Version: 1,
		SavedAt: now,
		Devices: make(map[string]Device, len(s.devices)),
		Pending: make(map[string]string, len(s.pending)),
	}
	for k, d := range s.devices {
		pf.Devices[k] = d
	}
	for k, v := range s.pending {
		pf.Pending[k] = v
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
	return nil
}

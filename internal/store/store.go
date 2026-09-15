// Package store defines persistence for adopted/discovered UniFi devices.
//
// CONTRACT (lanes C=internal/server and D=internal/adminapi must program against
// exactly these exported names; lane C owns the implementation):
package store

import (
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

// Device states (raw numbers used by UniFi inform protocol, see docs/PROTOCOL.md §3).
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
	LastSeen   int64    `json:"last_seen,omitempty"` //// unix seconds
	FirstSeen  int64    `json:"first_seen,omitempty"`
	CfgVersion string   `json:"cfg_version,omitempty"` // the version we TOLD the device
	AppliedCfg string   `json:"applied_cfg,omitempty"` // last cfgversion reported by device
	Authkeys   []string `json:"authkeys,omitempty"`    // hex keys this device may use; index 0 = default
	XAuthkey   string   `json:"x_authkey,omitempty"`   // per-device key we assigned (>=32 hex)
	AESGCM     bool     `json:"aes_gcm,omitempty"`     // device advertised GCM support
	Adopted    bool     `json:"adopted,omitempty"`
	LastUps    JSONMap  `json:"last_ups,omitempty"` // decoded stats snapshot from last inform
	Extra      JSONMap  `json:"extra,omitempty"`    // raw passthrough of interesting inform fields
}

// JSONMap is a loosely-typed JSON object (statistics passthrough etc.).
type JSONMap map[string]any

// DeviceStore persists UniFi devices across server restarts.
type DeviceStore interface {
	// Get returns the device with the given MAC (ErrNotFound if absent).
	Get(mac string) (Device, error)
	// Put stores (upserts) a device record.
	Put(d Device) error
	// Delete removes the device with the given MAC.
	Delete(mac string) error
	// List returns all devices ordered by MAC.
	List() ([]Device, error)
	// Pending returns discovered-but-unadopted MACs heard on the
	// discovery beacon channel (MAC -> body/annotation map).
	Pending() (map[string]string, error)
	// MarkPending records a discovery beacon sighting for adoption UI.
	MarkPending(mac, note string) error
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

// db is the shared in-memory store core used by both implementations.
type db struct {
	mu      sync.RWMutex
	devices map[string]Device
	pending map[string]string
}

func newDB() *db {
	return &db{devices: map[string]Device{}, pending: map[string]string{}}
}

func (m *db) Get(mac string) (Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.devices[canonicalMAC(mac)]
	if !ok {
		return Device{}, ErrNotFound
	}
	return d, nil
}

func (m *db) Put(d Device) error {
	d.MAC = canonicalMAC(d.MAC)
	if d.MAC == "" {
		return errors.New("store: empty MAC")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices[d.MAC] = d
	return nil
}

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
	defer m.mu.RUnlock()
	out := make([]Device, 0, len(m.devices))
	for _, d := range m.devices {
		out = append(out, d)
	}
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
// file. Writes are atomic: marshal under RLock to a temp file in the same
// directory, fsync, then rename over the target.
type jsonStore struct {
	*db
	path string
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

// save persists the current snapshot atomically (temp file + fsync + rename).
func (s *jsonStore) save() error {
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

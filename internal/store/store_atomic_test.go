package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type injectedTempFile struct {
	atomicTempFile
	failStage  string
	failErr    error
	shortWrite bool
	writeGate  *saveGate
}

func (f *injectedTempFile) Chmod(mode os.FileMode) error {
	if f.failStage == "chmod" {
		return f.failErr
	}
	return f.atomicTempFile.Chmod(mode)
}

func (f *injectedTempFile) Write(p []byte) (int, error) {
	if f.failStage == "write" {
		return 0, f.failErr
	}
	if f.shortWrite {
		n := len(p) / 2
		if n > 0 {
			if _, err := f.atomicTempFile.Write(p[:n]); err != nil {
				return 0, err
			}
		}
		return n, nil
	}
	return f.atomicTempFile.Write(p)
}

func (f *injectedTempFile) Sync() error {
	if f.writeGate != nil {
		f.writeGate.pauseFirst()
	}
	if f.failStage == "fsync" {
		return f.failErr
	}
	return f.atomicTempFile.Sync()
}

func (f *injectedTempFile) Close() error {
	if f.failStage == "close" {
		_ = f.atomicTempFile.Close()
		return f.failErr
	}
	return f.atomicTempFile.Close()
}

type saveGate struct {
	mu      sync.Mutex
	count   int
	entered chan struct{}
	release chan struct{}
}

func (g *saveGate) pauseFirst() {
	g.mu.Lock()
	g.count++
	first := g.count == 1
	g.mu.Unlock()
	if first {
		close(g.entered)
		<-g.release
	}
}

func wrapCreateTemp(js *jsonStore, wrap func(atomicTempFile) atomicTempFile) {
	create := js.ops.createTemp
	js.ops.createTemp = func(dir, pattern string) (atomicTempFile, error) {
		f, err := create(dir, pattern)
		if err != nil {
			return nil, err
		}
		return wrap(f), nil
	}
}

func persistedAt(t *testing.T, path string) PersistedFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pf PersistedFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		t.Fatal(err)
	}
	return pf
}

func TestJSONPrecommitFailuresAreFailureAtomic(t *testing.T) {
	stages := []string{"marshal", "temp", "chmod", "write", "short-write", "fsync", "close", "rename"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "devices.json")
			iface, err := NewJSONStore(path)
			if err != nil {
				t.Fatal(err)
			}
			js := iface.(*jsonStore)
			const mac = "aabbccddeeff"
			if err := js.Put(Device{MAC: mac, Name: "committed"}); err != nil {
				t.Fatal(err)
			}
			boom := fmt.Errorf("injected %s failure", stage)
			switch stage {
			case "temp":
				js.ops.createTemp = func(string, string) (atomicTempFile, error) { return nil, boom }
			case "chmod", "write", "short-write", "fsync", "close":
				wrapCreateTemp(js, func(file atomicTempFile) atomicTempFile {
					return &injectedTempFile{atomicTempFile: file, failStage: stage, failErr: boom, shortWrite: stage == "short-write"}
				})
			case "rename":
				js.ops.rename = func(string, string) error { return boom }
			}

			err = js.Update(mac, func(d *Device) error {
				d.Name = "uncommitted"
				if stage == "marshal" {
					d.Extra = JSONMap{"unmarshalable": make(chan int)}
				}
				return nil
			})
			if err == nil {
				t.Fatal("mutation unexpectedly committed")
			}
			if stage != "marshal" && stage != "short-write" && !errors.Is(err, boom) {
				t.Fatalf("error %v does not wrap injected error %v", err, boom)
			}
			if stage == "short-write" && !strings.Contains(err.Error(), "short write") {
				t.Fatalf("short-write error = %v, want short-write diagnosis", err)
			}

			live, err := js.Get(mac)
			if err != nil {
				t.Fatal(err)
			}
			if live.Name != "committed" || live.Extra != nil {
				t.Fatalf("failed save changed live state: %+v", live)
			}
			if got := persistedAt(t, path).Devices[mac].Name; got != "committed" {
				t.Fatalf("failed save changed persisted state: name=%q", got)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
				t.Fatalf("failed save left temporary files: %v", entries)
			}
		})
	}
}

func TestJSONDirectorySyncFailureIsPostCommitBestEffort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	if err := js.Put(Device{MAC: "aabbccddeeff", Name: "old"}); err != nil {
		t.Fatal(err)
	}
	js.ops.syncDir = func(string) error { return errors.New("injected directory sync failure") }
	if err := js.Update("aabbccddeeff", func(d *Device) error {
		d.Name = "committed"
		return nil
	}); err != nil {
		t.Fatalf("directory sync failure must not fail after rename: %v", err)
	}
	live, err := js.Get("aabbccddeeff")
	if err != nil || live.Name != "committed" {
		t.Fatalf("live state after committed rename = %+v, err=%v", live, err)
	}
	if got := persistedAt(t, path).Devices["aabbccddeeff"].Name; got != "committed" {
		t.Fatalf("persisted post-rename state = %q", got)
	}
}

func TestJSONUpdateCallbackErrorLeavesMemoryAndDiskUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	const mac = "aabbccddeeff"
	if err := js.Put(Device{MAC: mac, Name: "before"}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("abort callback")
	err = js.Update(mac, func(d *Device) error {
		d.Name = "aborted"
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Update error = %v, want callback error", err)
	}
	live, err := js.Get(mac)
	if err != nil || live.Name != "before" {
		t.Fatalf("callback abort changed live state: %+v, %v", live, err)
	}
	if got := persistedAt(t, path).Devices[mac].Name; got != "before" {
		t.Fatalf("callback abort changed disk state: %q", got)
	}
}

func TestJSONUpdateExistingPersistenceFailureIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	const mac = "aabbccddeeff"
	if err := js.Put(Device{MAC: mac, Name: "before"}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("injected UpdateExisting rename failure")
	js.ops.rename = func(string, string) error { return boom }
	called := false
	err = js.UpdateExisting(mac, func(d *Device) error {
		called = true
		d.Name = "uncommitted"
		return nil
	})
	if !called || !errors.Is(err, boom) {
		t.Fatalf("UpdateExisting called=%v err=%v, want callback and injected persistence error", called, err)
	}
	live, err := js.Get(mac)
	if err != nil || live.Name != "before" {
		t.Fatalf("failed UpdateExisting changed live state: %+v, %v", live, err)
	}
	if got := persistedAt(t, path).Devices[mac].Name; got != "before" {
		t.Fatalf("failed UpdateExisting changed disk state: %q", got)
	}
}

func TestJSONPutAndDeletePersistenceFailuresAreAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	const mac = "aabbccddeeff"
	if err := js.Put(Device{MAC: mac, Name: "before"}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("injected rename failure")
	js.ops.rename = func(string, string) error { return boom }
	if err := js.Put(Device{MAC: mac, Name: "put-candidate"}); !errors.Is(err, boom) {
		t.Fatalf("Put error = %v, want injected failure", err)
	}
	if err := js.Delete(mac); !errors.Is(err, boom) {
		t.Fatalf("Delete error = %v, want injected failure", err)
	}
	live, err := js.Get(mac)
	if err != nil || live.Name != "before" {
		t.Fatalf("failed Put/Delete changed live record: %+v, %v", live, err)
	}
	if got := persistedAt(t, path).Devices[mac].Name; got != "before" {
		t.Fatalf("failed Put/Delete changed persisted record: %q", got)
	}
}

func TestUpdateCallbackReadsAndRetainedPointerIsDetached(t *testing.T) {
	st := NewMemStore()
	const mac = "aabbccddeeff"
	if err := st.Put(Device{MAC: mac, Name: "before"}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkPending("112233445566", "beacon"); err != nil {
		t.Fatal(err)
	}
	var retained *Device
	done := make(chan error, 1)
	go func() {
		done <- st.Update(mac, func(d *Device) error {
			retained = d
			got, err := st.Get(mac)
			if err != nil || got.Name != "before" {
				return fmt.Errorf("Get in callback = %+v, %v", got, err)
			}
			list, err := st.List()
			if err != nil || len(list) != 1 || list[0].MAC != mac {
				return fmt.Errorf("List in callback = %+v, %v", list, err)
			}
			pending, err := st.Pending()
			if err != nil || pending["112233445566"] != "beacon" {
				return fmt.Errorf("Pending in callback = %v, %v", pending, err)
			}
			d.Name = "committed"
			d.SSHPublicKeys = []string{"key-before-retained-mutation"}
			d.Extra = JSONMap{"nested": []any{map[string]any{"value": "stored"}}}
			return nil
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Get/List/Pending from Update callback deadlocked")
	}
	retained.Name = "changed-after-callback"
	retained.SSHPublicKeys[0] = "changed-key"
	retained.Extra["nested"].([]any)[0].(map[string]any)["value"] = "changed-map"
	got, err := st.Get(mac)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "committed" || got.SSHPublicKeys[0] != "key-before-retained-mutation" ||
		got.Extra["nested"].([]any)[0].(map[string]any)["value"] != "stored" {
		t.Fatalf("retained callback pointer mutated published state: %+v", got)
	}
}

func TestJSONReadersSeeOldStateWhileCandidateSaveIsPaused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	const mac = "aabbccddeeff"
	if err := js.Put(Device{MAC: mac, Name: "old"}); err != nil {
		t.Fatal(err)
	}
	if err := js.MarkPending("112233445566", "visible"); err != nil {
		t.Fatal(err)
	}
	gate := &saveGate{entered: make(chan struct{}), release: make(chan struct{})}
	wrapCreateTemp(js, func(file atomicTempFile) atomicTempFile {
		return &injectedTempFile{atomicTempFile: file, writeGate: gate}
	})
	updateDone := make(chan error, 1)
	go func() {
		updateDone <- js.Update(mac, func(d *Device) error { d.Name = "new"; return nil })
	}()
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		close(gate.release)
		t.Fatal("save did not reach injected pause")
	}

	readDone := make(chan error, 1)
	go func() {
		d, err := js.Get(mac)
		if err != nil || d.Name != "old" {
			readDone <- fmt.Errorf("Get during save = %+v, %v", d, err)
			return
		}
		list, err := js.List()
		if err != nil || len(list) != 1 || list[0].Name != "old" {
			readDone <- fmt.Errorf("List during save = %+v, %v", list, err)
			return
		}
		pending, err := js.Pending()
		if err != nil || pending["112233445566"] != "visible" {
			readDone <- fmt.Errorf("Pending during save = %v, %v", pending, err)
			return
		}
		readDone <- nil
	}()
	select {
	case err := <-readDone:
		if err != nil {
			close(gate.release)
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		close(gate.release)
		t.Fatal("readers blocked behind candidate persistence")
	}
	close(gate.release)
	if err := <-updateDone; err != nil {
		t.Fatal(err)
	}
	if got, _ := js.Get(mac); got.Name != "new" {
		t.Fatalf("published state after save = %q", got.Name)
	}
}

func TestJSONDistinctMACCommitsPreserveLatestSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	if err := js.Put(Device{MAC: "aabbccddeeff", Name: "first-old"}); err != nil {
		t.Fatal(err)
	}
	gate := &saveGate{entered: make(chan struct{}), release: make(chan struct{})}
	wrapCreateTemp(js, func(file atomicTempFile) atomicTempFile {
		return &injectedTempFile{atomicTempFile: file, writeGate: gate}
	})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- js.Update("aabbccddeeff", func(d *Device) error { d.Name = "first-new"; return nil })
	}()
	select {
	case <-gate.entered:
	case <-time.After(3 * time.Second):
		close(gate.release)
		t.Fatal("first commit did not pause")
	}

	callbackRan := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- js.Update("112233445566", func(d *Device) error {
			close(callbackRan)
			d.Name = "second-new"
			return nil
		})
	}()
	select {
	case <-callbackRan:
	case <-time.After(3 * time.Second):
		close(gate.release)
		t.Fatal("second callback was incorrectly run under the first commit lock")
	}
	select {
	case err := <-secondDone:
		close(gate.release)
		t.Fatalf("second commit completed while first snapshot was paused: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(gate.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}

	reopened, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := reopened.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	second, err := reopened.Get("112233445566")
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != "first-new" || second.Name != "second-new" {
		t.Fatalf("reopened latest snapshot lost a distinct-MAC commit: first=%q second=%q", first.Name, second.Name)
	}
}

func TestPendingIsPureFilteredRead(t *testing.T) {
	st := NewMemStore()
	db := coreOf(t, st)
	firstSeen := time.Unix(1_700_000_000, 0)
	now := firstSeen
	db.now = func() time.Time { return now }
	if err := st.MarkPending("112233445566", "expired-soon"); err != nil {
		t.Fatal(err)
	}
	now = firstSeen.Add(pendingTTL + time.Second)
	if got, err := st.Pending(); err != nil || len(got) != 0 {
		t.Fatalf("filtered Pending = %v, %v; want no expired rows", got, err)
	}
	db.mu.RLock()
	_, retained := db.pending["112233445566"]
	db.mu.RUnlock()
	if !retained {
		t.Fatal("Pending must not mutate the retained pending map")
	}
}

func TestSuccessfulDeviceMutationPrunesExpiredPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	js.now = func() time.Time { return now }
	if err := js.MarkPending("112233445566", "expired-discovery"); err != nil {
		t.Fatal(err)
	}

	// Pending is a pure filtered read. The unrelated device mutation must
	// nevertheless prune the expired row from its successful commit candidate.
	now = t0.Add(pendingTTL + time.Second)
	if got, err := js.Pending(); err != nil || len(got) != 0 {
		t.Fatalf("Pending after expiration = %v, %v; want no expired rows", got, err)
	}
	if err := js.Put(Device{MAC: "aabbccddeeff", Name: "unrelated"}); err != nil {
		t.Fatal(err)
	}
	if pf := persistedAt(t, path); len(pf.Pending) != 0 {
		t.Fatalf("successful device mutation persisted expired pending rows: %v", pf.Pending)
	}

	reopened, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Pending(); err != nil || len(got) != 0 {
		t.Fatalf("reopened Pending = %v, %v; want no expired rows", got, err)
	}
	if rows := coreOf(t, reopened).pending; len(rows) != 0 {
		t.Fatalf("reopened store revived expired candidate: %v", rows)
	}
}

func TestCandidateRootCopySharesUnchangedDeviceValues(t *testing.T) {
	st := NewMemStore()
	const mac = "aabbccddeeff"
	if err := st.Put(Device{MAC: mac, Extra: JSONMap{"telemetry": []string{"large-but-unchanged"}}}); err != nil {
		t.Fatal(err)
	}
	db := coreOf(t, st)
	db.mu.RLock()
	candidate := db.candidateLocked()
	stored := db.devices[mac].Extra["telemetry"].([]string)
	staged := candidate.devices[mac].Extra["telemetry"].([]string)
	db.mu.RUnlock()
	if &stored[0] != &staged[0] {
		t.Fatal("candidate snapshot deep-copied an unchanged Device's telemetry")
	}
	candidate.devices[mac] = Device{MAC: mac, Name: "replacement"}
	got, err := st.Get(mac)
	if err != nil || got.Name != "" || got.Extra["telemetry"].([]string)[0] != "large-but-unchanged" {
		t.Fatalf("replacing candidate record mutated the published Device: %+v, %v", got, err)
	}
}

func TestMarkPendingRepeatPrunesOtherExpiredCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	db := js.db
	t0 := time.Unix(1_700_000_000, 0)
	now := t0
	db.now = func() time.Time { return now }
	if err := js.Put(Device{MAC: "aabbccddeeff", Extra: JSONMap{
		"telemetry": []any{map[string]any{"nested": []string{"preserve"}}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := js.MarkPending("112233445566", "stale-note"); err != nil {
		t.Fatal(err)
	}
	now = t0.Add(time.Hour)
	if err := js.MarkPending("223344556677", "same-note"); err != nil {
		t.Fatal(err)
	}
	before := persistedAt(t, path).SavedAt

	// The target repeat is still within TTL, but an unrelated older sighting
	// has expired. The same-note operation must persist that staged pruning.
	now = t0.Add(pendingTTL + time.Second)
	if err := js.MarkPending("223344556677", "same-note"); err != nil {
		t.Fatal(err)
	}
	pf := persistedAt(t, path)
	if pf.SavedAt != now.Unix() || pf.SavedAt == before {
		t.Fatalf("expired-row pruning did not commit: SavedAt=%d before=%d", pf.SavedAt, before)
	}
	if len(pf.Pending) != 1 || pf.Pending["223344556677"] != "same-note" {
		t.Fatalf("same-note prune persisted wrong pending map: %v", pf.Pending)
	}
	device, err := js.Get("aabbccddeeff")
	if err != nil || device.Extra["telemetry"].([]any)[0].(map[string]any)["nested"].([]string)[0] != "preserve" {
		t.Fatalf("committed pending prune damaged shared Device telemetry: %+v, %v", device, err)
	}
}

func TestMarkPendingExpiredRowsFreeCapAndFailuresAreAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	initial := PersistedFile{Version: 1, Devices: map[string]Device{}, Pending: map[string]string{}}
	for i := 0; i < maxPending; i++ {
		initial.Pending[fmt.Sprintf("%012x", i+1)] = "stale"
	}
	blob, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	core := js.db
	core.now = func() time.Time { return time.Now().Add(pendingTTL + time.Second) }

	// The full map is only stale in the candidate; failed persistence must not
	// publish pruning or the new insertion.
	boom := errors.New("injected MarkPending persistence failure")
	js.ops.createTemp = func(string, string) (atomicTempFile, error) { return nil, boom }
	if err := js.MarkPending("ffffffffffff", "new"); !errors.Is(err, boom) {
		t.Fatalf("MarkPending error = %v, want injected failure", err)
	}
	core.mu.RLock()
	retainedCount := len(core.pending)
	_, newPresent := core.pending["ffffffffffff"]
	core.mu.RUnlock()
	if retainedCount != maxPending || newPresent {
		t.Fatalf("failed MarkPending published staged prune/add: count=%d new=%v", retainedCount, newPresent)
	}
	if pf := persistedAt(t, path); len(pf.Pending) != maxPending {
		t.Fatalf("failed MarkPending changed disk snapshot: %d pending rows", len(pf.Pending))
	}

	// With the same expired map and successful persistence, stale rows free
	// capacity and the new entry starts a fresh TTL window.
	js.ops = defaultAtomicFileOps()
	if err := js.MarkPending("ffffffffffff", "new"); err != nil {
		t.Fatalf("expired pending entries did not free the cap: %v", err)
	}
	pending, err := js.Pending()
	if err != nil || len(pending) != 1 || pending["ffffffffffff"] != "new" {
		t.Fatalf("Pending after expiration/cap reuse = %v, %v", pending, err)
	}
	if pf := persistedAt(t, path); len(pf.Pending) != 1 || pf.Pending["ffffffffffff"] != "new" {
		t.Fatalf("successful staged prune not persisted: %v", pf.Pending)
	}
}

func TestJSONMarkPendingCapRejectDoesNotPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	initial := PersistedFile{
		Version: 1,
		Devices: map[string]Device{
			"aabbccddeeff": {MAC: "aabbccddeeff", Extra: JSONMap{
				"telemetry": []any{map[string]any{"nested": []string{"unchanged"}}},
			}},
		},
		Pending: map[string]string{},
	}
	for i := 0; i < maxPending; i++ {
		initial.Pending[fmt.Sprintf("%012x", i+1)] = "full"
	}
	blob, err := json.Marshal(initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
	iface, err := NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	js := iface.(*jsonStore)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := js.MarkPending("ffffffffffff", "over-cap"); !errors.Is(err, errPendingFull) {
		t.Fatalf("MarkPending at full unexpired cap = %v, want errPendingFull", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("rejected pending sighting changed the persisted bytes")
	}
	device, err := js.Get("aabbccddeeff")
	if err != nil || device.Extra["telemetry"].([]any)[0].(map[string]any)["nested"].([]any)[0] != "unchanged" {
		t.Fatalf("cap rejection damaged unrelated device telemetry: %+v, %v", device, err)
	}
}

func TestDeleteAndPostDeleteUpdateKeepOneStableMACStripe(t *testing.T) {
	st := NewMemStore()
	const mac = "aabbccddeeff"
	if err := st.Put(Device{MAC: mac, Name: "before"}); err != nil {
		t.Fatal(err)
	}
	core := coreOf(t, st)
	stripe := core.macLock(mac)

	entered := make(chan struct{})
	release := make(chan struct{})
	updateDone := make(chan error, 1)
	go func() {
		updateDone <- st.Update(mac, func(d *Device) error {
			close(entered)
			<-release
			d.Name = "updated-before-delete"
			return nil
		})
	}()
	<-entered
	deleteDone := make(chan error, 1)
	go func() { deleteDone <- st.Delete(mac) }()
	select {
	case err := <-deleteDone:
		t.Fatalf("Delete passed an active same-MAC Update: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-updateDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if got := core.macLock(mac); got != stripe {
		t.Fatal("Delete replaced/pruned the stable MAC stripe")
	}
	if err := st.Update(mac, func(d *Device) error { d.Name = "after-delete-upsert"; return nil }); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(mac)
	if err != nil || got.Name != "after-delete-upsert" {
		t.Fatalf("post-delete Update did not use stable stripe/upsert semantics: %+v, %v", got, err)
	}
}

func waitStoreBlockedFrame(t *testing.T, method, lockFrame string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buf, true)
		for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(stack, method) && strings.Contains(stack, lockFrame) {
				return
			}
		}
		runtime.Gosched()
	}
	n := runtime.Stack(buf, true)
	t.Fatalf("timed out waiting for %s blocked at %s:\n%s", method, lockFrame, buf[:n])
}

func TestDeleteQueuedUpdateAndPostDeleteUpdateStaySerialized(t *testing.T) {
	st := NewMemStore()
	const mac = "aabbccddeeff"
	if err := st.Put(Device{MAC: mac, Name: "initial"}); err != nil {
		t.Fatal(err)
	}
	core := coreOf(t, st)
	stripe := core.macLock(mac)

	// Hold the data lock so Delete acquires the MAC stripe and pauses while it
	// snapshots the candidate. The queued Update then resolves that same stripe.
	core.mu.Lock()
	dataLockHeld := true
	deleteDone := make(chan error, 1)
	queuedDone := make(chan error, 1)
	newDone := make(chan error, 1)
	queuedEntered := make(chan struct{}, 1)
	newEntered := make(chan struct{}, 1)
	releaseQueued := make(chan struct{})
	releaseNew := make(chan struct{})
	var queuedReleaseOnce, newReleaseOnce sync.Once
	var deleteLaunched, queuedLaunched, newLaunched bool
	var deleteComplete, queuedComplete, newComplete bool
	defer func() {
		queuedReleaseOnce.Do(func() { close(releaseQueued) })
		newReleaseOnce.Do(func() { close(releaseNew) })
		if dataLockHeld {
			core.mu.Unlock()
		}
		if deleteLaunched && !deleteComplete {
			select {
			case err := <-deleteDone:
				if err != nil {
					t.Errorf("cleanup Delete failed: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("cleanup timed out waiting for Delete")
			}
		}
		if queuedLaunched && !queuedComplete {
			select {
			case err := <-queuedDone:
				if err != nil {
					t.Errorf("cleanup queued Update failed: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("cleanup timed out waiting for queued Update")
			}
		}
		if newLaunched && !newComplete {
			select {
			case err := <-newDone:
				if err != nil {
					t.Errorf("cleanup post-Delete Update failed: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("cleanup timed out waiting for post-Delete Update")
			}
		}
	}()

	deleteLaunched = true
	go func() { deleteDone <- st.Delete(mac) }()
	waitStoreBlockedFrame(t, "(*db).Delete", "sync.(*RWMutex).RLock")

	queuedLaunched = true
	go func() {
		queuedDone <- st.Update(mac, func(d *Device) error {
			queuedEntered <- struct{}{}
			<-releaseQueued
			d.Name = "queued-update"
			return nil
		})
	}()
	waitStoreBlockedFrame(t, "(*db).update", "sync.(*Mutex).Lock")

	core.mu.Unlock()
	dataLockHeld = false
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	deleteComplete = true
	select {
	case <-queuedEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("queued Update did not enter after Delete")
	}
	if core.macLock(mac) != stripe {
		t.Fatal("Delete replaced the MAC stripe while an Update held its resolved pointer")
	}

	newLaunched = true
	go func() {
		newDone <- st.Update(mac, func(d *Device) error {
			newEntered <- struct{}{}
			<-releaseNew
			d.SiteID = "post-delete-update"
			return nil
		})
	}()
	waitStoreBlockedFrame(t, "(*db).update", "sync.(*Mutex).Lock")
	if len(newEntered) != 0 {
		t.Fatal("post-Delete callback overlapped the queued callback")
	}

	queuedReleaseOnce.Do(func() { close(releaseQueued) })
	if err := <-queuedDone; err != nil {
		t.Fatal(err)
	}
	queuedComplete = true
	select {
	case <-newEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("post-Delete callback did not enter after queued callback released the stripe")
	}
	newReleaseOnce.Do(func() { close(releaseNew) })
	if err := <-newDone; err != nil {
		t.Fatal(err)
	}
	newComplete = true

	got, err := st.Get(mac)
	if err != nil || got.Name != "queued-update" || got.SiteID != "post-delete-update" {
		t.Fatalf("serialized delete/update result = %+v, %v", got, err)
	}
}

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestMemStoreRoundtrip(t *testing.T) {
	st := NewMemStore()
	rec := Device{MAC: "AA:BB:CC:DD:EE:FF", State: StatePending, Model: "U7PG2"}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("aabbccddeeff") // canonical lookup ignores case/separators
	if err != nil {
		t.Fatal(err)
	}
	if got.Model != "U7PG2" || got.State != StatePending {
		t.Fatalf("got %+v", got)
	}
	if _, err := st.Get("112233445566"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := st.MarkPending("1 1:22:33:44:55:66", "discovery:platform=U7PG2"); err != nil {
		t.Fatal(err)
	}
	p, err := st.Pending()
	if err != nil || p["112233445566"] != "discovery:platform=U7PG2" {
		t.Fatalf("pending = %v, err = %v", p, err)
	}
	list, err := st.List()
	if err != nil || len(list) != 1 || !strings.EqualFold(list[0].MAC, "aabbccddeeff") {
		t.Fatalf("list = %v, err = %v", list, err)
	}
	if err := st.Delete("aabbccddeeff"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get("aabbccddeeff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
	if err := st.Delete("aabbccddeeff"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: want ErrNotFound, got %v", err)
	}
}

func TestJSONStorePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")

	// Fresh creation (idempotent on missing file).
	st, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("fresh create: %v", err)
	}
	if err := st.Put(Device{MAC: "aabbccddeeff", State: StateAdopting, XAuthkey: "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkPending("112233445566", "discovery:platform=U6Lite"); err != nil {
		t.Fatal(err)
	}

	// Reopen: data must survive.
	st2, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	rec, err := st2.Get("aabbccddeeff")
	if err != nil || rec.XAuthkey != "abc" || rec.State != StateAdopting {
		t.Fatalf("reopen got %+v err %v", rec, err)
	}
	pending, err := st2.Pending()
	if err != nil || pending["112233445566"] != "discovery:platform=U6Lite" {
		t.Fatalf("reopened pending = %v err = %v", pending, err)
	}

	// No temp files left behind.
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("expected exactly one store file, found %d: %v", len(entries), entries)
	}
}

func TestJSONStoreCorruptFileIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewJSONStore(path); err == nil {
		t.Fatal("expected error on corrupt store file")
	}
}

// ---- Update (§2c) -----------------------------------------------------------

func TestUpdateUpsertsUnknownMAC(t *testing.T) {
	st := NewMemStore()
	err := st.Update("aa:bb:cc:dd:ee:ff", func(d *Device) error {
		if d.MAC != "aabbccddeeff" {
			t.Fatalf("upsert seed mac = %q", d.MAC)
		}
		d.Model = "U7PG2"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("aabbccddeeff")
	if err != nil || got.Model != "U7PG2" {
		t.Fatalf("upsert failed: %+v %v", got, err)
	}
}

func TestUpdateFnErrorAborts(t *testing.T) {
	st := NewMemStore()
	if err := st.Put(Device{MAC: "aabbccddeeff", XAuthkey: "old"}); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("injected")
	if err := st.Update("aabbccddeeff", func(d *Device) error {
		d.XAuthkey = "mutated"
		return boom
	}); !errors.Is(err, boom) {
		t.Fatalf("want injected error, got %v", err)
	}
	got, _ := st.Get("aabbccddeeff")
	if got.XAuthkey != "old" {
		t.Fatalf("fn-error cycle mutated the record: %+v", got)
	}
}

// The RMW cycle serializes concurrent writers (the brick-the-key scenario:
// two goroutines rotating the same device).
func TestUpdateSerializesRaces(t *testing.T) {
	st := NewMemStore()
	if err := st.Put(Device{MAC: "aabbccddeeff", State: StatePending}); err != nil {
		t.Fatal(err)
	}
	// Truly concurrent RMW cycles for the same MAC: per-MAC serialization
	// guarantees no cycle sees another's partial mutation (caught by -race
	// otherwise, e.g. via the shared Authkeys backing array aliasing).
	const workers, cycles = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < cycles; i++ {
				if err := st.Update("aabbccddeeff", func(d *Device) error {
					d.Authkeys = append(d.Authkeys, fmt.Sprintf("k%02d-%02d", w, i))
					return nil
				}); err != nil {
					t.Errorf("worker %d cycle %d: %v", w, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	got, _ := st.Get("aabbccddeeff")
	if len(got.Authkeys) != workers*cycles {
		t.Fatalf("lost updates under concurrency: %d != %d", len(got.Authkeys), workers*cycles)
	}
}

// Get/List/Put must return detached deep copies (no aliasing into the
// store's own structures — protects against concurrent map writes during
// save's marshal).
func TestDeepCopyIsolation(t *testing.T) {
	st := NewMemStore()
	rec := Device{MAC: "aabbccddeeff", Authkeys: []string{"k1"},
		Extra: JSONMap{}, LastUps: JSONMap{"up": true}}
	rec.Extra["radio_table"] = []any{map[string]any{"name": "ra0", "channel": "0"}}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get("aabbccddeeff")
	// mutate the returned copies (nested!) — store must stay clean.
	got.Authkeys[0] = "hacked"
	rtm := got.Extra["radio_table"].([]any)[0].(map[string]any)
	rtm["name"] = "hacked"
	got.LastUps["up"] = false

	fresh, _ := st.Get("aabbccddeeff")
	if fresh.Authkeys[0] != "k1" {
		t.Fatalf("Authkeys aliased: %v", fresh.Authkeys)
	}
	rt := fresh.Extra["radio_table"].([]any)[0].(map[string]any)
	if rt["name"] != "ra0" {
		t.Fatalf("nested Extra aliased: %v", rt)
	}
	if fresh.LastUps["up"] != true {
		t.Fatalf("LastUps aliased: %v", fresh.LastUps)
	}
	// List detachment:
	lst, _ := st.List()
	lst[0].Extra["radio_table"].([]any)[0].(map[string]any)["name"] = "hacked2"
	fresh2, _ := st.Get("aabbccddeeff")
	if fresh2.Extra["radio_table"].([]any)[0].(map[string]any)["name"] != "ra0" {
		t.Fatal("List aliases store internals")
	}
}

// ---- pending cap (§6a) ------------------------------------------------------

func TestMarkPendingCap(t *testing.T) {
	st := NewMemStore()
	if err := st.MarkPending("112233445566", "note"); err != nil {
		t.Fatal(err)
	}
	// fill to the cap
	for i := 0; len(mapFromSt(t, st)) < maxPending; i++ {
		if err := st.MarkPending(fmt.Sprintf("aa00%010x", i), "n"); err != nil {
			t.Fatalf("cap insert %d failed: %v", i, err)
		}
	}
	// one MORE new MAC → error
	if err := st.MarkPending("ffffffffffff", "n"); err == nil {
		t.Fatal("new MAC beyond cap must error")
	}
	// existing MAC still refreshes fine
	if err := st.MarkPending("112233445566", "note2"); err != nil {
		t.Fatalf("existing sighting refresh failed: %v", err)
	}
	p, _ := st.Pending()
	if p["112233445566"] != "note2" {
		t.Fatalf("existing refresh lost: %q", p["112233445566"])
	}
}

// mapFromSt is a test helper converting the pending view length check.
func mapFromSt(t *testing.T, st DeviceStore) map[string]string {
	t.Helper()
	p, err := st.Pending()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

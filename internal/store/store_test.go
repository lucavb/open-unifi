package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

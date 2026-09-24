package app

// Blocked-client set round-trips through the real App + store: the
// admin-owned row behind the blocked_sta wire field (docs/PROTOCOL-mgmt.md
// §4/§6.2(d)). Covers idempotency, canonical ordering, error shapes for
// the adminapi route mapping (404/409), and persistence across a JSON
// store reopen.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/store"
)

func TestBlockedClientRoundTrip(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	const mac = "aabbccddeeff"
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: mac}); err != nil {
		t.Fatal(err)
	}

	// Fresh set: empty list, never nil (JSON []).
	v, err := a.ListBlockedClients(ctx, mac)
	if err != nil || v.Blocked == nil || len(v.Blocked) != 0 || v.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("fresh list: %+v err=%v", v, err)
	}

	// Block two clients in un-normalized spellings/call order: the stored
	// set is canonical-sorted, the view is colon-hex.
	if v, err = a.BlockClient(ctx, mac, "AA:BB:CC:DD:EE:FF"); err != nil || len(v.Blocked) != 1 || v.Blocked[0] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("first block: %+v err=%v", v, err)
	}
	if v, err = a.BlockClient(ctx, mac, "00-11-22-33-44-55"); err != nil || len(v.Blocked) != 2 {
		t.Fatalf("second block: %+v err=%v", v, err)
	}
	if v.Blocked[0] != "00:11:22:33:44:55" || v.Blocked[1] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("set order = %v, want canonical sort", v.Blocked)
	}

	// Idempotent re-block: same view, no duplicate row.
	if v, err = a.BlockClient(ctx, mac, "aabbccddeeff"); err != nil || len(v.Blocked) != 2 {
		t.Fatalf("re-block must be idempotent: %+v err=%v", v, err)
	}

	// The store record holds the canonical form.
	rec, err := st.Get(mac)
	if err != nil {
		t.Fatal(err)
	}
	if set := store.BlockedClients(rec); len(set) != 2 || set[0] != "001122334455" || set[1] != "aabbccddeeff" {
		t.Fatalf("stored set = %v", set)
	}

	// Unblock a not-blocked client: ErrNotFound (route 404), record intact.
	if _, err = a.UnblockClient(ctx, mac, "ff:ee:dd:cc:bb:aa"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("unblock not-blocked = %v, want ErrNotFound", err)
	}
	if rec, err = st.Get(mac); err != nil || len(store.BlockedClients(rec)) != 2 {
		t.Fatalf("failed unblock mutated the record: %+v err=%v", rec, err)
	}

	// Unblock one: the remainder is what the view and the record say.
	if v, err = a.UnblockClient(ctx, mac, "AABB.CCDD.EEFF"); err != nil || len(v.Blocked) != 1 || v.Blocked[0] != "00:11:22:33:44:55" {
		t.Fatalf("unblock: %+v err=%v", v, err)
	}

	// Unknown device: ErrNotFound from all three (the route's 404).
	for _, call := range []struct {
		name string
		fn   func() error
	}{
		{"list", func() error {
			_, err := a.ListBlockedClients(ctx, "ff:ff:ff:ff:ff:ff")
			return err
		}},
		{"block", func() error {
			_, err := a.BlockClient(ctx, "ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55")
			return err
		}},
		{"unblock", func() error {
			_, err := a.UnblockClient(ctx, "ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55")
			return err
		}},
	} {
		if err := call.fn(); !errors.Is(err, adminapi.ErrNotFound) {
			t.Fatalf("%s unknown device = %v, want ErrNotFound", call.name, err)
		}
	}
	// Unparseable device spelling: cannot exist, not-found semantics.
	if _, err = a.ListBlockedClients(ctx, "not-a-mac"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("unparseable device mac = %v, want ErrNotFound", err)
	}
	// Unparseable client spelling: adapter-side backstop conflict (the
	// adminapi boundary already 400'd; every Backend caller is fenced).
	if _, err = a.BlockClient(ctx, mac, "not-a-mac"); !errors.Is(err, adminapi.ErrConflict) {
		t.Fatalf("unparseable client mac = %v, want ErrConflict", err)
	}

	// Unblock the last: empty set drops the Extra row entirely.
	if v, err = a.UnblockClient(ctx, mac, "001122334455"); err != nil || len(v.Blocked) != 0 {
		t.Fatalf("final unblock: %+v err=%v", v, err)
	}
	if rec, err = st.Get(mac); err != nil {
		t.Fatal(err)
	}
	if _, ok := rec.Extra["blocked_sta"]; ok {
		t.Fatalf("empty set must drop the Extra row: %v", rec.Extra["blocked_sta"])
	}
}

// TestBlockedClientsPersistAcrossReopen: the blocked set is record data —
// it must survive a JSON store close/reopen (the []any Extra row marshals
// and re-loads losslessly for the store helper's canonical read).
func TestBlockedClientsPersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	st, err := store.NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	a := New(st, filepath.Join(t.TempDir(), "site-settings.json"), SiteSettings{}, quietLogger())
	ctx := context.Background()
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "aabbccddeeff"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.BlockClient(ctx, "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"); err != nil {
		// NOTE: device arg first, client second — this call blocks 11:22:33
		// on device aa:bb:cc:dd:ee:ff.
		t.Fatal(err)
	}

	st2, err := store.NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	a2 := New(st2, filepath.Join(t.TempDir(), "site-settings.json"), SiteSettings{}, quietLogger())
	v, err := a2.ListBlockedClients(ctx, "aabbccddeeff")
	if err != nil || len(v.Blocked) != 1 || v.Blocked[0] != "11:22:33:44:55:66" {
		t.Fatalf("post-reopen list: %+v err=%v", v, err)
	}
}

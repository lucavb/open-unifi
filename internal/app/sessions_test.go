package app

// ListDeviceClients round-trips the controller-owned session rows through
// the real App + store: the read-only projection the admin API serves
// (sorted colon-hex MACs, connected state, last-seen timestamps), seeded
// the way the inform path seeds them (store.RefreshSessions).

import (
	"context"
	"errors"
	"testing"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/store"
)

func TestListDeviceClients(t *testing.T) {
	a, st, _ := testApp(t)
	ctx := context.Background()
	const mac = "aabbccddeeff"
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: mac}); err != nil {
		t.Fatal(err)
	}

	// Fresh device: empty listing (never nil), not an error.
	rows, err := a.ListDeviceClients(ctx, mac)
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("fresh clients: %+v err=%v", rows, err)
	}

	// Seed sessions the way the inform path does: two connects (one in an
	// un-normalized spelling), then one disconnect.
	if err := st.Update(mac, func(d *store.Device) error {
		store.RefreshSessions(d, []string{"AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55"}, 1000)
		store.RefreshSessions(d, []string{"001122334455"}, 1010)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	rows, err = a.ListDeviceClients(ctx, mac)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want 2 (the disconnected row persists)", rows)
	}
	// Canonical (sorted) order: 001122334455 < aabbccddeeff.
	if rows[0].MAC != "00:11:22:33:44:55" || !rows[0].Connected || rows[0].LastSeen != 1010 {
		t.Fatalf("row[0] = %+v, want the connected survivor with its timestamp", rows[0])
	}
	if rows[1].MAC != "aa:bb:cc:dd:ee:ff" || rows[1].Connected || rows[1].LastSeen != 1000 {
		t.Fatalf("row[1] = %+v, want the disconnected row keeping its last proof", rows[1])
	}

	// Unknown / unparseable device: ErrNotFound (the route's 404).
	if _, err := a.ListDeviceClients(ctx, "ff:ff:ff:ff:ff:ff"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("unknown device = %v, want ErrNotFound", err)
	}
	if _, err := a.ListDeviceClients(ctx, "not-a-mac"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("unparseable device = %v, want ErrNotFound", err)
	}
}

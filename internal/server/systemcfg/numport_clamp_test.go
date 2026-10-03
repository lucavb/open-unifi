package systemcfg

// Regression tests ensure device-reported num_port cannot drive unbounded
// ethN expansion. Each entry is capped at 8 ports and the aggregate at 64.

import (
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

// ethernetTableRecord builds an adopted record whose Extra carries the given
// ethernet_table entries exactly as the server persists them from informs
// (numeric scalars decode as float64).
func ethernetTableRecord(entries ...map[string]any) store.Device {
	list := make([]any, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	return store.Device{
		MAC: "aabbccddeeff", Model: "U7PG2", State: store.StateAdopted,
		Extra: store.JSONMap{"ethernet_table": list},
	}
}

// TestNumPortClampLyingDevice: a single entry reporting num_port 1<<20 must
// yield known=true with at most 64 expanded names, not a million.
func TestNumPortClampLyingDevice(t *testing.T) {
	d := ethernetTableRecord(map[string]any{"num_port": float64(1 << 20)})
	ports, known := ethPortNamesFromEthernetTable(d)
	if !known {
		t.Fatal("ethernet_table entry with num_port should yield known=true")
	}
	t.Logf("expanded %d port names from num_port=%d", len(ports), 1<<20)
	if len(ports) > 64 {
		t.Fatalf("len(ports) = %d, want <= 64", len(ports))
	}
}

// TestNumPortClampSaneEntry: a sane entry (num_port 4) still expands to
// exactly eth0..eth3.
func TestNumPortClampSaneEntry(t *testing.T) {
	d := ethernetTableRecord(map[string]any{"num_port": float64(4)})
	ports, known := ethPortNamesFromEthernetTable(d)
	if !known {
		t.Fatal("ethernet_table entry with num_port should yield known=true")
	}
	t.Logf("expanded %d port names from num_port=4", len(ports))
	if len(ports) != 4 {
		t.Fatalf("len(ports) = %d, want 4", len(ports))
	}
	want := []string{"eth0", "eth1", "eth2", "eth3"}
	for i, name := range ports {
		if name != want[i] {
			t.Fatalf("ports[%d] = %q, want %q", i, name, want[i])
		}
	}
}

// TestNumPortClampAggregateCap: multiple entries are sum-capped — ten
// entries of num_port 10 would naively sum to 100 but must yield 64 names.
func TestNumPortClampAggregateCap(t *testing.T) {
	var entries []map[string]any
	for i := 0; i < 10; i++ {
		entries = append(entries, map[string]any{"num_port": float64(10)})
	}
	d := ethernetTableRecord(entries...)
	ports, known := ethPortNamesFromEthernetTable(d)
	if !known {
		t.Fatal("ethernet_table entries with num_port should yield known=true")
	}
	t.Logf("expanded %d port names from 10 entries of num_port=10", len(ports))
	if len(ports) != 64 {
		t.Fatalf("len(ports) = %d, want 64", len(ports))
	}
}

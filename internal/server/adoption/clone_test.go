package adoption

// Snapshot-independence pins for the engine's working clone: the clone is
// the only thing Decide may mutate, so every nested structure it shares a
// backing with the request snapshot (Extra leaves, Authkeys, the brightness
// pointee) must be deep-copied — a mutation through the clone can never be
// visible through the source device.

import (
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

func TestCloneDeviceSnapshotIndependence(t *testing.T) {
	brightness := 7
	src := store.Device{
		Authkeys:                   []string{"key-old", "key-new"},
		LEDOverrideColorBrightness: &brightness,
		Extra: store.JSONMap{
			"nested": map[string]any{"depth": "original"},
			"locs":   []string{"site-a", "site-b"},
		},
	}

	clone := cloneDevice(src)

	// Extra is part of every engine write path; a nil source extra still
	// yields a writable map on the clone.
	if clone.Extra == nil {
		t.Fatal("clone.Extra = nil, want a materialized map")
	}

	// Mutate every aliased structure through the clone...
	clone.Extra["nested"].(map[string]any)["depth"] = "mutated"
	clone.Extra["locs"].([]string)[0] = "mutated"
	*clone.LEDOverrideColorBrightness = 99
	clone.Authkeys[1] = "mutated"

	// ...and require the source device to be byte-for-byte untouched in all
	// four ways.
	if got := src.Extra["nested"].(map[string]any)["depth"]; got != "original" {
		t.Fatalf("nested Extra map aliased: src depth = %q, want %q", got, "original")
	}
	if got := src.Extra["locs"].([]string)[0]; got != "site-a" {
		t.Fatalf("[]string leaf aliased: src locs[0] = %q, want %q", got, "site-a")
	}
	if got := *src.LEDOverrideColorBrightness; got != 7 {
		t.Fatalf("brightness pointee aliased: %d, want %d", got, 7)
	}
	if got := src.Authkeys[1]; got != "key-new" {
		t.Fatalf("Authkeys aliased: src[1] = %q, want %q", got, "key-new")
	}

	// nil preserves the store's contract: nil extra in, writable empty map
	// out; nil LastUps stays nil (no spurious delta traffic).
	nilSrc := store.Device{}
	nilClone := cloneDevice(nilSrc)
	if nilClone.Extra == nil {
		t.Fatal("nil-source clone.Extra = nil, want an empty map")
	}
	if len(nilClone.Extra) != 0 {
		t.Fatalf("nil-source clone.Extra = %v, want empty", nilClone.Extra)
	}
	if nilClone.LastUps != nil {
		t.Fatalf("nil-source clone.LastUps = %v, want nil", nilClone.LastUps)
	}
}

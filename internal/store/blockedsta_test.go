package store

import (
	"reflect"
	"testing"
)

// The blocked-client set is the ADMIN-OWNED record row behind the
// blocked_sta wire field (docs/PROTOCOL-mgmt.md §4): canonical 12-hex,
// sorted, deduplicated, stored under the wire-named Extra key.
func TestBlockedClientsAddRemoveList(t *testing.T) {
	d := Device{MAC: "aabbccddeeff"} // nil Extra: pre-inform record

	added, err := AddBlockedClient(&d, "11:22:33:44:55:66")
	if err != nil || !added {
		t.Fatalf("first add: added=%v err=%v", added, err)
	}
	added, err = AddBlockedClient(&d, "1122334455 66") // same MAC, other spelling
	if err != nil || added {
		t.Fatalf("re-add must be idempotent: added=%v err=%v", added, err)
	}
	added, err = AddBlockedClient(&d, "AA-BB-CC-DD-EE-FF") // canonicalizes + upper case
	if err != nil || !added {
		t.Fatalf("second add: added=%v err=%v", added, err)
	}
	// Stored form: canonical, sorted, no separator spellings, non-string
	// entries impossible via the writers.
	want := []string{"112233445566", "aabbccddeeff"}
	if got := BlockedClients(d); !reflect.DeepEqual(got, want) {
		t.Fatalf("set = %v, want %v", got, want)
	}

	removed, err := RemoveBlockedClient(&d, "aabbccddeeff")
	if err != nil || !removed {
		t.Fatalf("remove: removed=%v err=%v", removed, err)
	}
	removed, err = RemoveBlockedClient(&d, "aabbccddeeff")
	if err != nil || removed {
		t.Fatalf("re-remove must be a no-op: removed=%v err=%v", removed, err)
	}
	if got := BlockedClients(d); !reflect.DeepEqual(got, []string{"112233445566"}) {
		t.Fatalf("after remove: %v", got)
	}

	// Emptying the set drops the key entirely (absent == empty).
	if _, err := RemoveBlockedClient(&d, "112233445566"); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Extra[blockedStaKey]; ok {
		t.Fatalf("empty set must delete the Extra key, got %v", d.Extra[blockedStaKey])
	}
	if got := BlockedClients(d); len(got) != 0 {
		t.Fatalf("empty set read: %v", got)
	}
}

func TestBlockedClientsRejectsInvalidMAC(t *testing.T) {
	d := Device{MAC: "aabbccddeeff", Extra: JSONMap{}}
	if _, err := AddBlockedClient(&d, "not-a-mac"); err == nil {
		t.Fatal("add must reject an unparseable MAC")
	}
	if _, err := RemoveBlockedClient(&d, "zz:bb:cc:dd:ee:ff"); err == nil {
		t.Fatal("remove must reject an unparseable MAC")
	}
	if got := BlockedClients(d); len(got) != 0 {
		t.Fatalf("failed writes must leave the set empty, got %v", got)
	}
}

// Reads tolerate stored noise: odd-typed or malformed entries are skipped,
// never fatal, and duplicate spellings collapse to one canonical entry.
func TestBlockedClientsReadToleratesNoise(t *testing.T) {
	d := Device{Extra: JSONMap{"blocked_sta": []any{
		"11:22:33:44:55:66",
		"112233445566", // duplicate, other spelling
		"aabbccddeeff",
		42,               // wrong type: skipped
		"not-a-mac",      // malformed: skipped
		"aabb.ccdd.eeff", // duplicate, dotted
		"00:11:22:33:44:55",
	}}}
	want := []string{"001122334455", "112233445566", "aabbccddeeff"}
	if got := BlockedClients(d); !reflect.DeepEqual(got, want) {
		t.Fatalf("noisy read = %v, want %v", got, want)
	}
}

// The set survives the store's deep clone (Get/List/Update hand out detached
// copies — aliasing the stored []any would be a store invariant violation).
func TestBlockedClientsSurviveStoreClone(t *testing.T) {
	st := NewMemStore()
	if err := st.Update("aabbccddeeff", func(d *Device) error {
		_, err := AddBlockedClient(d, "001122334455")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if set := BlockedClients(got); !reflect.DeepEqual(set, []string{"001122334455"}) {
		t.Fatalf("post-clone set = %v", set)
	}
}

package inform

// StationMACs decode gates: the absent/empty distinction (a sparse
// heartbeat must not read as "zero clients" — CONTEXT.md device-refreshable
// caps semantics), verbatim MAC spellings, and the never-fatal odd-row
// tolerance.

import "testing"

func TestStationMACsAbsentTable(t *testing.T) {
	// No table at all: a sparse heartbeat or a key with a non-array
	// value. Callers must leave session state untouched.
	for name, body := range map[string]map[string]any{
		"no key":        {"_type": "heartbeat"},
		"null value":    {"sta_table": nil},
		"string value":  {"sta_table": "aa:bb:cc:dd:ee:ff"},
		"object value":  {"sta_table": map[string]any{"mac": "aa:bb:cc:dd:ee:ff"}},
		"numeric value": map[string]any{"sta_table": 42},
		"bool value":    {"sta_table": true},
	} {
		macs, present := StationMACs(body)
		if present || macs != nil {
			t.Fatalf("%s: macs=%v present=%v, want nil/false", name, macs, present)
		}
	}
}

func TestStationMACsEmptyTable(t *testing.T) {
	// A JSON array with zero rows IS a report: zero clients associated.
	macs, present := StationMACs(map[string]any{"sta_table": []any{}})
	if !present || macs != nil {
		t.Fatalf("empty table: macs=%v present=%v, want nil/true", macs, present)
	}
}

func TestStationMACsRows(t *testing.T) {
	// Rows pass through verbatim — any spelling, in table order; the
	// store lane canonicalizes.
	body := map[string]any{"sta_table": []any{
		map[string]any{"mac": "AA:BB:CC:DD:EE:FF", "rssi": -60},
		map[string]any{"mac": "00-11-22-33-44-55"},
		map[string]any{"mac": "001122334455"},
	}}
	macs, present := StationMACs(body)
	if !present || len(macs) != 3 {
		t.Fatalf("macs=%v present=%v, want the 3 verbatim rows", macs, present)
	}
	want := []string{"AA:BB:CC:DD:EE:FF", "00-11-22-33-44-55", "001122334455"}
	for i := range want {
		if macs[i] != want[i] {
			t.Fatalf("row %d = %q, want %q (verbatim, table order)", i, macs[i], want[i])
		}
	}
}

func TestStationMACsOddRowsSkipped(t *testing.T) {
	// Odd rows never fail an inform: non-object rows, missing/empty/
	// non-string mac fields are skipped and the rest still decodes.
	body := map[string]any{"sta_table": []any{
		"raw-string-row",
		42,
		nil,
		map[string]any{"ip": "192.168.1.50"}, // no mac field
		map[string]any{"mac": ""},            // empty mac
		map[string]any{"mac": 66052},         // non-string mac
		map[string]any{"mac": "aa:bb:cc:dd:ee:ff", // the one good row
			"assoc": true},
		map[string]any{"signal": -70}, // another macless object
	}}
	macs, present := StationMACs(body)
	if !present || len(macs) != 1 || macs[0] != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("macs=%v present=%v, want only the one decodable row", macs, present)
	}
}

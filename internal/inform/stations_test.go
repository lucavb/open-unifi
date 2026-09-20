package inform

// StationMACs decode gates: the absent/empty distinction (a sparse
// heartbeat must not read as "zero clients" — CONTEXT.md device-refreshable
// caps semantics), verbatim MAC spellings, and the never-fatal odd-row
// tolerance. The nested-shape fixtures mirror the 2026-09-20 bench
// capture (U7PG2, fw 6.8.2.15592): stations arrive inside the vap rows
// as vap_table[].sta_table[], one vap's table possibly empty.

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

func TestStationMACsVapNestedLivePin(t *testing.T) {
	// The live-pinned shape (2026-09-20 capture): stations nested in the
	// vap rows; the 2.4 GHz vap's table is empty while 5 GHz carries the
	// one associated client. Fixture mirrors the captured inform.
	body := map[string]any{"vap_table": []any{
		map[string]any{
			"essid": "openunifi-gate-check", "name": "ath1", "radio": "na",
			"num_sta": 1, "state": "RUN", "up": true,
			"sta_table": []any{
				map[string]any{"mac": "aa:bb:cc:dd:ee:01", "uptime": 290},
			},
		},
		map[string]any{
			"essid": "openunifi-gate-check", "name": "ath0", "radio": "ng",
			"num_sta": 0, "state": "RUN", "up": true,
			"sta_table": []any{},
		},
	}}
	macs, present := StationMACs(body)
	if !present || len(macs) != 1 || macs[0] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("macs=%v present=%v, want the single 5 GHz station", macs, present)
	}
}

func TestStationMACsVapNestedAllEmptyIsReport(t *testing.T) {
	// Both vaps report empty tables: a genuine zero-client report —
	// present=true with no MACs, the disconnect-side evidence.
	body := map[string]any{"vap_table": []any{
		map[string]any{"name": "ath1", "num_sta": 0, "sta_table": []any{}},
		map[string]any{"name": "ath0", "num_sta": 0, "sta_table": []any{}},
	}}
	macs, present := StationMACs(body)
	if !present || macs != nil {
		t.Fatalf("macs=%v present=%v, want nil/true (zero clients)", macs, present)
	}
}

func TestStationMACsVapTableWithoutStaKeys(t *testing.T) {
	// A vap_table whose rows carry no sta_table key at all is an
	// uncertain shape, not a zero-client report: absent, sessions
	// untouched.
	body := map[string]any{"vap_table": []any{
		map[string]any{"essid": "x", "name": "ath1", "num_sta": 1},
	}}
	macs, present := StationMACs(body)
	if present || macs != nil {
		t.Fatalf("macs=%v present=%v, want nil/false (uncertain shape)", macs, present)
	}
}

func TestStationMACsSparseHeartbeat(t *testing.T) {
	// The ~935-byte notification heartbeats carry neither vap_table nor
	// sta_table: no client evidence, rows and events survive untouched.
	body := map[string]any{
		"cfgversion": "x", "state": "uap", "uptime": 123456,
		"inform_as_notif": true, "notif_reason": "heartbeat",
	}
	macs, present := StationMACs(body)
	if present || macs != nil {
		t.Fatalf("macs=%v present=%v, want nil/false (sparse heartbeat)", macs, present)
	}
}

func TestStationMACsBothShapesUnionAndDedupe(t *testing.T) {
	// The fallback top-level key and the pinned nested shape union;
	// the same MAC through both shapes is reported once, and the
	// wire order is top-level rows first, then vap order.
	body := map[string]any{
		"sta_table": []any{
			map[string]any{"mac": "aa:aa:aa:aa:aa:aa"},
			map[string]any{"mac": "aa:bb:cc:dd:ee:01"}, // also nested below
		},
		"vap_table": []any{
			map[string]any{"name": "ath1", "sta_table": []any{
				map[string]any{"mac": "aa:bb:cc:dd:ee:01"}, // deduped
				map[string]any{"mac": "bb:bb:bb:bb:bb:bb"},
			}},
			map[string]any{"name": "ath0", "sta_table": []any{}},
		},
	}
	macs, present := StationMACs(body)
	if !present {
		t.Fatal("present=false, want true")
	}
	want := []string{"aa:aa:aa:aa:aa:aa", "aa:bb:cc:dd:ee:01", "bb:bb:bb:bb:bb:bb"}
	if len(macs) != len(want) {
		t.Fatalf("macs=%v, want %v", macs, want)
	}
	for i := range want {
		if macs[i] != want[i] {
			t.Fatalf("row %d = %q, want %q", i, macs[i], want[i])
		}
	}
}

func TestStationMACsNestedOddRowsSkipped(t *testing.T) {
	// Odd rows inside a nested table are skipped like top-level ones;
	// the healthy sibling vap row still decodes.
	body := map[string]any{"vap_table": []any{
		map[string]any{"name": "ath1", "sta_table": []any{
			"noise",
			map[string]any{"mac": ""},
			map[string]any{"rssi": -60},
		}},
		map[string]any{"name": "ath0", "sta_table": []any{
			map[string]any{"mac": "cc:cc:cc:cc:cc:cc"},
		}},
	}}
	macs, present := StationMACs(body)
	if !present || len(macs) != 1 || macs[0] != "cc:cc:cc:cc:cc:cc" {
		t.Fatalf("macs=%v present=%v, want only the ath0 station", macs, present)
	}
}

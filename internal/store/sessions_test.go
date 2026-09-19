package store

// Session store tests: RefreshSessions transition rules and row
// persistence, mirroring the blocked-set tests' drive-through-the-public-
// API style. Every test asserts the persisted Extra shape (the JSON round
// trip's own encoding: float64 timestamps, bool connected, plain
// map[string]any rows) plus the event lists the adapter counts.

import (
	"encoding/json"
	"testing"
)

func sessDev() Device {
	return Device{MAC: "aabbccddeeff", Extra: JSONMap{}}
}

func TestRefreshSessionsRecordsRows(t *testing.T) {
	d := sessDev()
	connects, disconnects := RefreshSessions(&d, []string{"AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"}, 1000)
	if len(disconnects) != 0 {
		t.Fatalf("first sighting must not disconnect: %v", disconnects)
	}
	wantConnects := []string{"112233445566", "aabbccddeeff"}
	if len(connects) != 2 || connects[0] != wantConnects[0] || connects[1] != wantConnects[1] {
		t.Fatalf("connects = %v, want %v (canonical + sorted)", connects, wantConnects)
	}
	rows := ClientSessions(d)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if !r.Connected {
			t.Fatalf("fresh row %s must be connected", r.MAC)
		}
		if r.LastSeen != 1000 {
			t.Fatalf("row %s last_seen = %d, want the inform timestamp", r.MAC, r.LastSeen)
		}
	}
	// Persisted shape: plain JSON object keyed by canonical MAC, float64
	// timestamps, bool connected — the exact shape the reader loads back.
	raw, ok := d.Extra[SessionsExtraKey].(map[string]any)
	if !ok {
		t.Fatalf("Extra shape = %T, want map[string]any", d.Extra[SessionsExtraKey])
	}
	row, ok := raw["aabbccddeeff"].(map[string]any)
	if !ok {
		t.Fatalf("row shape = %T, want map[string]any", raw["aabbccddeeff"])
	}
	if ls, ok := row["last_seen"].(float64); !ok || ls != 1000 {
		t.Fatalf("row last_seen = %v (%T), want float64(1000)", row["last_seen"], row["last_seen"])
	}
	if c, ok := row["connected"].(bool); !ok || !c {
		t.Fatalf("row connected = %v (%T), want true", row["connected"], row["connected"])
	}
	// No disconnect happened: the pending-event flag must stay absent.
	if _, armed := d.Extra[SessionDisconnectEventExtraKey]; armed {
		t.Fatal("connect-only refresh must not arm the disconnect event")
	}
}

func TestRefreshSessionsDisconnectEvent(t *testing.T) {
	d := sessDev()
	if _, dsc := RefreshSessions(&d, []string{"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}, 1000); len(dsc) != 0 {
		t.Fatalf("setup disconnects: %v", dsc)
	}
	// Next full inform carries only the second client.
	connects, disconnects := RefreshSessions(&d, []string{"112233445566"}, 1010)
	if len(connects) != 0 {
		t.Fatalf("surviving client must not re-connect: %v", connects)
	}
	if len(disconnects) != 1 || disconnects[0] != "aabbccddeeff" {
		t.Fatalf("disconnects = %v, want [aabbccddeeff]", disconnects)
	}
	if v, ok := d.Extra[SessionDisconnectEventExtraKey].(bool); !ok || !v {
		t.Fatalf("disconnect must arm the one-shot event flag, got %v (%T)", d.Extra[SessionDisconnectEventExtraKey], d.Extra[SessionDisconnectEventExtraKey])
	}
	// The disconnected row persists (connected=false, last_seen keeps the
	// last proof); the surviving client's timestamp advances.
	rows := map[string]ClientSession{}
	for _, r := range ClientSessions(d) {
		rows[r.MAC] = r
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (disconnected row persists)", len(rows))
	}
	if got := rows["aabbccddeeff"]; got.Connected || got.LastSeen != 1000 {
		t.Fatalf("disconnected row = %+v, want connected=false last_seen=1000", got)
	}
	if got := rows["112233445566"]; !got.Connected || got.LastSeen != 1010 {
		t.Fatalf("surviving row = %+v, want connected=true last_seen=1010", got)
	}
}

func TestRefreshSessionsReconnect(t *testing.T) {
	d := sessDev()
	RefreshSessions(&d, []string{"aabbccddeeff"}, 1000)
	RefreshSessions(&d, nil, 1010) // empty table: the client left
	// The client returns in a later full inform.
	connects, disconnects := RefreshSessions(&d, []string{"aabbccddeeff"}, 1020)
	if len(disconnects) != 0 {
		t.Fatalf("reconnect must not disconnect: %v", disconnects)
	}
	if len(connects) != 1 || connects[0] != "aabbccddeeff" {
		t.Fatalf("connects = %v, want [aabbccddeeff]", connects)
	}
	rows := ClientSessions(d)
	if len(rows) != 1 || !rows[0].Connected || rows[0].LastSeen != 1020 {
		t.Fatalf("row = %+v, want reconnect connected=true last_seen=1020", rows)
	}
}

func TestRefreshSessionsEmptyTableDisconnectsAll(t *testing.T) {
	d := sessDev()
	RefreshSessions(&d, []string{"aabbccddeeff", "112233445566"}, 1000)
	// A PRESENT but EMPTY station table: the device reports zero clients —
	// both rows disconnect. (An ABSENT table is the caller's business: it
	// must not call RefreshSessions at all.)
	connects, disconnects := RefreshSessions(&d, nil, 1010)
	if len(connects) != 0 {
		t.Fatalf("empty table must not connect: %v", connects)
	}
	if len(disconnects) != 2 || disconnects[0] != "112233445566" || disconnects[1] != "aabbccddeeff" {
		t.Fatalf("disconnects = %v, want both rows", disconnects)
	}
}

func TestRefreshSessionsOddRowsSkipped(t *testing.T) {
	d := sessDev()
	// Unparseable / duplicate MAC entries are skipped or deduplicated —
	// never fatal, never an event.
	connects, disconnects := RefreshSessions(&d, []string{"not-a-mac", "aabbccddeeff", "AA:BB:CC:DD:EE:FF"}, 1000)
	if len(disconnects) != 0 {
		t.Fatalf("odd rows must not disconnect: %v", disconnects)
	}
	if len(connects) != 1 || connects[0] != "aabbccddeeff" {
		t.Fatalf("connects = %v, want the single deduplicated canonical row", connects)
	}
	if len(ClientSessions(d)) != 1 {
		t.Fatalf("rows = %d, want 1", len(ClientSessions(d)))
	}
}

func TestClientSessionsTolerantRead(t *testing.T) {
	// Odd stored shapes read as no rows / partial rows; the read side never
	// fails over stored noise.
	d := Device{MAC: "aabbccddeeff", Extra: JSONMap{
		SessionsExtraKey: "not-an-object",
	}}
	if rows := ClientSessions(d); len(rows) != 0 {
		t.Fatalf("odd Extra value must read as no rows, got %v", rows)
	}
	d = Device{MAC: "aabbccddeeff", Extra: JSONMap{
		SessionsExtraKey: map[string]any{
			"aabbccddeeff": map[string]any{"connected": true, "last_seen": float64(7)},
			"odd-row":      "not-a-map",
			"half-row":     map[string]any{"connected": "not-a-bool"},
		},
	}}
	rows := ClientSessions(d)
	if len(rows) != 2 {
		t.Fatalf("rows = %v, want the two readable rows", rows)
	}
	byMAC := map[string]ClientSession{}
	for _, r := range rows {
		byMAC[r.MAC] = r
	}
	if got := byMAC["aabbccddeeff"]; !got.Connected || got.LastSeen != 7 {
		t.Fatalf("good row = %+v", got)
	}
	if got := byMAC["half-row"]; got.Connected || got.LastSeen != 0 {
		t.Fatalf("row with odd values must read as defaults, got %+v", got)
	}
}

func TestSessionRowsJSONRoundTrip(t *testing.T) {
	// The persisted bytes must reload into exactly the same rows: the
	// store file round trip is the only other writer of these bytes.
	d := sessDev()
	RefreshSessions(&d, []string{"aabbccddeeff"}, 1000)
	RefreshSessions(&d, nil, 1010)
	blob, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Device
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	rows := ClientSessions(back)
	if len(rows) != 1 || rows[0].MAC != "aabbccddeeff" || rows[0].Connected || rows[0].LastSeen != 1000 {
		t.Fatalf("round-tripped rows = %+v", rows)
	}
	if v, ok := back.Extra[SessionDisconnectEventExtraKey].(bool); !ok || !v {
		t.Fatalf("round-tripped event flag = %v (%T), want true", back.Extra[SessionDisconnectEventExtraKey], back.Extra[SessionDisconnectEventExtraKey])
	}
}

func TestSessionRowsDroppedWhenEmpty(t *testing.T) {
	// A device that never had a session must not carry a zero-value object
	// in its persisted Extra — writeSessionRows deletes on empty.
	d := sessDev()
	if _, ok := d.Extra[SessionsExtraKey]; ok {
		t.Fatal("no refresh yet, key must be absent")
	}
	if rows := ClientSessions(d); len(rows) != 0 {
		t.Fatalf("rows = %v, want none", rows)
	}
}

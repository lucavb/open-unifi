// Session-row cap tests cover oldest-last_seen eviction through the public
// API. Ties are deterministic because canonical MAC is the tie-breaker.

package store

import (
	"fmt"
	"testing"
)

// capMAC returns the canonical MAC of synthetic client n: a fixed first
// octet keeps these well away from the device MAC and real client MACs
// other tests use.
func capMAC(n int) string {
	return fmt.Sprintf("01%06x0001", n)
}

// capBatch builds count distinct canonical client MACs starting at n.
func capBatch(n, count int) []string {
	macs := make([]string, 0, count)
	for i := n; i < n+count; i++ {
		macs = append(macs, capMAC(i))
	}
	return macs
}

// seedPastCap pushes the device past the cap with two batches of 1200
// distinct clients seen in consecutive full informs (the second batch a
// full 1000s later), leaving exactly sessionRowCap rows retained. The
// second refresh also legitimately arms the one-shot disconnect event:
// the whole first batch (both the rows the cap evicts and the
// survivors) left the table.
func seedPastCap(t *testing.T) Device {
	t.Helper()
	d := sessDev()
	RefreshSessions(&d, capBatch(0, 1200), 1000)
	RefreshSessions(&d, capBatch(1200, 1200), 2000)
	return d
}

func TestRefreshSessionsCapEvictsOldestRows(t *testing.T) {
	d := seedPastCap(t)
	rows := ClientSessions(d)
	if len(rows) != sessionRowCap {
		t.Fatalf("rows = %d, want exactly the cap %d", len(rows), sessionRowCap)
	}
	byMAC := map[string]ClientSession{}
	for _, r := range rows {
		byMAC[r.MAC] = r
	}
	// Batch 2 (lastSeen 2000, all newer) must be retained whole and
	// connected: it IS the second inform's station table.
	for _, m := range capBatch(1200, 1200) {
		r, ok := byMAC[m]
		if !ok {
			t.Fatalf("newest batch: row %s evicted", m)
		}
		if !r.Connected {
			t.Fatalf("newest-batch row %s must stay connected", m)
		}
		if r.LastSeen != 2000 {
			t.Fatalf("row %s lastSeen = %d, want 2000", m, r.LastSeen)
		}
	}
	// The overage (2400 - cap) must come from the oldest batch, i.e. the
	// 352 smallest MACs of batch 1: eviction picks the smallest last_seen
	// first, with the MAC tie-break ordering equal-timestamp rows.
	over := 2400 - sessionRowCap
	for i := 0; i < over; i++ {
		if _, ok := byMAC[capMAC(i)]; ok {
			t.Fatalf("oldest row %s must be evicted", capMAC(i))
		}
	}
	// The surviving batch-1 rows keep their seeding state: lastSeen 1000
	// and DISCONNECTED — they left the second inform's table (absent
	// rows flip to disconnected) before the cap evicted anything, and
	// eviction is a separate, silent retirement.
	for _, m := range capBatch(over, 1200-over) {
		r, ok := byMAC[m]
		if !ok {
			t.Fatalf("surviving batch-1 row %s evicted", m)
		}
		if r.Connected {
			t.Fatalf("surviving batch-1 row %s must stay disconnected (absent from the second table)", m)
		}
		if r.LastSeen != 1000 {
			t.Fatalf("row %s lastSeen = %d, want 1000", m, r.LastSeen)
		}
	}
}

func TestRefreshSessionsCapCountStableAroundSparseHeartbeat(t *testing.T) {
	d := seedPastCap(t)
	if got := len(ClientSessions(d)); got != sessionRowCap {
		t.Fatalf("setup rows = %d, want %d", got, sessionRowCap)
	}
	// The seeding refresh armed the one-shot disconnect flag (the first
	// batch left the second table); the adoption engine consumes it on
	// the device's next decision (armedLifecycle one-shot semantics).
	// Start the heartbeat scenario from that consumed, disarmed state —
	// the assertions below then prove the heartbeats alone do not arm it.
	if _, armed := d.Extra[SessionDisconnectEventExtraKey]; !armed {
		t.Fatal("seeding refresh must arm the disconnect event (first batch left the table)")
	}
	delete(d.Extra, SessionDisconnectEventExtraKey)
	// ABSENT station table (the sparse heartbeat): per RefreshSessions'
	// caller contract — invoked only when the inform carried a station
	// table — a heartbeat with no station list makes no RefreshSessions
	// call at all, so nothing refreshes and nothing wipes. Assert the
	// capped state is untouched.
	rows := ClientSessions(d)
	if len(rows) != sessionRowCap {
		t.Fatalf("rows after absent-table heartbeat = %d, want %d", len(rows), sessionRowCap)
	}
	if _, armed := d.Extra[SessionDisconnectEventExtraKey]; armed {
		t.Fatal("absent-table heartbeat must not arm the disconnect event")
	}
	// PRESENT-but-EMPTY table (nil slice, the documented empty-slice
	// refresh): every still-connected row disconnects — the seeding
	// refresh already flipped the surviving batch-1 rows, so only the
	// 1200 connected batch-2 rows produce events — but all rows
	// persist: the cap must not widen, shrink, or drop rows around
	// this pass.
	connected := 0
	for _, r := range rows {
		if r.Connected {
			connected++
		}
	}
	_, disconnects := RefreshSessions(&d, nil, 3000)
	if len(disconnects) != connected {
		t.Fatalf("empty-table refresh disconnects = %d, want one per connected row (%d)", len(disconnects), connected)
	}
	rows = ClientSessions(d)
	if len(rows) != sessionRowCap {
		t.Fatalf("rows after empty-table refresh = %d, want %d", len(rows), sessionRowCap)
	}
	for _, r := range rows {
		if r.Connected {
			t.Fatalf("row %s must be disconnected after the empty table", r.MAC)
		}
	}
}

func TestRefreshSessionsBelowCapNeverEvicts(t *testing.T) {
	d := sessDev()
	batch := capBatch(0, 10)
	RefreshSessions(&d, batch, 1000)
	// Second refresh sees only the first five clients: the other five
	// disconnect (rows persist) and nothing gets evicted either way.
	connects, disconnects := RefreshSessions(&d, batch[:5], 1010)
	if len(connects) != 0 || len(disconnects) != 5 {
		t.Fatalf("events = %v / %v, want no connects and five disconnects", connects, disconnects)
	}
	rows := ClientSessions(d)
	if len(rows) != 10 {
		t.Fatalf("rows = %d, want all 10 originals (no eviction below the cap)", len(rows))
	}
	byMAC := map[string]ClientSession{}
	for _, r := range rows {
		byMAC[r.MAC] = r
	}
	for _, m := range batch {
		if _, ok := byMAC[m]; !ok {
			t.Fatalf("original row %s must survive unchanged populations", m)
		}
	}
}

// Client-session refresh on the inform path: the adapter-side step that
// turns a decoded inform's station table into the record's
// controller-owned session rows (internal/store sessions), computed inside
// the per-MAC read-modify-write cycle immediately after the record
// absorption (absorbInform — whose rec.Absorb half preserves the
// previous rows through the trust policy's prev-wins before this
// refresh updates them) and BEFORE the engine decision (which reads the
// one-shot disconnect-event flag this refresh arms — the §6.2(e)
// trigger).
//
// Sparse heartbeats (no station table) refresh nothing and wipe nothing
// (device-refreshable caps semantics): the present flag from
// inform.StationMACs is the gate, and rows survive those informs
// untouched. Session events are counted AFTER the store cycle commits
// (metrics.IncClientSessionEvents — exactly-once per persisted
// transition, the same discipline as the adopt counters).
package server

import (
	"time"

	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/store"
)

// refreshClientSessions applies one decoded inform's station table to the
// record's session rows and returns the observed event counts. It runs
// inside absorbInform, immediately after the record absorption's
// trust-policy merge and before engine.Decide: the engine's §6.2(e)
// reconnect push consumes the disconnect-event flag this refresh arms,
// in the same cycle, so the response the device receives matches the
// record that persists.
func refreshClientSessions(rec *store.Device, body map[string]any, now time.Time) (connects, disconnects int) {
	macs, present := inform.StationMACs(body)
	if !present {
		// A sparse heartbeat carries no station table: no client
		// evidence, no transitions — rows and events survive untouched.
		return 0, 0
	}
	cons, dsc := store.RefreshSessions(rec, macs, now.Unix())
	return len(cons), len(dsc)
}

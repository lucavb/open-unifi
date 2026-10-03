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
// record's session rows and returns the observed transitions (connects,
// disconnects, same-AP radio changes). It must run inside the inform RMW
// cycle, after absorbInform and before engine.Decide: the engine's §6.2(e)
// reconnect push consumes the disconnect-event flag this refresh arms, in
// the same cycle, so the response the device receives matches the record
// that persists.
func refreshClientSessions(rec *store.Device, body map[string]any, now time.Time) []store.Transition {
	stations, present := inform.Stations(body)
	if !present {
		// A sparse heartbeat carries no station table: no client
		// evidence, no transitions — rows and events survive untouched.
		return nil
	}
	infos := make([]store.StationInfo, 0, len(stations))
	for _, st := range stations {
		infos = append(infos, store.StationInfo{
			MAC: st.MAC, Hostname: st.Hostname, IP: st.IP, ESSID: st.ESSID, Radio: st.Radio,
			Channel: st.Channel, Bytes: st.TxBytes + st.RxBytes,
		})
	}
	return store.RefreshSessionStations(rec, infos, now.Unix())
}

// countTransitions reduces transitions to the connect/disconnect counts the
// metrics hook takes (radio changes are not session events).
func countTransitions(ts []store.Transition) (connects, disconnects int) {
	for _, t := range ts {
		switch t.Kind {
		case store.TransitionConnect:
			connects++
		case store.TransitionDisconnect:
			disconnects++
		}
	}
	return connects, disconnects
}

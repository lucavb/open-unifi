package server

// Config.OnSessionTransitions end-to-end on the encrypted lane: the hook
// receives typed transitions carrying the vap-row station context
// (hostname, SSID, radio, channel, byte total), fires after the store
// cycle commits, skips sparse heartbeats, and reports the disconnect with
// the row's last proof.

import (
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

type transitionCall struct {
	mac string
	ts  []store.Transition
}

func TestSessionTransitionsCarryStationContext(t *testing.T) {
	var calls []transitionCall
	h, st := newServerWith(Config{OnSessionTransitions: func(mac string, ts []store.Transition) {
		calls = append(calls, transitionCall{mac, append([]store.Transition(nil), ts...)})
	}})
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, "aaaa", xkey)
	cfg := settleFromAdopted(t, h, st, xkey, nil) // settled with no stations
	calls = nil

	const client = "aa:2c:3b:5b:b7:10"
	vap := func(rows ...any) []any {
		if rows == nil {
			rows = []any{} // an empty table is a report; null would be absent
		}
		return []any{map[string]any{
			"essid": "TNG", "radio": "na", "channel": float64(149),
			"sta_table": rows,
		}}
	}
	station := map[string]any{
		"mac": client, "hostname": "mohr-trent-900", "tx_bytes": float64(100), "rx_bytes": float64(40),
	}

	seInform(t, h, xkey, cfg, nil, vap(station))
	if len(calls) != 1 || calls[0].mac != store.ColonMAC(testMAC) || len(calls[0].ts) != 1 {
		t.Fatalf("calls after connect = %+v", calls)
	}
	tr := calls[0].ts[0]
	if tr.Kind != store.TransitionConnect || tr.MAC != "aa2c3b5bb710" {
		t.Fatalf("transition = %+v", tr)
	}
	if s := tr.Session; s.Hostname != "mohr-trent-900" || s.ESSID != "TNG" || s.Radio != "na" || s.Channel != 149 || s.Bytes != 140 || s.Since == 0 {
		t.Fatalf("session context = %+v", s)
	}

	// A sparse heartbeat (no vap/sta table) produces no call.
	seInform(t, h, xkey, cfg, nil, nil)
	if len(calls) != 1 {
		t.Fatalf("sparse heartbeat fired the hook: %+v", calls)
	}

	// Channel change on the same AP: one radio_change transition.
	moved := map[string]any{"mac": client, "tx_bytes": float64(200)}
	seInform(t, h, xkey, cfg, nil, []any{map[string]any{
		"essid": "TNG", "radio": "ng", "channel": float64(6), "sta_table": []any{moved},
	}})
	if len(calls) != 2 || len(calls[1].ts) != 1 || calls[1].ts[0].Kind != store.TransitionRadioChange {
		t.Fatalf("calls after radio change = %+v", calls)
	}
	if p := calls[1].ts[0].Prev; p.Channel != 149 || p.Radio != "na" {
		t.Fatalf("prev = %+v", p)
	}

	// The station leaves: disconnect carrying the last context.
	seInform(t, h, xkey, cfg, nil, vap())
	if len(calls) != 3 || len(calls[2].ts) != 1 || calls[2].ts[0].Kind != store.TransitionDisconnect {
		t.Fatalf("calls after disconnect = %+v", calls)
	}
	if s := calls[2].ts[0].Session; s.Connected || s.Hostname != "mohr-trent-900" || s.Channel != 6 || s.Bytes != 200 {
		t.Fatalf("disconnect session = %+v", s)
	}
}

package store

import "testing"

func TestRefreshSessionStationsConnectCarriesContext(t *testing.T) {
	d := sessDev()
	ts := RefreshSessionStations(&d, []StationInfo{
		{MAC: "AA:BB:CC:DD:EE:FF", Hostname: "phone", ESSID: "TNG", Radio: "na", Channel: 149, Bytes: 10},
	}, 1000)
	if len(ts) != 1 || ts[0].Kind != TransitionConnect || ts[0].MAC != "aabbccddeeff" || ts[0].At != 1000 {
		t.Fatalf("transitions = %+v, want one connect", ts)
	}
	s := ts[0].Session
	if !s.Connected || s.Since != 1000 || s.Hostname != "phone" || s.ESSID != "TNG" || s.Radio != "na" || s.Channel != 149 || s.Bytes != 10 {
		t.Fatalf("session = %+v", s)
	}
	if ts[0].Prev.Connected || ts[0].Prev.Since != 0 {
		t.Fatalf("prev = %+v, want zero value", ts[0].Prev)
	}
	rows := ClientSessions(d)
	if len(rows) != 1 || rows[0] != s {
		t.Fatalf("persisted rows = %+v, want %+v", rows, s)
	}
}

func TestRefreshSessionStationsDisconnectKeepsContext(t *testing.T) {
	d := sessDev()
	RefreshSessionStations(&d, []StationInfo{{MAC: "aabbccddeeff", ESSID: "TNG", Channel: 36, Bytes: 99}}, 1000)
	RefreshSessionStations(&d, []StationInfo{{MAC: "aabbccddeeff", Bytes: 150}}, 1010)
	ts := RefreshSessionStations(&d, nil, 1020)
	if len(ts) != 1 || ts[0].Kind != TransitionDisconnect {
		t.Fatalf("transitions = %+v, want one disconnect", ts)
	}
	s := ts[0].Session
	if s.Connected || s.Since != 1000 || s.LastSeen != 1010 || s.ESSID != "TNG" || s.Channel != 36 || s.Bytes != 150 {
		t.Fatalf("session = %+v, want since=1000 lastSeen=1010 and kept context", s)
	}
	if !ts[0].Prev.Connected {
		t.Fatalf("prev = %+v, want connected", ts[0].Prev)
	}
	if d.Extra[SessionDisconnectEventExtraKey] != true {
		t.Fatal("disconnect must arm the one-shot flag")
	}
}

func TestRefreshSessionStationsRadioChange(t *testing.T) {
	d := sessDev()
	RefreshSessionStations(&d, []StationInfo{{MAC: "aabbccddeeff", Radio: "ng", Channel: 6}}, 1000)
	// Same radio and channel: no transition.
	if ts := RefreshSessionStations(&d, []StationInfo{{MAC: "aabbccddeeff", Radio: "ng", Channel: 6}}, 1010); len(ts) != 0 {
		t.Fatalf("steady refresh transitions = %+v", ts)
	}
	// Context omitted by the table: no change, context kept.
	if ts := RefreshSessionStations(&d, []StationInfo{{MAC: "aabbccddeeff"}}, 1015); len(ts) != 0 {
		t.Fatalf("context-less refresh transitions = %+v", ts)
	}
	ts := RefreshSessionStations(&d, []StationInfo{{MAC: "aabbccddeeff", Radio: "na", Channel: 149}}, 1020)
	if len(ts) != 1 || ts[0].Kind != TransitionRadioChange {
		t.Fatalf("transitions = %+v, want one radio_change", ts)
	}
	if ts[0].Prev.Channel != 6 || ts[0].Session.Channel != 149 || ts[0].Session.Since != 1000 {
		t.Fatalf("prev=%+v session=%+v", ts[0].Prev, ts[0].Session)
	}
	if d.Extra[SessionDisconnectEventExtraKey] == true {
		t.Fatal("radio change must not arm the disconnect flag")
	}
}

func TestRefreshSessionStationsReconnectResetsSince(t *testing.T) {
	d := sessDev()
	RefreshSessionStations(&d, []StationInfo{{MAC: "aabbccddeeff", ESSID: "old"}}, 1000)
	RefreshSessionStations(&d, nil, 1010)
	ts := RefreshSessionStations(&d, []StationInfo{{MAC: "aabbccddeeff"}}, 1020)
	if len(ts) != 1 || ts[0].Kind != TransitionConnect {
		t.Fatalf("transitions = %+v", ts)
	}
	if s := ts[0].Session; s.Since != 1020 || s.ESSID != "" {
		t.Fatalf("session = %+v, want fresh since and no carried-over context", s)
	}
}

func TestClientSessionsReadsLegacyRows(t *testing.T) {
	d := Device{Extra: JSONMap{SessionsExtraKey: map[string]any{
		"aabbccddeeff": map[string]any{"last_seen": float64(5), "connected": true},
	}}}
	rows := ClientSessions(d)
	if len(rows) != 1 || !rows[0].Connected || rows[0].LastSeen != 5 || rows[0].Since != 0 || rows[0].ESSID != "" {
		t.Fatalf("rows = %+v", rows)
	}
	// A surviving legacy row stays connected without a spurious transition.
	if ts := RefreshSessionStations(&d, []StationInfo{{MAC: "aabbccddeeff"}}, 10); len(ts) != 0 {
		t.Fatalf("transitions = %+v", ts)
	}
}

func TestRefreshSessionStationsDuplicateRowsOneTransition(t *testing.T) {
	d := sessDev()
	ts := RefreshSessionStations(&d, []StationInfo{{MAC: "AA:BB:CC:DD:EE:FF"}, {MAC: "aabbccddeeff"}, {MAC: "junk"}}, 1000)
	if len(ts) != 1 {
		t.Fatalf("transitions = %+v, want one", ts)
	}
}

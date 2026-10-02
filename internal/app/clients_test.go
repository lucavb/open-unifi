package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/clientevents"
	"github.com/lucavb/open-unifi/internal/store"
)

func TestListClientsFoldsAcrossDevices(t *testing.T) {
	a, st := testApp(t)
	ctx := context.Background()
	const apA, apB = "aabbccddee01", "aabbccddee02"
	for mac, name := range map[string]string{apA: "ap-a", apB: "ap-b"} {
		if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: mac, Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	const roamer, gone = "112233445566", "665544332211"
	seed := func(mac string, fn func(d *store.Device)) {
		if err := st.Update(mac, func(d *store.Device) error { fn(d); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	// roamer: connected on A, stale; then connected on B, fresher.
	seed(apA, func(d *store.Device) {
		store.RefreshSessionStations(d, []store.StationInfo{{MAC: roamer, ESSID: "TNG", Channel: 36}, {MAC: gone}}, 1000)
		store.RefreshSessionStations(d, []store.StationInfo{{MAC: roamer, ESSID: "TNG", Channel: 36}}, 1010)
	})
	seed(apB, func(d *store.Device) {
		store.RefreshSessionStations(d, []store.StationInfo{{MAC: roamer, Hostname: "phone", ESSID: "TNG", Channel: 149}}, 1020)
	})

	got := a.ListClients(ctx)
	if len(got) != 2 {
		t.Fatalf("clients = %+v, want 2", got)
	}
	r := got[0]
	if r.MAC != "11:22:33:44:55:66" || !r.Connected || r.APName != "ap-b" || r.AP != "aa:bb:cc:dd:ee:02" || r.Channel != 149 || r.Hostname != "phone" {
		t.Fatalf("roamer = %+v, want the fresher connected row on ap-b", r)
	}
	if g := got[1]; g.MAC != "66:55:44:33:22:11" || g.Connected || g.APName != "ap-a" {
		t.Fatalf("gone = %+v, want disconnected, last seen on ap-a", g)
	}
}

func TestListClientsEmpty(t *testing.T) {
	a, _ := testApp(t)
	if got := a.ListClients(context.Background()); got == nil || len(got) != 0 {
		t.Fatalf("clients = %+v, want empty non-nil", got)
	}
}

func TestEventsAndHistoryDisabledThenEnabled(t *testing.T) {
	a, _ := testApp(t)
	ctx := context.Background()

	if v := a.ListEvents(ctx, adminapi.EventsQuery{}); v.Enabled || v.Events == nil || len(v.Events) != 0 {
		t.Fatalf("disabled events = %+v", v)
	}
	if v := a.GetClientHistory(ctx, "aa:bb:cc:dd:ee:ff"); v.Enabled || v.Intervals == nil || len(v.Intervals) != 0 {
		t.Fatalf("disabled history = %+v", v)
	}

	sink, err := clientevents.NewFileSink(filepath.Join(t.TempDir(), "h.jsonl"), clientevents.FileSinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sink.Close() }()
	a.SetClientHistory(sink)
	now := time.Now()
	sink.Emit(clientevents.Event{Key: clientevents.KeyConnected, Client: "aa:bb:cc:dd:ee:ff", AP: "aa:bb:cc:dd:ee:01", APName: "ap-a", Time: now.Add(-time.Minute).UnixMilli(), Msg: "c"})
	sink.Emit(clientevents.Event{Key: clientevents.KeyRoam, Client: "aa:bb:cc:dd:ee:ff", APFrom: "aa:bb:cc:dd:ee:01", APTo: "aa:bb:cc:dd:ee:02", APToName: "ap-b", Time: now.UnixMilli(), Msg: "r"})
	sink.Emit(clientevents.Event{Key: clientevents.KeyConnected, Client: "00:00:00:00:00:09", AP: "aa:bb:cc:dd:ee:01", Time: now.UnixMilli(), Msg: "other"})

	v := a.ListEvents(ctx, adminapi.EventsQuery{Client: "aa:bb:cc:dd:ee:ff"})
	if !v.Enabled || len(v.Events) != 2 || v.Events[0].Key != clientevents.KeyRoam || v.Events[0].APToName != "ap-b" {
		t.Fatalf("events = %+v", v)
	}
	h := a.GetClientHistory(ctx, "aa:bb:cc:dd:ee:ff")
	if !h.Enabled || len(h.Intervals) != 2 || h.Intervals[0].To == 0 || h.Intervals[1].AP != "aa:bb:cc:dd:ee:02" || h.Intervals[1].To != 0 {
		t.Fatalf("history = %+v", h)
	}
}

package clientevents

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

const (
	apA    = "aa:00:00:00:00:01"
	apB    = "aa:00:00:00:00:02"
	client = "112233445566"
)

type collect struct {
	mu sync.Mutex
	ev []Event
}

func (c *collect) Emit(e Event) { c.mu.Lock(); c.ev = append(c.ev, e); c.mu.Unlock() }
func (c *collect) keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, e := range c.ev {
		out = append(out, e.Key)
	}
	return out
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestTracker() (*Tracker, *collect, *clock) {
	sink, clk := &collect{}, &clock{t: time.Unix(10_000, 0)}
	tr := NewTracker(Config{
		Grace: 30 * time.Second, Now: clk.now, Sinks: []Sink{sink},
		APName: func(mac string) string { return map[string]string{apA: "ap-a", apB: "ap-b"}[mac] },
	})
	return tr, sink, clk
}

func sess(connected bool, since, last int64, essid, radio string, ch int) store.ClientSession {
	return store.ClientSession{MAC: client, Connected: connected, Since: since, LastSeen: last, ESSID: essid, Radio: radio, Channel: ch, Hostname: "phone"}
}

func connectT(at int64, s store.ClientSession) store.Transition {
	return store.Transition{MAC: client, Kind: store.TransitionConnect, At: at, Session: s}
}
func disconnectT(at int64, s store.ClientSession) store.Transition {
	s.Connected = false
	return store.Transition{MAC: client, Kind: store.TransitionDisconnect, At: at, Session: s}
}

func wantKeys(t *testing.T, c *collect, want ...string) {
	t.Helper()
	got := c.keys()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestConnectEvent(t *testing.T) {
	tr, sink, _ := newTestTracker()
	tr.Observe(apA, []store.Transition{connectT(1000, sess(true, 1000, 1000, "TNG", "na", 149))})
	wantKeys(t, sink, KeyConnected)
	e := sink.ev[0]
	if e.Client != "11:22:33:44:55:66" || e.AP != apA || e.APName != "ap-a" || e.SSID != "TNG" || e.Time != 1_000_000 {
		t.Fatalf("event = %+v", e)
	}
	if e.Msg != "phone connected to TNG on ap-a." {
		t.Fatalf("msg = %q", e.Msg)
	}
}

func TestRoamDisconnectFirst(t *testing.T) {
	tr, sink, clk := newTestTracker()
	tr.Observe(apA, []store.Transition{connectT(1000, sess(true, 1000, 1000, "TNG", "na", 36))})
	tr.Observe(apA, []store.Transition{disconnectT(1100, sess(false, 1000, 1090, "TNG", "na", 36))})
	wantKeys(t, sink, KeyConnected) // held
	clk.t = clk.t.Add(5 * time.Second)
	tr.Observe(apB, []store.Transition{connectT(1105, sess(true, 1105, 1105, "TNG", "na", 149))})
	wantKeys(t, sink, KeyConnected, KeyRoam)
	e := sink.ev[1]
	if e.APFrom != apA || e.APTo != apB || e.ChannelFrom != 36 || e.ChannelTo != 149 || e.SSID != "TNG" {
		t.Fatalf("roam = %+v", e)
	}
	if e.Msg != "phone roamed from ap-a to ap-b." {
		t.Fatalf("msg = %q", e.Msg)
	}
	// The held disconnect was consumed by the roam.
	tr.Flush(clk.t.Add(time.Hour))
	wantKeys(t, sink, KeyConnected, KeyRoam)
}

func TestRoamConnectFirstDropsLateDisconnect(t *testing.T) {
	tr, sink, clk := newTestTracker()
	tr.Observe(apA, []store.Transition{connectT(1000, sess(true, 1000, 1000, "TNG", "na", 36))})
	tr.Observe(apB, []store.Transition{connectT(1100, sess(true, 1100, 1100, "TNG", "na", 149))})
	wantKeys(t, sink, KeyConnected, KeyRoam)
	// AP A's inform arrives late.
	tr.Observe(apA, []store.Transition{disconnectT(1100, sess(false, 1000, 1090, "TNG", "na", 36))})
	tr.Flush(clk.t.Add(time.Hour))
	wantKeys(t, sink, KeyConnected, KeyRoam)
	// And the client really leaving AP B later still disconnects.
	tr.Observe(apB, []store.Transition{disconnectT(1200, sess(false, 1100, 1190, "TNG", "na", 149))})
	tr.Flush(clk.t.Add(2 * time.Hour))
	wantKeys(t, sink, KeyConnected, KeyRoam, KeyDisconnected)
	if e := sink.ev[2]; e.AP != apB || e.Duration != 90 {
		t.Fatalf("disconnect = %+v", e)
	}
}

func TestDisconnectAfterGraceExpiry(t *testing.T) {
	tr, sink, clk := newTestTracker()
	s := sess(true, 1000, 1000, "TNG", "na", 36)
	s.Bytes = 2_500_000
	tr.Observe(apA, []store.Transition{connectT(1000, s)})
	dsc := s
	dsc.LastSeen = 4600
	tr.Observe(apA, []store.Transition{disconnectT(4610, dsc)})
	tr.Flush(clk.t.Add(29 * time.Second))
	wantKeys(t, sink, KeyConnected)
	tr.Flush(clk.t.Add(30 * time.Second))
	wantKeys(t, sink, KeyConnected, KeyDisconnected)
	e := sink.ev[1]
	if e.Duration != 3600 || e.Bytes != 2_500_000 || e.Time != 4_610_000 {
		t.Fatalf("disconnect = %+v", e)
	}
	if want := "phone disconnected from TNG. Time Connected: 1h 0m. Data Used: 2.5 MB. Last AP: ap-a."; e.Msg != want {
		t.Fatalf("msg = %q, want %q", e.Msg, want)
	}
	// Flushing twice emits nothing more, and a later connect is fresh.
	tr.Flush(clk.t.Add(time.Hour))
	tr.Observe(apB, []store.Transition{connectT(9000, sess(true, 9000, 9000, "TNG", "na", 36))})
	wantKeys(t, sink, KeyConnected, KeyDisconnected, KeyConnected)
}

func TestSameAPReconnectInsideGrace(t *testing.T) {
	tr, sink, _ := newTestTracker()
	tr.Observe(apA, []store.Transition{connectT(1000, sess(true, 1000, 1000, "TNG", "na", 36))})
	tr.Observe(apA, []store.Transition{disconnectT(1010, sess(false, 1000, 1005, "TNG", "na", 36))})
	tr.Observe(apA, []store.Transition{connectT(1015, sess(true, 1015, 1015, "TNG", "na", 36))})
	wantKeys(t, sink, KeyConnected, KeyDisconnected, KeyConnected)
}

func TestRadioChangeOnSameAP(t *testing.T) {
	tr, sink, _ := newTestTracker()
	tr.Observe(apA, []store.Transition{connectT(1000, sess(true, 1000, 1000, "TNG", "ng", 6))})
	tr.Observe(apA, []store.Transition{{
		MAC: client, Kind: store.TransitionRadioChange, At: 1100,
		Prev: sess(true, 1000, 1090, "TNG", "ng", 6), Session: sess(true, 1000, 1100, "TNG", "na", 149),
	}})
	wantKeys(t, sink, KeyConnected, KeyRoamRadio)
	e := sink.ev[1]
	if e.RadioFrom != "ng" || e.RadioTo != "na" || e.ChannelFrom != 6 || e.ChannelTo != 149 || e.AP != apA {
		t.Fatalf("event = %+v", e)
	}
	// A radio change reported by an AP the client is not on is ignored.
	tr.Observe(apB, []store.Transition{{MAC: client, Kind: store.TransitionRadioChange, At: 1200, Session: sess(true, 1, 1, "TNG", "ng", 1)}})
	wantKeys(t, sink, KeyConnected, KeyRoamRadio)
}

func TestSeedSuppressesConnectAndAllowsRoam(t *testing.T) {
	tr, sink, _ := newTestTracker()
	var d store.Device
	d.MAC = "aa0000000001"
	store.RefreshSessionStations(&d, []store.StationInfo{{MAC: client, ESSID: "TNG", Radio: "na", Channel: 36}}, 500)
	var old store.Device
	old.MAC = "aa0000000002"
	store.RefreshSessionStations(&old, []store.StationInfo{{MAC: client}}, 100) // staler row on another AP
	tr.Seed([]store.Device{old, d})
	wantKeys(t, sink) // no events from seeding

	// A surviving seeded client reported again by its AP produces nothing.
	tr.Observe(apA, []store.Transition{connectT(600, sess(true, 600, 600, "TNG", "na", 36))})
	wantKeys(t, sink)

	// And a later appearance on AP B is a roam from the seeded AP A.
	tr.Observe(apB, []store.Transition{connectT(700, sess(true, 700, 700, "TNG", "na", 149))})
	wantKeys(t, sink, KeyRoam)
	if e := sink.ev[0]; e.APFrom != apA || e.APTo != apB {
		t.Fatalf("roam = %+v", e)
	}
}

func TestStaleDisconnectForUntrackedClientIgnored(t *testing.T) {
	tr, sink, clk := newTestTracker()
	tr.Observe(apA, []store.Transition{disconnectT(1000, sess(false, 1, 2, "", "", 0))})
	tr.Flush(clk.t.Add(time.Hour))
	wantKeys(t, sink)
}

func TestSlogSink(t *testing.T) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&buf, nil))
	SlogSink{Logger: lg}.Emit(Event{Key: KeyRoam, Client: "11:22:33:44:55:66", APFrom: apA, APTo: apB, ChannelFrom: 36, ChannelTo: 149, Msg: "x roamed"})
	out := buf.String()
	for _, want := range []string{"client event", "key=EVT_WU_Roam", "ap_from=" + apA, "channel_to=149"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log %q missing %q", out, want)
		}
	}
}

func TestFormatHelpers(t *testing.T) {
	for in, want := range map[int64]string{0: "0s", 30: "30s", 564: "9m 24s", 5280: "1h 28m", 18600: "5h 10m", 90000: "1d 1h"} {
		if got := FormatDuration(in); got != want {
			t.Errorf("FormatDuration(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[int64]string{999: "999 B", 1500: "1.5 kB", 2_500_000: "2.5 MB"} {
		if got := FormatBytes(in); got != want {
			t.Errorf("FormatBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

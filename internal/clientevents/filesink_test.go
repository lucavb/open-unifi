package clientevents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ev(key, client, ap string, at time.Time) Event {
	e := Event{Key: key, Client: client, AP: ap, Time: at.UnixMilli(), Msg: key}
	return e
}

func jsonLine(e Event) (string, error) {
	b, err := json.Marshal(e)
	return string(b) + "\n", err
}

func testSink(t *testing.T, opts FileSinkOptions) (*FileSink, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "client-events.jsonl")
	s, err := NewFileSink(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestFileSinkAppendReloadAndMode(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	opts := FileSinkOptions{Now: func() time.Time { return now }}
	s, path := testSink(t, opts)
	s.Emit(ev(KeyConnected, "11:22:33:44:55:66", apA, now.Add(-2*time.Hour)))
	s.Emit(ev(KeyDisconnected, "11:22:33:44:55:66", apA, now.Add(-time.Hour)))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", fi.Mode().Perm())
	}
	s2, err := NewFileSink(path, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	got := s2.Query(Filter{})
	if len(got) != 2 || got[0].Key != KeyDisconnected || got[1].Key != KeyConnected {
		t.Fatalf("reloaded = %+v, want newest first", got)
	}
}

func TestFileSinkRetentionAndCapOnLoad(t *testing.T) {
	now := time.Unix(10_000_000, 0)
	path := filepath.Join(t.TempDir(), "h.jsonl")
	// Seed a file by hand: one expired, a torn line, then five fresh.
	var b strings.Builder
	b.WriteString(`{"key":"EVT_WU_Connected","time":1000,"client":"old"}` + "\n")
	b.WriteString("{torn\n")
	for i := 0; i < 5; i++ {
		e := ev(KeyConnected, "c", apA, now.Add(-time.Duration(5-i)*time.Hour))
		e.Client = "c" + string(rune('0'+i))
		line, _ := jsonLine(e)
		b.WriteString(line)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewFileSink(path, FileSinkOptions{Retention: 24 * time.Hour, MaxEvents: 3, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	got := s.Query(Filter{})
	if len(got) != 3 || got[0].Client != "c4" || got[2].Client != "c2" {
		t.Fatalf("retained = %+v, want the newest three", got)
	}
	// The file was compacted down to the retained events.
	data, _ := os.ReadFile(path)
	if n := strings.Count(string(data), "\n"); n != 3 {
		t.Fatalf("file has %d lines, want 3:\n%s", n, data)
	}
}

func TestFileSinkCompactDropsExpired(t *testing.T) {
	now := time.Unix(10_000_000, 0)
	clk := now
	s, path := testSink(t, FileSinkOptions{Retention: time.Hour, Now: func() time.Time { return clk }})
	s.Emit(ev(KeyConnected, "a", apA, now))
	clk = now.Add(30 * time.Minute)
	s.Emit(ev(KeyConnected, "b", apA, clk))
	clk = now.Add(90 * time.Minute)
	if err := s.Compact(); err != nil {
		t.Fatal(err)
	}
	if got := s.Query(Filter{}); len(got) != 1 || got[0].Client != "b" {
		t.Fatalf("after compact = %+v", got)
	}
	// Appends still land after the rewrite.
	s.Emit(ev(KeyConnected, "c", apA, clk))
	data, _ := os.ReadFile(path)
	if n := strings.Count(string(data), "\n"); n != 2 {
		t.Fatalf("file has %d lines, want 2", n)
	}
}

func TestFileSinkOutOfOrderEmitStaysSorted(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, _ := testSink(t, FileSinkOptions{Now: func() time.Time { return now }})
	s.Emit(ev(KeyConnected, "a", apA, now.Add(-10*time.Second)))
	s.Emit(ev(KeyConnected, "b", apA, now.Add(-1*time.Second)))
	s.Emit(ev(KeyDisconnected, "c", apA, now.Add(-5*time.Second))) // released late
	got := s.Query(Filter{})
	if len(got) != 3 || got[0].Client != "b" || got[1].Client != "c" || got[2].Client != "a" {
		t.Fatalf("order = %+v", got)
	}
}

func TestFileSinkQueryFilters(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, _ := testSink(t, FileSinkOptions{Now: func() time.Time { return now }})
	roam := ev(KeyRoam, "11:22:33:44:55:66", "", now.Add(-3*time.Minute))
	roam.APFrom, roam.APTo = apA, apB
	s.Emit(ev(KeyConnected, "11:22:33:44:55:66", apA, now.Add(-4*time.Minute)))
	s.Emit(roam)
	s.Emit(ev(KeyConnected, "aa:bb:cc:dd:ee:ff", apB, now.Add(-2*time.Minute)))
	s.Emit(ev(KeyDisconnected, "aa:bb:cc:dd:ee:ff", apB, now.Add(-1*time.Minute)))

	check := func(name string, f Filter, want int) {
		t.Helper()
		if got := s.Query(f); len(got) != want {
			t.Fatalf("%s: %d events, want %d (%+v)", name, len(got), want, got)
		}
	}
	check("client any spelling", Filter{Client: "112233445566"}, 2)
	check("ap matches roam ends", Filter{AP: "AA:00:00:00:00:02"}, 3)
	check("key", Filter{Key: KeyRoam}, 1)
	check("since", Filter{Since: now.Add(-150 * time.Second)}, 2)
	check("until", Filter{Until: now.Add(-150 * time.Second)}, 2)
	check("limit", Filter{Limit: 1}, 1)
	if got := s.Query(Filter{Limit: 1}); got[0].Key != KeyDisconnected {
		t.Fatalf("limit must keep the newest: %+v", got)
	}
}

func TestFoldHistory(t *testing.T) {
	at := func(s int64) int64 { return s * 1000 }
	evs := []Event{
		{Key: KeyConnected, AP: apA, APName: "ap-a", SSID: "TNG", Channel: 36, Time: at(100)},
		{Key: KeyRoamRadio, AP: apA, Channel: 100, Time: at(150)},
		{Key: KeyRoam, APFrom: apA, APTo: apB, APToName: "ap-b", SSID: "TNG", Channel: 149, Time: at(200)},
		{Key: KeyDisconnected, AP: apB, Time: at(300)},
		{Key: KeyConnected, AP: apA, Time: at(400)},
	}
	got := FoldHistory(evs)
	want := []Interval{
		{AP: apA, APName: "ap-a", SSID: "TNG", Channel: 100, From: at(100), To: at(200)},
		{AP: apB, APName: "ap-b", SSID: "TNG", Channel: 149, From: at(200), To: at(300)},
		{AP: apA, From: at(400)},
	}
	if len(got) != len(want) {
		t.Fatalf("intervals = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("interval %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestFileSinkHistory(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s, _ := testSink(t, FileSinkOptions{Now: func() time.Time { return now }})
	s.Emit(ev(KeyConnected, "11:22:33:44:55:66", apA, now.Add(-time.Hour)))
	s.Emit(ev(KeyConnected, "aa:bb:cc:dd:ee:ff", apB, now.Add(-50*time.Minute)))
	if h := s.History("112233445566"); len(h) != 1 || h[0].AP != apA || h[0].To != 0 {
		t.Fatalf("history = %+v", h)
	}
}

func TestParseRetention(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30d": 30 * 24 * time.Hour, "1d": 24 * time.Hour, "12h": 12 * time.Hour, "90m": 90 * time.Minute,
	} {
		got, err := ParseRetention(in)
		if err != nil || got != want {
			t.Errorf("ParseRetention(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "d", "0d", "-1d", "1.5d", "abc", "0s", "-5h"} {
		if _, err := ParseRetention(in); err == nil {
			t.Errorf("ParseRetention(%q) accepted, want error", in)
		}
	}
}

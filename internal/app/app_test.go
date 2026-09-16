package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucabecker/open-unifi/internal/adminapi"
	"github.com/lucabecker/open-unifi/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func testApp(t *testing.T) (*App, store.DeviceStore, string) {
	t.Helper()
	st := store.NewMemStore()
	wpath := filepath.Join(t.TempDir(), "wireless.json")
	a := New(st, wpath, quietLogger())
	return a, st, wpath
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// counterDefault returns the summed counter value of a metric family from
// the default Prometheus registry (metrics registers in init()).
func counterDefault(name string) float64 {
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return -1
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		var total float64
		for _, m := range f.Metric {
			if c := m.GetCounter(); c != nil {
				total += c.GetValue()
			}
		}
		return total
	}
	return 0 // family registered but no series yet / absent
}

// ---- device CRUD ---------------------------------------------------------

func TestDeviceCreateListGetRoundtrip(t *testing.T) {
	a, st, _ := testApp(t)
	ctx := context.Background()

	dv, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "F0:9F:C2:84:8F:2A", Name: "lobby", SiteID: "default"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if dv.MAC != "f0:9f:c2:84:8f:2a" || dv.State != store.StatePending {
		t.Fatalf("create view: %+v", dv)
	}

	// store record must be canonical bare 12-hex
	rec, err := st.Get("f09fc2848f2a")
	if err != nil || rec.State != store.StatePending || rec.Name != "lobby" {
		t.Fatalf("store record: %+v err=%v", rec, err)
	}

	got, err := a.GetDevice(ctx, "F0-9F-C2-84-8F-2A")
	if err != nil || got.Name != "lobby" || got.IP != "" {
		t.Fatalf("get: %+v err=%v", got, err)
	}
	list := a.ListDevices(ctx)
	if len(list) != 1 || list[0].MAC != "f0:9f:c2:84:8f:2a" || list[0].State != 1 {
		t.Fatalf("list: %+v", list)
	}
}

func TestDuplicateCreateIsIdempotentUpsert(t *testing.T) {
	a, _, _ := testApp(t)
	ctx := context.Background()
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "aabbccddeeff", Name: "first"}); err != nil {
		t.Fatal(err)
	}
	dv, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "AA-BB-CC-DD-EE-FF", Name: "second"})
	if err != nil {
		t.Fatalf("duplicate create returned error (would become HTTP 500): %v", err)
	}
	if dv.Name != "second" || dv.State != store.StatePending {
		t.Fatalf("upsert result: %+v", dv)
	}
	if n := len(a.ListDevices(ctx)); n != 1 {
		t.Fatalf("duplicate created %d records", n)
	}
}

func TestAdoptPendingFlow(t *testing.T) {
	a, st, _ := testApp(t)
	ctx := context.Background()

	if err := st.MarkPending("a040a0aabbcc", "discovery:platform=U7PG2"); err != nil {
		t.Fatal(err)
	}
	dv, err := a.AdoptPending(ctx, "A0:40:A0:AA:BB:CC")
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if dv.MAC != "a0:40:a0:aa:bb:cc" || dv.State != store.StatePending {
		t.Fatalf("adopt view: %+v", dv)
	}
	rec, err := st.Get("a040a0aabbcc")
	if err != nil || rec.State != store.StatePending {
		t.Fatalf("after adopt: %+v err=%v", rec, err)
	}

	// adopted devices vanish from the pending list
	if pen := a.ListPending(ctx); len(pen) != 0 {
		t.Fatalf("pending after adopt: %+v", pen)
	}

	// adopting again: PENDING record is valid for re-adopt (idempotent)
	if dv, err := a.AdoptPending(ctx, "a0:40:a0:aa:bb:cc"); err != nil || dv.State != store.StatePending {
		t.Fatalf("re-adopt: %+v err=%v", dv, err)
	}
}

func TestAdoptUnknownMACErrors(t *testing.T) {
	a, _, _ := testApp(t)
	if _, err := a.AdoptPending(context.Background(), "ff:ff:ff:ff:ff:ff"); err == nil {
		t.Fatal("adopt of unknown mac must return an error")
	}
}

func TestGetDeleteUnknownMACErrors(t *testing.T) {
	a, _, _ := testApp(t)
	ctx := context.Background()
	_, err := a.GetDevice(ctx, "ff:ff:ff:ff:ff:ff")
	if !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("get unknown: want adminapi.ErrNotFound wrapped, got %v", err)
	}
	if err := a.DeleteDevice(ctx, "ff:ff:ff:ff:ff:ff"); !errors.Is(err, adminapi.ErrNotFound) {
		t.Fatalf("delete unknown: want adminapi.ErrNotFound wrapped, got %v", err)
	}
}

// ---- end-to-end wiring: real adapter behind the real adminapi handler ----

// TestHTTPNotFoundThroughRealAdapter composes App (real Backend) with a real
// adminapi handler and exercises unknown-MAC paths over httptest recorders —
// no sockets. Pins the wire contract: unknown device must be HTTP 404 with a
// JSON error body on GET/DELETE/adopt, never 500.
func TestHTTPNotFoundThroughRealAdapter(t *testing.T) {
	a, _, _ := testApp(t)
	h := adminapi.New(adminapi.Config{}, a) // App implements Backend

	for _, tc := range []struct {
		name, method, path string
	}{
		{"get unknown", "GET", "/api/v1/devices/ff:ff:ff:ff:ff:ff"},
		{"delete unknown", "DELETE", "/api/v1/devices/ff:ff:ff:ff:ff:ff"},
		{"adopt unknown", "POST", "/api/v1/pending/ff:ff:ff:ff:ff:ff/adopt"},
	} {
		req, err := http.NewRequest(tc.method, tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d (%s), want 404", tc.name, rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body not JSON: %q", tc.name, rec.Body.String())
		}
		if s, _ := body["error"].(string); s == "" {
			t.Fatalf("%s: missing error key", tc.name)
		}
	}

	// known devices still work end to end (sanity of the composition)
	if _, err := a.CreateDevice(context.Background(), adminapi.DeviceUpsert{MAC: "F0:9F:C2:84:8F:2A"}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/v1/devices/f0:9f:c2:84:8f:2a", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get known through adapter: %d (%s)", rec.Code, rec.Body.String())
	}
}

// ---- wireless persistence ------------------------------------------------

func TestWirelessRoundTripPersistence(t *testing.T) {
	a, _, wpath := testApp(t)
	ctx := context.Background()

	// default empty document before first write
	got := a.GetWireless(ctx)
	if len(got.Wlans) != 0 {
		t.Fatalf("default wireless: %+v", got)
	}

	env := adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{
		{ID: "w1", Name: "home", SSID: "home-net", Security: "wpa-p", Passphrase: "correct-horse", VLAN: 1, Enabled: true},
		{Name: "guest", SSID: "guests", Security: "open", VLAN: 20},
	}}
	if err := a.PutWireless(ctx, env); err != nil {
		t.Fatalf("put wireless: %v", err)
	}

	// reads echo what was written
	if back := a.GetWireless(ctx); len(back.Wlans) != 2 || back.Wlans[0].SSID != "home-net" || back.Wlans[1].VLAN != 20 {
		t.Fatalf("readback: %+v", back)
	}

	// persistence: reopen a fresh App over the same file
	a2 := New(store.NewMemStore(), wpath, quietLogger())
	if re := a2.GetWireless(ctx); len(re.Wlans) != 2 || re.Wlans[0].Passphrase != "correct-horse" {
		t.Fatalf("reopened: %+v", re)
	}

	// no temp files left behind
	entries, _ := os.ReadDir(filepath.Dir(wpath))
	if len(entries) != 1 {
		t.Fatalf("expected exactly one wireless file, got %d: %v", len(entries), entries)
	}
}

// ---- metrics poller ------------------------------------------------------

// pollerSetup builds a fresh App + MemStore fixture for poller tests.
func pollerSetup(t *testing.T) (*App, store.DeviceStore) {
	t.Helper()
	a, st, _ := testApp(t)
	return a, st
}

func TestPollerSeedsAdoptedWithoutCounting(t *testing.T) {
	a, st := pollerSetup(t)
	// Fresh heartbeat: the lost sweep must not touch this device.
	lastSeen := time.Now().Unix()
	if err := st.Put(store.Device{MAC: "f09fc2848f2a", State: store.StateAdopted, Model: "U7PG2",
		LastSeen: lastSeen, Extra: store.JSONMap{"uptime": 7231.0},
		LastUps: store.JSONMap{"user-num_sta": 12.0, "user-tx_bytes": 1048576.0, "user-rx_bytes": 2097152.0},
	}); err != nil {
		t.Fatal(err)
	}
	bAdopt := counterDefault("openunifi_adopt_total")
	bFail := counterDefault("openunifi_adopt_fail_total")

	a.PollOnce()

	if got := counterDefault("openunifi_adopt_total"); got != bAdopt {
		t.Fatalf("first observation must not count a transition: adopt %v -> %v", bAdopt, got)
	}
	if got := counterDefault("openunifi_adopt_fail_total"); got != bFail {
		t.Fatalf("first observation counted a fail: %v -> %v", bFail, got)
	}

	// numeric fields must reach the gauges honestly
	checkGauge(t, "openunifi_uptime_seconds", 7231)
	checkGauge(t, "openunifi_sta_count", 12)
	// NOTE: byte snapshots are honest GAUGES (see metrics.go) — the family
	// names do NOT carry the Prometheus counter suffix _total.
	checkGauge(t, "openunifi_user_tx_bytes", 1048576)
	checkGauge(t, "openunifi_user_rx_bytes", 2097152)
	checkGauge(t, "openunifi_device_state", 3)
	checkGauge(t, "openunifi_last_inform_timestamp", float64(lastSeen))
}

func checkGauge(t *testing.T, family string, want float64) {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, m := range f.Metric {
			if g := m.GetGauge(); g != nil {
				if got := g.GetValue(); got != want {
					t.Fatalf("%s gauge = %v, want %v", family, got, want)
				}
				return
			}
		}
	}
	t.Fatalf("gauge family %s has no series (missing data for %v)", family, want)
}

func TestPollerAdoptTransitions(t *testing.T) {
	a, st := pollerSetup(t)
	if err := st.Put(store.Device{MAC: "010203040506", State: store.StatePending, Model: "U6Lite"}); err != nil {
		t.Fatal(err)
	}

	a.PollOnce() // seed prevStates = pending

	// transition pending -> adopted: counts exactly one adopt
	d, _ := st.Get("010203040506")
	d.State = store.StateAdopted
	if err := st.Put(d); err != nil {
		t.Fatal(err)
	}
	bA := counterDefault("openunifi_adopt_total")
	bF := counterDefault("openunifi_adopt_fail_total")
	a.PollOnce()
	if got := counterDefault("openunifi_adopt_total"); got != bA+1 {
		t.Fatalf("adopt_total = %v, want %v+1", got, bA)
	}
	if got := counterDefault("openunifi_adopt_fail_total"); got != bF {
		t.Fatalf("adopt_fail_total changed unexpectedly: %v -> %v", bF, got)
	}

	// transition adopted -> lost: counts exactly one adopt failure
	d, _ = st.Get("010203040506")
	d.State = store.StateLost
	if err := st.Put(d); err != nil {
		t.Fatal(err)
	}
	a.PollOnce()
	if got := counterDefault("openunifi_adopt_total"); got != bA+1 {
		t.Fatalf("adopt_total grew again: %v", got)
	}
	if got := counterDefault("openunifi_adopt_fail_total"); got != bF+1 {
		t.Fatalf("adopt_fail_total = %v, want %v+1", got, bF)
	}
}

func TestRunPollerStopsOnContextCancel(t *testing.T) {
	a, _ := pollerSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.RunPoller(ctx, time.Hour) // huge interval: only exit path is ctx
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunPoller did not exit after context cancel")
	}
}

// ---- wireless cache (load-once, no per-request file I/O) ------------------

func TestNewWithCorruptWirelessFileRetainsError(t *testing.T) {
	dir := t.TempDir()
	wpath := filepath.Join(dir, "wireless.json")
	if err := os.WriteFile(wpath, []byte("{this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := New(store.NewMemStore(), wpath, quietLogger())

	env, err := a.CurrentWireless()
	if err == nil {
		t.Fatal("corrupt wireless.json must be a retained load error at New")
	}
	if len(env.Wlans) != 0 {
		t.Fatalf("corrupt load must serve the empty default, got %+v", env)
	}

	// main-style startup gate: the process must refuse the corrupt file.
	if startupErr := func() error {
		_, err := a.CurrentWireless()
		return err
	}(); startupErr == nil {
		t.Fatal("startup check (CurrentWireless) must keep returning the error")
	}
}

func TestNewWithMissingWirelessFileIsEmptyDefault(t *testing.T) {
	a, _, _ := testApp(t) // wpath in a fresh tempdir: file never written
	env := a.GetWireless(context.Background())
	if len(env.Wlans) != 0 {
		t.Fatalf("missing file must yield empty default, got %+v", env)
	}
	if _, err := a.CurrentWireless(); err != nil {
		t.Fatalf("missing file is not an error (first boot), got %v", err)
	}
}

// The load path runs the SAME validation as PUT /api/v1/wireless
// (adminapi.ValidateWlan): a document that only DECODES but violates the
// rules must fail startup, and the error must name the offending wlan
// (FID-39), not wrap silently like the original json.Unmarshal-only path.
func TestNewRejectsInvalidWirelessDocument(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantText string
	}{
		{"wpa-eap without RADIUS support", `{"wlans":[{"name":"corp","ssid":"corp","security":"wpa-eap","vlan":1}]}`, "wpa-eap requires RADIUS profiles"},
		{"vlan out of range", `{"wlans":[{"ssid":"x","security":"wpa-p","passphrase":"longenough","vlan":5000}]}`, "vlan must be 1..4094"},
		{"bad security enum", `{"wlans":[{"ssid":"x","security":"wpa2","passphrase":"longenough","vlan":1}]}`, "security must be one of open, wpa-p"},
		{"control char ssid", `{"wlans":[{"ssid":"a\nb","security":"open","vlan":1}]}`, "control characters"},
		{"name too long", `{"wlans":[{"name":"` + strings.Repeat("n", 65) + `","ssid":"x","security":"open","vlan":1}]}`, "name must be at most 64 characters"},
	} {
		dir := t.TempDir()
		wpath := filepath.Join(dir, "wireless.json")
		if err := os.WriteFile(wpath, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		a := New(store.NewMemStore(), wpath, quietLogger())
		env, err := a.CurrentWireless()
		if err == nil {
			t.Fatalf("%s: invalid document must fail the load error", tc.name)
		}
		if !strings.Contains(err.Error(), tc.wantText) {
			t.Fatalf("%s: error %q must name the rule violation", tc.name, err.Error())
		}
		if !strings.Contains(err.Error(), "wlan[0]") {
			t.Fatalf("%s: error %q must name the offending wlan index", tc.name, err.Error())
		}
		if len(env.Wlans) != 0 {
			t.Fatalf("%s: invalid load must still serve the empty default, got %+v", tc.name, env)
		}
	}
}

// TestWirelessServedFromCacheWithoutFileIO proves GetWireless/CurrentWireless
// hit the in-memory cache, not the disk: after PutWireless, the backing file
// is removed and then replaced with garbage — reads keep serving the NEW
// envelope with a nil error regardless.
func TestWirelessServedFromCacheWithoutFileIO(t *testing.T) {
	a, _, wpath := testApp(t)
	ctx := context.Background()

	env := adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{
		{ID: "w1", Name: "home", SSID: "home-net", Security: "wpa-p", Passphrase: "correct-horse", Enabled: true},
	}}
	if err := a.PutWireless(ctx, env); err != nil {
		t.Fatalf("put wireless: %v", err)
	}

	// Destroy every trace of the file: gone, then corrupt.
	if err := os.Remove(wpath); err != nil {
		t.Fatal(err)
	}
	if got := a.GetWireless(ctx); len(got.Wlans) != 1 || got.Wlans[0].SSID != "home-net" {
		t.Fatalf("post-delete read must serve the cached NEW envelope, got %+v", got)
	}
	if _, err := a.CurrentWireless(); err != nil {
		t.Fatalf("post-delete CurrentWireless must be nil-error, got %v", err)
	}
	if err := os.WriteFile(wpath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := a.GetWireless(ctx); len(got.Wlans) != 1 {
		t.Fatalf("post-corrupt read must still serve the cache, got %+v", got)
	}
}

func TestPutWirelessFailureLeavesCacheUntouched(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a := New(store.NewMemStore(), filepath.Join(dir, "wireless.json"), quietLogger())

	if err := a.PutWireless(ctx, adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{{Name: "ok", SSID: "ok"}}}); err != nil {
		t.Fatal(err)
	}

	// Make persistence impossible: the temp file lives in dir, so a 0000
	// directory forces CreateTemp to fail AFTER the cache is populated.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod inject: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	err := a.PutWireless(ctx, adminapi.WlansEnvelope{Wlans: []adminapi.Wlan{{Name: "fail", SSID: "fail"}}})
	if err == nil {
		t.Fatal("put into an unwritable directory must fail")
	}
	if got := a.GetWireless(ctx); len(got.Wlans) != 1 || got.Wlans[0].Name != "ok" {
		t.Fatalf("failed persist must leave the cache unchanged, got %+v", got)
	}
}

// ---- lost sweep (StateLost finally has a producer) ------------------------

func TestLostSweepMarksStaleAdoptedDeviceLost(t *testing.T) {
	a, st := pollerSetup(t)
	now := time.Now().Unix()

	mk := func(mac string) error {
		return st.Put(store.Device{MAC: mac, State: store.StateAdopted, LastSeen: now - lostAfterSeconds - 121})
	}
	if err := mk("f09fc2848f2a"); err != nil {
		t.Fatal(err)
	}
	// fresh adopted: must be untouched
	if err := st.Put(store.Device{MAC: "010203040506", State: store.StateAdopted, LastSeen: now - 15}); err != nil {
		t.Fatal(err)
	}
	// other states with ancient LastSeen: never swept
	if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StatePending, LastSeen: now - 9999}); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(store.Device{MAC: "112233445566", State: store.StateAdopting, LastSeen: now - 9999}); err != nil {
		t.Fatal(err)
	}

	bFail := counterDefault("openunifi_adopt_fail_total")
	a.PollOnce()

	if d, err := st.Get("f09fc2848f2a"); err != nil || d.State != store.StateLost {
		t.Fatalf("stale adopted must be StateLost, got %+v err=%v", d, err)
	}
	if d, err := st.Get("010203040506"); err != nil || d.State != store.StateAdopted {
		t.Fatalf("fresh adopted must stay Adopted, got %+v err=%v", d, err)
	}
	if d, err := st.Get("aabbccddeeff"); err != nil || d.State != store.StatePending {
		t.Fatalf("pending must never be swept, got %+v err=%v", d, err)
	}
	if d, err := st.Get("112233445566"); err != nil || d.State != store.StateAdopting {
		t.Fatalf("adopting must never be swept, got %+v err=%v", d, err)
	}
	if got := counterDefault("openunifi_adopt_fail_total"); got != bFail+1 {
		t.Fatalf("sweep transition must count exactly one adopt failure: %v -> %v", bFail, got)
	}
}

func TestLostSweepSkipsAdoptedWithZeroLastSeen(t *testing.T) {
	a, st := pollerSetup(t)
	if err := st.Put(store.Device{MAC: "f09fc2848f2a", State: store.StateAdopted, LastSeen: 0}); err != nil {
		t.Fatal(err)
	}
	bFail := counterDefault("openunifi_adopt_fail_total")
	a.PollOnce()
	if d, err := st.Get("f09fc2848f2a"); err != nil || d.State != store.StateAdopted {
		t.Fatalf("LastSeen==0 (never seen) must not be swept to Lost, got %+v err=%v", d, err)
	}
	if got := counterDefault("openunifi_adopt_fail_total"); got != bFail {
		t.Fatalf("no sweep transition, no fail count: %v -> %v", bFail, got)
	}
}

func TestPrevStatesPrunedForDeletedDevices(t *testing.T) {
	a, st := pollerSetup(t)
	if err := st.Put(store.Device{MAC: "f09fc2848f2a", State: store.StateAdopted, LastSeen: time.Now().Unix()}); err != nil {
		t.Fatal(err)
	}
	a.PollOnce() // seeds prevStates
	a.prevMu.Lock()
	seeded := len(a.prevStates)
	a.prevMu.Unlock()
	if seeded != 1 {
		t.Fatalf("expected exactly one prevStates entry, got %d", seeded)
	}

	if err := st.Delete("f09fc2848f2a"); err != nil {
		t.Fatal(err)
	}
	a.PollOnce() // device gone: prevStates entry must be pruned, not leak
	a.prevMu.Lock()
	left := len(a.prevStates)
	a.prevMu.Unlock()
	if left != 0 {
		t.Fatalf("prevStates entry for deleted device must be pruned, %d left", left)
	}
}

// Deleting a device must also remove its metric series (FID-38): per-device
// gauges keyed by MAC would otherwise survive inventory churn forever, with
// mac labels enumerating devices that are no longer ours to track.
func TestDeleteDevicePrunesMetricSeries(t *testing.T) {
	a, st := pollerSetup(t)
	ctx := context.Background()

	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "F0:9F:C2:84:8F:2A", Name: "lobby"}); err != nil {
		t.Fatal(err)
	}
	d, err := st.Get("f09fc2848f2a")
	if err != nil {
		t.Fatal(err)
	}
	d.State = store.StateAdopted
	d.Model = "U7PG2"
	d.LastSeen = time.Now().Unix()
	if err := st.Put(d); err != nil {
		t.Fatal(err)
	}
	a.PollOnce() // seeds the per-device gauges

	if got := seriesForMAC(gatherDefault(t), "f0:9f:c2:84:8f:2a"); got < 6 {
		t.Fatalf("expected seeded series (state+last_seen+uptime+tx+rx), got %d", got)
	}

	if err := a.DeleteDevice(ctx, "f0:9f:c2:84:8f:2a"); err != nil {
		t.Fatal(err)
	}

	if got := seriesForMAC(gatherDefault(t), "f0:9f:c2:84:8f:2a"); got != 0 {
		t.Fatalf("deleted device still has %d metric series", got)
	}
}

// gatherDefault and seriesForMAC count exposition series for a MAC label,
// since the process-global registry accumulates series from earlier tests.

// gatherDefault collects one exposition snapshot from the default registry,
// keyed "<family>{label=value,...}".
func gatherDefault(t *testing.T) map[string]*dto.Metric {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*dto.Metric{}
	for _, f := range fams {
		for _, m := range f.Metric {
			labels := ""
			for _, l := range m.GetLabel() {
				labels += l.GetName() + "=" + l.GetValue() + ","
			}
			out[f.GetName()+"{"+labels+"}"] = m
		}
	}
	return out
}

// seriesForMAC counts gathered series whose mac label matches.
func seriesForMAC(g map[string]*dto.Metric, mac string) int {
	n := 0
	for k := range g {
		if strings.Contains(k, "mac="+mac+",") {
			n++
		}
	}
	return n
}

// ---- MAC consolidation (store.CanonicalMAC is the single normalizer) -----

func TestInvalidMACIsRejectedOrNotFound(t *testing.T) {
	a, _, _ := testApp(t)
	ctx := context.Background()

	for _, bad := range []string{"zz", "not a mac at all"} {
		if _, err := a.GetDevice(ctx, bad); !errors.Is(err, adminapi.ErrNotFound) {
			t.Fatalf("get %q: want not-found, got %v", bad, err)
		}
		if err := a.DeleteDevice(ctx, bad); !errors.Is(err, adminapi.ErrNotFound) {
			t.Fatalf("delete %q: want not-found, got %v", bad, err)
		}
		if _, err := a.AdoptPending(ctx, bad); err == nil {
			t.Fatalf("adopt %q: want error", bad)
		}
	}
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "zz"}); err == nil {
		t.Fatal("create with unparseable mac must reject")
	}
	// valid input is behavior-identical to the old private normalizer
	if _, err := a.CreateDevice(ctx, adminapi.DeviceUpsert{MAC: "A0.40.A0.AA.BB.CC"}); err != nil {
		t.Fatalf("dot-separated mac must normalize: %v", err)
	}
}

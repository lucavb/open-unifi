package server

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

const informCycleTestKey = "11112222333344445555666677778888"

func putInformCycleDevice(t *testing.T, st store.DeviceStore, mac string) {
	t.Helper()
	if err := st.Put(store.Device{
		MAC: mac, State: store.StateAdopted, CfgVersion: "aaaa", AppliedCfg: "aaaa",
		XAuthkey: informCycleTestKey, Authkeys: []string{informCycleTestKey}, Model: "U7PG2",
		Extra: store.JSONMap{"wlan_cfg_sha": wireless.WlanListHash(nil), "wlan_cfg_applied_wlans": `[]`},
	}); err != nil {
		t.Fatal(err)
	}
}

func plainSessionInformBytes(t *testing.T, mac, cfg string, stations []any) []byte {
	t.Helper()
	body := infoBody(cfg)
	body["mac"] = store.ColonMAC(mac)
	body["_authkey"] = informCycleTestKey
	if stations != nil {
		body["sta_table"] = stations
	}
	return mustJSON(t, body)
}

func servePlainSessionInform(h http.Handler, raw []byte, w http.ResponseWriter) {
	req := httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(raw))
	h.ServeHTTP(w, req)
}

type cycleHookNotice struct {
	name      string
	connected bool
	rows      int
	err       error
}

func sessionRowsAfterHook(st store.DeviceStore, mac string) (bool, int, error) {
	rec, err := st.Get(mac)
	if err != nil {
		return false, 0, err
	}
	rows := store.ClientSessions(rec)
	connected := len(rows) > 0 && rows[0].Connected
	return connected, len(rows), nil
}

func TestInformCycleSerializesSameMACThroughCallbacks(t *testing.T) {
	st := store.NewMemStore()
	putInformCycleDevice(t, st, testMAC)
	firstHookEntered := make(chan struct{})
	releaseFirstHook := make(chan struct{})
	notices := make(chan cycleHookNotice, 8)
	var firstOnce sync.Once
	s := New(Config{
		AllowPlainText: true,
		OnSessionEvents: func(mac string, connects, disconnects int) {
			connected, rows, err := sessionRowsAfterHook(st, mac)
			name := "event-disconnect"
			if connects > 0 {
				name = "event-connect"
			}
			notices <- cycleHookNotice{name: name, connected: connected, rows: rows, err: err}
			if connects > 0 {
				firstOnce.Do(func() {
					close(firstHookEntered)
					<-releaseFirstHook
				})
			}
		},
		OnSessionTransitions: func(mac string, ts []store.Transition) {
			connected, rows, err := sessionRowsAfterHook(st, mac)
			name := "transition-disconnect"
			if len(ts) > 0 && ts[0].Kind == store.TransitionConnect {
				name = "transition-connect"
			}
			notices <- cycleHookNotice{name: name, connected: connected, rows: rows, err: err}
		},
	}, st, testLogger())
	h := s.InformHandler()
	firstRaw := plainSessionInformBytes(t, testMAC, "aaaa", staRows("00:11:22:33:44:55"))
	secondRaw := plainSessionInformBytes(t, testMAC, "aaaa", []any{})
	firstDone := make(chan int, 1)
	go func() {
		rr := httptest.NewRecorder()
		servePlainSessionInform(h, firstRaw, rr)
		firstDone <- rr.Code
	}()

	select {
	case notice := <-notices:
		if notice.name != "event-connect" || notice.err != nil || !notice.connected || notice.rows != 1 {
			t.Fatalf("first hook did not observe committed connect: %+v", notice)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first session hook did not enter")
	}
	<-firstHookEntered

	secondStarted := make(chan struct{})
	secondDone := make(chan int, 1)
	go func() {
		close(secondStarted)
		rr := httptest.NewRecorder()
		servePlainSessionInform(h, secondRaw, rr)
		secondDone <- rr.Code
	}()
	<-secondStarted
	// The first callback is held at a barrier. The same-MAC transaction and
	// callbacks must remain behind it rather than overtaking its event order.
	select {
	case code := <-secondDone:
		t.Fatalf("second same-MAC inform completed while first callback was held (HTTP %d)", code)
	case notice := <-notices:
		t.Fatalf("second same-MAC callback overtook first: %+v", notice)
	case <-time.After(75 * time.Millisecond):
	}

	close(releaseFirstHook)
	select {
	case code := <-firstDone:
		if code != http.StatusOK {
			t.Fatalf("first inform status = %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first inform did not finish after releasing callback")
	}
	select {
	case code := <-secondDone:
		if code != http.StatusOK {
			t.Fatalf("second inform status = %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second inform did not finish after first callback")
	}

	got := []string{}
	for len(got) < 3 { // first transition, second event, second transition
		select {
		case notice := <-notices:
			if notice.err != nil {
				t.Fatalf("hook store read failed: %v", notice.err)
			}
			got = append(got, notice.name)
		case <-time.After(2 * time.Second):
			t.Fatalf("missing callback sequence, got %v", got)
		}
	}
	want := []string{"transition-connect", "event-disconnect", "transition-disconnect"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("callback sequence = %v, want %v", got, want)
	}
}

func TestNoncollidingInformCyclesProgressIndependently(t *testing.T) {
	mac1, mac2 := noncollidingInformMACs()
	if informCycleStripeIndex(mac1) == informCycleStripeIndex(mac2) {
		t.Fatal("test MACs collide on inform cycle stripes")
	}
	st := store.NewMemStore()
	putInformCycleDevice(t, st, mac1)
	putInformCycleDevice(t, st, mac2)
	firstHookEntered := make(chan struct{})
	releaseFirstHook := make(chan struct{})
	secondHookEntered := make(chan struct{})
	var firstOnce sync.Once
	s := New(Config{
		AllowPlainText: true,
		OnSessionEvents: func(mac string, connects, _ int) {
			if connects == 0 {
				return
			}
			if strings.EqualFold(mac, store.ColonMAC(mac1)) {
				firstOnce.Do(func() {
					close(firstHookEntered)
					<-releaseFirstHook
				})
				return
			}
			if strings.EqualFold(mac, store.ColonMAC(mac2)) {
				close(secondHookEntered)
			}
		},
	}, st, testLogger())
	h := s.InformHandler()
	firstRaw := plainSessionInformBytes(t, mac1, "aaaa", staRows("00:11:22:33:44:55"))
	secondRaw := plainSessionInformBytes(t, mac2, "aaaa", staRows("00:11:22:33:44:66"))
	firstDone := make(chan int, 1)
	go func() {
		rr := httptest.NewRecorder()
		servePlainSessionInform(h, firstRaw, rr)
		firstDone <- rr.Code
	}()
	select {
	case <-firstHookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first AP hook did not enter")
	}
	secondDone := make(chan int, 1)
	go func() {
		rr := httptest.NewRecorder()
		servePlainSessionInform(h, secondRaw, rr)
		secondDone <- rr.Code
	}()
	select {
	case <-secondHookEntered:
		// The independent AP advanced while the first AP's hook was blocked.
	case <-time.After(2 * time.Second):
		t.Fatal("noncolliding AP was blocked by another AP's callback")
	}
	close(releaseFirstHook)
	for name, done := range map[string]<-chan int{"first": firstDone, "second": secondDone} {
		select {
		case code := <-done:
			if code != http.StatusOK {
				t.Fatalf("%s AP status = %d", name, code)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s AP did not finish", name)
		}
	}
}

func noncollidingInformMACs() (string, string) {
	first := "aa:bb:cc:dd:ee:01"
	for i := 2; i < 255; i++ {
		candidate := fmt.Sprintf("aa:bb:cc:dd:ee:%02x", i)
		if informCycleStripeIndex(first) != informCycleStripeIndex(candidate) {
			return first, candidate
		}
	}
	panic("could not find noncolliding test MACs")
}

type blockingResponseWriter struct {
	header  http.Header
	started chan struct{}
	release chan struct{}
}

func (w *blockingResponseWriter) Header() http.Header { return w.header }
func (w *blockingResponseWriter) WriteHeader(int)     {}
func (w *blockingResponseWriter) Write(p []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(p), nil
}

func TestInformCycleStripeReleasedBeforeResponseWrite(t *testing.T) {
	st := store.NewMemStore()
	putInformCycleDevice(t, st, testMAC)
	secondDisconnectHookEntered := make(chan struct{})
	var secondDisconnectOnce sync.Once
	s := New(Config{
		AllowPlainText: true,
		OnSessionEvents: func(_ string, connects, disconnects int) {
			if disconnects > 0 {
				secondDisconnectOnce.Do(func() { close(secondDisconnectHookEntered) })
			}
		},
	}, st, testLogger())
	h := s.InformHandler()
	firstRaw := plainSessionInformBytes(t, testMAC, "aaaa", staRows("00:11:22:33:44:55"))
	secondRaw := plainSessionInformBytes(t, testMAC, "aaaa", []any{})
	writer := &blockingResponseWriter{header: make(http.Header), started: make(chan struct{}), release: make(chan struct{})}
	firstDone := make(chan struct{})
	go func() {
		servePlainSessionInform(h, firstRaw, writer)
		close(firstDone)
	}()
	select {
	case <-writer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first response did not reach the blocked writer")
	}
	secondDone := make(chan int, 1)
	go func() {
		rr := httptest.NewRecorder()
		servePlainSessionInform(h, secondRaw, rr)
		secondDone <- rr.Code
	}()
	select {
	case <-secondDisconnectHookEntered:
		// The second same-MAC inform reaches its post-commit hook while the
		// first response writer is still blocked.
	case <-time.After(2 * time.Second):
		t.Fatal("blocked response write retained the inform-cycle stripe")
	}
	select {
	case code := <-secondDone:
		if code != http.StatusOK {
			t.Fatalf("second inform status = %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second inform did not return while first response was blocked")
	}
	close(writer.release)
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first response writer did not unblock")
	}
}

type failAfterInformCallbackStore struct {
	store.DeviceStore
	err error
}

func (s *failAfterInformCallbackStore) UpdateExisting(mac string, fn func(*store.Device) error) error {
	rec, err := s.Get(mac)
	if err != nil {
		return err
	}
	if err := fn(&rec); err != nil {
		return err
	}
	return s.err
}

func TestInformCommitFailurePublishesNoHooksOrNoopTarget(t *testing.T) {
	oldRandom := noopRandom
	noopRandom = func() float64 { return 0 }
	t.Cleanup(func() { noopRandom = oldRandom })

	for _, failCommit := range []bool{true, false} {
		name := "successful control"
		if failCommit {
			name = "failed commit"
		}
		t.Run(name, func(t *testing.T) {
			base := store.NewMemStore()
			putInformCycleDevice(t, base, testMAC)
			db := base
			if failCommit {
				db = &failAfterInformCallbackStore{DeviceStore: base, err: errors.New("injected persistence failure")}
			}
			hooks := 0
			s := New(Config{
				OnSessionEvents:      func(string, int, int) { hooks++ },
				OnSessionTransitions: func(string, []store.Transition) { hooks++ },
			}, db, testLogger())
			s.noopTarget[testMAC] = 777
			body := infoBody("aaaa")
			body["sta_table"] = staRows("00:11:22:33:44:55")
			response := post(t, s.InformHandler(), encryptCBC(t, mustJSON(t, body), hexKey(t, informCycleTestKey), testIV))
			if response.Code != http.StatusOK {
				t.Fatalf("inform response status = %d", response.Code)
			}
			_, reply := decryptResponse(t, response.Body.Bytes(), hexKey(t, informCycleTestKey))
			if reply["_type"] != "noop" {
				t.Fatalf("scheduled encrypted inform = %v, want noop", reply["_type"])
			}
			rec, err := base.Get(testMAC)
			if err != nil {
				t.Fatal(err)
			}
			if failCommit {
				if hooks != 0 {
					t.Fatalf("failed commit invoked %d session hooks", hooks)
				}
				if got := s.noopTargetSnapshot(testMAC); got != 777 {
					t.Fatalf("failed commit published noop target %d, want unchanged 777", got)
				}
				if rows := store.ClientSessions(rec); len(rows) != 0 {
					t.Fatalf("failed commit persisted session rows: %+v", rows)
				}
				return
			}
			if hooks != 2 {
				t.Fatalf("successful commit invoked %d hooks, want both session hooks", hooks)
			}
			if got := s.noopTargetSnapshot(testMAC); got == 777 || got == 0 {
				t.Fatalf("successful commit did not publish scheduled noop target: %d", got)
			}
			if rows := store.ClientSessions(rec); len(rows) != 1 || !rows[0].Connected {
				t.Fatalf("successful commit did not persist connect: %+v", rows)
			}
		})
	}
}

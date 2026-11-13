package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/app"
	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/store"
)

const resetLifecycleCfg = "aaaabbbbccccdddd"
const resetLifecycleKey = "11112222333344445555666677778888"

func putResetLifecycleDevice(t *testing.T, st store.DeviceStore) {
	t.Helper()
	if err := st.Put(store.Device{
		MAC: testMAC, State: store.StateAdopted,
		CfgVersion: resetLifecycleCfg, AppliedCfg: resetLifecycleCfg,
		XAuthkey: resetLifecycleKey, Authkeys: []string{resetLifecycleKey},
		KeyConfirmed: true, Model: "U7PG2", SiteID: "reset-site",
		SSHPassword: "retained-admin-password", LEDOverride: "off",
		Extra: store.JSONMap{
			store.WlanCfgShaKey:          "pre-reset-baseline",
			store.WlanCfgAttemptsKey:     4,
			store.DeviceWLANsExtraKey:    `[{"name":"guest","ssid":"guest-net","enabled":true}]`,
			store.SSHSha512PasswdKey:     "retained-sha-cache",
			store.SSHMd5PasswdKey:        "retained-md5-cache",
			store.SystemCfgExtraLinesKey: []any{"admin-setting"},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func resetLifecycleHandlers(st store.DeviceStore, allowPlain bool) (http.Handler, http.Handler) {
	admin := adminapi.New(adminapi.Config{}, app.New(st, testLogger()))
	return admin, New(Config{AllowPlainText: allowPlain}, st, testLogger()).InformHandler()
}

func resetInformBody(cfg string, typ string) map[string]any {
	body := infoBody(cfg)
	body["_type"] = typ
	return body
}

func armedResetServer(t *testing.T) (http.Handler, store.DeviceStore) {
	t.Helper()
	st := store.NewMemStore()
	putResetLifecycleDevice(t, st)
	admin, informH := resetLifecycleHandlers(st, false)
	if rec := postAdmin(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/factory-reset"); rec.Code != http.StatusOK {
		t.Fatalf("arm status = %d", rec.Code)
	}
	return informH, st
}

func preparedResetServer(t *testing.T) (http.Handler, store.DeviceStore) {
	t.Helper()
	informH, st := armedResetServer(t)
	oldKey := hexKey(t, resetLifecycleKey)
	resp := post(t, informH, encryptCBC(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("initial reset emission = %d", resp.Code)
	}
	rec, err := st.Get(testMAC)
	if err != nil || !rec.FactoryResetInFlight {
		t.Fatalf("reset fixture not in flight: %+v (%v)", rec, err)
	}
	return informH, st
}

func TestFactoryResetInFlightSurvivesJSONRestartAndRetries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	st, err := store.NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	putResetLifecycleDevice(t, st)
	admin, informH := resetLifecycleHandlers(st, false)
	oldKey := hexKey(t, resetLifecycleKey)
	defaultKey := hexKey(t, inform.DefaultKeyHex)

	arm := postAdmin(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/factory-reset")
	if arm.Code != http.StatusOK {
		t.Fatalf("arm status = %d %s", arm.Code, arm.Body.String())
	}
	// The response is intentionally ignored to model a lost socket response;
	// the server transaction still durably records the in-flight phase.
	first := post(t, informH, encryptGCM(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, bytes16(0x21)))
	if first.Code != http.StatusOK {
		t.Fatalf("initial reset inform = %d", first.Code)
	}
	beforeRestart, err := st.Get(testMAC)
	if err != nil || !beforeRestart.FactoryResetInFlight || beforeRestart.XAuthkey != resetLifecycleKey {
		t.Fatalf("initial reset did not persist retry state: %+v (%v)", beforeRestart, err)
	}

	// Reopen the actual JSON store and build a fresh Server/App pair, modeling
	// a process restart between emission and reset confirmation.
	reopened, err := store.NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	admin2, inform2 := resetLifecycleHandlers(reopened, false)
	if pending := getPendingCommand(t, admin2); pending != "factory-reset" {
		t.Fatalf("restarted in-flight command view = %q, want factory-reset", pending)
	}
	retried := post(t, inform2, encryptCBC(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, testIV))
	if retried.Code != http.StatusOK {
		t.Fatalf("old-key retry = %d", retried.Code)
	}
	_, retryBytes := decryptResponseRaw(t, retried.Body.Bytes(), oldKey)
	if !reSetdefaultBytes.Match(retryBytes) {
		t.Fatalf("retry response = %q, want exact setdefault wire bytes", retryBytes)
	}
	reopenedRec, err := reopened.Get(testMAC)
	if err != nil || !reopenedRec.FactoryResetInFlight || reopenedRec.XAuthkey != resetLifecycleKey || !reopenedRec.KeyConfirmed {
		t.Fatalf("retry lost durable identity/marker: %+v (%v)", reopenedRec, err)
	}

	confirmed := post(t, inform2, encryptGCM(t, mustJSON(t, resetInformBody("", "info")), defaultKey, bytes16(0x22)))
	if confirmed.Code != http.StatusOK {
		t.Fatalf("factory-key confirmation = %d", confirmed.Code)
	}
	flags, reply := decryptResponse(t, confirmed.Body.Bytes(), defaultKey)
	if flags&inform.FlagGCM == 0 || reply["_type"] != "setparam" || reply["mgmt_cfg"] == nil {
		t.Fatalf("factory confirmation was not atomically followed by adoption: flags=%04x reply=%v", flags, reply)
	}
	reopenedRec, err = reopened.Get(testMAC)
	if err != nil || reopenedRec.FactoryResetInFlight || reopenedRec.State != store.StateAdopting ||
		reopenedRec.XAuthkey == "" || reopenedRec.XAuthkey == resetLifecycleKey || reopenedRec.KeyConfirmed {
		t.Fatalf("confirmed reset record = %+v (%v)", reopenedRec, err)
	}
}

func TestFactoryResetArmHandlerConflictsUntilEncryptedKeyConfirmation(t *testing.T) {
	tests := []struct {
		name string
		dev  store.Device
	}{
		{
			name: "unconfirmed adopted record",
			dev: store.Device{MAC: testMAC, State: store.StateAdopted,
				XAuthkey: resetLifecycleKey, Authkeys: []string{resetLifecycleKey}},
		},
		{
			name: "pending candidate",
			dev: store.Device{MAC: testMAC, State: store.StatePending,
				XAuthkey: resetLifecycleKey, Authkeys: []string{resetLifecycleKey}, KeyConfirmed: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := store.NewMemStore()
			if err := st.Put(tc.dev); err != nil {
				t.Fatal(err)
			}
			admin, _ := resetLifecycleHandlers(st, false)
			resp := postAdmin(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/factory-reset")
			if resp.Code != http.StatusConflict || !strings.Contains(resp.Body.String(), "wait for an encrypted inform") {
				t.Fatalf("factory-reset response = %d %s, want actionable 409", resp.Code, resp.Body.String())
			}
			after, err := st.Get(testMAC)
			if err != nil {
				t.Fatal(err)
			}
			if after.FactoryResetInFlight || after.Extra[store.FlagSetdefaultArmed] != nil {
				t.Fatalf("conflicted request changed reset state: %+v", after)
			}
		})
	}
}

func TestLegacyArmedResetWaitsForAssignedEncryptedInform(t *testing.T) {
	st := store.NewMemStore()
	dev := store.Device{
		MAC: testMAC, State: store.StateAdopting,
		CfgVersion: resetLifecycleCfg, XAuthkey: resetLifecycleKey,
		Authkeys: []string{resetLifecycleKey}, Model: "U7PG2",
		Extra: store.JSONMap{store.FlagSetdefaultArmed: true, store.FlagRebootOnConnect: true},
	}
	store.ArmCmdTask(&dev, "restart")
	if err := st.Put(dev); err != nil {
		t.Fatal(err)
	}
	_, h := resetLifecycleHandlers(st, false)
	defaultKey := hexKey(t, inform.DefaultKeyHex)
	first := post(t, h, encryptCBC(t, mustJSON(t, resetInformBody("", "info")), defaultKey, testIV))
	if first.Code != http.StatusOK {
		t.Fatalf("legacy pre-key factory inform = %d", first.Code)
	}
	_, adoption := decryptResponse(t, first.Body.Bytes(), defaultKey)
	if adoption["_type"] != "setparam" || adoption["mgmt_cfg"] == nil {
		t.Fatalf("factory-key traffic did not proceed through ordinary adoption: %v", adoption)
	}
	got, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if got.FactoryResetInFlight || got.KeyConfirmed || got.State != store.StateAdopting ||
		got.Extra[store.FlagSetdefaultArmed] != true || got.Extra[store.FlagRebootOnConnect] != true || store.ArmedCmdTask(got) == nil {
		t.Fatalf("pre-key adoption consumed reset/other arms or confirmed plaintext key: %+v", got)
	}

	assignedKey := hexKey(t, got.XAuthkey)
	retry := post(t, h, encryptCBC(t, mustJSON(t, resetInformBody(got.CfgVersion, "info")), assignedKey, testIV))
	if retry.Code != http.StatusOK {
		t.Fatalf("assigned-key reset emission = %d", retry.Code)
	}
	_, resetReply := decryptResponse(t, retry.Body.Bytes(), assignedKey)
	if resetReply["_type"] != "setdefault" {
		t.Fatalf("assigned-key response = %v, want setdefault", resetReply)
	}
	got, err = st.Get(testMAC)
	if err != nil || !got.FactoryResetInFlight || !got.KeyConfirmed {
		t.Fatalf("assigned-key reset did not atomically establish confirmation: %+v (%v)", got, err)
	}
	if got.Extra[store.FlagSetdefaultArmed] != nil || got.Extra[store.FlagRebootOnConnect] != nil || store.ArmedCmdTask(got) != nil {
		t.Fatalf("setdefault did not consume superseded arms: %+v", got.Extra)
	}
}

func TestLegacyUnconfirmedInFlightResetRequiresAssignedKeyRetry(t *testing.T) {
	h, st := preparedResetServer(t)
	if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
		d.KeyConfirmed = false // model a pre-marker in-flight record
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defaultKey := hexKey(t, inform.DefaultKeyHex)
	rejected := post(t, h, encryptCBC(t, mustJSON(t, resetInformBody("", "info")), defaultKey, testIV))
	if rejected.Code != http.StatusNotFound {
		t.Fatalf("legacy unconfirmed factory-key request = %d, want 404", rejected.Code)
	}
	got, err := st.Get(testMAC)
	if err != nil || !got.FactoryResetInFlight || got.KeyConfirmed || got.XAuthkey != resetLifecycleKey || got.State != store.StateAdopted {
		t.Fatalf("rejected legacy confirmation changed reset identity: %+v (%v)", got, err)
	}

	oldKey := hexKey(t, resetLifecycleKey)
	retry := post(t, h, encryptCBC(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, testIV))
	if retry.Code != http.StatusOK {
		t.Fatalf("assigned-key migration retry = %d", retry.Code)
	}
	_, retryReply := decryptResponse(t, retry.Body.Bytes(), oldKey)
	if retryReply["_type"] != "setdefault" {
		t.Fatalf("assigned-key migration response = %v, want setdefault", retryReply)
	}
	got, err = st.Get(testMAC)
	if err != nil || !got.FactoryResetInFlight || !got.KeyConfirmed || got.XAuthkey != resetLifecycleKey {
		t.Fatalf("assigned-key retry failed to confirm in-flight identity: %+v (%v)", got, err)
	}

	complete := post(t, h, encryptGCM(t, mustJSON(t, resetInformBody("", "heartbeat")), defaultKey, bytes16(0x27)))
	if complete.Code != http.StatusOK {
		t.Fatalf("confirmed factory-key completion = %d", complete.Code)
	}
	_, completionReply := decryptResponse(t, complete.Body.Bytes(), defaultKey)
	if completionReply["_type"] != "setparam" || completionReply["mgmt_cfg"] == nil {
		t.Fatalf("migrated reset completion = %v, want adoption setparam", completionReply)
	}
	got, err = st.Get(testMAC)
	if err != nil || got.FactoryResetInFlight || got.XAuthkey == "" || got.XAuthkey == resetLifecycleKey || got.KeyConfirmed {
		t.Fatalf("migrated reset did not complete/adopt: %+v (%v)", got, err)
	}
}

func TestPlaintextCannotAuthorizeLegacyInFlightFactoryConfirmation(t *testing.T) {
	for _, mode := range []string{"CBC", "GCM"} {
		t.Run(mode, func(t *testing.T) {
			_, st := preparedResetServer(t)
			if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
				d.KeyConfirmed = false
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			_, h := resetLifecycleHandlers(st, true)
			plain := resetInformBody(resetLifecycleCfg, "info")
			plain["_authkey"] = resetLifecycleKey
			plainResp := post(t, h, mustJSON(t, plain))
			var plainReply map[string]any
			if plainResp.Code != http.StatusOK || json.Unmarshal(plainResp.Body.Bytes(), &plainReply) != nil || plainReply["_type"] != "noop" {
				t.Fatalf("plaintext legacy retry = %d %v, want noop without establishing confirmation", plainResp.Code, plainReply)
			}

			defaultKey := hexKey(t, inform.DefaultKeyHex)
			var packet []byte
			if mode == "CBC" {
				packet = encryptCBC(t, mustJSON(t, resetInformBody("", "info")), defaultKey, testIV)
			} else {
				packet = encryptGCM(t, mustJSON(t, resetInformBody("", "info")), defaultKey, bytes16(0x29))
			}
			rejected := post(t, h, packet)
			if rejected.Code != http.StatusNotFound {
				t.Fatalf("%s factory-key confirmation after plaintext = %d, want 404", mode, rejected.Code)
			}
			got, err := st.Get(testMAC)
			if err != nil || !got.FactoryResetInFlight || got.KeyConfirmed || got.XAuthkey != resetLifecycleKey {
				t.Fatalf("%s plaintext claim altered legacy reset identity: %+v (%v)", mode, got, err)
			}
		})
	}
}

type failingResetResponseWriter struct {
	header http.Header
	status int
	writes int
}

func (w *failingResetResponseWriter) Header() http.Header { return w.header }
func (w *failingResetResponseWriter) WriteHeader(status int) {
	w.status = status
}
func (w *failingResetResponseWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("simulated socket write failure")
}

func TestFactoryResetResponseWriteFailureLeavesRetryableMarker(t *testing.T) {
	h, st := armedResetServer(t)
	oldKey := hexKey(t, resetLifecycleKey)
	wire := encryptGCM(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, bytes16(0x41))
	w := &failingResetResponseWriter{header: make(http.Header)}
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(wire)))
	if w.status != http.StatusOK || w.writes == 0 {
		t.Fatalf("response writer was not exercised: status=%d writes=%d", w.status, w.writes)
	}
	rec, err := st.Get(testMAC)
	if err != nil || !rec.FactoryResetInFlight || rec.XAuthkey != resetLifecycleKey {
		t.Fatalf("write failure lost committed reset retry state: %+v (%v)", rec, err)
	}
	retry := post(t, h, encryptCBC(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, testIV))
	if retry.Code != http.StatusOK {
		t.Fatalf("retry after response write failure = %d", retry.Code)
	}
	_, raw := decryptResponseRaw(t, retry.Body.Bytes(), oldKey)
	if !reSetdefaultBytes.Match(raw) {
		t.Fatalf("retry response after failed write = %q, want setdefault", raw)
	}
}

func TestFactoryResetConfirmationCommitFailureKeepsRetryIdentity(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "devices.json")
	parkedDir := filepath.Join(root, "parked-data")
	st, err := store.NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	putResetLifecycleDevice(t, st)
	admin, informH := resetLifecycleHandlers(st, false)
	if rec := postAdmin(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/factory-reset"); rec.Code != http.StatusOK {
		t.Fatalf("arm status = %d", rec.Code)
	}
	oldKey := hexKey(t, resetLifecycleKey)
	if resp := post(t, informH, encryptCBC(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, testIV)); resp.Code != http.StatusOK {
		t.Fatalf("initial reset emission = %d", resp.Code)
	}
	before, err := st.Get(testMAC)
	if err != nil || !before.FactoryResetInFlight {
		t.Fatalf("reset was not in flight before failure setup: %+v (%v)", before, err)
	}
	persistedBefore, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The next atomic JSON commit cannot create its tempfile while the store
	// directory is parked. Keep the persisted in-flight snapshot intact so a
	// later successful confirmation can prove recovery, not just memory state.
	if err := os.Rename(dir, parkedDir); err != nil {
		t.Fatal(err)
	}
	defaultKey := hexKey(t, inform.DefaultKeyHex)
	resp := post(t, informH, encryptCBC(t, mustJSON(t, resetInformBody("", "info")), defaultKey, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("failed confirmation response status = %d", resp.Code)
	}
	_, reply := decryptResponse(t, resp.Body.Bytes(), defaultKey)
	if reply["_type"] != "noop" {
		t.Fatalf("failed commit response = %v, want safe noop", reply)
	}
	after, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if !after.FactoryResetInFlight || after.State != before.State || after.XAuthkey != before.XAuthkey ||
		after.CfgVersion != before.CfgVersion || after.AppliedCfg != before.AppliedCfg ||
		!after.KeyConfirmed || after.Extra[store.WlanCfgShaKey] != before.Extra[store.WlanCfgShaKey] {
		t.Fatalf("failed factory-reset commit changed old in-flight record: before=%+v after=%+v", before, after)
	}
	persistedAfterFailure, err := os.ReadFile(filepath.Join(parkedDir, "devices.json"))
	if err != nil || !bytes.Equal(persistedAfterFailure, persistedBefore) {
		t.Fatalf("failed confirmation changed persisted snapshot: err=%v", err)
	}
	if err := os.Rename(parkedDir, dir); err != nil {
		t.Fatal(err)
	}

	// Restore persistence and retry the same factory-key status. It must now
	// complete reset and adoption, with the original in-flight keys still
	// available to authenticate the retry after the failed commit.
	resp = post(t, informH, encryptGCM(t, mustJSON(t, resetInformBody("", "info")), defaultKey, bytes16(0x42)))
	if resp.Code != http.StatusOK {
		t.Fatalf("confirmation retry after restoring persistence = %d", resp.Code)
	}
	flags, reply := decryptResponse(t, resp.Body.Bytes(), defaultKey)
	if flags&inform.FlagGCM == 0 || reply["_type"] != "setparam" {
		t.Fatalf("restored confirmation response flags=%04x payload=%v", flags, reply)
	}
	after, err = st.Get(testMAC)
	if err != nil || after.FactoryResetInFlight || after.State != store.StateAdopting || after.XAuthkey == resetLifecycleKey {
		t.Fatalf("restored confirmation did not complete reset: %+v (%v)", after, err)
	}
	reopened, err := store.NewJSONStore(path)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened.Get(testMAC)
	if err != nil || persisted.FactoryResetInFlight || persisted.XAuthkey != after.XAuthkey {
		t.Fatalf("successful retry did not persist completion: %+v (%v)", persisted, err)
	}
}

type confirmationBarrierStore struct {
	store.DeviceStore
	holdNext atomic.Bool
	entered  chan struct{}
	release  chan struct{}
}

func (s *confirmationBarrierStore) UpdateExisting(mac string, fn func(*store.Device) error) error {
	return s.DeviceStore.UpdateExisting(mac, func(d *store.Device) error {
		if err := fn(d); err != nil {
			return err
		}
		if s.holdNext.Swap(false) {
			close(s.entered)
			<-s.release
		}
		return nil
	})
}

func TestPredecodedRetiredKeyCannotMutateAfterResetConfirmation(t *testing.T) {
	base := store.NewMemStore()
	putResetLifecycleDevice(t, base)
	barrier := &confirmationBarrierStore{DeviceStore: base, entered: make(chan struct{}), release: make(chan struct{})}
	admin, informH := resetLifecycleHandlers(barrier, false)
	if rec := postAdmin(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/factory-reset"); rec.Code != http.StatusOK {
		t.Fatalf("arm status = %d", rec.Code)
	}
	oldKey := hexKey(t, resetLifecycleKey)
	if resp := post(t, informH, encryptCBC(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, testIV)); resp.Code != http.StatusOK {
		t.Fatalf("initial setdefault = %d", resp.Code)
	}

	srv := New(Config{}, barrier, testLogger())
	decodedStale := make(chan string, 1)
	allowStaleCycle := make(chan struct{})
	srv.afterEncryptedDecode = func(_ string, usedKey string) {
		if strings.EqualFold(usedKey, resetLifecycleKey) {
			decodedStale <- usedKey
			<-allowStaleCycle
		}
	}
	h := srv.InformHandler()
	defaultKey := hexKey(t, inform.DefaultKeyHex)
	confirmWire := encryptCBC(t, mustJSON(t, resetInformBody("", "info")), defaultKey, testIV)
	barrier.holdNext.Store(true)
	confirmDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(confirmWire)))
		confirmDone <- rr
	}()
	select {
	case <-barrier.entered:
		// The reset candidate has been built but not committed; its Server
		// inform stripe is still held.
	case <-time.After(2 * time.Second):
		t.Fatal("factory confirmation did not reach pre-commit barrier")
	}
	staleBody := resetInformBody("retired-request-version", "info")
	staleBody["serial"] = "predecoded-stale-request"
	staleWire := encryptCBC(t, mustJSON(t, staleBody), oldKey, testIV)
	staleDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(staleWire)))
		staleDone <- rr
	}()
	select {
	case key := <-decodedStale:
		if !strings.EqualFold(key, resetLifecycleKey) {
			t.Fatalf("stale request decoded with unexpected key %q", key)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stale old-key request did not decode before confirmation commit")
	}
	close(barrier.release)
	select {
	case rr := <-confirmDone:
		if rr.Code != http.StatusOK {
			t.Fatalf("factory confirmation status = %d", rr.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("factory confirmation did not commit")
	}
	close(allowStaleCycle)
	select {
	case rr := <-staleDone:
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "unable to decrypt inform payload") {
			t.Fatalf("predecoded retired-key request status = %d, want 400 rejection", rr.Code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("predecoded stale request did not finish")
	}
	rec, err := base.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Serial == "predecoded-stale-request" || rec.AppliedCfg == "retired-request-version" || rec.FactoryResetInFlight {
		t.Fatalf("predecoded stale request mutated post-reset record: %+v", rec)
	}
}

func TestPlaintextAndGentleInformCannotConfirmFactoryReset(t *testing.T) {
	st := store.NewMemStore()
	putResetLifecycleDevice(t, st)
	if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
		if d.Extra == nil {
			d.Extra = store.JSONMap{}
		}
		d.Extra[store.FlagSetdefaultArmed] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, h := resetLifecycleHandlers(st, true)
	oldKey := hexKey(t, resetLifecycleKey)
	plainAssigned := resetInformBody(resetLifecycleCfg, "info")
	plainAssigned["_authkey"] = resetLifecycleKey
	resp := post(t, h, mustJSON(t, plainAssigned))
	var reply map[string]any
	if resp.Code != http.StatusOK || json.Unmarshal(resp.Body.Bytes(), &reply) != nil || reply["_type"] != "setdefault" {
		t.Fatalf("plaintext reset command compatibility: status=%d reply=%v", resp.Code, reply)
	}
	resetPending(t, st)

	// Even a factory-default _authkey claim on the plaintext lane is not
	// cryptographic confirmation; it receives only legacy plaintext handling.
	plainDefault := resetInformBody("", "info")
	plainDefault["_authkey"] = inform.DefaultKeyHex
	resp = post(t, h, mustJSON(t, plainDefault))
	if resp.Code != http.StatusOK {
		t.Fatalf("plaintext default claim status = %d", resp.Code)
	}
	resetPending(t, st)

	// Unknown gentle noops preserve the marker too, even with the old assigned
	// encryption key and a factory-looking cfgversion in the body.
	gentle := resetInformBody("", "scan")
	resp = post(t, h, encryptCBC(t, mustJSON(t, gentle), oldKey, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("encrypted gentle noop status = %d", resp.Code)
	}
	_, reply = decryptResponse(t, resp.Body.Bytes(), oldKey)
	if reply["_type"] != "noop" {
		t.Fatalf("gentle response = %v, want noop", reply)
	}
	resetPending(t, st)
}

func TestLostInFlightFactoryResetCanConfirmAndAdopt(t *testing.T) {
	h, st := preparedResetServer(t)
	if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
		d.State = store.StateLost
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defaultKey := hexKey(t, inform.DefaultKeyHex)
	resp := post(t, h, encryptCBC(t, mustJSON(t, resetInformBody("", "heartbeat")), defaultKey, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("lost in-flight reset confirmation = %d", resp.Code)
	}
	_, reply := decryptResponse(t, resp.Body.Bytes(), defaultKey)
	if reply["_type"] != "setparam" || reply["mgmt_cfg"] == nil {
		t.Fatalf("lost reset did not continue adoption: %v", reply)
	}
	rec, err := st.Get(testMAC)
	if err != nil || rec.FactoryResetInFlight || rec.State != store.StateAdopting || rec.XAuthkey == "" {
		t.Fatalf("lost reset completion = %+v (%v)", rec, err)
	}
}

func TestInFlightFactoryResetOutranksCommandsArmedLater(t *testing.T) {
	st := store.NewMemStore()
	putResetLifecycleDevice(t, st)
	admin, informH := resetLifecycleHandlers(st, false)
	if rec := postAdmin(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/factory-reset"); rec.Code != http.StatusOK {
		t.Fatalf("reset arm = %d", rec.Code)
	}
	oldKey := hexKey(t, resetLifecycleKey)
	if resp := post(t, informH, encryptCBC(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, testIV)); resp.Code != http.StatusOK {
		t.Fatalf("initial reset emission = %d", resp.Code)
	}

	// A reboot and task armed while reset is outstanding cannot preempt an
	// assigned-key reset retry; the retry consumes both as reset-superseded.
	if rec := postAdmin(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/reboot"); rec.Code != http.StatusOK {
		t.Fatalf("reboot arm = %d", rec.Code)
	}
	if rec := postAdminBody(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/cmd", `{"cmd":"restart"}`); rec.Code != http.StatusOK {
		t.Fatalf("task arm = %d %s", rec.Code, rec.Body.String())
	}
	retry := post(t, informH, encryptCBC(t, mustJSON(t, resetInformBody(resetLifecycleCfg, "info")), oldKey, testIV))
	_, raw := decryptResponseRaw(t, retry.Body.Bytes(), oldKey)
	if !reSetdefaultBytes.Match(raw) {
		t.Fatalf("in-flight reset did not outrank later commands: %q", raw)
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rec.Extra[store.FlagRebootOnConnect]; ok {
		t.Fatal("reset retry left later reboot armed")
	}
	if _, ok := rec.Extra[store.CmdTaskKey]; ok {
		t.Fatal("reset retry left later task armed")
	}

	// Arms racing in after another retry are also retired by confirmation.
	if rec := postAdmin(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/reboot"); rec.Code != http.StatusOK {
		t.Fatalf("second reboot arm = %d", rec.Code)
	}
	if rec := postAdminBody(t, admin, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/cmd", `{"cmd":"restart"}`); rec.Code != http.StatusOK {
		t.Fatalf("second task arm = %d", rec.Code)
	}
	defaultKey := hexKey(t, inform.DefaultKeyHex)
	confirm := post(t, informH, encryptGCM(t, mustJSON(t, resetInformBody("", "info")), defaultKey, bytes16(0x43)))
	_, reply := decryptResponse(t, confirm.Body.Bytes(), defaultKey)
	if reply["_type"] != "setparam" {
		t.Fatalf("command arms preempted reset confirmation: %v", reply)
	}
	rec, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rec.Extra[store.FlagRebootOnConnect]; ok {
		t.Fatal("reset confirmation left later reboot armed")
	}
	if _, ok := rec.Extra[store.CmdTaskKey]; ok {
		t.Fatal("reset confirmation left later task armed")
	}
}

func resetPending(t *testing.T, st store.DeviceStore) {
	t.Helper()
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.FactoryResetInFlight || rec.XAuthkey != resetLifecycleKey || rec.CfgVersion != resetLifecycleCfg || !rec.KeyConfirmed {
		t.Fatalf("non-confirming request changed reset retry state: %+v", rec)
	}
}

func TestInformCannotForgeFactoryResetMarker(t *testing.T) {
	_, h, st := lifecycleFixture(t)
	registerAdopted(t, st, resetLifecycleCfg, resetLifecycleKey)
	if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
		d.KeyConfirmed = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body := resetInformBody(resetLifecycleCfg, "info")
	body["factory_reset_in_flight"] = true
	resp := post(t, h, encryptCBC(t, mustJSON(t, body), hexKey(t, resetLifecycleKey), testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("forged marker inform status = %d", resp.Code)
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.FactoryResetInFlight {
		t.Fatal("inform body introduced typed factory reset marker")
	}
	if _, exists := rec.Extra[store.FactoryResetInFlightKey]; exists {
		t.Fatalf("inform body introduced raw factory reset marker: %v", rec.Extra[store.FactoryResetInFlightKey])
	}
}

func TestFactoryResetRejectsMalformedOrNonStatusTypes(t *testing.T) {
	badTypes := []struct {
		name  string
		value any
	}{
		{name: "null", value: nil},
		{name: "false", value: false},
		{name: "number", value: float64(7)},
		{name: "object", value: map[string]any{"status": "info"}},
		{name: "array", value: []any{"info"}},
		{name: "unknown string", value: "scan"},
		{name: "known non-status string", value: "cmd"},
		{name: "setparam", value: "setparam"},
	}
	for _, mode := range []string{"CBC", "GCM"} {
		for _, tc := range badTypes {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				h, st := preparedResetServer(t)
				before, err := st.Get(testMAC)
				if err != nil {
					t.Fatal(err)
				}
				body := resetInformBody("", "info")
				body["_type"] = tc.value
				defaultKey := hexKey(t, inform.DefaultKeyHex)
				var wire []byte
				if mode == "CBC" {
					wire = encryptCBC(t, mustJSON(t, body), defaultKey, testIV)
				} else {
					wire = encryptGCM(t, mustJSON(t, body), defaultKey, bytes16(0x31))
				}
				resp := post(t, h, wire)
				if resp.Code != http.StatusNotFound || resp.Body.Len() != 0 {
					t.Fatalf("invalid factory-key status got HTTP %d body %q, want rejected/no lifecycle response", resp.Code, resp.Body.String())
				}
				after, err := st.Get(testMAC)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(after, before) {
					t.Fatalf("invalid _type %s mutated in-flight record:\nbefore=%+v\nafter=%+v", tc.name, before, after)
				}
			})
		}
	}
}

func TestFactoryResetAcceptsOnlyExplicitStatusShapes(t *testing.T) {
	permitted := []struct {
		name     string
		typ      string
		omitType bool
		mode     string
	}{
		{name: "absent CBC", omitType: true, mode: "CBC"},
		{name: "empty string GCM", typ: "", mode: "GCM"},
		{name: "info CBC", typ: "info", mode: "CBC"},
		{name: "heartbeat GCM", typ: "heartbeat", mode: "GCM"},
	}
	for _, tc := range permitted {
		t.Run(tc.name, func(t *testing.T) {
			h, st := preparedResetServer(t)
			body := resetInformBody("", tc.typ)
			if tc.omitType {
				delete(body, "_type")
			}
			defaultKey := hexKey(t, inform.DefaultKeyHex)
			var wire []byte
			if tc.mode == "CBC" {
				wire = encryptCBC(t, mustJSON(t, body), defaultKey, testIV)
			} else {
				wire = encryptGCM(t, mustJSON(t, body), defaultKey, bytes16(0x32))
			}
			resp := post(t, h, wire)
			if resp.Code != http.StatusOK {
				t.Fatalf("permitted status inform response = %d %q", resp.Code, resp.Body.String())
			}
			flags, reply := decryptResponse(t, resp.Body.Bytes(), defaultKey)
			if (tc.mode == "GCM") != (flags&inform.FlagGCM != 0) || reply["_type"] != "setparam" || reply["mgmt_cfg"] == nil {
				t.Fatalf("status confirmation did not adopt in %s lane: flags=%04x reply=%v", tc.mode, flags, reply)
			}
			rec, err := st.Get(testMAC)
			if err != nil {
				t.Fatal(err)
			}
			if rec.FactoryResetInFlight || rec.State != store.StateAdopting || rec.XAuthkey == "" || rec.XAuthkey == resetLifecycleKey {
				t.Fatalf("permitted status did not complete reset/adoption: %+v", rec)
			}
		})
	}
}

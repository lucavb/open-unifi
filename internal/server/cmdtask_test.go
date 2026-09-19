package server

// §6.3 stored-task replay transport tests: the exact response BYTES at
// the adapter's serialization boundary (Server.applyOutcome is the
// single emission point the sealed envelope wraps), the full admin→inform
// loop over both crypto lanes (admin POST /devices/{mac}/cmd stores the
// task row over the real adminapi handler backed by the real App; the
// device's next sealed inform answers the §6.3 shape byte-exact and the
// arming is consumed one-shot), the trust-policy side (an inform body can
// neither forge nor smuggle a stored task), and the wire-level ranking
// pin (an armed task preempts a pending drift; the drift's full
// provisioning follows on the next inform, deferred not lost).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/server/adoption"
	"github.com/lucavb/open-unifi/internal/store"
)

// The §6.3 response shape as RAW BYTES. encoding/json sorts map keys, so
// this regexp pins the exact serialization the sealed envelope carries —
// key order included — for the stored row open-unifi arms: {"cmd","mac"}
// in the record's canonical identity spelling (the §6.3 jar rows carry
// the controller DB identity; open-unifi's canonical form is 12-hex —
// recorded as a live-proof obligation). server_time_in_utc is the §5
// universal timestamp (digit-only, epoch ms as a string).
var reCmdBytes = regexp.MustCompile(
	`^\{"_type":"cmd","cmd":"restart","mac":"aabbccddeeff","server_time_in_utc":"[0-9]+"\}$`)

// reCmdExtended pins the mergeFrom passthrough for a hypothetical third
// task field (sorted-key order: _type < cmd < future_field < mac <
// server_time_in_utc).
var reCmdExtended = regexp.MustCompile(
	`^\{"_type":"cmd","cmd":"x","future_field":"rides-verbatim","mac":"aabbccddeeff","server_time_in_utc":"[0-9]+"\}$`)

// postAdminBody is postAdmin with a request body: the cmd enqueue is the
// remote-command family's first admin POST route that carries one.
func postAdminBody(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestCmdResponseExactBytesAtSerializationBoundary pins the §6.3 shape at
// Server.applyOutcome — the single serialization point both transports
// seal. The stored row rides VERBATIM (voidsuper o00000: `new
// Object("cmd")` + `object.mergeFrom((X)task)` copies EVERY task field
// into the response), which the extended-row variant pins: a future task
// field round-trips unexamined.
func TestCmdResponseExactBytesAtSerializationBoundary(t *testing.T) {
	s := New(Config{}, store.NewMemStore(), testLogger())
	rec := &store.Device{MAC: testMAC, Extra: store.JSONMap{}}

	b, err := json.Marshal(s.applyOutcome(testMAC, rec, adoption.Outcome{
		Kind:    adoption.KindCmd,
		CmdTask: store.JSONMap{"cmd": "restart", "mac": testMAC},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !reCmdBytes.Match(b) {
		t.Fatalf("§6.3 cmd bytes = %q", b)
	}

	// mergeFrom semantics: every stored task field rides the response
	// verbatim — an extended row is not filtered to a known-key set.
	b, err = json.Marshal(s.applyOutcome(testMAC, rec, adoption.Outcome{
		Kind: adoption.KindCmd,
		CmdTask: store.JSONMap{
			"cmd": "x", "mac": testMAC, "future_field": "rides-verbatim",
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !reCmdExtended.Match(b) {
		t.Fatalf("§6.3 extended-row bytes = %q", b)
	}
}

// TestCmdTaskEndToEnd: admin POST /devices/{mac}/cmd stores the task row
// (record otherwise untouched — no §6.2 mint at enqueue); the 200 view
// reports pending_command "cmd"; the device's next CBC-sealed inform
// answers the §6.3 shape byte-exact in the same key; the arming is
// consumed; the follow-up status inform is an ordinary noop again.
func TestCmdTaskEndToEnd(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xkey)
	kx := hexKey(t, xkey)

	// 1. admin enqueues the task; 200 carries the view naming the
	// response _type the next inform will carry.
	rec := postAdminBody(t, adminH, http.MethodPost,
		"/api/v1/devices/aa:bb:cc:dd:ee:ff/cmd", `{"cmd":"restart"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cmd enqueue: %d %s", rec.Code, rec.Body.String())
	}
	var dv struct {
		PendingCommand string `json:"pending_command"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil {
		t.Fatal(err)
	}
	if dv.PendingCommand != "cmd" {
		t.Fatalf("enqueue view pending_command = %q, want cmd", dv.PendingCommand)
	}
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.CmdTaskCmd(d); got != "restart" {
		t.Fatalf("stored cmd = %q, want restart", got)
	}
	if row := store.ArmedCmdTask(d); row == nil || row["mac"] != testMAC {
		t.Fatalf("stored row identity = %+v, want canonical mac %q", row, testMAC)
	}
	if d.State != store.StateAdopted || d.CfgVersion != cfg || d.XAuthkey != xkey || d.AppliedCfg != cfg {
		t.Fatalf("enqueue must not touch state/key/cfgversion: %+v", d)
	}

	// 2. the device's next sealed inform answers §6.3 — byte-exact.
	resp := post(t, informH, encryptCBC(t, mustJSON(t, infoBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("armed inform: %d", resp.Code)
	}
	_, raw := decryptResponseRaw(t, resp.Body.Bytes(), kx)
	if !reCmdBytes.Match(raw) {
		t.Fatalf("§6.3 response bytes = %q", raw)
	}
	var jm map[string]any
	if err := json.Unmarshal(raw, &jm); err != nil {
		t.Fatal(err)
	}
	if jm["_type"] != "cmd" || jm["cmd"] != "restart" || jm["mac"] != testMAC {
		t.Fatalf("§6.3 response shape: %q", raw)
	}
	if srv, ok := jm["server_time_in_utc"].(string); !ok || srv == "0" {
		t.Fatalf("server_time_in_utc missing/empty: %q", raw)
	}

	// 3. one-shot: the row is consumed; the record stands.
	d, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, armed := d.Extra[store.CmdTaskKey]; armed {
		t.Fatalf("stored task survived emission: %+v", d.Extra[store.CmdTaskKey])
	}
	if d.State != store.StateAdopted || d.CfgVersion != cfg || d.XAuthkey != xkey {
		t.Fatalf("record disturbed by cmd emission: %+v", d)
	}

	// 4. the follow-up status inform is an ordinary noop again.
	resp = post(t, informH, encryptCBC(t, mustJSON(t, infoBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("post-cmd inform: %d", resp.Code)
	}
	_, jm = decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] != "noop" {
		t.Fatalf("post-cmd inform response: %v", jm["_type"])
	}
}

// TestCmdTaskGCMEndToEnd pins the GCM lane: the replay answers in the
// request's crypto lane (§7 GCM response bit), byte-exact, one-shot.
func TestCmdTaskGCMEndToEnd(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xkey)
	kx := hexKey(t, xkey)

	rec := postAdminBody(t, adminH, http.MethodPost,
		"/api/v1/devices/aa:bb:cc:dd:ee:ff/cmd", `{"cmd":"restart"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cmd enqueue: %d %s", rec.Code, rec.Body.String())
	}

	resp := post(t, informH, encryptGCM(t, mustJSON(t, infoBody(cfg)), kx, bytes16(0x09)))
	if resp.Code != http.StatusOK {
		t.Fatalf("armed inform: %d", resp.Code)
	}
	flags, raw := decryptResponseRaw(t, resp.Body.Bytes(), kx)
	if flags&inform.FlagGCM == 0 {
		t.Fatalf("response not sealed in the request crypto lane: flags %04x", flags)
	}
	if !reCmdBytes.Match(raw) {
		t.Fatalf("§6.3 response bytes = %q", raw)
	}
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, armed := d.Extra[store.CmdTaskKey]; armed {
		t.Fatalf("stored task survived emission: %+v", d.Extra[store.CmdTaskKey])
	}
}

// TestCmdTaskRowSurvivesDeviceInformBodies pins the trust-policy side of
// the stored-task row (CONTEXT.md: admin-owned): an inform body that
// tries to replace, forge or clear the armed task changes nothing — the
// admin-armed row wins and fires — and a device-smuggled row never
// introduces an arming.
func TestCmdTaskRowSurvivesDeviceInformBodies(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xkey)
	kx := hexKey(t, xkey)

	rec := postAdminBody(t, adminH, http.MethodPost,
		"/api/v1/devices/aa:bb:cc:dd:ee:ff/cmd", `{"cmd":"restart"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cmd enqueue: %d %s", rec.Code, rec.Body.String())
	}

	// A device inform carrying a forged task row (different cmd): the
	// body copy is discarded (admin-owned row), the ADMIN's task fires.
	body := infoBody(cfg)
	body[store.CmdTaskKey] = map[string]any{"cmd": "evil", "mac": testMAC}
	resp := post(t, informH, encryptCBC(t, mustJSON(t, body), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("hostile inform: %d", resp.Code)
	}
	_, raw := decryptResponseRaw(t, resp.Body.Bytes(), kx)
	if !reCmdBytes.Match(raw) {
		t.Fatalf("armed task must fire with the ADMIN's cmd despite the forged body: %q", raw)
	}
	if strings.Contains(string(raw), "evil") {
		t.Fatalf("forged body cmd leaked into the replay: %q", raw)
	}
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, armed := d.Extra[store.CmdTaskKey]; armed {
		t.Fatalf("stored task not consumed (or reintroduced): %+v", d.Extra[store.CmdTaskKey])
	}

	// And a task row CANNOT be smuggled in by a device inform on its
	// own: with no admin arming, the same body shape never fires and the
	// row is never persisted.
	hostile := infoBody(cfg)
	hostile[store.CmdTaskKey] = map[string]any{"cmd": "smuggled", "mac": testMAC}
	resp = post(t, informH, encryptCBC(t, mustJSON(t, hostile), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("smuggled-task inform: %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] == "cmd" {
		t.Fatalf("device-smuggled task fired: %v", jm["_type"])
	}
	d, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, armed := d.Extra[store.CmdTaskKey]; armed {
		t.Fatalf("device-smuggled task persisted: %+v", d.Extra[store.CmdTaskKey])
	}
}

// TestCmdTaskOutranksDriftEndToEnd pins the wire-level ranking: a device
// with pending drift AND an armed task answers the §6.3 replay first;
// the drift's full provisioning follows on the next inform — deferred,
// not lost.
func TestCmdTaskOutranksDriftEndToEnd(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xkey)
	// Pending drift: a stale envelope baseline the next settled inform
	// would act on (full provisioning), if not preempted.
	if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
		if d.Extra == nil {
			d.Extra = store.JSONMap{}
		}
		d.Extra["wlan_cfg_sha"] = "stalebaseline"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	kx := hexKey(t, xkey)

	rec := postAdminBody(t, adminH, http.MethodPost,
		"/api/v1/devices/aa:bb:cc:dd:ee:ff/cmd", `{"cmd":"restart"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("cmd enqueue: %d %s", rec.Code, rec.Body.String())
	}

	// 1. The armed task preempts the drift: §6.3 bytes, not setparam.
	resp := post(t, informH, encryptCBC(t, mustJSON(t, infoBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("armed inform: %d", resp.Code)
	}
	_, raw := decryptResponseRaw(t, resp.Body.Bytes(), kx)
	if !reCmdBytes.Match(raw) {
		t.Fatalf("armed task must preempt the pending drift: %q", raw)
	}

	// 2. The drift is deferred, not lost: the follow-up inform takes the
	// full provisioning path (fresh cfgversion + system_cfg together).
	resp = post(t, informH, encryptCBC(t, mustJSON(t, infoBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("post-cmd inform: %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] != "setparam" {
		t.Fatalf("deferred drift must full-provision on the next inform: %v", jm["_type"])
	}
	if _, ok := jm["system_cfg"]; !ok {
		t.Fatalf("deferred drift response not full provisioning: %v", jm)
	}
	if _, ok := jm["cfgversion"]; !ok {
		t.Fatalf("full provisioning missing top-level cfgversion: %v", jm)
	}
}

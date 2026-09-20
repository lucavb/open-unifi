package server

// Lifecycle transport tests (§6.5 reboot / §6.6 setdefault): the exact
// response BYTES at the adapter's serialization boundary
// (Server.applyOutcome is the single emission point the sealed envelope
// wraps), and the full admin→inform loops — admin POST arms the record
// over the real adminapi handler backed by the real App, the device's
// next sealed inform answers the lifecycle shape, the flag is consumed,
// and (factory reset) the post-reset default-key re-inform is re-adopted
// by the existing flow.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/app"
	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/server/adoption"
	"github.com/lucavb/open-unifi/internal/store"
)

// The §6.5/§6.6 response shapes as RAW BYTES. encoding/json sorts map
// keys, so these regexps pin the exact serialization the sealed
// envelope carries — including key order and the digit-only
// server_time_in_utc (§5 servlet injects it into every response as
// Long.toString of epoch ms).
var (
	reRebootBytes     = regexp.MustCompile(`^\{"_type":"reboot","reboot_type":"soft","server_time_in_utc":"[0-9]+"\}$`)
	reSetdefaultBytes = regexp.MustCompile(`^\{"_type":"setdefault","server_time_in_utc":"[0-9]+"\}$`)
)

// decryptResponseRaw is decryptResponse without the JSON decode: it
// returns the exact plaintext response bytes for byte-level shape pins.
func decryptResponseRaw(t *testing.T, respBody []byte, keyHex []byte) (uint16, []byte) {
	t.Helper()
	pkt, perr := inform.ParsePacket(respBody)
	if perr != nil {
		t.Fatalf("response framing: %v", perr)
	}
	if len(respBody) != inform.HeaderLen+len(pkt.Payload) {
		t.Fatalf("response payloadLen %d, body %d", len(pkt.Payload), len(respBody)-inform.HeaderLen)
	}
	flags := pkt.Flags
	if flags&(inform.FlagGCM|inform.FlagEncCBC) == 0 {
		t.Fatalf("response not encrypted: flags %04x", flags)
	}
	plain, derr := pkt.DecryptPayload(keyHex)
	if derr != nil {
		t.Fatalf("response decrypt failed: %v", derr)
	}
	return flags, plain
}

// lifecycleFixture wires the real admin API (adminapi handler over App)
// and the real inform handler over ONE store, and returns both handlers.
func lifecycleFixture(t *testing.T) (admin, informH http.Handler, st store.DeviceStore) {
	t.Helper()
	st = store.NewMemStore()
	a := app.New(st, filepath.Join(t.TempDir(), "wireless.json"), testLogger())
	return adminapi.New(adminapi.Config{}, a), New(Config{}, st, testLogger()).InformHandler(), st
}

// postAdmin issues an authenticated-free (token-less) admin API request.
func postAdmin(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestLifecycleResponseExactBytesAtSerializationBoundary pins the two
// response shapes at Server.applyOutcome — the single serialization point
// both transports seal. No record deltas ride these bare outcomes; the
// byte shape is the whole assertion.
func TestLifecycleResponseExactBytesAtSerializationBoundary(t *testing.T) {
	s := New(Config{}, store.NewMemStore(), testLogger())
	rec := &store.Device{MAC: testMAC, Extra: store.JSONMap{}}

	// §6.5: {"_type":"reboot","reboot_type":"soft","server_time_in_utc":"…"}
	b, err := json.Marshal(s.applyOutcome(testMAC, rec, adoption.Outcome{Kind: adoption.KindReboot}))
	if err != nil {
		t.Fatal(err)
	}
	if !reRebootBytes.Match(b) {
		t.Fatalf("§6.5 reboot bytes = %q", b)
	}

	// §6.6: {"_type":"setdefault","server_time_in_utc":"…"} — the bare
	// shape, no payload keys beyond the §5 universal timestamp.
	b, err = json.Marshal(s.applyOutcome(testMAC, rec, adoption.Outcome{Kind: adoption.KindSetdefault}))
	if err != nil {
		t.Fatal(err)
	}
	if !reSetdefaultBytes.Match(b) {
		t.Fatalf("§6.6 setdefault bytes = %q", b)
	}
}

// TestRebootLifecycleEndToEnd: admin POST /devices/{mac}/reboot arms the
// flag (record otherwise untouched — no §6.2 mint at arming); the
// device's next CBC-sealed inform answers the §6.5 shape byte-exact in
// the same key; the flag is consumed; the follow-up status inform is an
// ordinary noop again.
func TestRebootLifecycleEndToEnd(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xkey)
	kx := hexKey(t, xkey)

	// 1. admin arms the reboot; 200 carries the unchanged device view.
	rec := postAdmin(t, adminH, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/reboot")
	if rec.Code != http.StatusOK {
		t.Fatalf("reboot arm: %d %s", rec.Code, rec.Body.String())
	}
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := d.Extra["reboot_on_connect"]; !ok || v != true {
		t.Fatalf("reboot flag not armed after POST: %+v", d.Extra)
	}
	if d.State != store.StateAdopted || d.CfgVersion != cfg || d.XAuthkey != xkey || d.AppliedCfg != cfg {
		t.Fatalf("arming must not touch state/key/cfgversion: %+v", d)
	}

	// 2. the device's next sealed inform answers §6.5 — byte-exact.
	resp := post(t, informH, encryptCBC(t, mustJSON(t, infoBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("armed inform: %d", resp.Code)
	}
	_, raw := decryptResponseRaw(t, resp.Body.Bytes(), kx)
	if !reRebootBytes.Match(raw) {
		t.Fatalf("§6.5 response bytes = %q", raw)
	}
	var jm map[string]any
	if err := json.Unmarshal(raw, &jm); err != nil {
		t.Fatal(err)
	}
	if jm["_type"] != "reboot" || jm["reboot_type"] != "soft" {
		t.Fatalf("reboot response shape: %q", raw)
	}
	if srv, ok := jm["server_time_in_utc"].(string); !ok || srv == "0" {
		t.Fatalf("server_time_in_utc missing/empty: %q", raw)
	}

	// 3. one-shot: the flag is consumed; the record stands.
	d, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, armed := d.Extra["reboot_on_connect"]; armed {
		t.Fatalf("reboot flag survived emission: %+v", d.Extra)
	}
	if d.State != store.StateAdopted || d.CfgVersion != cfg || d.XAuthkey != xkey {
		t.Fatalf("record disturbed by reboot emission: %+v", d)
	}

	// 4. the follow-up status inform is an ordinary noop again.
	resp = post(t, informH, encryptCBC(t, mustJSON(t, infoBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("post-reboot inform: %d", resp.Code)
	}
	_, jm = decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] != "noop" {
		t.Fatalf("post-reboot inform response: %v", jm["_type"])
	}
}

// TestFactoryResetLifecycleEndToEnd: admin POST
// /devices/{mac}/factory-reset arms the flag; the next GCM-sealed inform
// answers the §6.6 shape byte-exact and the record lands in the
// pending-candidate shape (controller-owned WLAN bookkeeping cleared);
// the factory-reset device re-informs on the factory default key and is
// re-adopted by the existing flow (mgmt_cfg-only push with fresh key and
// cfgversion), whose post-key-rotation follow-up inform takes the ordinary
// full provisioning path.
func TestFactoryResetLifecycleEndToEnd(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xkey)
	// Stale controller-owned bookkeeping: the demotion must clear it, or
	// the re-adopted device would settle into connected noops against a
	// baseline its factory config never matched.
	if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
		if d.Extra == nil {
			d.Extra = store.JSONMap{}
		}
		d.Extra["wlan_cfg_sha"] = "stalebaseline"
		d.Extra["wlan_cfg_attempts"] = 3.0
		// Seed the site ssh password cache as well: absorption's
		// controller-owned restoration must carry it through the inform,
		// and the §6.6 sweep must SPARE the site-fact cache.
		d.Extra[store.SSHSha512PasswdKey] = "site-cache-sentinel"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	kx := hexKey(t, xkey)

	// 1. arm the factory reset.
	rec := postAdmin(t, adminH, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/factory-reset")
	if rec.Code != http.StatusOK {
		t.Fatalf("factory-reset arm: %d %s", rec.Code, rec.Body.String())
	}
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := d.Extra["setdefault_armed"]; !ok || v != true {
		t.Fatalf("setdefault flag not armed after POST: %+v", d.Extra)
	}

	// 2. GCM-sealed inform → §6.6 bytes; record demoted.
	resp := post(t, informH, encryptGCM(t, mustJSON(t, infoBody(cfg)), kx, bytes16(0x09)))
	if resp.Code != http.StatusOK {
		t.Fatalf("armed inform: %d", resp.Code)
	}
	flags, raw := decryptResponseRaw(t, resp.Body.Bytes(), kx)
	if flags&inform.FlagGCM == 0 {
		t.Fatalf("response not sealed in the request crypto lane: flags %04x", flags)
	}
	if !reSetdefaultBytes.Match(raw) {
		t.Fatalf("§6.6 response bytes = %q", raw)
	}
	d, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if d.State != store.StatePending || d.XAuthkey != "" || d.CfgVersion != "" ||
		d.AppliedCfg != "" || len(d.Authkeys) != 0 {
		t.Fatalf("record not in pending-candidate shape: %+v", d)
	}
	if _, armed := d.Extra["setdefault_armed"]; armed {
		t.Fatalf("setdefault flag survived emission: %+v", d.Extra)
	}
	for _, k := range store.FactoryResetSweepKeys {
		if _, ok := d.Extra[k]; ok {
			t.Fatalf("controller-owned %q survived the demotion: %+v", k, d.Extra)
		}
	}
	if got, want := d.Extra[store.SSHSha512PasswdKey], "site-cache-sentinel"; got != want {
		t.Fatalf("the §6.6 sweep must spare the site ssh password cache: %v, want %q", got, want)
	}

	// 3. factory-reset device re-informs on the factory default key →
	// existing adoption flow: mgmt_cfg-only push, fresh key + cfgversion.
	kd := hexKey(t, inform.DefaultKeyHex)
	resp = post(t, informH, encryptCBC(t, mustJSON(t, infoBody("")), kd, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("default-key re-inform: %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), kd)
	if jm["_type"] != "setparam" {
		t.Fatalf("re-adoption response: %v", jm["_type"])
	}
	exactKeys(t, jm, "_type", "server_time_in_utc", "mgmt_cfg")
	mgmt, _ := jm["mgmt_cfg"].(string)
	if !strings.Contains(mgmt, "authkey=") {
		t.Fatalf("re-adoption mgmt_cfg missing authkey rotation: %q", mgmt)
	}
	d, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if d.State != store.StateAdopting {
		t.Fatalf("re-adoption state: %+v", d)
	}
	if d.XAuthkey == "" || d.XAuthkey == xkey || !isHex(d.XAuthkey) || len(d.XAuthkey) != 32 {
		t.Fatalf("re-adoption key not fresh 32-hex: %q", d.XAuthkey)
	}
	if !containsKey(d.Authkeys, d.XAuthkey) {
		t.Fatalf("fresh key not in authkeys: %v", d.Authkeys)
	}
	if !isHex(d.CfgVersion) || len(d.CfgVersion) != 16 || d.CfgVersion == cfg {
		t.Fatalf("re-adoption cfgversion not fresh 16-hex: %q", d.CfgVersion)
	}

	// 4. the post-key-rotation follow-up inform continues the ordinary
	// adoption flow: §6.2 d full provisioning (cfgversion + system_cfg
	// together).
	kNew := hexKey(t, d.XAuthkey)
	resp = post(t, informH, encryptCBC(t, mustJSON(t, infoBody("")), kNew, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("post-key-rotation inform: %d", resp.Code)
	}
	_, jm = decryptResponse(t, resp.Body.Bytes(), kNew)
	if jm["_type"] != "setparam" {
		t.Fatalf("post-key-rotation inform response: %v", jm["_type"])
	}
	if _, ok := jm["system_cfg"]; !ok {
		t.Fatalf("post-key-rotation inform not full provisioning: %v", jm)
	}
	if _, ok := jm["cfgversion"]; !ok {
		t.Fatalf("full provisioning missing top-level cfgversion: %v", jm)
	}
}

// TestArmedFlagsSurviveDeviceInformBodies pins the trust-policy side of
// the arming flags: an inform body that tries to introduce, forge or
// clear them changes nothing — the flags are admin-owned rows, and the
// admin-owned absorb wins over any device payload.
func TestArmedFlagsSurviveDeviceInformBodies(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xkey)
	kx := hexKey(t, xkey)

	rec := postAdmin(t, adminH, http.MethodPost, "/api/v1/devices/aa:bb:cc:dd:ee:ff/reboot")
	if rec.Code != http.StatusOK {
		t.Fatalf("reboot arm: %d", rec.Code)
	}

	// A device inform that carries a forged flag value and a forged
	// setdefault arming: both must be discarded (admin-owned rows).
	body := infoBody(cfg)
	body["reboot_on_connect"] = false // attempt to clear the armed command
	body["setdefault_armed"] = true   // attempt to arm factory reset
	resp := post(t, informH, encryptCBC(t, mustJSON(t, body), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("hostile inform: %d", resp.Code)
	}
	_, raw := decryptResponseRaw(t, resp.Body.Bytes(), kx)
	if !reRebootBytes.Match(raw) {
		t.Fatalf("armed reboot must still fire despite the forged body: %q", raw)
	}
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, armed := d.Extra["setdefault_armed"]; armed {
		t.Fatalf("device body introduced a setdefault arming: %+v", d.Extra)
	}
	if _, armed := d.Extra["reboot_on_connect"]; armed {
		t.Fatalf("reboot flag not consumed (or reintroduced): %+v", d.Extra)
	}

	// And a plain armed flag CANNOT be smuggled in by a device inform on
	// its own: the same body shape without any admin arming never fires.
	hostile := infoBody(cfg)
	hostile["reboot_on_connect"] = true
	resp = post(t, informH, encryptCBC(t, mustJSON(t, hostile), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("smuggled-arm inform: %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] == "reboot" {
		t.Fatalf("device-smuggled reboot arming fired: %v", jm["_type"])
	}
	d, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, armed := d.Extra["reboot_on_connect"]; armed {
		t.Fatalf("device-smuggled flag persisted: %+v", d.Extra)
	}
}

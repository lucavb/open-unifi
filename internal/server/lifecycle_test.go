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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/app"
	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/server/adoption"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
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
	return lifecycleFixtureWLANS(t, nil)
}

func lifecycleFixtureWLANS(t *testing.T, wlans []Wlan) (admin, informH http.Handler, st store.DeviceStore) {
	t.Helper()
	st = store.NewMemStore()
	a := app.New(st, testLogger())
	cfg := Config{}
	if wlans != nil {
		cfg.WirelessForDevice = func(_ store.Device) []Wlan { return wlans }
	}
	return adminapi.New(adminapi.Config{}, a), New(cfg, st, testLogger()).InformHandler(), st
}

// postAdmin issues an authenticated-free (token-less) admin API request.
// (postAdminBody — the method+path+JSON-body variant — is shared with
// cmdtask_test.go.)
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
		// Seed the per-device ssh password cache as well: absorption's
		// prev-or-delete restoration carries it through the inform, and
		// the §6.6 sweep deliberately spares it (it holds the DEVICE's
		// last controller-pushed password and survives the demotion).
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
		t.Fatalf("the §6.6 sweep must spare the per-device ssh password cache: %v, want %q", got, want)
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

// ---- site-settings E2E: save → mint → inform → setparam --------------------
//
// These four tests close the DONE-WHEN loop of the site-settings lane: an
// admin save through the REAL admin handler lands in the app record, the
// save's mint sweep re-stamps the device's cfgversion, and the device's
// next inform delivers (or is gated on) the new sshd facts.

// Synthetic authorized_keys lines (the systemcfg tests' marker'd RFC 4253
// blobs — never real keys). keyEd25519/k2 carry different shapes: family 1
// and 3 have comments, family 2 has none (pins the comment-only-when-
// non-empty emission).
const (
	ssKeyLine1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB test@ap"
	ssKeyLine2 = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
	ssKeyLine3 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRoaXJka2V5QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC third@ap"
)

func patchDeviceSSHIntent(t *testing.T, adminH http.Handler, mac string, country int, keys []string) {
	t.Helper()
	body := map[string]any{
		"regulatory_country_code": country,
		"ssh_public_keys":         keys,
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	rec := postAdminBody(t, adminH, http.MethodPatch, "/api/v1/devices/"+mac, string(b))
	if rec.Code != http.StatusOK {
		t.Fatalf("device SSH intent PATCH: %d %s", rec.Code, rec.Body.String())
	}
}

// gateInformBody is an info body whose reported version trips the U7PG2
// 6.8.2.15592 gate lane.
func gateInformBody(appliedCfg string) map[string]any {
	body := infoBody(appliedCfg)
	body["version"] = "6.8.2.15592"
	return body
}

// TestSiteSettingsSaveDeliversSSHDRowsFullProvisioningE2E: save → mint →
// inform answers full provisioning whose
// system_cfg carries the saved sshd facts — exactly 3 numbered
// sshd.auth.key families (1..3: status/value/type, comment only when
// non-empty, NO .0 or .4 rows), the always-enabled sshd.auth.passwd row,
// and the full mgmt_cfg/blocked_sta shape.
func TestDeviceSSHKeysSaveDeliversSSHDRowsFullProvisioningE2E(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xk = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xk)
	kx := hexKey(t, xk)

	patchDeviceSSHIntent(t, adminH, store.ColonMAC(testMAC), 840, []string{ssKeyLine1, ssKeyLine2, ssKeyLine3})
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	minted := d.CfgVersion
	if minted == cfg || !isHex(minted) || len(minted) != 16 {
		t.Fatalf("save sweep minted %q, want a fresh 16-hex != %q", minted, cfg)
	}

	resp := post(t, informH, encryptCBC(t, mustJSON(t, gateInformBody("")), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform: %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), kx)
	// Full provisioning shape: all four config keys (the exact set the
	// drift tests pin) and the record's minted cfgversion at the top
	// level — the record IS the source of the pushed version.
	exactKeys(t, jm, "_type", "server_time_in_utc", "cfgversion", "system_cfg", "blocked_sta", "mgmt_cfg")
	if jm["cfgversion"] != minted {
		t.Fatalf("full provisioning cfgversion %v, want the minted %q", jm["cfgversion"], minted)
	}
	sys, _ := jm["system_cfg"].(string)
	for _, want := range []string{
		// Exactly three numbered families, in slice order.
		"sshd.auth.key.1.status=enabled\n",
		"sshd.auth.key.1.value=AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n",
		"sshd.auth.key.1.type=ssh-ed25519\n",
		"sshd.auth.key.1.comment=test@ap\n",
		"sshd.auth.key.2.status=enabled\n",
		"sshd.auth.key.2.value=AAAAB3NzaC1yc2EAAAADAQABAAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n",
		"sshd.auth.key.2.type=ssh-rsa\n",
		"sshd.auth.key.3.status=enabled\n",
		"sshd.auth.key.3.value=AAAAC3NzaC1lZDI1NTE5AAAAIHRoaXJka2V5QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJC\n",
		"sshd.auth.key.3.type=ssh-ed25519\n",
		"sshd.auth.key.3.comment=third@ap\n",
		"sshd.auth.passwd=enabled\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("full provisioning system_cfg missing %q:\n%s", want, sys)
		}
	}
	// Comment row ONLY when non-empty: family 2 carries none.
	if strings.Contains(sys, "sshd.auth.key.2.comment") {
		t.Fatalf("key family 2 has no comment in the record — no comment row may render:\n%s", sys)
	}
	// NO .0 or .4 rows: exactly n families.
	if strings.Contains(sys, "sshd.auth.key.0.") || strings.Contains(sys, "sshd.auth.key.4.") {
		t.Fatalf("unexpected zero- or fourth-index sshd rows:\n%s", sys)
	}
}

// TestSiteSettingsSaveUngatedForeignModelDeliversE2E: a site-settings save on
// a non-U7PG2 device reaches full provisioning and carries the new sshd rows.
func TestDeviceSSHKeysSaveUngatedForeignModelDeliversE2E(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xk = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xk)
	kx := hexKey(t, xk)

	patchDeviceSSHIntent(t, adminH, store.ColonMAC(testMAC), 276, []string{ssKeyLine1})
	body := infoBody("")
	body["model"] = "UAP-AC-Pro" // NOT the gated model
	resp := post(t, informH, encryptCBC(t, mustJSON(t, body), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform: %d %s", resp.Code, resp.Body.String())
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] != "setparam" || jm["system_cfg"] == nil {
		t.Fatalf("ungated device must full-provision, got %v", jm["_type"])
	}
	sys, _ := jm["system_cfg"].(string)
	for _, want := range []string{
		"sshd.auth.key.1.status=enabled\n",
		"sshd.auth.key.1.value=AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\n",
		"sshd.auth.key.1.type=ssh-ed25519\n",
		"sshd.auth.passwd=enabled\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("ungated full provisioning missing %q:\n%s", want, sys)
		}
	}
}

// TestSiteSettingsSaveEscapesExhaustedWLANDeliveryE2E: the settings save is
// an operator mint, and the pending-delivery gate must not hold it hostage.
// The device is seeded into the mid-WLAN-pending delivery state
// (wlan_cfg_pending_sha + wlan_cfg_offered_cfgversion + an EXHAUSTED retry
// budget — the end state TestOperatorMintEscapesExhaustedDeliveryGate and
// TestEnvelopeDriftDeliveryIsBounded's budget arithmetic reach): its next
// inform would answer noop-pending-wlan. Then the settings save mints a
// fresh cfgversion (M2 ≠ the offered one), and the SAME inform yields ONE
// full provisioning carrying BOTH the pending envelope (the E2 SSID row)
// AND the new sshd facts — not the hold.
func TestDeviceSSHKeysSaveEscapesExhaustedWLANDeliveryE2E(t *testing.T) {
	e1 := []Wlan{{Name: "old", SSID: "oldnet", Security: "open", Enabled: true}}
	e2 := []Wlan{{Name: "pending", SSID: "pendingnet", Security: "open", Enabled: true}}
	adminH, informH, st := lifecycleFixtureWLANS(t, e2)
	const cfg = "aaaabbbbccccdddd"
	const xk = "11112222333344445555666677778888"
	// u7pg2Record() (radio_table present — the aaa.* wireless rows need it
	// to render) shaped as an adopted device echoing its applied cfg.
	rec := u7pg2Record()
	rec.XAuthkey, rec.Authkeys = xk, []string{xk}
	rec.CfgVersion, rec.AppliedCfg = cfg, cfg
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	kx := hexKey(t, xk)

	// Seed the mid-pending state the drift-armed fixtures reach: baseline
	// hash = E1, pending = E2, exhausted budget, offered cfgversion = the
	// applied cfg the device echoes.
	snap1, err := json.Marshal(e1)
	if err != nil {
		t.Fatal(err)
	}
	snap2, err := json.Marshal(e2)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
		if d.Extra == nil {
			d.Extra = store.JSONMap{}
		}
		// Baseline hash = E1 (NOT the current envelope E2), pending hash =
		// E2 with the offered cfgversion stamped, retry budget EXHAUSTED:
		// the exhausted gate would hold the unchanged envelope delivery.
		d.Extra["wlan_cfg_sha"] = wireless.WlanListHash(e1)
		d.Extra["wlan_cfg_applied_wlans"] = string(snap1)
		d.Extra["wlan_cfg_pending_sha"] = wireless.WlanListHash(e2)
		d.Extra["wlan_cfg_pending_wlans"] = string(snap2)
		d.Extra["wlan_cfg_pending_old_wlans"] = string(snap1)
		d.Extra["wlan_cfg_attempt_sha"] = wireless.WlanListHash(e2)
		d.Extra["wlan_cfg_attempts"] = adoption.WlanMaxAttempts
		d.Extra["wlan_cfg_last_attempt"] = time.Now().Unix()
		d.Extra["wlan_cfg_offered_cfgversion"] = cfg
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Pre-save: the exhausted gate HOLDS — noop-pending-wlan (the same
	// shape TestOperatorMintEscapesExhaustedDeliveryGate pins engine-side).
	resp := post(t, informH, encryptCBC(t, mustJSON(t, infoBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("held inform: %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] != "noop" {
		t.Fatalf("exhausted pending delivery must hold at the gate, got %v", jm["_type"])
	}

	// 2. The settings save: an effective change → the mint sweep stamps a
	// fresh cfgversion on the provisioned device (M2 ≠ the offered one).
	patchDeviceSSHIntent(t, adminH, store.ColonMAC(testMAC), 840, []string{ssKeyLine1})
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	minted := d.CfgVersion
	if minted == cfg || !isHex(minted) || len(minted) != 16 {
		t.Fatalf("save sweep minted %q, want a fresh 16-hex != %q", minted, cfg)
	}

	// 3. The SAME inform now yields ONE full provisioning carrying BOTH the
	// pending envelope AND the new sshd facts (the operatorMint escape —
	// NOT the noop-pending-wlan hold).
	resp = post(t, informH, encryptCBC(t, mustJSON(t, infoBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("escaped inform: %d", resp.Code)
	}
	_, jm = decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] != "setparam" || jm["system_cfg"] == nil || jm["cfgversion"] == nil {
		t.Fatalf("post-save inform = %v, want ONE full provisioning (the operator-mint escape)", jm)
	}
	if jm["cfgversion"] != minted {
		t.Fatalf("escape offer cfgversion %v, want the minted %q", jm["cfgversion"], minted)
	}
	sys, _ := jm["system_cfg"].(string)
	for _, want := range []string{
		"aaa.1.ssid=pendingnet\n",          // the pending envelope rode the same push
		"sshd.auth.key.1.status=enabled\n", // the new sshd facts rode the same push
		"sshd.auth.passwd=enabled\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("escape offer missing %q:\n%s", want, sys)
		}
	}
}

// ---- per-device SSH password E2E -------------------------------------------
//
// The per-device SSH password rides the device record's typed field
// (PATCH /api/v1/devices/{mac}, admin intent); the site-settings record
// carries no password anymore. These three devices pins ride the REAL
// admin→inform loop over ONE store (the established
// TestRadioIntentRidesFullProvisioning pattern) on the established
// pattern fixtures — and only legitimately, because the session runtime
// is a fixture factory.

// sshPasswordFixture is lifecycleFixture with an EMPTY WLAN envelope: no
// sshd key rows, so password-only provisioning rides the ordinary full-
// provisioning arc (password changes are UNGATED — the §13 gate reads
// key rows only).
func sshPasswordFixture(t *testing.T) (admin, informH http.Handler, st store.DeviceStore) {
	return lifecycleFixture(t)
}

// patchDevicePassword saves the per-device SSH password through the real
// admin handler. pw-nil semantics live in the wire body: a present=false
// call omits the key (nil = untouched); a present=true call sends the
// value verbatim ("" = the explicit clear = stop managing).
func patchDevicePassword(t *testing.T, adminH http.Handler, mac, pw string, present bool) {
	t.Helper()
	var body string
	if present {
		b, err := json.Marshal(map[string]any{"ssh_password": pw})
		if err != nil {
			panic(err)
		}
		body = string(b)
	} else {
		body = "{}"
	}
	rec := postAdminBody(t, adminH, http.MethodPatch, "/api/v1/devices/"+mac, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("device password PATCH (present=%v): %d %s", present, rec.Code, rec.Body.String())
	}
	var dv map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &dv); err != nil {
		t.Fatal(err)
	}
	// DeviceView.SSHPassword carries omitempty (locked design: unmanaged
	// devices read clean; "" = unmanaged): the clear echo omits the key
	// entirely, a set value echoes verbatim.
	if present {
		if pw == "" {
			if v, echoed := dv["ssh_password"]; echoed {
				t.Fatalf("PATCH view echo: %v, want the key ABSENT (omitempty: \"\" = unmanaged)", v)
			}
		} else if dv["ssh_password"] != pw {
			t.Fatalf("PATCH view echo: %v, want %q", dv["ssh_password"], pw)
		}
	}
}

// provisionInform drives ONE echo-mismatch inform (the device still echoes
// an applied version the record's desired stamp does not match) and
// returns the full-provisioning response map plus its system_cfg blob. A
// response that is not one full provisioning fails the test.
func provisionInform(t *testing.T, informH http.Handler, kx []byte) (map[string]any, string) {
	t.Helper()
	resp := post(t, informH, encryptCBC(t, mustJSON(t, infoBody("zzzz-drift")), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform: %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] != "setparam" || jm["system_cfg"] == nil || jm["cfgversion"] == nil {
		t.Fatalf("want ONE full provisioning, got %v", jm["_type"])
	}
	return jm, jm["system_cfg"].(string)
}

// noopInform drives one echo-matching inform and requires the ordinary noop.
func noopInform(t *testing.T, informH http.Handler, echo string, kx []byte) {
	t.Helper()
	resp := post(t, informH, encryptCBC(t, mustJSON(t, infoBody(echo)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform: %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), kx)
	if jm["_type"] != "noop" {
		t.Fatalf("settled inform must noop, got %v (%v)", jm["_type"], jm)
	}
}

// sshCacheBytes marshals the record's credential-cache rows (the bytes the
// adapter must not re-touch on an unset render) and returns the sha512 row
// for row-level comparisons. NOT the whole Extra map: a provisioning pass
// legitimately rewrites other Extra rows (record absorption folds the
// device's echo; the wlan_cfg_* delivery bookkeeping advances), which would
// false-fail the untouched-cache pins.
func sshCacheBytes(t *testing.T, st store.DeviceStore, mac string) (string, string) {
	t.Helper()
	d, err := st.Get(mac)
	if err != nil {
		t.Fatal(err)
	}
	caches := map[string]any{
		store.SSHSha512PasswdKey: d.Extra[store.SSHSha512PasswdKey],
		store.SSHMd5PasswdKey:    d.Extra[store.SSHMd5PasswdKey],
	}
	b, err := json.Marshal(caches)
	if err != nil {
		t.Fatal(err)
	}
	row, _ := d.Extra[store.SSHSha512PasswdKey].(string)
	return string(b), row
}

// seedAdoptedRecord seeds the canonical adopted-device record (u7pg2Record
// + per-device key credentials) and returns it.
func seedAdoptedRecord(t *testing.T, st store.DeviceStore, xk string) store.Device {
	t.Helper()
	rec := u7pg2Record()
	rec.XAuthkey, rec.Authkeys = xk, []string{xk}
	rec.CfgVersion, rec.AppliedCfg = "aaaa", "aaaa"
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	return stRec(t, st)
}

// stRec fetches the record (helper for the cache dances below).
func stRec(t *testing.T, st store.DeviceStore) store.Device {
	t.Helper()
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestSSHPasswordUnsetPreservesCacheE2E — the locked UNSET contract ("stop
// managing"): an adopted device with a populated cache row and an emptied
// record password keeps its row BYTE-IDENTICALLY on the unset full
// provisioning, and no credential delta lands (the device's actual SSH
// password never changes when the admin clears the knob).
func TestSSHPasswordUnsetPreservesCacheE2E(t *testing.T) {
	adminH, informH, st := sshPasswordFixture(t)
	const xk = "11112222333344445555666677778888"
	kx := hexKey(t, xk)

	// Provision once under a set password: the cache row becomes the
	// controller-pushed hash of "oldpw" (a REAL hash, applied by the
	// adapter's credential-delta path).
	rec := seedAdoptedRecord(t, st, xk)
	rec.SSHPassword = "oldpw"
	rec.CfgVersion, rec.AppliedCfg = "aaaa", "aaaa"
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	_, sys := provisionInform(t, informH, kx)
	rowOld := users1PasswordRow(t, sys)
	if !strings.HasPrefix(rowOld, "users.1.password=$6$") {
		t.Fatalf("first provisioning row shape: %q", rowOld)
	}
	if d := stRec(t, st); d.Extra[store.SSHSha512PasswdKey] != rowOld[len("users.1.password="):] {
		t.Fatalf("credential delta not applied to the record cache: %v vs %q",
			d.Extra[store.SSHSha512PasswdKey], rowOld[len("users.1.password="):])
	}

	// The admin clears the knob: "" ≠ "oldpw" → effective → mints.
	patchDevicePassword(t, adminH, testMAC, "", true)
	d := stRec(t, st)
	minted := d.CfgVersion
	if d.SSHPassword != "" || minted == "aaaa" || !isHex(minted) || len(minted) != 16 {
		t.Fatalf("clear save: ssh_password %q cfgversion %q — mint missing", d.SSHPassword, minted)
	}
	before, _ := sshCacheBytes(t, st, testMAC)

	// The unset full provisioning reuses the last controller-pushed row
	// verbatim and minted NO fresh delta (the record cache is untouched).
	_, sys = provisionInform(t, informH, kx)
	if row2 := users1PasswordRow(t, sys); row2 != rowOld {
		t.Fatalf("unset provisioning must reuse the cached row verbatim:\n%s\nwant\n%s", row2, rowOld)
	}
	after, _ := sshCacheBytes(t, st, testMAC)
	if before != after {
		t.Fatalf("unset reuse applied a credential delta (cache changed):\nbefore %s\nafter  %s", before, after)
	}
	if d := stRec(t, st); d.SSHPassword != "" {
		t.Fatalf("record password disturbed: %+v", d.SSHPassword)
	}
}

// TestSSHPasswordSetApplyClearE2E — the full set→apply→clear arc:
//
//	set "newpw"     → mint m1 → provisioning row_new ≠ row_old (no cache
//	                    under unset: the fresh hash of newpw)
//	inform echo m1  → noop (the credential delta applied; byte-stable)
//	clear ""        → mint m2 → provisioning reuses the set-password
//	                    cache row verbatim (the device KEEPS newpw; the
//	                    clear STOPS MANAGING — it never resets to ubnt)
//	inform echo m2  → noop
func TestSSHPasswordSetApplyClearE2E(t *testing.T) {
	adminH, informH, st := sshPasswordFixture(t)
	const xk = "11112222333344445555666677778888"
	kx := hexKey(t, xk)

	seedAdoptedRecord(t, st, xk)

	// 1. SET via the real admin intent → mint; provisioning carries a
	// fresh $6$ row different from the (unseated) unset render.
	patchDevicePassword(t, adminH, testMAC, "newpw", true)
	d := stRec(t, st)
	m1 := d.CfgVersion
	if d.SSHPassword != "newpw" || m1 == "aaaa" || !isHex(m1) || len(m1) != 16 {
		t.Fatalf("set save: ssh_password %q cfgversion %q — mint missing", d.SSHPassword, m1)
	}
	jm, sys := provisionInform(t, informH, kx)
	if jm["cfgversion"] != m1 {
		t.Fatalf("provisioning cfgversion %v, want the minted %q", jm["cfgversion"], m1)
	}
	rowNew := users1PasswordRow(t, sys)
	d = stRec(t, st)
	if got := d.Extra[store.SSHSha512PasswdKey]; got != rowNew[len("users.1.password="):] {
		t.Fatalf("set-path cache not the fresh hash: %v vs %q", got, rowNew)
	}

	// 2. the applied device now runs newpw, echoing m1 → noop (byte-stable
	// converged state).
	noopInform(t, informH, m1, kx)

	// 3. CLEAR via the real admin intent → mint m2; the next provisioning
	// reuses the set-password cache verbatim.
	patchDevicePassword(t, adminH, testMAC, "", true)
	d = stRec(t, st)
	m2 := d.CfgVersion
	if d.SSHPassword != "" || m2 == m1 || !isHex(m2) {
		t.Fatalf("clear save: ssh_password %q cfgversion %q", d.SSHPassword, m2)
	}
	before, cached := sshCacheBytes(t, st, testMAC)
	_, sys = provisionInform(t, informH, kx)
	if row3 := users1PasswordRow(t, sys); row3 != "users.1.password="+cached {
		t.Fatalf("clear-provisioning must reuse the set-password row verbatim:\n%s\nwant\n%s", row3, "users.1.password="+cached)
	}
	if after, cached2 := sshCacheBytes(t, st, testMAC); after != before || cached2 != cached {
		t.Fatalf("clear-path reuse must not re-touch the cache:\nbefore %s\nafter  %s", before, after)
	}

	// 4. converged noop on the post-clear applied stamp.
	noopInform(t, informH, m2, kx)
}

// TestSSHPasswordMigrationShapeE2E — DEPLOYED-RECORD shape: a device whose
// record carries a well-formed $6$ cache row and no password ANYONE can
// name anymore (the pre-per-device site-password era: only the cache row
// survived into the record). The locked contract — and this pin exists
// because a future passer-by will be tempted to "helpfully fix" the
// renderer's unset branch into a fresh reset: the row the cache holds is
// deliberately reused verbatim, across provisioning after provisioning and
// through settled noops, so the AP keeps its password. It is the CONTRACT,
// not an accident.
func TestSSHPasswordMigrationShapeE2E(t *testing.T) {
	_, informH, st := sshPasswordFixture(t)
	const xk = "11112222333344445555666677778888"
	kx := hexKey(t, xk)

	rec := seedAdoptedRecord(t, st, xk)
	// A well-formed $6$ row (sha512CacheFormatRx shape: "$6$" + 8 salt
	// chars + "$" + 86 hash chars) whose source PASSWORD is unknowable —
	// exactly the migration-era record shape.
	const mysteryRow = "users.1.password=$6$0Vt2Ue1V$cZ7N8BjYvOhq2jbFLYMyiJC8t1j3QroXfPzolNy0KhHypWV4OQqLPTerxeYg4LjtLpHzdXH2QCxaOmB2Pup0cz"
	rec.Extra[store.SSHSha512PasswdKey] = mysteryRow[len("users.1.password="):]
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}

	// Provisioning #1: the mystery row ships verbatim; the cache is
	// untouched (no delta, the controller never re-hashes it).
	_, sys := provisionInform(t, informH, kx)
	if row := users1PasswordRow(t, sys); row != mysteryRow {
		t.Fatalf("migration-shape provisioning must ship the unknowable-password row verbatim:\n%s\nwant\n%s", row, mysteryRow)
	}
	d := stRec(t, st)
	if got := d.Extra[store.SSHSha512PasswdKey]; got != mysteryRow[len("users.1.password="):] {
		t.Fatalf("migration cache re-touched: %v, want verbatim survival", got)
	}

	// Force a SECOND provisioning (hand-mint the record like an operator
	// device-save): the mystery row must STILL ship verbatim.
	if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
		d.CfgVersion = "bbbb1111cccc4444"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, sys = provisionInform(t, informH, kx)
	if row := users1PasswordRow(t, sys); row != mysteryRow {
		t.Fatalf("migration cache must survive a second provisioning verbatim:\n%s\nwant\n%s", row, mysteryRow)
	}

	// And the settled device noops on the applied stamp — the mystery row
	// keeps riding every render-only path (no renders happen on a noop,
	// which is the byte-stability device the contract names).
	noopInform(t, informH, "bbbb1111cccc4444", kx)
}

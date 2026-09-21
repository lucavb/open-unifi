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
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/app"
	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/server/adoption"
	"github.com/lucavb/open-unifi/internal/server/systemcfg"
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
	return siteSettingsFixture(t, app.SiteSettings{}, nil, false)
}

// siteSettingsFixture is lifecycleFixture with a seeded site-settings
// record, the app→server settings source wired exactly like
// cmd/openunifi (the single raw-lines→parsed-keys seam), an optional WLAN
// envelope for the WirelessSource, and the live-provisioning gate opt-in.
func siteSettingsFixture(t *testing.T, seed app.SiteSettings, wlans []Wlan, gatedLiveWLAN bool) (admin, informH http.Handler, st store.DeviceStore) {
	t.Helper()
	st = store.NewMemStore()
	a := app.New(st, filepath.Join(t.TempDir(), "wireless.json"), filepath.Join(t.TempDir(), "site-settings.json"), seed, testLogger())
	cfg := Config{AllowGatedLiveWLAN: gatedLiveWLAN, SiteSettings: appSettingsSource(a)}
	if wlans != nil {
		cfg.WirelessSource = func() []Wlan { return wlans }
	}
	return adminapi.New(adminapi.Config{}, a), New(cfg, st, testLogger()).InformHandler(), st
}

// appSettingsSource is the adapter seam cmd/openunifi uses: the app
// record's RAW authorized_keys lines are parsed into the server's fact
// shape at this single conversion point (the fail-closed single parser;
// a record line that never reached the parser would be a trust-policy
// breach, not something the server re-validates away). The closure reads
// the record LIVE per call, so a site-settings save is visible on the
// device's next inform. On a load error the error propagates (render
// fails before any record mutation); the engine gate reads zero facts
// and stays inert.
func appSettingsSource(a *app.App) func() (SiteSettings, error) {
	return func() (SiteSettings, error) {
		rec, err := a.CurrentSiteSettings()
		if err != nil {
			return SiteSettings{}, err
		}
		keys := make([]systemcfg.PublicKey, 0, len(rec.SSHPublicKeys))
		for i, line := range rec.SSHPublicKeys {
			k, perr := systemcfg.ParsePublicKey(line)
			if perr != nil {
				return SiteSettings{}, fmt.Errorf("invalid AP SSH public key #%d: %w", i+1, perr)
			}
			keys = append(keys, k)
		}
		return SiteSettings{
			CountryCode:        rec.CountryCode,
			SSHPassword:        rec.SSHPassword,
			SSHPublicKeys:      keys,
			SSHDisablePassword: rec.SSHDisablePassword,
		}, nil
	}
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

// siteSettingsPutBodyJSON renders a whole-document PUT body.
func siteSettingsPutBodyJSON(country int, password string, keys []string, disable bool) string {
	keyJSON := make([]string, 0, len(keys))
	for _, k := range keys {
		b, err := json.Marshal(k)
		if err != nil {
			panic(err)
		}
		keyJSON = append(keyJSON, string(b))
	}
	return fmt.Sprintf(`{"regulatory_country_code":%d,"ap_ssh_password":%q,"ap_ssh_public_keys":[%s],"ap_ssh_disable_password":%t}`,
		country, password, strings.Join(keyJSON, ","), disable)
}

// putSiteSettings saves the document through the real admin handler.
func putSiteSettings(t *testing.T, adminH http.Handler, country int, password string, keys []string, disable bool) {
	t.Helper()
	rec := postAdminBody(t, adminH, http.MethodPut, "/api/v1/site-settings",
		siteSettingsPutBodyJSON(country, password, keys, disable))
	if rec.Code != http.StatusOK {
		t.Fatalf("site settings PUT: %d %s", rec.Code, rec.Body.String())
	}
}

// gateInformBody is an info body whose reported version trips the U7PG2
// 6.8.2.15592 gate lane.
func gateInformBody(appliedCfg string) map[string]any {
	body := infoBody(appliedCfg)
	body["version"] = "6.8.2.15592"
	return body
}

// TestSiteSettingsSaveGatedByLiveGate501E2E: on an adopted U7PG2 /
// 6.8.2.15592 device with an EMPTY WLAN envelope, a site-settings save
// carrying keys + disable is minted by the save sweep, but the device's
// next inform answers the TYPED 501 (the live-provisioning gate reads the
// saved facts at gate time — no opt-in). The record is untouched by the
// rejected emission: the store cycle aborted (the save's mint stands, the
// inform persisted nothing — no credential cache, no WLAN bookkeeping).
func TestSiteSettingsSaveGatedByLiveGate501E2E(t *testing.T) {
	adminH, informH, st := siteSettingsFixture(t, app.SiteSettings{}, nil, false)
	const cfg = "aaaabbbbccccdddd"
	const xk = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xk)
	kx := hexKey(t, xk)

	// 1. Admin saves 2 keys + password-disable through the real handler.
	putSiteSettings(t, adminH, 840, "", []string{ssKeyLine1, ssKeyLine2}, true)

	// 2. The save's mint sweep re-stamped the provisioned device.
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	minted := d.CfgVersion
	if minted == cfg || !isHex(minted) || len(minted) != 16 {
		t.Fatalf("save sweep minted %q, want a fresh 16-hex != %q", minted, cfg)
	}

	// 3. The device informs → the typed 501 (no opt-in, ssh facts alone).
	resp := post(t, informH, encryptCBC(t, mustJSON(t, gateInformBody("")), kx, testIV))
	if resp.Code != http.StatusNotImplemented {
		t.Fatalf("gated inform status = %d, want 501 (body %q)", resp.Code, resp.Body.String())
	}

	// 4. The record is untouched by the rejected emission: the save's mint
	// stands, and the rejected inform persisted nothing.
	d, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if d.State != store.StateAdopted || d.CfgVersion != minted || d.AppliedCfg != cfg {
		t.Fatalf("gate must not mutate the record: %+v", d)
	}
	for _, k := range []string{"ssh_sha512passwd", "ssh_md5passwd", "wlan_cfg_pending_sha", "wlan_cfg_offered_cfgversion"} {
		if _, present := d.Extra[k]; present {
			t.Fatalf("rejected inform must persist no %q (Extra: %+v)", k, d.Extra)
		}
	}
}

// TestSiteSettingsSaveDeliversSSHDRowsFullProvisioningE2E: with the gate
// opt-in, the SAME save → mint → inform arc answers full provisioning whose
// system_cfg carries the saved sshd facts — exactly 3 numbered
// sshd.auth.key families (1..3: status/value/type, comment only when
// non-empty, NO .0 or .4 rows), sshd.auth.passwd=disabled, the 840 country
// coercion, and the full mgmt_cfg/blocked_sta shape.
func TestSiteSettingsSaveDeliversSSHDRowsFullProvisioningE2E(t *testing.T) {
	adminH, informH, st := siteSettingsFixture(t, app.SiteSettings{}, nil, true)
	const cfg = "aaaabbbbccccdddd"
	const xk = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xk)
	kx := hexKey(t, xk)

	putSiteSettings(t, adminH, 840, "", []string{ssKeyLine1, ssKeyLine2, ssKeyLine3}, true)
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
		// The disable knob (radio country rows need a radio_table this bare
		// record has none of — the country coercion is pinned at the wired
		// seam in server_test.go).
		"sshd.auth.passwd=disabled\n",
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

// TestSiteSettingsSaveUngatedForeignModelDeliversE2E: the gate is scoped to
// the EXACT U7PG2 / 6.8.2.15592 lane — the same save on a non-U7PG2 device
// reaches full provisioning WITHOUT the opt-in and carries the new sshd
// rows (the save's mint sweep is model-agnostic; the gate is the only
// per-model check).
func TestSiteSettingsSaveUngatedForeignModelDeliversE2E(t *testing.T) {
	adminH, informH, st := siteSettingsFixture(t, app.SiteSettings{}, nil, false)
	const cfg = "aaaabbbbccccdddd"
	const xk = "11112222333344445555666677778888"
	registerAdopted(t, st, cfg, xk)
	kx := hexKey(t, xk)

	putSiteSettings(t, adminH, 276, "", []string{ssKeyLine1}, true)
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
		"sshd.auth.passwd=disabled\n",
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
func TestSiteSettingsSaveEscapesExhaustedWLANDeliveryE2E(t *testing.T) {
	e1 := []Wlan{{Name: "old", SSID: "oldnet", Security: "open", Enabled: true}}
	e2 := []Wlan{{Name: "pending", SSID: "pendingnet", Security: "open", Enabled: true}}
	adminH, informH, st := siteSettingsFixture(t, app.SiteSettings{}, e2, false)
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
	putSiteSettings(t, adminH, 840, "", []string{ssKeyLine1}, true)
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
		"sshd.auth.passwd=disabled\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("escape offer missing %q:\n%s", want, sys)
		}
	}
}

package server

// Tests build inform packets by hand per docs/PROTOCOL.md §1 so they do not
// depend on internal/inform's helper constructors — only the contract
// functions (ParsePacket / DecryptPayload / EncryptPayload) exercised through
// the handler itself.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucabecker/open-unifi/internal/store"
)

const (
	testMagic      = 0x544E4255 // "TNBU"
	testFlagEncCBC = 0x0001
	testFlagGCM    = 0x0008
	testDefaultKey = "ba86f2bbe107c7c57eb5f2690775c712" // MD5("ubnt")
	testMAC        = "aabbccddeeff"
)

var testIV = bytes16(0x07)

func bytes16(fill byte) []byte { return bytes.Repeat([]byte{fill}, 16) }
func testMACRaw() []byte       { return []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} }

// ---- packet construction helpers ----------------------------------------

func pkcs7Pad(b []byte) []byte {
	p := aes.BlockSize - len(b)%aes.BlockSize
	return append(append([]byte{}, b...), bytes.Repeat([]byte{byte(p)}, p)...)
}

func unpadCBC(b []byte) ([]byte, error) {
	if len(b) == 0 || len(b)%aes.BlockSize != 0 {
		return nil, errors.New("bad cbc length")
	}
	p := int(b[len(b)-1])
	if p == 0 || p > aes.BlockSize {
		return nil, errors.New("bad pad byte")
	}
	if !bytes.Equal(b[len(b)-p:], bytes.Repeat([]byte{byte(p)}, p)) {
		return nil, errors.New("bad pad content")
	}
	return b[:len(b)-p], nil
}

func buildInform(t *testing.T, mac []byte, flags uint16, iv []byte, payload []byte) []byte {
	t.Helper()
	hdr := make([]byte, 40)
	binary.BigEndian.PutUint32(hdr[0:4], testMagic)
	binary.BigEndian.PutUint32(hdr[4:8], 0) // packet version 0
	copy(hdr[8:14], mac)
	binary.BigEndian.PutUint16(hdr[14:16], flags)
	copy(hdr[16:32], iv)
	binary.BigEndian.PutUint32(hdr[32:36], 1) // data version must be 1
	binary.BigEndian.PutUint32(hdr[36:40], uint32(len(payload)))
	return append(hdr, payload...)
}

func encryptCBC(t *testing.T, jsonBody []byte, keyHex, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	padded := pkcs7Pad(jsonBody)
	ctext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ctext, padded)
	return buildInform(t, testMACRaw(), testFlagEncCBC, iv, ctext)
}

// encryptGCM seals with a 16-byte nonce and AAD = 40-byte header (payloadLen
// ct+tag), tag appended — Java AES/GCM/NoPadding semantics, §1.
func encryptGCM(t *testing.T, jsonBody []byte, keyHex, iv []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	hdr := make([]byte, 40)
	binary.BigEndian.PutUint32(hdr[0:4], testMagic)
	binary.BigEndian.PutUint32(hdr[4:8], 0)
	copy(hdr[8:14], testMACRaw())
	binary.BigEndian.PutUint16(hdr[14:16], testFlagGCM)
	copy(hdr[16:32], iv)
	binary.BigEndian.PutUint32(hdr[32:36], 1)
	binary.BigEndian.PutUint32(hdr[36:40], uint32(len(jsonBody)+16))
	return buildInform(t, testMACRaw(), testFlagGCM, iv, aead.Seal(nil, iv, jsonBody, hdr))
}

// post posts a raw body to the handler and returns the recorder.
func post(t *testing.T, h http.Handler, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-binary")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// decryptResponse parses/decrypts an encrypted 200 response with keyHex and
// returns (flags, decoded JSON map). The GCM tag verifies against the
// response's OWN 40-byte header (fresh IV, flags 0x0009, dataVersion
// unchanged — decompiled servlet mutates IV/flags/length in place and builds
// the AAD after), so body[:40] is the correct AAD.
func decryptResponse(t *testing.T, respBody []byte, keyHex []byte) (uint16, map[string]any) {
	t.Helper()
	if len(respBody) < 40 {
		t.Fatalf("response too short: %d", len(respBody))
	}
	if m := binary.BigEndian.Uint32(respBody[0:4]); m != testMagic {
		t.Fatalf("bad magic in response: %08x", m)
	}
	if dv := binary.BigEndian.Uint32(respBody[32:36]); dv != 1 {
		t.Fatalf("response dataVersion %d, want 1 (bytecode: dataVersion is never mutated on responses)", dv)
	}
	flags := binary.BigEndian.Uint16(respBody[14:16])
	iv := respBody[16:32]
	dlen := binary.BigEndian.Uint32(respBody[36:40])
	if uint32(len(respBody)-40) != dlen {
		t.Fatalf("response payloadLen %d, body %d", dlen, len(respBody)-40)
	}
	payload := respBody[40:]

	block, err := aes.NewCipher(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	var plain []byte
	switch {
	case flags&testFlagGCM != 0:
		aead, err := cipher.NewGCMWithNonceSize(block, 16)
		if err != nil {
			t.Fatal(err)
		}
		plain, err = aead.Open(nil, iv, payload, respBody[:40])
		if err != nil {
			t.Fatalf("response GCM open failed: %v", err)
		}
	case flags&testFlagEncCBC != 0:
		if len(payload)%aes.BlockSize != 0 || len(payload) == 0 {
			t.Fatalf("bad response CBC payload len %d", len(payload))
		}
		plain = make([]byte, len(payload))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, payload)
		plain, err = unpadCBC(plain)
		if err != nil {
			t.Fatalf("response unpad failed: %v", err)
		}
	default:
		t.Fatalf("response not encrypted: flags %04x", flags)
	}

	var jm map[string]any
	if err := json.Unmarshal(plain, &jm); err != nil {
		t.Fatalf("response JSON: %v (%q)", err, plain)
	}
	return flags, jm
}

// exactKeys asserts m has exactly the given key set.
func exactKeys(t *testing.T, m map[string]any, want ...string) {
	t.Helper()
	if len(m) != len(want) {
		t.Fatalf("response JSON keys = %v, want exactly %v", keysOf(m), want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Fatalf("response JSON missing key %q (keys: %v)", k, keysOf(m))
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// infoBody builds an info body map for the test device; appliedCfg may be "".
func infoBody(appliedCfg string) map[string]any {
	jm := map[string]any{
		"_type":      "info",
		"mac":        "aa:bb:cc:dd:ee:ff",
		"model":      "U7PG2",
		"version":    "6.6.55",
		"serial":     "F4TTESTSERIAL",
		"ip":         "10.0.0.23",
		"inform_url": "http://10.0.0.5:8080/inform",
		"uptime":     1234,
		"x_aes_gcm":  true,
		"hash_id":    "32hexhashid",
		"stat":       map[string]any{"user-num_sta": 4.0},
	}
	if appliedCfg != "" {
		jm["cfgversion"] = appliedCfg
	}
	return jm
}

// registerPending registers the test device as admin-pending.
func registerPending(t *testing.T, st store.DeviceStore) {
	t.Helper()
	if err := st.Put(store.Device{MAC: testMAC, State: store.StatePending}); err != nil {
		t.Fatal(err)
	}
}

// registerAdopted seeds a fully adopted device for drift/rogue-key tests.
func registerAdopted(t *testing.T, st store.DeviceStore, cfg, xkey string) {
	t.Helper()
	rec := store.Device{
		MAC:        testMAC,
		State:      store.StateAdopted,
		CfgVersion: cfg,
		AppliedCfg: cfg,
		XAuthkey:   xkey,
		Authkeys:   []string{xkey},
		Model:      "U7PG2",
	}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func isHex(s string) bool { return len(s) > 0 && strings.Trim(s, "0123456789abcdef") == "" }

func containsKey(keys []string, k string) bool {
	for _, x := range keys {
		if strings.ToLower(x) == strings.ToLower(k) {
			return true
		}
	}
	return false
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&strings.Builder{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

// quietLogger captures nothing but keeps warn-level messages (used for
// tests that expect a warn, e.g. wpa-eap without RADIUS).
func testWarnLogger(buf *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func newServerWith(cfg Config) (http.Handler, store.DeviceStore) {
	st := store.NewMemStore()
	return New(cfg, st, testLogger()).InformHandler(), st
}

func hexKey(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		t.Fatalf("bad key hex %q: %v", s, err)
	}
	return b
}

// ---- tests ---------------------------------------------------------------

// (b) unknown MAC: classic 404, MAC recorded as pending with inform:factory.
func TestInformUnknownMAC404(t *testing.T) {
	h, st := newServerWith(Config{})
	body := encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, testDefaultKey), testIV)
	resp := post(t, h, body)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.Code)
	}
	pending, err := st.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if pending[testMAC] != "inform:factory" {
		t.Fatalf("pending = %v, want inform:factory", pending)
	}
}

// (a) plaintext JSON inform: rejected by default, allowed under AllowPlainText.
func TestInformPlainText(t *testing.T) {
	plain, err := json.Marshal(infoBody(""))
	if err != nil {
		t.Fatal(err)
	}

	h0, _ := newServerWith(Config{})
	resp := post(t, h0, plain)
	if resp.Code != http.StatusBadRequest ||
		!strings.Contains(resp.Body.String(), "Plain text inform is not supported") {
		t.Fatalf("plaintext w/o allow: want 400 rejection, got %d %q",
			resp.Code, resp.Body.String())
	}

	h, st := newServerWith(Config{AllowPlainText: true})
	registerPending(t, st)
	resp = post(t, h, plain)
	if resp.Code != http.StatusOK || resp.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("plaintext allowed: want 200 application/json, got %d %s",
			resp.Code, resp.Header().Get("Content-Type"))
	}
	var jm map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
		t.Fatal(err)
	}
	if _, ok := jm["server_time_in_utc"]; !ok {
		t.Fatal("missing server_time_in_utc in plaintext reply")
	}
	if jm["_type"] != "noop" && jm["_type"] != "setparam" {
		t.Fatalf("plaintext reply type = %v", jm["_type"])
	}
	if jm["_type"] == "setparam" && jm["mgmt_cfg"] == nil {
		t.Fatal("setparam without mgmt_cfg")
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StateAdopting && rec.State != store.StateAdopted {
		t.Fatalf("plaintext inform left state = %d", rec.State)
	}
}

// (c) happy adoption path: pending + default-key (CBC) inform → setparam with
// fresh x_authkey; re-keyed inform with matching cfgversion → noop (+adopted).
func TestHappyAdoption(t *testing.T) {
	h, st := newServerWith(Config{})
	registerPending(t, st)

	// Inform #1: factory default key, no cfgversion applied yet.
	resp := post(t, h, encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, testDefaultKey), testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform#1: status %d", resp.Code)
	}
	if ct := resp.Header().Get("Content-Type"); ct != "application/x-binary" {
		t.Fatalf("inform#1 content-type: %s", ct)
	}
	flags, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, testDefaultKey))
	if flags&testFlagGCM != 0 {
		t.Fatalf("inform#1 response should echo CBC, flags %04x", flags)
	}
	if jm["_type"] != "setparam" {
		t.Fatalf("inform#1 type = %v, want setparam", jm["_type"])
	}
	// Adoption push (§6.2 a/c/f): mgmt_cfg ONLY, no top-level cfgversion.
	exactKeys(t, jm, "_type", "server_time_in_utc", "mgmt_cfg")
	mgmt, _ := jm["mgmt_cfg"].(string)
	if mgmt == "" || !strings.HasSuffix(mgmt, "\n") {
		t.Fatalf("inform#1 mgmt_cfg not \\n-terminated: %q", mgmt)
	}
	if !strings.Contains(mgmt, "cfgversion=") ||
		!strings.Contains(mgmt, "capability=notif,notif-assoc-stat") {
		t.Fatalf("inform#1 mgmt_cfg = %q", mgmt)
	}
	if strings.Contains(mgmt, "unifi.") {
		t.Fatalf("inform#1 mgmt_cfg has superseded unifi.* keys: %q", mgmt)
	}
	if !strings.Contains(mgmt, "authkey=") {
		t.Fatalf("inform#1 adoption mgmt_cfg missing authkey rotation line: %q", mgmt)
	}

	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StateAdopting {
		t.Fatalf("state after inform#1 = %d, want adopting", rec.State)
	}
	if len(rec.XAuthkey) != 32 || !isHex(rec.XAuthkey) {
		t.Fatalf("x_authkey not stored as 32 hex: %q", rec.XAuthkey)
	}
	if !containsKey(rec.Authkeys, rec.XAuthkey) {
		t.Fatalf("x_authkey not in authkeys: %v", rec.Authkeys)
	}
	xkey := rec.XAuthkey
	cfg := rec.CfgVersion
	if len(cfg) != 16 || !isHex(cfg) {
		t.Fatalf("cfgversion not 16 hex: %q", cfg)
	}

	// Inform #2: device re-keyed to x_authkey and applied the config.
	resp = post(t, h, encryptCBC(t, mustJSON(t, infoBody(cfg)), hexKey(t, xkey), testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform#2: status %d", resp.Code)
	}
	flags, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "noop" {
		t.Fatalf("inform#2 type = %v, want noop", jm["_type"])
	}
	if jm["interval"] != "15" {
		t.Fatalf("interval = %v, want string \"15\"", jm["interval"])
	}
	flags2 := binary.BigEndian.Uint16(resp.Body.Bytes()[14:16])
	if flags2&testFlagGCM != 0 {
		t.Fatalf("inform#2 response should echo CBC, flags %04x", flags2)
	}
	rec, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StateAdopted {
		t.Fatalf("state after inform#2 = %d, want adopted", rec.State)
	}
	if rec.Model != "U7PG2" || rec.AppliedCfg != cfg || rec.LastSeen == 0 {
		t.Fatalf("record not updated: %+v", rec)
	}

	// GCM capability round-trip: inform #3 uses GCM; response must echo GCM
	// (flags = GCM|EncCBC = 0x0009) encrypted with the same per-device key.
	resp = post(t, h, encryptGCM(t, mustJSON(t, infoBody(cfg)), hexKey(t, xkey), testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform#3: status %d", resp.Code)
	}
	flags, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "noop" {
		t.Fatalf("inform#3 type = %v, want noop", jm["_type"])
	}
	if flags != testFlagGCM|testFlagEncCBC {
		t.Fatalf("inform#3 response flags = %04x, want 0x0009", flags)
	}
	// The response IV must be FRESH, never the request's IV (servlet:
	// _O02.IV = C.random(16) before the GCM/CBC branch, both directions).
	if bytes.Equal(resp.Body.Bytes()[16:32], testIV) {
		t.Fatal("inform#3 response reused the request IV")
	}
	// MAC/flags echo discipline on the response header.
	if !bytes.Equal(resp.Body.Bytes()[8:14], testMACRaw()) {
		t.Fatal("inform#3 response MAC not echoed from the request")
	}
}

// (d) cfgversion drift after adoption → FULL provisioning setparam (all four
// config keys), state back to adopting. Device is on its x_authkey, so the
// mgmt_cfg must NOT carry the authkey rotation line.
func TestCfgVersionDriftFullProvisioning(t *testing.T) {
	h, st := newServerWith(Config{})
	const k = "11112222333344445555666677778888"
	registerAdopted(t, st, "aaaa", k)

	body := encryptCBC(t, mustJSON(t, infoBody("bogus-drift")), hexKey(t, k), testIV)
	resp := post(t, h, body)
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, k))
	if jm["_type"] != "setparam" {
		t.Fatalf("drift reply type = %v, want setparam", jm["_type"])
	}
	exactKeys(t, jm, "_type", "server_time_in_utc",
		"cfgversion", "system_cfg", "blocked_sta", "mgmt_cfg")

	if jm["cfgversion"] != "aaaa" {
		t.Fatalf("top-level cfgversion = %v, want record value %q", jm["cfgversion"], "aaaa")
	}
	if sta, _ := jm["blocked_sta"].(string); sta != "" {
		t.Fatalf("blocked_sta = %q, want empty (no block list yet)", sta)
	}
	sys, _ := jm["system_cfg"].(string)
	for _, want := range []string{
		"# system\n", "system.timezone=UTC\n",
		"# unifi\n", "unifi.version=0.1.0-dev\n",
		"# users\n", "users.status=enabled\n", "users.1.name=ubnt\n",
		"users.2.name=nobody\n",
		"# sshd\n", "sshd.status=enabled\n", "sshd.1.status=enabled\n",
		"# misc\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("system_cfg missing %q:\n%s", want, sys)
		}
	}
	if strings.Contains(sys, "wireless.") || strings.Contains(sys, "aaa.") {
		t.Fatalf("system_cfg invented unpublished wireless lines:\n%s", sys)
	}

	mgmt, _ := jm["mgmt_cfg"].(string)
	if strings.Contains(mgmt, "authkey=") {
		t.Fatalf("full-provisioning mgmt_cfg must omit authkey when device is on x_authkey: %q", mgmt)
	}
	if !strings.Contains(mgmt, "cfgversion=aaaa\n") {
		t.Fatalf("full-provisioning mgmt_cfg missing record cfgversion: %q", mgmt)
	}
	for _, want := range []string{
		"capability=notif,notif-assoc-stat\n",
		"selfrun_guest_mode=pass\n",
		"led_enabled=true\n",
		"stun_url=stun://10.0.0.5:3478/\n",
		"mgmt_url=https://10.0.0.5:8443/manage/site/default\n",
		"inform_url=http://10.0.0.5:8080/inform\n",
		"use_aes_gcm=true\n",
		"report_crash=true\n",
	} {
		if !strings.Contains(mgmt, want) {
			t.Fatalf("mgmt_cfg missing %q:\n%s", want, mgmt)
		}
	}
	if strings.Contains(mgmt, "is_setup_completed") {
		t.Fatalf("mgmt_cfg is UDM-only line: %q", mgmt)
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StateAdopting {
		t.Fatalf("drift state = %d, want adopting", rec.State)
	}
	if rec.CfgVersion != "aaaa" {
		t.Fatalf("full provisioning must keep the record cfgversion, got %q", rec.CfgVersion)
	}
}

// (e) inform with the forbidden default key after adoption → regenerate
// x_authkey, put device back into adoption, respond setparam (default key).
func TestDefaultKeyAfterAdoptionRegenerates(t *testing.T) {
	h, st := newServerWith(Config{})
	const k = "99998888777766665555444433332222"
	registerAdopted(t, st, "aaaa", k)

	body := encryptCBC(t, mustJSON(t, infoBody("aaaa")), hexKey(t, testDefaultKey), testIV)
	resp := post(t, h, body)
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, testDefaultKey))
	if jm["_type"] != "setparam" {
		t.Fatalf("type = %v, want setparam", jm["_type"])
	}
	// Adoption-push shape: no top-level cfgversion.
	exactKeys(t, jm, "_type", "server_time_in_utc", "mgmt_cfg")
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.XAuthkey == k {
		t.Fatal("x_authkey not regenerated")
	}
	if rec.State != store.StateAdopting {
		t.Fatalf("state = %d, want adopting (back into adoption)", rec.State)
	}
	if !containsKey(rec.Authkeys, rec.XAuthkey) {
		t.Fatalf("authkeys missing new x_authkey: %v", rec.Authkeys)
	}
	mgmt, _ := jm["mgmt_cfg"].(string)
	if !strings.Contains(mgmt, "authkey="+rec.XAuthkey+"\n") {
		t.Fatalf("regenerated mgmt_cfg %q missing new x_authkey %q", mgmt, rec.XAuthkey)
	}
}

// A known-but-stale authkey (≠ x_authkey) used during adoption → hostile/
// unexpected: regenerate x_authkey, respond setparam encrypted in usedKey.
func TestUnexpectedKeyDuringAdoption(t *testing.T) {
	h, st := newServerWith(Config{})
	// Seeded mid-adoption record: our assigned x_authkey is "deadbeef...", but
	// the device still holds the older admin key "1111..." from a previous cycle.
	const stale = "11112222333344445555666677778888"
	const xauth = "deadbeefdeadbeefdeadbeefdeadbeef"
	if err := st.Put(store.Device{
		MAC:        testMAC,
		State:      store.StateAdopting,
		CfgVersion: "aaaa",
		AppliedCfg: "",
		XAuthkey:   xauth,
		Authkeys:   []string{stale, testDefaultKey},
	}); err != nil {
		t.Fatal(err)
	}

	resp := post(t, h, encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, stale), testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform: status %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, stale))
	if jm["_type"] != "setparam" {
		t.Fatalf("type = %v, want setparam", jm["_type"])
	}
	// Stale-x_authkey inform → same adoption-push shape (mgmt_cfg only),
	// carrying the freshly rotated authkey line.
	exactKeys(t, jm, "_type", "server_time_in_utc", "mgmt_cfg")
	mgmt, _ := jm["mgmt_cfg"].(string)
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.XAuthkey == xauth {
		t.Fatal("x_authkey not regenerated on unexpected key")
	}
	if rec.State != store.StateAdopting {
		t.Fatalf("state = %d, want adopting", rec.State)
	}
	if !containsKey(rec.Authkeys, rec.XAuthkey) {
		t.Fatalf("authkeys missing new x_authkey: %v", rec.Authkeys)
	}
	if !strings.Contains(mgmt, "authkey="+rec.XAuthkey+"\n") {
		t.Fatalf("adoption push mgmt_cfg %q missing rotated authkey line", mgmt)
	}
}

// ---- wireless provisioning tests (docs/PROTOCOL-systemcfg-wireless.md) ----

// workedEnvelope mirrors doc §7: corp (wpa-p / correcthorse / VLAN 42) +
// guest (open, DISABLED — must be omitted with no trace).
func workedEnvelope() []Wlan {
	return []Wlan{
		{Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correcthorse",
			VLAN: 42, Enabled: true, ID: "5629b670e3f80a139930d113"},
		{Name: "guest", SSID: "guest", Security: "open", Enabled: false},
	}
}

// u7pg2Record returns a fake U7PG2 record whose Extra carries the radio
// table exactly as the server persists it from informs (whole-body
// passthrough; float64 channel for the na radio to exercise numeric
// normalization).
func u7pg2Record() store.Device {
	return store.Device{
		MAC: testMAC, Model: "U7PG2", State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
		XAuthkey: testDefaultKey, Authkeys: []string{testDefaultKey},
		Extra: store.JSONMap{"radio_table": []any{
			map[string]any{"name": "ra0", "radio": "ng", "channel": "0",
				"tx_power_mode": "auto", "tx_power": "auto",
				"builtin_antenna": true, "builtin_ant_gain": 0.0},
			map[string]any{"name": "rai0", "radio": "na", "channel": 0.0,
				"tx_power_mode": "auto", "tx_power": "auto",
				"builtin_antenna": true, "builtin_ant_gain": 0.0},
		}},
	}
}

// Worked-example snapshot: the emitted wireless compound must match the
// doc §7 shape verbatim ( radios sorted by name ra0<rai0; corp vap on both
// bands → ath0+ath1, wireless.1/2, aaa.1/2, br0.42 with both ath ports,
// vlan.1 eth0/42, netconf br0.42 row only; disabled guest ABSENT everywhere).
func TestWorkedExampleWirelessSystemCfg(t *testing.T) {
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }}, store.NewMemStore(), testLogger())
	sys := s.buildSystemCfg(u7pg2Record())
	start := strings.Index(sys, "# wlans (radio)\n")
	end := strings.Index(sys, "# sshd\n")
	if start < 0 || end <= start {
		t.Fatalf("wireless block not found in system_cfg:\n%s", sys)
	}
	got := sys[start:end]
	want := strings.Join([]string{
		"# wlans (radio)",
		"radio.status=enabled",
		"radio.countrycode=840",
		"aaa.status=enabled",
		"wireless.status=enabled",
		"radio.outdoor=disabled",
		"radio.1.phyname=ra0",
		"radio.1.ack.auto=disabled",
		"radio.1.acktimeout=64",
		"radio.1.ampdu.status=enabled",
		"radio.1.clksel=1",
		"radio.1.countrycode=840",
		"radio.1.cwm.enable=0",
		"radio.1.cwm.mode=0",
		"radio.1.forbiasauto=0",
		"radio.1.channel=0",
		"radio.1.backup_channel=0",
		"radio.1.ieee_mode=11nght20",
		"radio.1.mode=master",
		"radio.1.rate.auto=enabled",
		"radio.1.rate.mcs=auto",
		"radio.1.rfscan=disabled",
		"radio.1.bcmc_l2_filter.status=enabled",
		"radio.1.bgscan.status=disabled",
		"radio.1.antenna.gain=0",
		"radio.1.antenna=-1",
		"radio.1.txpower_mode=auto",
		"radio.1.txpower=auto",
		"radio.1.hard_noisefloor.status=disabled",
		"radio.2.phyname=rai0",
		"radio.2.ack.auto=disabled",
		"radio.2.acktimeout=64",
		"radio.2.ampdu.status=enabled",
		"radio.2.clksel=1",
		"radio.2.countrycode=840",
		"radio.2.cwm.enable=0",
		"radio.2.cwm.mode=0",
		"radio.2.forbiasauto=0",
		"radio.2.channel=0",
		"radio.2.backup_channel=0",
		"radio.2.ieee_mode=11naht20",
		"radio.2.mode=master",
		"radio.2.rate.auto=enabled",
		"radio.2.rate.mcs=auto",
		"radio.2.rfscan=disabled",
		"radio.2.bcmc_l2_filter.status=enabled",
		"radio.2.bgscan.status=disabled",
		"radio.2.antenna.gain=0",
		"radio.2.antenna=-1",
		"radio.2.txpower_mode=auto",
		"radio.2.txpower=auto",
		"radio.2.hard_noisefloor.status=disabled",
		"aaa.1.pmf.status=disabled",
		"aaa.1.pmf.mode=0",
		"aaa.1.ft.status=disabled",
		"aaa.1.country_beacon=disabled",
		"aaa.1.11k.status=disabled",
		"aaa.1.br.devname=br0.42",
		"aaa.1.devname=ath0",
		"aaa.1.driver=madwifi",
		"aaa.1.ssid=corp",
		"aaa.1.status=enabled",
		"aaa.1.verbose=2",
		"aaa.1.wpa=2",
		"aaa.1.eapol_version=2",
		"aaa.1.wpa.group_rekey=3600",
		"aaa.1.p2p=disabled",
		"aaa.1.p2p_cross_connect=disabled",
		"aaa.1.proxy_arp=disabled",
		"aaa.1.is_guest=false",
		"aaa.1.tdls_prohibit=disabled",
		"aaa.1.bss_transition=enabled",
		"aaa.1.id=5629b670e3f80a139930d113",
		"aaa.1.wpa.key.1.mgmt=WPA-PSK",
		"aaa.1.wpa.psk=correcthorse",
		"aaa.1.wpa.1.pairwise=CCMP",
		"aaa.1.pmf.cipher=AES-128-CMAC",
		"aaa.1.radius.macacl.status=disabled",
		"aaa.1.hide_ssid=false",
		"wireless.1.mode=master",
		"wireless.1.devname=ath0",
		"wireless.1.id=5629b670e3f80a139930d113",
		"wireless.1.status=enabled",
		"wireless.1.authmode=1",
		"wireless.1.l2_isolation=disabled",
		"wireless.1.is_guest=false",
		"wireless.1.security=none",
		"wireless.1.addmtikie=disabled",
		"wireless.1.ssid=corp",
		"wireless.1.hide_ssid=false",
		"wireless.1.mac_acl.status=enabled",
		"wireless.1.mac_acl.policy=deny",
		"wireless.1.wmm=enabled",
		"wireless.1.uapsd=disabled",
		"wireless.1.parent=ra0",
		"wireless.1.puren=0",
		"wireless.1.pureg=1",
		"wireless.1.usage=user",
		"wireless.1.wds=disabled",
		"wireless.1.mcast.enhance=0",
		"wireless.1.autowds=disabled",
		"wireless.1.vport=disabled",
		"wireless.1.vwire=disabled",
		"wireless.1.schedule_enabled=disabled",
		"wireless.1.no2ghz_oui=disabled",
		"wireless.1.element_adopt=disabled",
		"wireless.1.mcastrate=auto",
		"wireless.1.dtim_period=3",
		"aaa.2.pmf.status=disabled",
		"aaa.2.pmf.mode=0",
		"aaa.2.ft.status=disabled",
		"aaa.2.country_beacon=disabled",
		"aaa.2.11k.status=disabled",
		"aaa.2.br.devname=br0.42",
		"aaa.2.devname=ath1",
		"aaa.2.driver=madwifi",
		"aaa.2.ssid=corp",
		"aaa.2.status=enabled",
		"aaa.2.verbose=2",
		"aaa.2.wpa=2",
		"aaa.2.eapol_version=2",
		"aaa.2.wpa.group_rekey=3600",
		"aaa.2.p2p=disabled",
		"aaa.2.p2p_cross_connect=disabled",
		"aaa.2.proxy_arp=disabled",
		"aaa.2.is_guest=false",
		"aaa.2.tdls_prohibit=disabled",
		"aaa.2.bss_transition=enabled",
		"aaa.2.id=5629b670e3f80a139930d113",
		"aaa.2.wpa.key.1.mgmt=WPA-PSK",
		"aaa.2.wpa.psk=correcthorse",
		"aaa.2.wpa.1.pairwise=CCMP",
		"aaa.2.pmf.cipher=AES-128-CMAC",
		"aaa.2.radius.macacl.status=disabled",
		"aaa.2.hide_ssid=false",
		"wireless.2.mode=master",
		"wireless.2.devname=ath1",
		"wireless.2.id=5629b670e3f80a139930d113",
		"wireless.2.status=enabled",
		"wireless.2.authmode=1",
		"wireless.2.l2_isolation=disabled",
		"wireless.2.is_guest=false",
		"wireless.2.security=none",
		"wireless.2.addmtikie=disabled",
		"wireless.2.ssid=corp",
		"wireless.2.hide_ssid=false",
		"wireless.2.mac_acl.status=enabled",
		"wireless.2.mac_acl.policy=deny",
		"wireless.2.wmm=enabled",
		"wireless.2.uapsd=disabled",
		"wireless.2.parent=rai0",
		"wireless.2.puren=0",
		"wireless.2.pureg=1",
		"wireless.2.usage=user",
		"wireless.2.wds=disabled",
		"wireless.2.mcast.enhance=0",
		"wireless.2.autowds=disabled",
		"wireless.2.vport=disabled",
		"wireless.2.vwire=disabled",
		"wireless.2.schedule_enabled=disabled",
		"wireless.2.no2ghz_oui=disabled",
		"wireless.2.element_adopt=disabled",
		"wireless.2.mcastrate=auto",
		"wireless.2.dtim_period=3",
		"# vlan",
		"vlan.1.devname=eth0",
		"vlan.1.id=42",
		"# bridge",
		"bridge.1.devname=br0",
		"bridge.1.fd=1",
		"bridge.1.stp.status=disabled",
		"bridge.1.port.1.devname=eth0",
		"bridge.2.devname=br0.42",
		"bridge.2.fd=1",
		"bridge.2.stp.status=disabled",
		"bridge.2.port.1.devname=ath0",
		"bridge.2.port.2.devname=ath1",
		"# netconf",
		"netconf.1.devname=br0.42",
		"netconf.1.ip=0.0.0.0",
		"netconf.1.autoip.status=disabled",
		"netconf.1.promisc=enabled",
		"netconf.1.up=enabled",
		"# dhcpc",
		"dhcpc.status=enabled",
		"",
	}, "\n")
	if got != want {
		t.Fatalf("wireless block mismatch:\n--- got ---\n%s\n--- want ---\n%s",
			got, want)
	}
	// disabled guest: omitted with no trace anywhere in the block.
	if strings.Contains(got, "ssid=guest") || strings.Contains(got, "ath2") ||
		strings.Contains(got, "br0.2\n") {
		t.Fatalf("disabled wlan leaked into provisioning:\n%s", got)
	}
}

// No radios in the stored inform data → the §1 no-radio variant and no other
// wireless rows at all.
func TestNoRadiosWirelessVariant(t *testing.T) {
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }}, store.NewMemStore(), testLogger())
	rec := u7pg2Record()
	delete(rec.Extra, "radio_table")
	sys := s.buildSystemCfg(rec)
	if want := "# no wlan provisioned as no radio found\nradio.status=disabled\n"; !strings.Contains(sys, want) {
		t.Fatalf("missing no-radio variant in:\n%s", sys)
	}
	if strings.Contains(sys, "aaa.") || strings.Contains(sys, "wireless.") ||
		strings.Contains(sys, "bridge.") {
		t.Fatalf("no-radio variant emitted wireless rows:\n%s", sys)
	}
}

// WPA-EAP without RADIUS fields: fixed block + WPA-EAP mgmt + fallback psk +
// dynamic_vlan=0, and the server warns.
func TestWpaEapWirelessMinimal(t *testing.T) {
	var logs strings.Builder
	s := New(Config{WirelessSource: func() []Wlan {
		return []Wlan{
			{Name: "ent", SSID: "ent", Security: "wpa-eap", Enabled: true, ID: "eapident"},
		}
	}}, store.NewMemStore(), testWarnLogger(&logs))
	sys := s.buildSystemCfg(u7pg2Record())
	for _, want := range []string{
		"aaa.1.wpa.key.1.mgmt=WPA-EAP\n",
		"aaa.1.wpa.psk=letmeinnow\n",
		"aaa.1.auth_cache=enabled\n",
		"aaa.1.dynamic_vlan=0\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("wpa-eap block missing %q in:\n%s", want, sys)
		}
	}
	if !strings.Contains(logs.String(), "RADIUS") {
		t.Fatal("expected RADIUS warn for wpa-eap provisioning")
	}
}

// ---- sha512crypt (users.1) -----------------------------------------------

// Golden vectors from OpenSSL 3.x (`openssl passwd -6 -salt S P`) — the
// OpenSSL SHA-512 crypt implements the same SHA-crypt (Drepper) spec as
// glibc and the bundled commons-codec on the classic controller; plus the
// controller cache self-check.
func TestSha512CryptVectorTests(t *testing.T) {
	vv := []struct{ pw, salt, want string }{
		{"ubnt", "abcd1234", "$6$abcd1234$zkx0G4Hd6kNhG.Pis3ng0rgjOuz3ZXjZ6EPChBV2anHZ3lRNKTUSYYj1g2jbmG0/vop6b9TKgKszoDdMeJE39."},
		{"ubnt", "testsalt", "$6$testsalt$BOcp0ABcwNH6T6E6hVlHRAPmXVmWPjTdTBdbUOuQx4pRbu5jM1bflFSIVQpa/getBK25jGzZgMYbsIFhSSap3/"},
		{"ubnt", "01234567", "$6$01234567$oPY8xJmDi4MvySVS8bYMY2fLLPzERYmsfHYofoivH4rpDgQeLmIIHX07W3Od32Q4cVg1FX75RdOJ3e4T5cTos."},
		{"ubnt", "/0ab", "$6$/0ab$f3xVoSoW9z1rE.UG1lqLpck0HAVRs.iywxojvHm0HmhpoijLmUIfnhCmJe70l2DLqGDZjTY9xaJ.pw8qqETuY0"},
		{"letmeinnow", "abcd1234", "$6$abcd1234$cy1En37fRI8Y7LYYDOvRRQNc.Ml.FNa7g7Fe.xAQ0MBd0fhX0jTu7BVvJ4.cPjhkj2FefvYf.9ODGzrSQSK2S/"},
		{"letmeinnow", "testsalt", "$6$testsalt$wqpaSda43LzhSf60diJ0nWTRy1a52w5SsE4cquPVah5gJhPAtBffV/plRfW8hLU4N.fz6GShf9wZGChtHpz1y/"},
		{"letmeinnow", "01234567", "$6$01234567$pNVV8eDqwPmRWmNUMkbXAU78mouUHAPQUMhfj8j0ylS/O9p4CxlWuT/9dtqJxbhx7.A8YbxGoNVQXJ4PlC0.H/"},
		{"letmeinnow", "/0ab", "$6$/0ab$eP33xgO55Li7PT0DLMd/q/8QOcyYKchtx2YZRpssIqazJfWbBwCFwLCLzul5E3adon421ECqz6ANkhprwxDvg1"},
		{"correcthorse", "abcd1234", "$6$abcd1234$Y/PARXisSI98RlkbOdASp5yUqeBK8LkQfXwyrr.gvPDUYTUIHXm2uSNBRV6Bzkp3xvll8aVxJM0OCvzr1h6R5/"},
		{"correcthorse", "testsalt", "$6$testsalt$Tw0mpSk/FHPv7FUgG5EYIxY4BskslsTI2C9V78g4HvOrDMoLYageEbNMpuwIX1Vv26fQQgVXDmPp57z9SvdQt0"},
		{"correcthorse", "01234567", "$6$01234567$wSEs7eXXvPURUjaP16otdkbL07jpN0zkg29rzkGPC8xITzmUHecAzkd6pcEa5eFj6Vd5E3T4iDp1vLAzK7/0K/"},
		{"correcthorse", "/0ab", "$6$/0ab$IUuHnCRa136i8vXldE3gvWQxRa/f0L179MEoXUmpAQkkz9dxAk8QBeRrnEgEm91XLUPlffo3fvmwCfhEzQ7WE."},
	}
	for _, v := range vv {
		got := sha512CryptRaw([]byte(v.pw), []byte(v.salt))
		if got != v.want {
			t.Errorf("sha512crypt(%q, %q)\n got %s\nwant %s", v.pw, v.salt, got, v.want)
		}
		// cache self-check must accept the reference hash (re-crypt with the
		// embedded salt only).
		if !sha512CryptMatches(v.pw, v.want) {
			t.Errorf("cache self-check rejected reference hash for %q", v.pw)
		}
	}
}

// users.1/users.2 row shape + per-device cache stability across pushes.
func TestUsers1CacheStability(t *testing.T) {
	rec := u7pg2Record()
	s := New(Config{}, store.NewMemStore(), testLogger())
	sys1 := s.buildSystemCfg(rec)
	pw1 := systemCfgUsersPassword(t, sys1)
	if !sha512BodyRx.MatchString(pw1) {
		t.Fatalf("users.1.password shape not $6$salt$hash: %q", pw1)
	}
	rec.Extra["ssh_sha512passwd"] = pw1
	sys2 := s.buildSystemCfg(rec)
	pw2 := systemCfgUsersPassword(t, sys2)
	if pw1 != pw2 {
		t.Fatalf("users.1.password not stable across pushes: %q vs %q", pw1, pw2)
	}
	if !sha512CryptMatches(defaultSSHPassword, pw1) {
		t.Fatal("cached hash does not self-check against default password ubnt")
	}
	// shape: no users.1.shell row; users.2 has its rows.
	if strings.Contains(sys1, "users.1.shell") {
		t.Fatal("users.1 must not carry a shell row (doc §10.1)")
	}
	for _, want := range []string{"users.2.name=nobody\n", "users.2.password=x\n",
		"users.2.shell=/bin/false\n", "users.2.status=enabled\n"} {
		if !strings.Contains(sys1, want) {
			t.Fatalf("users.2 missing %q", want)
		}
	}
}

// radioBody returns the inform body map for the worked-example device
// (radio_table rides in the body exactly as the server persists it).
func radioBody(appliedCfg string) map[string]any {
	jm := infoBody(appliedCfg)
	jm["radio_table"] = u7pg2Record().Extra["radio_table"]
	return jm
}

// systemCfgUsersPassword extracts the users.1.password value.
func systemCfgUsersPassword(t *testing.T, sys string) string {
	t.Helper()
	for _, l := range strings.Split(sys, "\n") {
		if after, ok := strings.CutPrefix(l, "users.1.password="); ok {
			return after
		}
	}
	t.Fatal("users.1.password row missing")
	return ""
}

// ---- FSM wireless-hash bump ------------------------------------------------

// infoBodyCBC builds and posts a CBC inform for the test device with env
// as the WirelessSource backing, returning (recorder, store).
func wiredServer(t *testing.T, env func() []Wlan, st store.DeviceStore) http.Handler {
	t.Helper()
	s := New(Config{WirelessSource: env}, st, testLogger())
	return s.InformHandler()
}

// TestWirelessDriftFSM: hash bump on wireless change forces full
// provisioning; unchanged hash + applied cfgversion → noop; the emitted
// provisioning captures the new envelope hash.
func TestWirelessDriftFSM(t *testing.T) {
	env := workedEnvelope()
	st := store.NewMemStore()
	xkey := "11112222333344445555666677778888"
	if err := st.Put(store.Device{
		MAC: testMAC, State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "",
		XAuthkey: xkey, Authkeys: []string{xkey}, Model: "U7PG2",
		Extra: u7pg2Record().Extra,
	}); err != nil {
		t.Fatal(err)
	}
	h := wiredServer(t, func() []Wlan { return env }, st)

	// inform#1: no stored hash yet, AppliedCfg "" ≠ "aaaa" → full
	// provisioning; hash of envelope captured, users.1 cached.
	body := encryptCBC(t, mustJSON(t, radioBody("")), hexKey(t, xkey), testIV)
	resp := post(t, h, body)
	if resp.Code != http.StatusOK {
		t.Fatalf("inform#1: %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "setparam" || jm["system_cfg"] == nil {
		t.Fatalf("inform#1 type = %v (want setparam full provisioning)", jm["_type"])
	}
	if !strings.Contains(jm["system_cfg"].(string), "{\\") &&
		!strings.Contains(jm["system_cfg"].(string), "aaa.1.wpa.psk=correcthorse") {
		t.Fatalf("inform#1 system_cfg missing corp vap:\n%q", jm["system_cfg"])
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := wlanListHash(env)
	if rec.Extra["wlan_cfg_sha"] != wantHash {
		t.Fatalf("wlan_cfg_sha = %v, want %q", rec.Extra["wlan_cfg_sha"], wantHash)
	}
	cached, _ := rec.Extra["ssh_sha512passwd"].(string)
	if !sha512BodyRx.MatchString(cached) {
		t.Fatalf("ssh_sha512passwd not cached: %q", cached)
	}

	// inform#2: applied matches, envelope unchanged → noop.
	body = encryptCBC(t, mustJSON(t, radioBody(rec.CfgVersion)), hexKey(t, xkey), testIV)
	resp = post(t, h, body)
	_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "noop" {
		t.Fatalf("inform#2 type = %v, want noop", jm["_type"])
	}

	// inform#3: envelope changed (SSID) → hash bump → full provisioning.
	env[0].SSID = "corpnet"
	body = encryptCBC(t, mustJSON(t, radioBody(rec.CfgVersion)), hexKey(t, xkey), testIV)
	resp = post(t, h, body)
	_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "setparam" {
		t.Fatalf("inform#3 type = %v, want setparam (wireless drift)", jm["_type"])
	}
	rec, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	newHash := wlanListHash(env)
	if rec.Extra["wlan_cfg_sha"] != newHash {
		t.Fatalf("hash not refreshed: %v want %q", rec.Extra["wlan_cfg_sha"], newHash)
	}
	if rec.CfgVersion == "aaaa" {
		t.Fatal("CfgVersion not regenerated on wireless drift")
	}
	if rec.State != store.StateAdopting {
		t.Fatalf("state = %d, want adopting", rec.State)
	}
	if !strings.Contains(jm["system_cfg"].(string), "aaa.1.ssid=corpnet") {
		t.Fatalf("inform#3 system_cfg not rendered from new envelope")
	}

	// inform#4: re-apply new config → noop again.
	body = encryptCBC(t, mustJSON(t, radioBody(rec.CfgVersion)), hexKey(t, xkey), testIV)
	resp = post(t, h, body)
	_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "noop" {
		t.Fatalf("inform#4 type = %v, want noop", jm["_type"])
	}
}

// Adoption push (default key) must NOT touch the stored hash: the device
// has not received system_cfg yet.
func TestAdoptionPushLeavesHash(t *testing.T) {
	env := []Wlan{{Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correcthorse", VLAN: 42, Enabled: true}}
	st := store.NewMemStore()
	if err := st.Put(store.Device{MAC: testMAC, State: store.StatePending}); err != nil {
		t.Fatal(err)
	}
	h := wiredServer(t, func() []Wlan { return env }, st)

	body := encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, testDefaultKey), testIV)
	resp := post(t, h, body)
	_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, testDefaultKey))
	if jm["_type"] != "setparam" || !strings.HasPrefix(jm["mgmt_cfg"].(string), "capability=") {
		t.Fatalf("adoption push shape wrong: %v", jm)
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rec.Extra["wlan_cfg_sha"]; ok {
		t.Fatalf("adoption push stored wlan_cfg_sha: %v", rec.Extra["wlan_cfg_sha"])
	}
	// but a full provisioning later does capture it.
	if !containsKey(rec.Authkeys, rec.XAuthkey) {
		t.Fatal("x_authkey not appended")
	}
}

package server

// Tests build inform packets by hand per docs/PROTOCOL.md §1 so they do not
// depend on internal/inform's helper constructors — only the contract
// functions (ParsePacket / DecryptPayload / EncryptPayload) exercised through
// the handler itself.

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lucabecker/open-unifi/internal/inform"
	"github.com/lucabecker/open-unifi/internal/store"
)

const (
	testMagic      = 0x544E4255 // "TNBU"
	testFlagEncCBC = 0x0001
	testFlagGCM    = 0x0008
	testDefaultKey = "ba86f2bbe107c7c57eb5f2690775c712" // MD5("ubnt")
	testMAC        = "aabbccddeeff"
)

func TestNoopIntervalScheduling(t *testing.T) {
	oldRandom := noopRandom
	t.Cleanup(func() { noopRandom = oldRandom })
	tests := []struct {
		name string
		r    float64
		rec  store.Device
		now  int64
		want int64
	}{
		{"first low", 0, store.Device{Model: "U7PG2", Extra: store.JSONMap{}}, 1000, 10},
		{"first high", .9, store.Device{Model: "U7PG2", Extra: store.JSONMap{}}, 1000, 14},
		{"watching", .5, store.Device{Model: "U7PG2", Extra: store.JSONMap{"watching": true}}, 1000, 5},
		{"ubios fallback", .5, store.Device{Model: "UDM-Pro", Extra: store.JSONMap{}}, 1000, 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noopRandom = func() float64 { return tt.r }
			s := New(Config{}, nil, slog.Default())
			got := s.noopRespFor(testMAC, &tt.rec, tt.now)["interval"]
			if got != tt.want {
				t.Fatalf("interval = %v, want %d", got, tt.want)
			}
		})
	}
	t.Run("target advances and cap fallback does not persist", func(t *testing.T) {
		noopRandom = func() float64 { return 0 }
		s := New(Config{}, nil, slog.Default())
		r := store.Device{Model: "U7PG2", Extra: store.JSONMap{}}
		if got := s.noopRespFor(testMAC, &r, 1000)["interval"]; got != int64(10) {
			t.Fatal(got)
		}
		if got := s.noopRespFor(testMAC, &r, 1005)["interval"]; got != int64(10) {
			t.Fatal(got)
		}
		s.noopMu.Lock()
		s.noopTarget[testMAC] = 1100
		s.noopMu.Unlock()
		noopRandom = func() float64 { return .5 }
		if got := s.noopRespFor(testMAC, &r, 1000)["interval"]; got != int64(58) {
			t.Fatal(got)
		}
	})
	if got := (&Server{}).noopResp()["interval"]; got != 10 {
		t.Fatalf("fallback = %v", got)
	}
}

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
		// SHA-512 password capability bit (real U7PG2 informs carry it;
		// FID-22 users.1 branch).
		"fw_caps": 0x400,
		"hash_id": "32hexhashid",
		"stat":    map[string]any{"user-num_sta": 4.0},
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
		if strings.EqualFold(x, k) {
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

// mustBuildSys renders system_cfg for tests; a build error (FID-23 path)
// fails the test unless the test specifically asserts the failure.
func mustBuildSys(t *testing.T, s *Server, rec store.Device) string {
	t.Helper()
	sys, err := s.buildSystemCfg(rec)
	if err != nil {
		t.Fatalf("system_cfg build: %v", err)
	}
	return sys
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

// (a) plaintext JSON inform: rejected by default (400 before any store
// lookup or key path). Under AllowPlainText a pending record with NO
// assignment receives a noop and STAYS StatePending — plaintext can never
// initiate adoption (deviation from the classic debug-build rotation,
// validator-approved).
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
	if jm["_type"] != "noop" {
		t.Fatalf("plaintext reply type = %v, want noop for an unassigned device", jm["_type"])
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StatePending || rec.XAuthkey != "" {
		t.Fatalf("plaintext inform mutated pending record: state=%d xauthkey=%q",
			rec.State, rec.XAuthkey)
	}
}

// (a2) framed packet with NO encryption flags: gated like plain JSON
// (classic InformServlet gates unencrypted informs, docs §5 L262-265).
func TestFramedPlainTextGate(t *testing.T) {
	pkt := buildInform(t, testMACRaw(), 0, bytes16(0x01), mustJSON(t, infoBody("")))
	// note: dataVersion 1, payload plaintext (unparseable JSON not even needed)

	h0, st := newServerWith(Config{})
	registerPending(t, st)
	resp := post(t, h0, pkt)
	if resp.Code != http.StatusBadRequest ||
		!strings.Contains(resp.Body.String(), "Plain text inform is not supported") {
		t.Fatalf("framed plain w/o allow: want 400, got %d %q", resp.Code, resp.Body.String())
	}
	pending, _ := st.Pending()
	if pending[testMAC] != "" {
		t.Fatal("framed plain info must not touch the store before the gate")
	}
}

// (a3) AllowPlainText + framed zlib-only (0x02) inform: MAC from the header,
// payload inflated by DecryptPayload's transparent zlib path, then the plain
// semantics (noop for the unassigned pending record).
func TestFramedPlainZlib(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zlib.NewWriter(&zbuf)
	if _, err := zw.Write(mustJSON(t, infoBody(""))); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	pkt := buildInform(t, testMACRaw(), inform.FlagZlib, bytes16(0x02), zbuf.Bytes())

	h, st := newServerWith(Config{AllowPlainText: true})
	registerPending(t, st)
	resp := post(t, h, pkt)
	if resp.Code != http.StatusOK {
		t.Fatalf("framed zlib plain: %d %q", resp.Code, resp.Body.String())
	}
	var jm map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
		t.Fatal(err)
	}
	if jm["_type"] != "noop" {
		t.Fatalf("type = %v, want noop (no assignment)", jm["_type"])
	}
}

// (a4) plaintext claim = stale/missing key → mgmt_cfg-only push carrying
// the CURRENT XAuthkey, NO rotation, state unchanged.
func TestPlainRekeyPushNoRotation(t *testing.T) {
	const xk = "11112222333344445555666677778888"
	plain, err := json.Marshal(infoBody("aaaa"))
	if err != nil {
		t.Fatal(err)
	}
	h, st := newServerWith(Config{AllowPlainText: true})
	registerAdopted(t, st, "aaaa", xk)

	resp := post(t, h, plain) // no _authkey claim in body
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d %q", resp.Code, resp.Body.String())
	}
	var jm map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
		t.Fatal(err)
	}
	exactKeys(t, jm, "_type", "server_time_in_utc", "mgmt_cfg")
	mgmt := jm["mgmt_cfg"].(string)
	if !strings.Contains(mgmt, "authkey="+xk+"\n") {
		t.Fatalf("plain push mgmt_cfg missing current assignment: %q", mgmt)
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.XAuthkey != xk || rec.CfgVersion != "aaaa" || rec.State != store.StateAdopted {
		t.Fatalf("plain push rotated/mutated assignment: %+v", rec)
	}
}

// (a5) plaintext claim == XAuthkey with cfgversion drift → full provisioning.
func TestPlainClaimDriftFullProvision(t *testing.T) {
	const xk = "11112222333344445555666677778888"
	h, st := newServerWith(Config{AllowPlainText: true})
	registerAdopted(t, st, "aaaa", xk)

	// with the claim equal to the assigned key
	withClaim := infoBody("stale-1")
	withClaim["_authkey"] = xk
	plain, err := json.Marshal(withClaim)
	if err != nil {
		t.Fatal(err)
	}
	resp := post(t, h, plain)
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	var jm map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
		t.Fatal(err)
	}
	if jm["_type"] != "setparam" || jm["system_cfg"] == nil || jm["cfgversion"] != "aaaa" {
		t.Fatalf("plain claim drift type = %v, want full provisioning", jm["_type"])
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
	// FID-11: interval is a JSON number of seconds.
	if iv, ok := jm["interval"].(float64); !ok || iv < 1 || iv > 90 {
		t.Fatalf("interval = %v (%T), want number in [1,90]", jm["interval"], jm["interval"])
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

// (c-live) regression from the 2026-09-16 acceptance session: real firmware
// (U7PG2 on BZ.6.8.2) sends its periodic status informs with NO _type key at
// all, factory key, ~15 s cadence. The empty-_type inform IS the jar's
// main-dispatcher (voidsuper) inform (PROTOCOL-mgmt.md §6.2): the adoption
// push must fire on it, not the gentle noop, or a real device can never be
// adopted (the original gate nooped it before the key/state switch ran).
func TestEmptyTypeStatusInformAdopts(t *testing.T) {
	h, st := newServerWith(Config{})
	registerPending(t, st)

	body := infoBody("")
	delete(body, "_type") // exactly what the real device sends
	resp := post(t, h, encryptCBC(t, mustJSON(t, body), hexKey(t, testDefaultKey), testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform: status %d", resp.Code)
	}
	_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, testDefaultKey))
	if jm["_type"] != "setparam" {
		t.Fatalf("type = %v, want setparam adoption push for the real-device empty-_type inform", jm["_type"])
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StateAdopting {
		t.Fatalf("state = %d, want adopting", rec.State)
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
	// Real section head order (int.txt:17208-17216): `# unifi` first
	// (with the idp + cfgcap_info tail rows), then `# users`. The
	// `# system` section is deliberately omitted (no site locale; the
	// factory baseline carries no system rows — see
	// buildGeneratedSystemCfg).
	for _, want := range []string{
		"# unifi\n", "unifi.version=0.1.0-dev\n", "unifi.siteid=default\n",
		"unifi.idp=disabled\n", "unifi.cfgcap_info=0x7\n",
		"# users\n", "users.status=enabled\n", "users.1.name=ubnt\n",
		"users.2.name=nobody\n",
		"sshd.status=enabled\n", "sshd.1.status=enabled\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("system_cfg missing %q:\n%s", want, sys)
		}
	}
	// FID-20/FID-62: no invented "# sshd"/"# misc" section headers.
	for _, wrong := range []string{"# sshd\n", "# misc\n"} {
		if strings.Contains(sys, wrong) {
			t.Fatalf("system_cfg must not carry the invented header %q:\n%s", wrong, sys)
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
		// FID-16: no inform_url row — the row is emitted only when the
		// controller URL is explicitly overridden (this Config{} is not).
		"use_aes_gcm=true\n",
		"report_crash=true\n",
	} {
		if !strings.Contains(mgmt, want) {
			t.Fatalf("mgmt_cfg missing %q:\n%s", want, mgmt)
		}
	}
	if strings.Contains(mgmt, "inform_url=") {
		t.Fatalf("unoverridden mgmt_cfg must omit the inform_url row:\n%s", mgmt)
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

// (e) inform with the forbidden default key AFTER adoption → REJECTED: the
// state-gated factory key (FID-1) maps to the classic 404 marker (devmgr
// "used default key in ADOPTED state, reject it!" → ÖoÓ000 → servlet 404)
// and the record must stay completely untouched.
func TestDefaultKeyAfterAdoptionRejected(t *testing.T) {
	h, st := newServerWith(Config{})
	const k = "99998888777766665555444433332222"
	registerAdopted(t, st, "aaaa", k)

	body := encryptCBC(t, mustJSON(t, infoBody("aaaa")), hexKey(t, testDefaultKey), testIV)
	resp := post(t, h, body)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (default key rejected post-adoption)", resp.Code)
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.XAuthkey != k || rec.CfgVersion != "aaaa" || rec.State != store.StateAdopted {
		t.Fatalf("rejected default-key inform mutated the record: %+v", rec)
	}
	if !containsKey(rec.Authkeys, k) {
		t.Fatalf("authkeys touched by rejection: %v", rec.Authkeys)
	}

	// Pending and adopting records still accept the default key (the
	// UNKNOWN/two-phase acceptance window), covered by TestHappyAdoption,
	// TestGCMAdoptionMatrix and TestAuthkeysPrunedToTwo.
}

// A known-but-stale authkey (≠ x_authkey) used during adoption → hostile/
// unexpected, but FID-36 (jar rotation-pending push): the broker RE-PUSHES
// the existing per-device key via the authkey= line WITHOUT rotating it.
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
	// Stale-x_authkey inform → adoption-push shape (mgmt_cfg only) carrying
	// the CURRENT assignment, no rotation (FID-36).
	exactKeys(t, jm, "_type", "server_time_in_utc", "mgmt_cfg")
	mgmt, _ := jm["mgmt_cfg"].(string)
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.XAuthkey != xauth {
		t.Fatalf("x_authkey must be re-pushed unchanged, got %q (want %q)", rec.XAuthkey, xauth)
	}
	if rec.State != store.StateAdopting {
		t.Fatalf("state = %d, want adopting", rec.State)
	}
	if len(rec.Authkeys) != 2 || !containsKey(rec.Authkeys, stale) || !containsKey(rec.Authkeys, testDefaultKey) {
		t.Fatalf("authkeys touched by re-push: %v", rec.Authkeys)
	}
	if !strings.Contains(mgmt, "authkey="+xauth+"\n") {
		t.Fatalf("adoption push mgmt_cfg %q missing current assignment authkey line", mgmt)
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
		// fw_caps = 0x0400: the SHA-512 password capability bit real U7PG2
		// reports (drives the users.1 $6$ branch, FID-22).
		Extra: store.JSONMap{"fw_caps": 1024.0, "radio_table": []any{
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
// vlan.1 eth0/42, netconf factory echo — 1=br0 mgmt (192.168.1.20/24),
// 2=eth0 up, 3/4=ath0/ath1 slots down — then the tagged netconf.5=br0.42;
// disabled guest ABSENT everywhere).
func TestWorkedExampleWirelessSystemCfg(t *testing.T) {
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, u7pg2Record())
	start := strings.Index(sys, "# wlans (radio)\n")
	// The wireless compound ends at the last dhcpc row; the factory-echo
	// sections + sshd rows follow and are covered by the minimal-diff
	// gate test, not this snapshot.
	end := strings.Index(sys, "dhcpc.1.devname=br0\n")
	if end >= 0 {
		end += len("dhcpc.1.devname=br0\n")
	}
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
		"radio.1.rate.auto=enabled", "radio.1.rate.mcs=auto",
		"radio.1.rfscan=disabled",
		"radio.1.bcmc_l2_filter.status=enabled",
		"radio.1.bgscan.status=disabled",
		"radio.1.antenna.gain=0",
		"radio.1.antenna=-1",
		"radio.1.txpower_mode=auto",
		"radio.1.txpower=auto",
		"radio.1.hard_noisefloor.status=disabled",
		"radio.1.devname=ath0",
		"radio.1.status=enabled",
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
		"radio.2.ieee_mode=11naht40",
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
		"radio.2.devname=ath1",
		"radio.2.status=enabled",
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
		"aaa.1.wpa=3",
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
		"aaa.2.wpa=3",
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
		"vlan.status=enabled",
		"vlan.1.devname=eth0",
		"vlan.1.id=42",
		"# bridge",
		"bridge.status=enabled",
		"bridge.1.devname=br0",
		"bridge.1.fd=1",
		"bridge.1.stp.status=disabled",
		"bridge.1.port.1.devname=eth0",
		"bridge.2.devname=br0.42",
		"bridge.2.fd=1",
		"bridge.2.stp.status=disabled",
		"bridge.2.port.1.devname=eth0.42",
		"bridge.2.port.2.devname=ath0",
		"bridge.2.port.3.devname=ath1",
		"# netconf",
		"netconf.status=enabled",
		"netconf.1.autoip.status=disabled",
		"netconf.1.devname=br0",
		"netconf.1.ip=192.168.1.20",
		"netconf.1.netmask=255.255.255.0",
		"netconf.1.status=enabled",
		"netconf.1.up=enabled",
		"netconf.2.autoip.status=disabled",
		"netconf.2.devname=eth0",
		"netconf.2.ip=0.0.0.0",
		"netconf.2.promisc=enabled",
		"netconf.2.status=enabled",
		"netconf.2.up=enabled",
		"netconf.3.autoip.status=disabled",
		"netconf.3.devname=ath0",
		"netconf.3.ip=0.0.0.0",
		"netconf.3.promisc=enabled",
		"netconf.3.status=enabled",
		"netconf.3.up=disabled",
		"netconf.4.autoip.status=disabled",
		"netconf.4.devname=ath1",
		"netconf.4.ip=0.0.0.0",
		"netconf.4.promisc=enabled",
		"netconf.4.status=enabled",
		"netconf.4.up=disabled",
		"netconf.5.status=enabled",
		"netconf.5.devname=br0.42",
		"netconf.5.ip=0.0.0.0",
		"netconf.5.autoip.status=disabled",
		"netconf.5.promisc=enabled",
		"netconf.5.up=enabled",
		"# dhcpc",
		"dhcpc.status=enabled",
		"dhcpc.1.status=enabled",
		"dhcpc.1.devname=br0",
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
	sys := mustBuildSys(t, s, rec)
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
	sys := mustBuildSys(t, s, u7pg2Record())
	// FID-25 row order (int AAA writer): mgmt → psk → auth_cache →
	// [radius.*] → dynamic_vlan → wpa.1.pairwise → pmf.cipher.
	ordered := []string{
		"aaa.1.wpa.key.1.mgmt=WPA-EAP\n",
		"aaa.1.wpa.psk=letmeinnow\n",
		"aaa.1.auth_cache=enabled\n",
		"aaa.1.dynamic_vlan=0\n",
		"aaa.1.wpa.1.pairwise=CCMP\n",
		"aaa.1.pmf.cipher=AES-128-CMAC\n",
	}
	last := 0
	for _, w := range ordered {
		i := strings.Index(sys, w)
		if i < 0 || i < last {
			t.Fatalf("wpa-eap row order broken (want %q after offset %d):\n%s", w, last, sys)
		}
		last = i + len(w)
	}
	if !strings.Contains(logs.String(), "RADIUS") {
		t.Fatal("expected RADIUS warn for wpa-eap provisioning")
	}
}

// FID-14: the `# vlan` / `# bridge` / `# netconf` status rows are ALWAYS
// on; with no tagged WLAN the vlan table is empty → vlan.status=disabled
// (classic writer: ports×vids empty ⇒ disabled) while the mgmt bridge row
// keeps bridge.status=enabled, and netconf/dhcpc carry their unconditional
// status rows. netconf.1 is the mgmt instance (factory echo
// 192.168.1.20/24 — the mcad validator REQUIRES netconf.1.status, so it
// is emitted even with zero tagged rows); the eth/ath base inventory
// follows (2=eth0, 3/4=ath0/ath1), tagged instances would start at 5.
func TestVlanWiringStatusRowsAlwaysOn(t *testing.T) {
	env := []Wlan{{Name: "net", SSID: "net", Security: "wpa-p",
		Passphrase: "correcthorse", Enabled: true}} // untagged only
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, u7pg2Record())
	for _, want := range []string{
		"# vlan\nvlan.status=disabled\n",
		"bridge.status=enabled\nbridge.1.devname=br0\n",
		"# netconf\nnetconf.status=enabled\n" +
			"netconf.1.autoip.status=disabled\nnetconf.1.devname=br0\n" +
			"netconf.1.ip=192.168.1.20\nnetconf.1.netmask=255.255.255.0\n" +
			"netconf.1.status=enabled\nnetconf.1.up=enabled\n" +
			"netconf.2.autoip.status=disabled\nnetconf.2.devname=eth0\n" +
			"netconf.2.ip=0.0.0.0\nnetconf.2.promisc=enabled\n" +
			"netconf.2.status=enabled\nnetconf.2.up=enabled\n" +
			"netconf.3.autoip.status=disabled\nnetconf.3.devname=ath0\n" +
			"netconf.3.ip=0.0.0.0\nnetconf.3.promisc=enabled\n" +
			"netconf.3.status=enabled\nnetconf.3.up=disabled\n" +
			"netconf.4.autoip.status=disabled\nnetconf.4.devname=ath1\n" +
			"netconf.4.ip=0.0.0.0\nnetconf.4.promisc=enabled\n" +
			"netconf.4.status=enabled\nnetconf.4.up=disabled\n",
		"dhcpc.status=enabled\ndhcpc.1.status=enabled\ndhcpc.1.devname=br0\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("status wiring missing %q in:\n%s", want, sys)
		}
	}
	for _, wrong := range []string{"vlan.1.", "netconf.5.", "bridge.2."} {
		if strings.Contains(sys, wrong) {
			t.Fatalf("no-tagged-wlans build must not emit %q rows:\n%s", wrong, sys)
		}
	}
}

// Regression gate for the mcad validator keys (the root-cause fix behind
// the netconf.1 emission in emitNetconfSection): the AP firmware's mcad
// daemon (fw 6.8.2.15592, Ghidra 0x0040a924 renamed
// mcad_validate_system_cfg) hard-rejects any system_cfg whose parsed tree
// lacks `users.1.status`, `netconf.1.status` or `sshd.status` — it logs
// "[apply-config] Unable to write system.cfg or its contents are invalid."
// and apply-config never runs (live-observed 2026-09-16;
// docs/AP-FIRMWARE-APPLY-PATH.md §3). Every system_cfg generation path
// must carry all three gate rows, each exactly once, with their emitted
// values.
//
// Covered paths: (a) the worked-example device with radios + WLANs
// (full wireless compound) and (b) the no-radio early-return variant
// (u7pg2Record minus radio_table) — the path that now calls
// emitNetconfSection with empty vids. Both generate through
// buildSystemCfg/buildGeneratedSystemCfg (via mustBuildSys); the
// fail-closed U7PG2 gate error path never reaches emission, so there is
// nothing to cover there.
func TestSystemCfgMcadValidatorGateKeysPresent(t *testing.T) {
	gateRows := []string{
		"users.1.status=enabled\n",
		"netconf.1.status=enabled\n",
		"sshd.status=enabled\n",
	}
	// Both cases carry no mgmt facts, so netconf.1 is the factory-echo
	// mgmt instance (the eth/ath base inventory follows; tagged
	// instances would start past the base inventory).
	netconfDefault := "# netconf\nnetconf.status=enabled\n" +
		"netconf.1.autoip.status=disabled\nnetconf.1.devname=br0\n" +
		"netconf.1.ip=192.168.1.20\nnetconf.1.netmask=255.255.255.0\n" +
		"netconf.1.status=enabled\nnetconf.1.up=enabled\n"

	assertGate := func(label, sys string) {
		t.Helper()
		for _, row := range gateRows {
			if n := strings.Count(sys, row); n != 1 {
				t.Fatalf("%s: mcad gate row %q emitted %d times, want exactly 1:\n%s", label, row, n, sys)
			}
		}
		if !strings.Contains(sys, netconfDefault) {
			t.Fatalf("%s: factory-echo netconf.1 block missing:\n%s", label, sys)
		}
	}

	// (a) radios + WLANs: the full worked-example generation path.
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }}, store.NewMemStore(), testLogger())
	assertGate("with-radios", mustBuildSys(t, s, u7pg2Record()))

	// (b) no radio_table: the "no wlan provisioned" early-return path
	// still emits the netconf section (empty vids).
	rec := u7pg2Record()
	delete(rec.Extra, "radio_table")
	s2 := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }}, store.NewMemStore(), testLogger())
	sys2 := mustBuildSys(t, s2, rec)
	if want := "# no wlan provisioned as no radio found\nradio.status=disabled\n"; !strings.Contains(sys2, want) {
		t.Fatalf("case (b) did not hit the no-radio variant:\n%s", sys2)
	}
	assertGate("no-radio", sys2)
}

// FID-15: aaa.<n>.status for open WLANs is gated on the RECORD's wifi_caps
// bit 0x2000 (Device.hasWifiCapability reading `wifi_caps`, NOT fw_caps);
// an absent field means disabled (X.getInt default 0).
func TestOpenHostapdNeedsWifiCapsBit0x2000(t *testing.T) {
	env := []Wlan{{Name: "open", SSID: "opennet", Security: "open", Enabled: true, ID: "idOA"}}
	cases := []struct {
		name     string
		extraVal float64
		fwCaps   float64 // legacy misread target: must be ignored
		wantEn   bool
	}{
		{"absent → disabled (not optimistic)", 0, 0, false},
		{"wifi_caps 0x2000 → enabled", 0x2000, 0, true},
		{"wifi_caps other bits → disabled", 64, 0, false},
		{"fw_caps alone must be ignored", 0, 0x2000, false},
	}
	for _, tc := range cases {
		rec := u7pg2Record()
		if tc.extraVal != 0 {
			rec.Extra["wifi_caps"] = tc.extraVal
		}
		if tc.fwCaps != 0 {
			rec.Extra["fw_caps"] = tc.fwCaps
		}
		s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
		sys := mustBuildSys(t, s, rec)
		have := "aaa.1.status=disabled\n"
		if tc.wantEn {
			have = "aaa.1.status=enabled\n"
		}
		if !strings.Contains(sys, have) {
			t.Fatalf("%s: missing %q in:\n%s", tc.name, have, sys)
		}
	}
}

// FID-51: wireless.<n>.bga_filter is emitted ONLY when the record reports
// wifi_caps bit 64 — absent capability means no row at all (not
// "disabled") — and the value is enabled at our defaults.
func TestBgaFilterGatedOnWifiCapsBit64(t *testing.T) {
	env := workedEnvelope()
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, u7pg2Record())
	if strings.Contains(sys, "bga_filter") {
		t.Fatalf("absent wifi_caps must skip the bga_filter row:\n%s", sys)
	}

	rec := u7pg2Record()
	rec.Extra["wifi_caps"] = float64(0x40)
	sys = mustBuildSys(t, s, rec)
	for _, want := range []string{"wireless.1.bga_filter=enabled\n", "wireless.2.bga_filter=enabled\n"} {
		if !strings.Contains(sys, want) {
			t.Fatalf("wifi_caps 0x40 must emit %q in:\n%s", want, sys)
		}
	}
}

// FID-2: the eth inventory rides in the record passthrough
// (ethernet_table entries with num_port) and feeds the `# vlan` rows
// (vid×port pairs) AND the bridge port sets (`<eth>.<vid>` sub-interfaces
// alongside the vap aths).
func TestEthInventoryInformsVlanRows(t *testing.T) {
	rec := u7pg2Record()
	rec.Extra["ethernet_table"] = []any{
		map[string]any{"num_port": 2.0},
	}
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	for _, want := range []string{
		"vlan.status=enabled\n",
		"vlan.1.devname=eth0\nvlan.1.id=42\n",
		"vlan.2.devname=eth1\nvlan.2.id=42\n",
		"bridge.1.port.1.devname=eth0\nbridge.1.port.2.devname=eth1\n",
		"bridge.2.port.1.devname=eth0.42\nbridge.2.port.2.devname=eth1.42\n" +
			"bridge.2.port.3.devname=ath0\nbridge.2.port.4.devname=ath1\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("eth-inventory wiring missing %q in:\n%s", want, sys)
		}
	}
}

// FID-2 partial-inventory flag: a record with NO ethernet_table falls back
// to the single eth0 uplink and the server warns (wlans with radios).
func TestPartialEthInventoryWarns(t *testing.T) {
	var logs strings.Builder
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }},
		store.NewMemStore(), testWarnLogger(&logs))
	sys := mustBuildSys(t, s, u7pg2Record())
	if !strings.Contains(sys, "vlan.1.devname=eth0\n") {
		t.Fatalf("fallback eth0 uplink missing:\n%s", sys)
	}
	if !strings.Contains(logs.String(), "partial eth inventory") {
		t.Fatalf("expected partial-inventory warn, log:\n%s", logs.String())
	}
}

// FID-2 if_table fallback: 6.8.2 U7PG2 sends no ethernet_table (live
// acceptance 2026-09-16) but reports its interfaces in if_table (observed:
// [{name: "eth0", up: true}]). The ethN names there must feed the vlan rows
// and silence the partial-inventory warn; non-eth interfaces in the same table
// must not leak into the config.
func TestEthInventoryFromIfTable(t *testing.T) {
	var logs strings.Builder
	rec := u7pg2Record()
	rec.Extra["if_table"] = []any{
		map[string]any{"name": "eth0", "up": true},
		map[string]any{"name": "ath0", "up": true},
		map[string]any{"name": "ath1", "up": true},
	}
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }},
		store.NewMemStore(), testWarnLogger(&logs))
	sys := mustBuildSys(t, s, rec)
	if !strings.Contains(sys, "vlan.1.devname=eth0\nvlan.1.id=42\n") {
		t.Fatalf("if_table-derived eth0 vlan row missing:\n%s", sys)
	}
	if strings.Contains(sys, "vlan.2.") {
		t.Fatalf("non-eth iface leaked into vlan rows:\n%s", sys)
	}
	if strings.Contains(logs.String(), "partial eth inventory") {
		t.Fatalf("partial-inventory warn should be silenced by if_table, log:\n%s", logs.String())
	}
}

// FID-2 if_table multi-port: every distinct ethN name in if_table is emitted
// sorted, matching the ethernet_table-derived shape.
func TestEthInventoryFromIfTableMultiPort(t *testing.T) {
	rec := u7pg2Record()
	rec.Extra["if_table"] = []any{
		map[string]any{"name": "eth1", "up": true},
		map[string]any{"name": "eth0", "up": true},
	}
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	for _, want := range []string{
		"vlan.1.devname=eth0\nvlan.1.id=42\n",
		"vlan.2.devname=eth1\nvlan.2.id=42\n",
		"bridge.1.port.1.devname=eth0\nbridge.1.port.2.devname=eth1\n",
		"bridge.2.port.1.devname=eth0.42\nbridge.2.port.2.devname=eth1.42\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("if_table eth inventory wiring missing %q in:\n%s", want, sys)
		}
	}
}

// FID-2 uplink-only fallback: with no ethernet_table and no if_table the
// learned uplink names the port (no hardcoded eth0) and the partial-inventory
// warn still fires. port_table is present here on purpose — its labels must
// not be mistaken for interfaces.
func TestEthInventoryUplinkOnlyStillWarns(t *testing.T) {
	var logs strings.Builder
	rec := u7pg2Record()
	rec.Extra["uplink"] = "eth1"
	rec.Extra["port_table"] = []any{
		map[string]any{"name": "Main", "is_uplink": true, "port_idx": 1.0},
		map[string]any{"name": "Secondary", "is_uplink": false, "port_idx": 2.0},
	}
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }},
		store.NewMemStore(), testWarnLogger(&logs))
	sys := mustBuildSys(t, s, rec)
	if !strings.Contains(sys, "vlan.1.devname=eth1\n") {
		t.Fatalf("learned-uplink vlan row missing:\n%s", sys)
	}
	if !strings.Contains(logs.String(), "partial eth inventory") {
		t.Fatalf("expected partial-inventory warn, log:\n%s", logs.String())
	}
}

// FID-13: the mgmt dhcp client row follows Extra["mgmt_dev"].
func TestDhcpcMgmtRowUsesMgmtDev(t *testing.T) {
	rec := u7pg2Record()
	rec.Extra["mgmt_dev"] = "br0.9"
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if !strings.Contains(sys, "dhcpc.1.devname=br0.9\n") {
		t.Fatalf("dhcpc mgmt row must follow mgmt_dev:\n%s", sys)
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
	sys1 := mustBuildSys(t, s, rec)
	pw1 := systemCfgUsersPassword(t, sys1)
	if !sha512BodyRx.MatchString(pw1) {
		t.Fatalf("users.1.password shape not $6$salt$hash: %q", pw1)
	}
	rec.Extra["ssh_sha512passwd"] = pw1
	sys2 := mustBuildSys(t, s, rec)
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

// runningVAPs builds firmware-shaped vap_table entries for the worked
// example: one entry per enabled WLAN per worked-example radio (every
// caller seeds fixtures from u7pg2Record, whose radio_table names are
// ra0/rai0). Keys are FIRMWARE-VERIFIED — mcad FUN_0041cecc;
// docs/AP-FIRMWARE-APPLY-PATH.md, corroborated by the live log
// "vap_table reports state RUN" (docs/PROTOCOL.md:388): essid/state/
// radio_name/name (the old ssid/status/parent spellings were synthetic
// fixture inventions that hid the settle break; pending capture
// cross-check).
func runningVAPs(wlans []Wlan) []any {
	return vapTable(wlans, "ra0", "rai0")
}

// vapTable is runningVAPs with an explicit radio set, so tests can exercise
// wrong-radio confirmation attempts.
func vapTable(wlans []Wlan, radios ...string) []any {
	var out []any
	ath := 0
	for _, w := range wlans {
		if !w.Enabled {
			continue
		}
		for _, r := range radios {
			out = append(out, map[string]any{
				"essid":      w.SSID,
				"state":      "RUN",
				"radio_name": r,
				"name":       "ath" + strconv.Itoa(ath),
			})
			ath++
		}
	}
	return out
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
	if rec.Extra["wlan_cfg_pending_sha"] != wantHash {
		t.Fatalf("wlan_cfg_pending_sha = %v, want %q", rec.Extra["wlan_cfg_pending_sha"], wantHash)
	}
	cached, _ := rec.Extra["ssh_sha512passwd"].(string)
	if !sha512BodyRx.MatchString(cached) {
		t.Fatalf("ssh_sha512passwd not cached: %q", cached)
	}

	// inform#2: applied matches, envelope unchanged → noop.
	settle := radioBody(rec.CfgVersion)
	settle["vap_table"] = runningVAPs(env)
	body = encryptCBC(t, mustJSON(t, settle), hexKey(t, xkey), testIV)
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
	if rec.Extra["wlan_cfg_pending_sha"] != newHash {
		t.Fatalf("pending hash not refreshed: %v want %q", rec.Extra["wlan_cfg_pending_sha"], newHash)
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
	settle = radioBody(rec.CfgVersion)
	settle["vap_table"] = runningVAPs(env)
	body = encryptCBC(t, mustJSON(t, settle), hexKey(t, xkey), testIV)
	resp = post(t, h, body)
	_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "noop" {
		t.Fatalf("inform#4 type = %v, want noop after confirmation", jm["_type"])
	}
}

// Adoption push (default key) SEEDS the wireless-envelope baseline: the
// cfgversion minted in the push and the envelope it corresponds to are one
// unit. Live finding (2026-09-16 acceptance session): real firmware reaches
// connected-noop on its first re-keyed inform (mgmt_cfg echo) without ever
// receiving system_cfg, so a baseline seeded only by full provisioning would
// never appear and WLAN changes could not be detected as drift.
func TestAdoptionPushSeedsHash(t *testing.T) {
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
	if rec.Extra["wlan_cfg_sha"] != wlanListHash(env) {
		t.Fatalf("adoption push wlan_cfg_sha = %v, want %q", rec.Extra["wlan_cfg_sha"], wlanListHash(env))
	}
	if !containsKey(rec.Authkeys, rec.XAuthkey) {
		t.Fatal("x_authkey not appended")
	}
}

// Live-sequence regression (2026-09-16 acceptance session, U7PG2 on
// BZ.6.8.2): adoption happened with zero WLANs; the device echoed the
// adoption mgmt_cfg's cfgversion on its first re-keyed inform (connected
// noop, no system_cfg ever sent — matches the jar's cfgversion-equal path,
// voidsuper bytes 3287-3306); the operator then added the first WLAN and
// the envelope drift must force full provisioning. Before the seeding fix
// the baseline was never captured on this path and the WLAN change was
// silently never pushed.
func TestAdoptionEchoThenEnvelopeDrift(t *testing.T) {
	env := []Wlan{} // the live AP adopted with an empty wireless config
	st := store.NewMemStore()
	if err := st.Put(store.Device{MAC: testMAC, State: store.StatePending}); err != nil {
		t.Fatal(err)
	}
	h := wiredServer(t, func() []Wlan { return env }, st)

	// inform#1 (factory key): adoption push.
	resp := post(t, h, encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, testDefaultKey), testIV))
	_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, testDefaultKey))
	if jm["_type"] != "setparam" {
		t.Fatalf("inform#1 type = %v, want setparam adoption push", jm["_type"])
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	xkey, cfg := rec.XAuthkey, rec.CfgVersion
	if rec.Extra["wlan_cfg_sha"] != wlanListHash(env) {
		t.Fatalf("adoption push did not seed the empty-envelope baseline: %v", rec.Extra["wlan_cfg_sha"])
	}

	// inform#2 (re-keyed, echoes the mgmt_cfg cfgversion): connected noop.
	resp = post(t, h, encryptCBC(t, mustJSON(t, radioBody(cfg)), hexKey(t, xkey), testIV))
	_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "noop" {
		t.Fatalf("inform#2 type = %v, want noop (adoption mgmt_cfg echo)", jm["_type"])
	}
	rec, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StateAdopted {
		t.Fatalf("state after echo = %d, want adopted", rec.State)
	}

	// Operator configures the first WLAN (live: PUT /api/v1/wireless).
	env = append(env, Wlan{Name: "corp", SSID: "openunifi-test", Security: "wpa-p", Passphrase: "live-validate-2026", VLAN: 1, Enabled: true})

	// inform#3: envelope drift → full provisioning.
	resp = post(t, h, encryptCBC(t, mustJSON(t, radioBody(cfg)), hexKey(t, xkey), testIV))
	_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "setparam" || jm["system_cfg"] == nil {
		t.Fatalf("inform#3 type = %v, want setparam full provisioning after WLAN add", jm["_type"])
	}
	if !strings.Contains(jm["system_cfg"].(string), "aaa.1.ssid=openunifi-test") {
		t.Fatalf("inform#3 system_cfg missing the new SSID:\n%q", jm["system_cfg"])
	}
	rec, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Extra["wlan_cfg_pending_sha"] != wlanListHash(env) {
		t.Fatalf("pending hash not refreshed after provisioning: %v", rec.Extra["wlan_cfg_pending_sha"])
	}

	// inform#4: applied → connected noop again.
	settle := radioBody(rec.CfgVersion)
	settle["vap_table"] = runningVAPs(env)
	resp = post(t, h, encryptCBC(t, mustJSON(t, settle), hexKey(t, xkey), testIV))
	_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "noop" {
		t.Fatalf("inform#4 type = %v, want noop", jm["_type"])
	}
}

// The ENCRYPTED transport (the only one a real U7PG2 uses) is also gated:
// the unsupported-live-WLAN rejection lives in assignedKeyFlow (the single
// emission point both transports share), so a drifted/adopted U7PG2 on
// 6.8.2.15592 with a managed WLAN answers the inform with the typed 501 and
// NEVER emits a system_cfg — and the record is not mutated by the gate.
func TestEncryptedGateBlocksSystemCfg(t *testing.T) {
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

	body := infoBody("")
	body["version"] = "6.8.2.15592"
	resp := post(t, h, encryptCBC(t, mustJSON(t, body), hexKey(t, xkey), testIV))
	if resp.Code != http.StatusNotImplemented {
		t.Fatalf("gated inform status = %d, want 501", resp.Code)
	}
	if strings.Contains(resp.Body.String(), "system_cfg") {
		t.Fatalf("gated inform leaked system_cfg: %q", resp.Body.String())
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StateAdopted || rec.CfgVersion != "aaaa" {
		t.Fatalf("gate must not mutate the record: state=%d cfg=%q", rec.State, rec.CfgVersion)
	}
}

// Firmware normalization (fix 2): the gate must fire on BOTH wire spellings
// of the 6.8.2 build 15592 — the short form and the long BZ.qca956x form
// (docs/PROTOCOL.md:374-375) — and must NOT fire for other firmware or
// other models.
func TestGateFirmwareForms(t *testing.T) {
	env := workedEnvelope()
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	cases := []struct {
		model, fw string
		want      bool
	}{
		{"U7PG2", "6.8.2.15592", true},
		{"U7PG2", "BZ.qca956x_6.8.2+15592.260126.1358", true},
		{"U7PG2", "6.6.55", false},
		{"U7PG2", "", false},
		{"U6LR", "6.8.2.15592", false},
	}
	for _, c := range cases {
		got := s.rejectUnsupportedLiveWLAN(store.Device{Model: c.model, Firmware: c.fw}) != nil
		if got != c.want {
			t.Fatalf("gate(model=%q, fw=%q) = %v, want %v", c.model, c.fw, got, c.want)
		}
	}
}

// With the gate moved into assignedKeyFlow, a plaintext mgmt_cfg-only
// re-send (XAuthkey mismatch → adoption push) from a gated device SUCCEEDS:
// mgmt pushes keep working, only system_cfg emission is blocked.
func TestPlainMgmtResendNotGated(t *testing.T) {
	env := workedEnvelope()
	st := store.NewMemStore()
	rec := store.Device{
		MAC: testMAC, State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
		XAuthkey: "22223333444455556666777788889999",
		Authkeys: []string{"22223333444455556666777788889999"}, Model: "U7PG2",
	}
	if err := st.Put(rec); err != nil {
		t.Fatal(err)
	}
	h := New(Config{WirelessSource: func() []Wlan { return env }, AllowPlainText: true}, st, testLogger()).InformHandler()

	body := infoBody("aaaa")
	body["version"] = "6.8.2.15592"
	body["_authkey"] = "stale-claim" // ≠ rec.XAuthkey → re-send current assignment
	resp := post(t, h, mustJSON(t, body))
	if resp.Code != http.StatusOK {
		t.Fatalf("mgmt-only push from gated device: %d %q", resp.Code, resp.Body.String())
	}
	var jm map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
		t.Fatal(err)
	}
	if jm["_type"] != "setparam" {
		t.Fatalf("mgmt re-send type = %v, want setparam (adoption push)", jm["_type"])
	}
	if _, has := jm["system_cfg"]; has {
		t.Fatalf("mgmt-only push must not carry system_cfg: %v", jm)
	}
	if _, has := jm["mgmt_cfg"]; !has {
		t.Fatalf("mgmt re-send missing mgmt_cfg: %v", jm)
	}
}

// Settle FSM with firmware-shaped vap_table (fix 3): confirmation requires
// every desired SSID RUN on its PLACED radio (placements survive absorption
// via extraPrevWins). A wrong-radio VAP cannot settle the delivery — the
// guarantee the pre-fix placements loss made dead — and exhausted attempts
// flip wlan_cfg_delivery_status to "exhausted".
func TestSettleFSMPlacementsAndExhaustion(t *testing.T) {
	env := workedEnvelope()
	xkey := "11112222333344445555666677778888"

	// helper: provision once and return the handler-bound store state.
	provision := func(t *testing.T, st store.DeviceStore) store.Device {
		t.Helper()
		h := wiredServer(t, func() []Wlan { return env }, st)
		resp := post(t, h, encryptCBC(t, mustJSON(t, radioBody("")), hexKey(t, xkey), testIV))
		if resp.Code != http.StatusOK {
			t.Fatalf("inform#1: %d", resp.Code)
		}
		_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
		if jm["_type"] != "setparam" || jm["system_cfg"] == nil {
			t.Fatalf("inform#1 type = %v, want setparam", jm["_type"])
		}
		rec, err := st.Get(testMAC)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Extra["wlan_cfg_delivery_status"] != "pending" {
			t.Fatalf("delivery_status = %v, want pending", rec.Extra["wlan_cfg_delivery_status"])
		}
		if rec.Extra["wlan_cfg_pending_placements"] == nil {
			t.Fatal("pending placements not recorded at provisioning time")
		}
		return rec
	}

	t.Run("confirmed", func(t *testing.T) {
		st := store.NewMemStore()
		if err := st.Put(store.Device{
			MAC: testMAC, State: store.StateAdopted,
			CfgVersion: "aaaa", AppliedCfg: "",
			XAuthkey: xkey, Authkeys: []string{xkey}, Model: "U7PG2",
			Extra: u7pg2Record().Extra,
		}); err != nil {
			t.Fatal(err)
		}
		rec := provision(t, st)
		h := wiredServer(t, func() []Wlan { return env }, st)
		settle := radioBody(rec.CfgVersion)
		settle["vap_table"] = runningVAPs(env) // corp RUN on ra0 AND rai0
		resp := post(t, h, encryptCBC(t, mustJSON(t, settle), hexKey(t, xkey), testIV))
		if resp.Code != http.StatusOK {
			t.Fatalf("settle inform: %d", resp.Code)
		}
		rec, err := st.Get(testMAC)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Extra["wlan_cfg_delivery_status"] != "confirmed" {
			t.Fatalf("delivery_status = %v, want confirmed", rec.Extra["wlan_cfg_delivery_status"])
		}
		if rec.Extra["wlan_cfg_pending_sha"] != nil {
			t.Fatalf("pending sha not cleared on confirmation: %v", rec.Extra["wlan_cfg_pending_sha"])
		}
	})

	t.Run("wrong-radio-no-settle", func(t *testing.T) {
		st := store.NewMemStore()
		if err := st.Put(store.Device{
			MAC: testMAC, State: store.StateAdopted,
			CfgVersion: "aaaa", AppliedCfg: "",
			XAuthkey: xkey, Authkeys: []string{xkey}, Model: "U7PG2",
			Extra: u7pg2Record().Extra,
		}); err != nil {
			t.Fatal(err)
		}
		rec := provision(t, st)
		h := wiredServer(t, func() []Wlan { return env }, st)
		settle := radioBody(rec.CfgVersion)
		// A RUN VAP on a radio that is NOT in the placement set (ra1 is
		// neither worked-example radio) consumes no placement: need stays
		// positive → no settle. (Pre-fix this settled anyway — the
		// placements map never survived absorption, so the
		// len(placements)==0 fallback decremented need by ANY RUN VAP.)
		settle["vap_table"] = vapTable(env, "ra1")
		resp := post(t, h, encryptCBC(t, mustJSON(t, settle), hexKey(t, xkey), testIV))
		if resp.Code != http.StatusOK {
			t.Fatalf("wrong-radio inform: %d", resp.Code)
		}
		rec, err := st.Get(testMAC)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Extra["wlan_cfg_delivery_status"] != "pending" {
			t.Fatalf("wrong-radio VAP must not settle: status = %v", rec.Extra["wlan_cfg_delivery_status"])
		}
		if rec.Extra["wlan_cfg_pending_sha"] == nil {
			t.Fatal("pending sha dropped without confirmation")
		}
	})

	t.Run("exhausted", func(t *testing.T) {
		// The retry budget check itself (wlanRetryDue): a pending hash with
		// the attempt counter at the cap flips the delivery status to
		// "exhausted" and stops rate-limiting (next inform re-provisions).
		rec := store.Device{Extra: store.JSONMap{
			"wlan_cfg_pending_sha": wlanListHash(env),
			"wlan_cfg_attempt_sha": wlanListHash(env),
			"wlan_cfg_attempts":    wlanMaxAttempts,
		}}
		if due := wlanRetryDue(&rec, time.Now()); due {
			t.Fatal("attempts at cap must not still be retry-due")
		}
		if rec.Extra["wlan_cfg_delivery_status"] != "exhausted" {
			t.Fatalf("delivery_status = %v, want exhausted", rec.Extra["wlan_cfg_delivery_status"])
		}
	})
}

// Section head order (H12): `# unifi` < `# users` in the generated
// config — the Contains loop in the drift test cannot catch a swap,
// these index-of assertions can (int.txt:17208-17216; the `# system`
// section is deliberately omitted: no site locale, factory baseline
// carries no system rows).
func TestSystemCfgSectionHeadOrder(t *testing.T) {
	s := New(Config{}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, u7pg2Record())
	prev := -1
	for _, sec := range []string{"# unifi\n", "# users\n"} {
		i := strings.Index(sys, sec)
		if i < 0 || i < prev {
			t.Fatalf("section head order broken (want %q after offset %d):\n%s", sec, prev, sys)
		}
		prev = i
	}
}

// Multi-VLAN contiguous numbering (fix 3 netconf scope): tagged instances
// number continuously past the factory base inventory (1=br0 mgmt,
// 2=eth0, 3/4=ath0/ath1) — netconf.5/netconf.6 for vid 42/43, and the
// `# vlan` table numbers its eth×vid rows from 1 the same way.
func TestMultiVLANContiguousNumbering(t *testing.T) {
	env := []Wlan{
		{Name: "corp", SSID: "corp", Security: "wpa-p", Passphrase: "correcthorse", VLAN: 42, Enabled: true},
		{Name: "iot", SSID: "iot", Security: "wpa-p", Passphrase: "correcthorse", VLAN: 43, Enabled: true},
	}
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, u7pg2Record())
	for _, want := range []string{
		"netconf.1.devname=br0\n",
		"netconf.5.status=enabled\nnetconf.5.devname=br0.42\n",
		"netconf.6.status=enabled\nnetconf.6.devname=br0.43\n",
		"vlan.1.devname=eth0\nvlan.1.id=42\n",
		"vlan.2.devname=eth0\nvlan.2.id=43\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("multi-VLAN numbering pin missing %q in:\n%s", want, sys)
		}
	}
}

// Self-heal: a record adopted before baseline seeding existed reaches
// connected-noop with no stored baseline — the controller mints a fresh
// cfgversion (forcing exactly one full provisioning on the next inform)
// instead of silently never detecting drift again. This exact state was
// left behind on the live AP by the pre-fix binary.
func TestMissingBaselineForcesProvisioning(t *testing.T) {
	env := workedEnvelope()
	st := store.NewMemStore()
	xkey := "11112222333344445555666677778888"
	extra := u7pg2Record().Extra
	delete(extra, "wlan_cfg_sha")
	if err := st.Put(store.Device{
		MAC: testMAC, State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
		XAuthkey: xkey, Authkeys: []string{xkey}, Model: "U7PG2",
		Extra: extra,
	}); err != nil {
		t.Fatal(err)
	}
	h := wiredServer(t, func() []Wlan { return env }, st)

	// inform#1: applied==current but no baseline → noop reply, cfgversion
	// regenerated for a forced provisioning.
	resp := post(t, h, encryptCBC(t, mustJSON(t, radioBody("aaaa")), hexKey(t, xkey), testIV))
	_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "noop" {
		t.Fatalf("inform#1 type = %v, want noop", jm["_type"])
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.CfgVersion == "aaaa" {
		t.Fatal("missing baseline did not regenerate cfgversion")
	}
	if v, ok := rec.Extra["wlan_cfg_sha"].(string); ok && v != "" {
		t.Fatalf("baseline captured too early: %v", rec.Extra["wlan_cfg_sha"])
	}

	// inform#2 (device still reports "aaaa"): mismatch → full provisioning,
	// baseline captured.
	resp = post(t, h, encryptCBC(t, mustJSON(t, radioBody("aaaa")), hexKey(t, xkey), testIV))
	_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "setparam" || jm["system_cfg"] == nil {
		t.Fatalf("inform#2 type = %v, want forced full provisioning", jm["_type"])
	}
	rec, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Extra["wlan_cfg_pending_sha"] != wlanListHash(env) {
		t.Fatalf("baseline not left pending before runtime proof: %v", rec.Extra["wlan_cfg_pending_sha"])
	}

	// inform#3: applied → plain connected noop (no further forcing).
	settle := radioBody(rec.CfgVersion)
	settle["vap_table"] = runningVAPs(env)
	resp = post(t, h, encryptCBC(t, mustJSON(t, settle), hexKey(t, xkey), testIV))
	_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
	if jm["_type"] != "noop" {
		t.Fatalf("inform#3 type = %v, want noop", jm["_type"])
	}
	if rec, err = st.Get(testMAC); err != nil || rec.State != store.StateAdopted {
		t.Fatalf("state after re-provision = %+v (%v)", rec, err)
	}
}

// ---- failing store / false branches (§8e, §2e) ----------------------------

// failingStore wraps NewMemStore with injectable Get/Update failures.
type failingStore struct {
	store.DeviceStore
	failGet    bool
	failUpdate bool
	// goneUpdate makes UpdateExisting return store.ErrNotFound — the
	// record-vanished-mid-flight race the inform path must answer with the
	// jar's unknown-MAC marker (404), never a 500.
	goneUpdate bool
}

func (f *failingStore) Get(mac string) (store.Device, error) {
	if f.failGet {
		return store.Device{}, errors.New("injected Get failure")
	}
	return f.DeviceStore.Get(mac)
}

func (f *failingStore) Update(mac string, fn func(*store.Device) error) error {
	return f.UpdateExisting(mac, fn)
}

func (f *failingStore) UpdateExisting(mac string, fn func(*store.Device) error) error {
	if f.goneUpdate {
		return store.ErrNotFound
	}
	if f.failUpdate {
		return errors.New("injected Update/UpdateExisting failure")
	}
	return f.DeviceStore.UpdateExisting(mac, fn)
}

// FID-71: a MAC that disappears between the existence check and the RMW
// cycle (e.g. admin delete / expiry) must NOT resurrect, noop, or 500 — the
// jar answers an unknown MAC with the ÖoÓ000 marker → servlet 404.
func TestInformVanishedMACRecord404(t *testing.T) {
	st := &failingStore{DeviceStore: store.NewMemStore(), goneUpdate: true}
	if err := st.Put(store.Device{MAC: testMAC, State: store.StatePending}); err != nil {
		t.Fatal(err)
	}
	h := New(Config{}, st, testLogger()).InformHandler()
	resp := post(t, h, encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, testDefaultKey), testIV))
	if resp.Code != http.StatusNotFound {
		t.Fatalf("vanished record: want 404 (unknown-MAC marker), got %d %q", resp.Code, resp.Body.String())
	}

	// plaintext path: same marker.
	h2 := New(Config{AllowPlainText: true}, st, testLogger()).InformHandler()
	resp = post(t, h2, mustJSON(t, infoBody("")))
	if resp.Code != http.StatusNotFound {
		t.Fatalf("plaintext vanished record: want 404, got %d %q", resp.Code, resp.Body.String())
	}
}

// FID-69: internal inform failures answer HTTP 200 with a noop payload.
// The store Get failure happens before decryption, so no key is established
// and the noop rides out as plain JSON.
func TestStoreGetErrorNoop(t *testing.T) {
	st := &failingStore{DeviceStore: store.NewMemStore(), failGet: true}
	s := New(Config{}, st, testLogger())
	body := encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, testDefaultKey), testIV)
	resp := post(t, s.InformHandler(), body)
	if resp.Code != http.StatusOK || resp.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("want 200 plain-JSON noop on store Get error, got %d %s", resp.Code, resp.Header().Get("Content-Type"))
	}
	var jm map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
		t.Fatal(err)
	}
	if jm["_type"] != "noop" {
		t.Fatalf("internal-error payload = %v, want noop", jm["_type"])
	}
}

// FID-69 + FID-71: a store update failure (here: UpdateExisting wrapping the
// inform RMW) must not persist anything and answers a SEALED noop — the
// per-device key was already established by the successful decryption.
func TestStorePutErrorNoop(t *testing.T) {
	st := &failingStore{DeviceStore: store.NewMemStore(), failUpdate: true}
	if err := st.Put(store.Device{MAC: testMAC, State: store.StatePending}); err != nil {
		t.Fatal(err)
	}
	s := New(Config{}, st, testLogger())
	body := encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, testDefaultKey), testIV)
	resp := post(t, s.InformHandler(), body)
	if resp.Code != http.StatusOK || resp.Header().Get("Content-Type") != "application/x-binary" {
		t.Fatalf("want 200 sealed noop on store update error, got %d %s", resp.Code, resp.Header().Get("Content-Type"))
	}
	flags, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, testDefaultKey))
	_ = flags
	if jm["_type"] != "noop" {
		t.Fatalf("sealed internal-error payload = %v, want noop", jm["_type"])
	}
	// the failed record cycle must not leak into the store
	got, err := st.DeviceStore.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if got.XAuthkey != "" || got.CfgVersion != "" || got.State != store.StatePending {
		t.Fatalf("failed cycle persisted a rotation: %+v", got)
	}
}

func TestHandlerFalseBranches(t *testing.T) {
	h, st := newServerWith(Config{})
	registerPending(t, st)

	// 405 non-POST
	req := httptest.NewRequest(http.MethodGet, "/inform", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /inform: want 405, got %d", rec.Code)
	}

	// > 10 MB body
	resp := post(t, h, bytes.Repeat([]byte{0}, maxInformBody+1))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "payload too large") {
		t.Fatalf("oversize: want 400 payload too large, got %d %q", resp.Code, resp.Body.String())
	}

	// wrong-key encrypted inform
	resp = post(t, h, encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, "99998888777766665555444433332222"), testIV))
	if resp.Code != http.StatusBadRequest || !strings.Contains(resp.Body.String(), "unable to decrypt inform payload") {
		t.Fatalf("wrong key: want 400 unable to decrypt, got %d %q", resp.Code, resp.Body.String())
	}
}

// ---- authkeys pruning (§4) -------------------------------------------------

// After three default-key rotations only the newest two assigned keys may
// decrypt; the first rotated key is gone (GCM requests — lenient CBC would
// accept garbage).
func TestAuthkeysPrunedToTwo(t *testing.T) {
	h, st := newServerWith(Config{})
	registerPending(t, st)

	keys := []string{}
	for i := 0; i < 3; i++ {
		body := encryptGCM(t, mustJSON(t, infoBody("")), hexKey(t, testDefaultKey), testIV)
		resp := post(t, h, body)
		if resp.Code != http.StatusOK {
			t.Fatalf("rotation#%d: status %d", i+1, resp.Code)
		}
		rec, err := st.Get(testMAC)
		if err != nil {
			t.Fatal(err)
		}
		if !containsKey(rec.Authkeys, rec.XAuthkey) {
			t.Fatalf("rotation#%d: XAuthkey missing from Authkeys", i+1)
		}
		if len(rec.Authkeys) > 2 {
			t.Fatalf("rotation#%d: Authkeys not capped (len %d): %v", i+1, len(rec.Authkeys), rec.Authkeys)
		}
		keys = append(keys, rec.XAuthkey)
	}
	// fists key pruned; decrypt must fail → 400.
	resp := post(t, h, encryptGCM(t, mustJSON(t, infoBody("")), hexKey(t, keys[0]), testIV))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("pruned key#1 still decrypts: %d", resp.Code)
	}
	// second-newest key still decrypts (mid-rotation tolerance) → FID-36:
	// the broker re-pushes the existing assignment WITHOUT rotating it.
	resp = post(t, h, encryptGCM(t, mustJSON(t, infoBody("")), hexKey(t, keys[1]), testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("second-newest key rejected: %d", resp.Code)
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.XAuthkey != keys[2] {
		t.Fatalf("stale-key usage must re-push the assignment unchanged; x_authkey = %q, want %q",
			rec.XAuthkey, keys[2])
	}
}

// ---- injection-guard test (§3b) --------------------------------------------

// Newlines in inform-fed values must never reach config rows: the guarded
// writer skips the whole row and logs (fail loud, never emit).
func TestNewlineInjectionGuarded(t *testing.T) {
	rec := u7pg2Record()
	rec.Extra["timezone"] = "UTC\ninjected=1"
	rec.Extra["radio_table"] = []any{
		map[string]any{"name": "ra0", "radio": "ng", "channel": "5\nevil=1",
			"tx_power_mode": "auto", "tx_power": "auto",
			"builtin_antenna": true, "builtin_ant_gain": 0.0},
	}
	s := New(Config{WirelessSource: func() []Wlan { return workedEnvelope() }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, rec)
	if strings.Contains(sys, "injected=1") || strings.Contains(sys, "evil=1") {
		t.Fatalf("injected newline value leaked into system_cfg:\n%s", sys)
	}
	if !strings.Contains(sys, "radio.1.phyname=ra0\n") {
		t.Fatalf("radio rows unexpectedly absent:\n%s", sys)
	}

	// mgmt_cfg: device IP with newline → the doubtful rows are skipped.
	mrec := store.Device{MAC: testMAC, CfgVersion: "aaaa", XAuthkey: testDefaultKey,
		InformURL: "http://10.0.0.5:8080/inform", IP: "10.0.0.1\nbad=1"}
	mgmt := s.buildMgmtCfg(mrec, testDefaultKey)
	if strings.Contains(mgmt, "bad=1") {
		t.Fatalf("newline value leaked into mgmt_cfg: %q", mgmt)
	}
}

// ---- CBC legacy zero-pad fallback (§8d) ------------------------------------

func TestCBCLegacyZeroPadFallback(t *testing.T) {
	// NOT PKCS7-valid: "hello world" + NUL padding to a block boundary.
	msg := []byte("hello world")
	buf := make([]byte, (aes.BlockSize + len(msg)/aes.BlockSize*aes.BlockSize))
	copy(buf, msg)
	buf[11] = 0
	block, err := aes.NewCipher(hexKey(t, testDefaultKey))
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(buf))
	cipher.NewCBCEncrypter(block, testIV).CryptBlocks(ct, buf)
	wire := buildInform(t, testMACRaw(), testFlagEncCBC, testIV, ct)
	pkt, err := inform.ParsePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pkt.DecryptPayload(hexKey(t, testDefaultKey))
	if err != nil {
		t.Fatalf("lenient decrypt failed: %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(got, "\x00"), msg) {
		t.Fatalf("legacy fallback round trip mismatch: %q", got)
	}
}

// ---- discovery table tests (§8a) -------------------------------------------

// mkTLV frames one TLV entry [type:1][len:2 BE][value] (oooO.o00000(B,[B)).
func mkTLV(typ byte, val []byte) []byte {
	out := []byte{typ, byte(len(val) >> 8), byte(len(val) & 0xff)}
	return append(out, val...)
}

// mkDiscoveryPacket frames a modern packet [ver:1][cmd:1][len:2 BE][TLVs…]
// (oooO.o00000() finalize: bytes 2-3 carry the total TLV payload length).
func mkDiscoveryPacket(ver, cmd byte, tlvs ...[]byte) []byte {
	var payload []byte
	for _, t := range tlvs {
		payload = append(payload, t...)
	}
	n := len(payload)
	return append([]byte{ver, cmd, byte(n >> 8), byte(n & 0xff)}, payload...)
}

// mkDiscoveryV2 mirrors the real emulator beacon (docs/PROTOCOL-discovery.md
// §2.3: the v2 builder auto-adds TLV 18 seq then TLV 19 sender MAC before
// the caller TLVs).
func mkDiscoveryV2(seq int, outer [6]byte, ipAdd []byte, extra ...[]byte) []byte {
	tlvs := [][]byte{
		// TLV2: alias, MAC(6)+IP(4) — 10.2.2.1 documented shape
		mkTLV(2, append([]byte{0x00, 0x15, 0x6d, 0x01, 0x00, 0x01}, ipAdd...)),
		mkTLV(1, []byte{0x00, 0x15, 0x6d, 0x01, 0x00, 0x01}), // TLV1 device MAC
	}
	tlvs = append(tlvs, extra...)
	seqB := make([]byte, 4)
	binary.BigEndian.PutUint32(seqB, uint32(seq))
	tlvs = append(tlvs, mkTLV(18, seqB))
	tlvs = append(tlvs, mkTLV(19, outer[:]))
	return mkDiscoveryPacket(2, 6, tlvs...)
}

// BEacon1988 Beacon fixture is TLV11/12/13 extras; discovery_test helpers.
func beaconTLV11(value string) []byte { return mkTLV(11, []byte(value)) }
func beaconTLV21(value string) []byte { return mkTLV(21, []byte(value)) }
func beaconTLV3(value string) []byte  { return mkTLV(3, []byte(value)) }

// beaconAround asserts the pending map content for a given MAC or emptiness.
func beaconPending(t *testing.T, st store.DeviceStore) map[string]string {
	t.Helper()
	pending, err := st.Pending()
	if err != nil {
		t.Fatal(err)
	}
	return pending
}

func TestParseDiscovery(t *testing.T) {
	devMAC := [6]byte{0x00, 0x15, 0x6d, 0x01, 0x00, 0x01}
	outer := [6]byte{0x24, 0xa4, 0x3c, 0xaa, 0xbb, 0xcc}
	ip := []byte{10, 2, 2, 1}

	cases := []struct {
		name   string
		body   []byte
		mac    string
		reject bool
	}{
		{"v2 valid beacon (docs §2.3)", mkDiscoveryV2(1, outer, ip,
			beaconTLV3("BZ.ar7240.v3.1.0.15.150311.1401"),
			beaconTLV21("BZ2"),
			mkTLV(22, []byte("3.1.0")),
			mkTLV(23, []byte{1}),
			mkTLV(10, []byte{0, 0, 0x0e, 0x10}),
		), "00156d010001", false},
		{"byte 0 0x80 rejected (no 0x7f mask)", append([]byte{0x80}, mkDiscoveryV2(1, outer, ip)[1:]...), "", true},
		{"v2 missing TLV19", func() []byte {
			// v2 + TLV1 + TLV18 but no TLV19: decode the frame back and
			// remove the sender-MAC TLV.
			return mkDiscoveryPacket(2, 6,
				mkTLV(1, devMAC[:]), mkTLV(18, []byte{0, 0, 0, 1}))
		}(), "", true},
		{"v2 missing TLV1", mkDiscoveryPacket(2, 6,
			mkTLV(18, []byte{0, 0, 0, 1}), mkTLV(19, outer[:])), "", true},
		{"v2 seq 0", mkDiscoveryV2(0, outer, ip), "", true},
		{"v2 cmd8 parses as reply-only", mkDiscoveryPacket(2, 8,
			mkTLV(1, devMAC[:]), mkTLV(18, []byte{0, 0, 0, 1}), mkTLV(19, outer[:])), "00156d010001", false},
		{"v1 challenge parses (dropped at dispatch)", mkDiscoveryPacket(1, 2,
			mkTLV(1, devMAC[:])), "00156d010001", false},
		{"v0 legacy valid", append(append([]byte{0,
			0x24, 0x5a, 0x4c, 0x11, 0x22, 0x33,
			192, 168, 1, 50,
			0, 0, 0, 1,
		}, []byte("BZ.ar7240.v3.1.0.15.150311.1401")...), 0), "245a4c112233", false},
		{"v0 too short", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, "", true},
		{"unknown version 3", []byte{3, 6, 0, 0}, "", true},
		{"header too short", []byte{1, 6, 0}, "", true},
		{"payload len beyond datagram", []byte{2, 6, 0xff, 0xff}, "", true},
		{"TLV len overruns payload", mkDiscoveryPacket(2, 6,
			mkTLV(1, devMAC[:]), mkTLV(18, []byte{0, 0, 0, 1}), mkTLV(19, outer[:]),
			mkTLV(9, nil)), "", true},
	}
	s := New(Config{}, store.NewMemStore(), testLogger())
	s.setDiscoveryTestIdentity("5a:5a:5a:5a:5a:5a")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, ok := s.parseDiscovery(nil, tc.body)
			if tc.reject {
				if ok {
					t.Fatalf("expected rejection, got %+v", info)
				}
				return
			}
			if !ok {
				t.Fatalf("expected acceptance, got rejection")
			}
			if got := discoveryCanonicalMAC(info.mac); got != tc.mac {
				t.Fatalf("mac=%q, want %q", got, tc.mac)
			}
		})
	}
}

// TestDiscoveryV2Gates walks the pending feed (handleDiscoveryPacket) with
// the real v2 wire shape — verdict item 4/6/7.
func TestDiscoveryV2Gates(t *testing.T) {
	deviceMAC := [6]byte{0x00, 0x15, 0x6d, 0x01, 0x00, 0x01}
	ip := []byte{10, 2, 2, 1}

	t.Run("self-MAC echo dropped", func(t *testing.T) {
		st := store.NewMemStore()
		s := New(Config{}, st, testLogger())
		s.setDiscoveryTestIdentity("24:a4:3c:aa:bb:cc")
		defer func() { s.setDiscoveryTestIdentity("") }()
		s.handleDiscoveryPacket(nil, mkDiscoveryV2(1, [6]byte{0x24, 0xa4, 0x3c, 0xaa, 0xbb, 0xcc}, ip))
		if got := beaconPending(t, st); len(got) != 0 {
			t.Fatalf("self-MAC echo must not record: %v", got)
		}
	})
	t.Run("blocklisted mFi model dropped", func(t *testing.T) {
		st := store.NewMemStore()
		s := New(Config{}, st, testLogger())
		s.setDiscoveryTestIdentity("5a:5a:5a:5a:5a:5a")
		defer func() { s.setDiscoveryTestIdentity("") }()
		s.handleDiscoveryPacket(nil, mkDiscoveryV2(1, [6]byte{0x24, 0xa4, 0x3c, 0xaa, 0xbb, 0xcc}, ip, beaconTLV21("M2M")))
		if got := beaconPending(t, st); len(got) != 0 {
			t.Fatalf("mFi blocklist must not record: %v", got)
		}
	})
	t.Run("cmd8 dropped", func(t *testing.T) {
		st := store.NewMemStore()
		s := New(Config{}, st, testLogger())
		s.setDiscoveryTestIdentity("5a:5a:5a:5a:5a:5a")
		defer func() { s.setDiscoveryTestIdentity("") }()
		s.handleDiscoveryPacket(nil, mkDiscoveryPacket(2, 8,
			mkTLV(1, deviceMAC[:]), mkTLV(18, []byte{0, 0, 0, 1}),
			mkTLV(19, []byte{0x24, 0xa4, 0x3c, 0xaa, 0xbb, 0xcc})))
		if got := beaconPending(t, st); len(got) != 0 {
			t.Fatalf("cmd8 handled outside the announce path: %v", got)
		}
	})
	t.Run("v1 cmd2 challenge records nothing", func(t *testing.T) {
		st := store.NewMemStore()
		s := New(Config{}, st, testLogger())
		s.setDiscoveryTestIdentity("5a:5a:5a:5a:5a:5a")
		defer func() { s.setDiscoveryTestIdentity("") }()
		s.handleDiscoveryPacket(nil, mkDiscoveryPacket(1, 2, mkTLV(1, deviceMAC[:])))
		if got := beaconPending(t, st); len(got) != 0 {
			t.Fatalf("cmd2 challenge must not record: %v", got)
		}
	})
	t.Run("v2 valid beacon pending with keyed note (cmd6 on X feed)", func(t *testing.T) {
		st := store.NewMemStore()
		s := New(Config{}, st, testLogger())
		s.setDiscoveryTestIdentity("5a:5a:5a:5a:5a:5a")
		defer func() { s.setDiscoveryTestIdentity("") }()
		s.handleDiscoveryPacket(nil, mkDiscoveryV2(1, [6]byte{0x24, 0xa4, 0x3c, 0xaa, 0xbb, 0xcc}, ip,
			beaconTLV3("BZ.ar7240.v3.1.0.15.150311.1401"),
			beaconTLV21("BZ2"),
			mkTLV(22, []byte("3.1.0")),
			beaconTLV11("uap-lab"),
			mkTLV(10, []byte{0, 0, 0x0e, 0x10}),
			mkTLV(28, []byte{0, 0, 0, 22}),
		))
		pending := beaconPending(t, st)
		note := pending["00156d010001"]
		for key, want := range map[string]bool{
			"discovery:":  true,
			"uptime=3600": true,
			"version=BZ.ar7240.v3.1.0.15.150311.1401": true,
			"model=BZ2":        true,
			"sshd_port=22":     true,
			"ip=10.2.2.1":      true,
			"hostname=uap-lab": true,
		} {
			if want && !strings.Contains(note, key) {
				t.Fatalf("pending note %q missing %q", note, key)
			}
		}
	})
}

// TestDiscoveryAntiReplay pins the anti-replay contract (item 5/:862-928).
func TestDiscoveryAntiReplay(t *testing.T) {
	outer := [6]byte{0x24, 0xa4, 0x3c, 0xaa, 0xbb, 0xcc}
	ip := []byte{10, 2, 2, 1}
	t.Run("same seq inside window dropped, higher seq accepted", func(t *testing.T) {
		st := store.NewMemStore()
		s := New(Config{}, st, testLogger())
		s.setDiscoveryTestIdentity("5a:5a:5a:5a:5a:5a")
		first := mkDiscoveryV2(5, outer, ip)
		s.handleDiscoveryPacket(nil, first)
		if len(beaconPending(t, st)) != 1 {
			t.Fatal("first sighting must record")
		}
		// same beacon again: drop (seq<=lastSeq inside window)
		s.handleDiscoveryPacket(nil, first)
		if n := len(beaconPending(t, st)); n != 1 {
			t.Fatalf("same-seq repeat inside window must drop; pending=%d", n)
		}
		// higher seq: accept
		s.handleDiscoveryPacket(nil, mkDiscoveryV2(6, outer, ip))
		if n := len(beaconPending(t, st)); n != 1 {
			t.Fatalf("higher seq must re-record same candidate; pending=%d", n)
		}
	})
	t.Run("stale window resets", func(t *testing.T) {
		st := store.NewMemStore()
		s := New(Config{}, st, testLogger())
		st2 := s.discoverySightings()
		st2.mu.Lock()
		st2.byMAC["00:15:6d:01:00:01"] = discoverySighting{lastSeq: 5, lastSeen: time.Now().Add(-6 * time.Second)}
		st2.mu.Unlock()
		if !s.seeDiscovery(discoveryInfo{ver: 2, mac: []byte{0x00, 0x15, 0x6d, 0x01, 0x00, 0x01}, seq: 1}) {
			t.Fatal("stale last-seen must reset and accept")
		}
	})
}

// seeDiscovery: the anti-replay map is keyed by MAC (equality by string
// key), pruning above discoveryPruneThreshold is the documented deviation.
func TestSeeDiscoveryDedupe(t *testing.T) {
	s := New(Config{}, store.NewMemStore(), testLogger())
	info := discoveryInfo{ver: 2, mac: []byte{0x24, 0xa4, 0x3c, 0x11, 0x22, 0x33}}
	if !s.seeDiscovery(mkInfo(info, 5)) {
		t.Fatal("first sighting must pass")
	}
	if s.seeDiscovery(mkInfo(info, 5)) {
		t.Fatal("same seq inside window must drop")
	}
	if !s.seeDiscovery(mkInfo(info, 6)) {
		t.Fatal("higher seq inside window must pass")
	}
}

// mkInfo clones a discoveryInfo so mutation in seeDiscovery state stays nil.
func mkInfo(base discoveryInfo, seq int) discoveryInfo {
	out := base
	out.seq = seq
	out.mac = append([]byte(nil), base.mac...)
	return out
}

// full discovery-record path: MarkPending note shape (real v2 packet).
func TestDiscoveryMarkPendingNote(t *testing.T) {
	st := store.NewMemStore()
	s := New(Config{}, st, testLogger())
	s.setDiscoveryTestIdentity("5a:5a:5a:5a:5a:5a")
	defer func() { s.setDiscoveryTestIdentity("") }()
	s.handleDiscoveryPacket(nil, mkDiscoveryV2(1, [6]byte{0x24, 0xa4, 0x3c, 0xaa, 0xbb, 0xcc},
		[]byte{10, 2, 2, 1},
		beaconTLV21("BZ2"), beaconTLV11("uap-lab"), mkTLV(10, []byte{0, 0, 0x0e, 0x10})))
	pending, err := st.Pending()
	if err != nil {
		t.Fatal(err)
	}
	note := pending["00156d010001"]
	if !strings.Contains(note, "discovery:") {
		t.Fatalf("pending note = %q", note)
	}
	if !strings.Contains(note, "model=BZ2") || !strings.Contains(note, "hostname=uap-lab") {
		t.Fatalf("pending note = %q", note)
	}
}

// ---- GCM adoption parameterization (§8b) -----------------------------------

// TestGCMAdoptionMatrix runs the adoption lifecycle over both cipher
// families. The FIRST packet shape (factory default key + GCM) is the #1
// real-world risk: response must be a GCM-sealed adoption push (flags
// 0x0009, dataVersion untouched 1) that decrypts under the RESPONSE's own
// header AAD rule.
func TestGCMAdoptionMatrix(t *testing.T) {
	for _, family := range []struct {
		name      string
		req       func(t *testing.T, plain []byte, key []byte) []byte
		wantFlags uint16
	}{
		{"cbc", func(t *testing.T, plain []byte, key []byte) []byte {
			return encryptCBC(t, plain, key, testIV)
		}, testFlagEncCBC},
		{"gcm", func(t *testing.T, plain []byte, key []byte) []byte {
			return encryptGCM(t, plain, key, testIV)
		}, testFlagGCM | testFlagEncCBC},
	} {
		t.Run(family.name, func(t *testing.T) {
			h, st := newServerWith(Config{})
			registerPending(t, st)

			// inform#1: factory-fresh device, DEFAULT key.
			body := family.req(t, mustJSON(t, radioBody("")), hexKey(t, testDefaultKey))
			resp := post(t, h, body)
			if resp.Code != http.StatusOK {
				t.Fatalf("inform#1: %d %q", resp.Code, resp.Body.String())
			}
			flags, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, testDefaultKey))
			if flags != family.wantFlags {
				t.Fatalf("inform#1 response flags %04x, want %04x", flags, family.wantFlags)
			}
			if jm["_type"] != "setparam" {
				t.Fatalf("inform#1 type = %v", jm["_type"])
			}
			exactKeys(t, jm, "_type", "server_time_in_utc", "mgmt_cfg")
			rec, err := st.Get(testMAC)
			if err != nil {
				t.Fatal(err)
			}
			xkey := rec.XAuthkey

			// inform#2: re-keyed + cfg applied → noop (same family).
			body = family.req(t, mustJSON(t, radioBody(rec.CfgVersion)), hexKey(t, xkey))
			resp = post(t, h, body)
			if resp.Code != http.StatusOK {
				t.Fatalf("inform#2: %d", resp.Code)
			}
			_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
			if jm["_type"] != "noop" || flags != family.wantFlags {
				t.Fatalf("inform#2 type=%v flags=%04x want noop/%04x", jm["_type"], flags, family.wantFlags)
			}
			rec, err = st.Get(testMAC)
			if err != nil {
				t.Fatal(err)
			}

			// inform#3: cfgversion drift on the assigned key → full provisioning.
			body = family.req(t, mustJSON(t, radioBody("bogus-drift")), hexKey(t, xkey))
			resp = post(t, h, body)
			_, jm = decryptResponse(t, resp.Body.Bytes(), hexKey(t, xkey))
			if jm["_type"] != "setparam" || jm["system_cfg"] == nil {
				t.Fatalf("inform#3 type = %v, want full provisioning", jm["_type"])
			}
			if rec, _ := st.Get(testMAC); rec.State != store.StateAdopting {
				t.Fatalf("inform#3 state %d, want adopting", rec.State)
			}
		})
	}
}

// ---- multi-WLAN system_cfg pin (§8c) ---------------------------------------

// Two enabled WLANs (untagged open + tagged 42 wpa-p — the
// examples/terraform scenario): pins the GLOBAL ath counter (ath0..ath3 in
// radio-sorted, wlan-order), radio.<n>.virtual.* rows appearing only at
// vapIdxOnRadio>0, and br0/br0.42 membership ordering.
func TestMultiWlanSystemCfg(t *testing.T) {
	env := []Wlan{
		{Name: "open", SSID: "opennet", Security: "open", Enabled: true, ID: "id00000000000000000000OA"},
		{Name: "sec", SSID: "secnet", Security: "wpa-p", Passphrase: "correcthorse", VLAN: 42, Enabled: true, ID: "id00000000000000000000SB"},
	}
	s := New(Config{WirelessSource: func() []Wlan { return env }}, store.NewMemStore(), testLogger())
	sys := mustBuildSys(t, s, u7pg2Record())

	// global ath counter: the vap counter assigns ath0..ath3 in radio-sorted,
	// wlan-order (radio1: open,sec; radio2: open,sec). Pin the explicit
	// aaa/wireless devname bindings (virtual rows come earlier in emission
	// order and must not confound the ordering check).
	for _, want := range []string{
		"aaa.1.devname=ath0\n", "aaa.2.devname=ath1\n",
		"aaa.3.devname=ath2\n", "aaa.4.devname=ath3\n",
		"wireless.1.devname=ath0\n", "wireless.2.devname=ath1\n",
		"wireless.3.devname=ath2\n", "wireless.4.devname=ath3\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("global ath counter wiring wrong, missing %q", want)
		}
	}

	// virtual companion rows ONLY where a radio hosts its second vap; the
	// FIRST vap of each radio gets the plain radio.<n>.devname/status rows
	// (FID-5: devname/status for EVERY vap, virtual prefix only >0).
	for _, want := range []string{
		"radio.1.devname=ath0\n", "radio.1.status=enabled\n",
		"radio.2.devname=ath2\n", "radio.2.status=enabled\n",
		"radio.1.virtual.1.devname=ath1\n", "radio.1.virtual.1.status=enabled\n",
		"radio.2.virtual.1.devname=ath3\n", "radio.2.virtual.1.status=enabled\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("missing devname/status row %q", want)
		}
	}
	if strings.Contains(sys, "radio.1.virtual.0") || strings.Contains(sys, "radio.1.virtual.2") {
		t.Fatal("unexpected virtual row indices")
	}

	// bridges: br0 gets eth0 + the two untagged aths; br0.42 carries the
	// eth0.42 sub-interface AND the tagged aths (FID-2 merge model).
	for _, want := range []string{
		"bridge.1.devname=br0\nbridge.1.fd=1\nbridge.1.stp.status=disabled\n" +
			"bridge.1.port.1.devname=eth0\nbridge.1.port.2.devname=ath0\nbridge.1.port.3.devname=ath2\n",
		"bridge.2.devname=br0.42\nbridge.2.fd=1\nbridge.2.stp.status=disabled\n" +
			"bridge.2.port.1.devname=eth0.42\nbridge.2.port.2.devname=ath1\nbridge.2.port.3.devname=ath3\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("bridge wiring mismatch, missing:\n%s\n---system_cfg---\n%s", want, sys)
		}
	}
	if !strings.Contains(sys, "bridge.2.port.3.devname=ath3\n") {
		t.Fatalf("br0.42 port order wrong:\n%s", sys)
	}
	// aaa bridges: untagged vap on br0, tagged on br0.42
	if strings.Contains(sys, "aaa.1.br.devname=br0.42") {
		t.Fatal("untagged vap must sit on br0")
	}
	if !strings.Contains(sys, "aaa.2.br.devname=br0.42\n") ||
		!strings.Contains(sys, "aaa.4.br.devname=br0.42\n") {
		t.Fatal("tagged vaps (aaa.2/aaa.4) must sit on br0.42")
	}
	if !strings.Contains(sys, "aaa.1.authmode=") {
		// open vap: wireless.1.authmode=0, aaa.1 has no wpa rows
		if !strings.Contains(sys, "wireless.1.authmode=0\n") {
			t.Fatal("open vap authmode must be 0")
		}
		if strings.Contains(sys, "aaa.1.wpa=") {
			t.Fatal("open vap must not carry wpa rows")
		}
	}
	if !strings.Contains(sys, "aaa.2.wpa.psk=correcthorse\n") {
		t.Fatal("tagged wpa vap missing psk rows")
	}
	if !strings.Contains(sys, "vlan.1.devname=eth0\nvlan.1.id=42\n") {
		t.Fatal("missing vlan wiring")
	}
}

// ---- mgmt_cfg golden (§8f) --------------------------------------------------

func TestMgmtCfgGolden(t *testing.T) {
	s := New(Config{ControllerURL: "http://10.0.0.5:8080"}, store.NewMemStore(), testLogger())
	d := store.Device{
		MAC: testMAC, CfgVersion: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	d.CfgVersion = "aaaaaaaaaaaaaaaa"
	d.XAuthkey = "11112222333344445555666677778888"
	d.InformURL = "http://10.0.0.9:8080/inform"
	got := s.buildMgmtCfg(d, "ba86f2bbe107c7c57eb5f2690775c712")
	want := "capability=notif,notif-assoc-stat\n" +
		"selfrun_guest_mode=pass\n" +
		"cfgversion=aaaaaaaaaaaaaaaa\n" +
		"led_enabled=true\n" +
		"stun_url=stun://10.0.0.5:3478/\n" +
		"mgmt_url=https://10.0.0.5:8443/manage/site/default\n" +
		"authkey=11112222333344445555666677778888\n" +
		"inform_url=http://10.0.0.5:8080/inform\n" +
		"use_aes_gcm=true\n" +
		"report_crash=true\n"
	if got != want {
		t.Fatalf("mgmt_cfg golden mismatch:\n got %q\nwant %q", got, want)
	}
	// same-key inform → no authkey line
	got2 := s.buildMgmtCfg(d, d.XAuthkey)
	if strings.Contains(got2, "authkey=") {
		t.Fatalf("authkey line must be omitted when keys match: %q", got2)
	}
}

// ---- server_time shape (§8g) ------------------------------------------------

func TestServerTimeDigits(t *testing.T) {
	ts := nowMS()
	if ts == "" || strings.Trim(ts, "0123456789") != "" {
		t.Fatalf("server_time_in_utc must be a digit string: %q", ts)
	}
	// and the JSON responses carry it (framed + unframed paths)
	h, st := newServerWith(Config{AllowPlainText: true})
	registerPending(t, st)
	resp := post(t, h, mustJSON(t, infoBody(""))) // plaintext JSON
	var jm map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
		t.Fatal(err)
	}
	if ts, ok := jm["server_time_in_utc"].(string); !ok || strings.Trim(ts, "0123456789") != "" {
		t.Fatalf("plaintext server_time_in_utc bad: %v", jm["server_time_in_utc"])
	}
}

// ---- users.1 identity across provisionings (§8h) ----------------------------

// Two FULL provisionings separated by inform cycles emit the byte-identical
// users.1.password: the ssh_sha512passwd cache survives the inform pattern
// (reserved Extra key), not just the direct-call transitively pinned case.
func TestUsers1PasswordIdenticalAcrossProvisionings(t *testing.T) {
	st := store.NewMemStore()
	xk := "11112222333344445555666677778888"
	if err := st.Put(store.Device{MAC: testMAC, State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa", XAuthkey: xk, Authkeys: []string{xk}}); err != nil {
		t.Fatal(err)
	}
	env := []Wlan{{Name: "net", SSID: "net", Security: "open", Enabled: true}}
	s := New(Config{WirelessSource: func() []Wlan { return env }}, st, testLogger())
	h := s.InformHandler()

	pw := ""
	for i := 0; i < 2; i++ {
		if i == 1 {
			// A heartbeat inform runs absorbInform (an Extra overwrite →
			// the cache would be lost without preservation).
			resp := post(t, h, encryptCBC(t, mustJSON(t, infoBody("aaaa")), hexKey(t, xk), testIV))
			if resp.Code != http.StatusOK {
				t.Fatalf("heartbeat: %d", resp.Code)
			}
			// admin changes the envelope → drift bump → full provisioning again.
			env[0].SSID = "net" + strconv.Itoa(i)
		}
		resp := post(t, h, encryptCBC(t, mustJSON(t, infoBody("zzz-drift")), hexKey(t, xk), testIV))
		if resp.Code != http.StatusOK {
			t.Fatalf("prov#%d: %d", i+1, resp.Code)
		}
		_, jm := decryptResponse(t, resp.Body.Bytes(), hexKey(t, xk))
		sys := jm["system_cfg"].(string)
		pwI := systemCfgUsersPassword(t, sys)
		if pw != "" && pw != pwI {
			t.Fatalf("users.1.password changed across provisionings: %q vs %q", pw, pwI)
		}
		pw = pwI
	}
	if !sha512BodyRx.MatchString(pw) {
		t.Fatalf("users.1.password shape broken: %q", pw)
	}
}

// ---- radio_table preservation / refresh (§8i) -------------------------------

func TestRadioTablePreserveAndRefresh(t *testing.T) {
	h, st := newServerWith(Config{AllowPlainText: true})
	registerAdopted(t, st, "aaaa", "11112222333344445555666677778888")
	xk := "11112222333344445555666677778888"

	// full inform WITH radio_table.
	full := infoBody("aaaa")
	full["_authkey"] = xk
	full["radio_table"] = u7pg2Record().Extra["radio_table"]
	resp := post(t, h, mustJSON(t, full))
	if resp.Code != http.StatusOK {
		t.Fatalf("full inform: %d %q", resp.Code, resp.Body.String())
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Extra["radio_table"] == nil {
		t.Fatal("radio_table missing after full inform")
	}

	// sparse heartbeat WITHOUT radio_table → preserved (fillIfAbsent).
	sparse := infoBody("aaaa")
	sparse["_authkey"] = xk
	delete(sparse, "radio_table") // infoBody has none anyway; be explicit
	resp = post(t, h, mustJSON(t, sparse))
	if resp.Code != http.StatusOK {
		t.Fatalf("sparse inform: %d", resp.Code)
	}
	rec, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Extra["radio_table"] == nil {
		t.Fatal("radio_table wiped by sparse heartbeat")
	}

	// full inform with an UPDATED radio_table → refreshed (prev must NOT win).
	updated := infoBody("aaaa")
	updated["_authkey"] = xk
	updated["radio_table"] = []any{map[string]any{"name": "ra0", "radio": "ng", "channel": 6.0}}
	resp = post(t, h, mustJSON(t, updated))
	if resp.Code != http.StatusOK {
		t.Fatalf("refresh inform: %d", resp.Code)
	}
	rec, err = st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := rec.Extra["radio_table"].([]any)
	if len(rt) != 1 {
		t.Fatalf("radio_table not refreshed (len %d): %v", len(rt), rec.Extra["radio_table"])
	}
	first, _ := rt[0].(map[string]any)
	if first["name"] != "ra0" || first["channel"] != 6.0 {
		t.Fatalf("refreshed radio_table wrong: %v", first)
	}
}

// ---- FID-22: users.1 hash variant branches on the SHA-512 capability ----

// Golden vectors from OpenSSL 3.x (`openssl passwd -1 -salt S P`) — the
// glibc/Apache md5crypt the classic controller's commons-codec Md5Crypt
// mirrors byte-for-byte.
func TestMD5CryptVectorTests(t *testing.T) {
	vv := []struct{ pw, salt, want string }{
		{"ubnt", "abcd1234", "$1$abcd1234$UPyGHXXYPYzFOkGgbE7uo0"},
		{"ubnt", "testsalt", "$1$testsalt$phdRQ10fojI.hrEiZfZVU/"},
		{"ubnt", "01234567", "$1$01234567$vigV.l7xN3EZbzxgDJoUg."},
		{"ubnt", "/0ab", "$1$/0ab$2Pwalw/7N95C047k71opS0"},
		{"letmeinnow", "abcd1234", "$1$abcd1234$7IaawFGkVaJc9HfqkbLCx."},
		{"letmeinnow", "testsalt", "$1$testsalt$YP2koC9HPVZjUpyIa288z."},
	}
	for _, v := range vv {
		got := "$1$" + v.salt + "$" + md5CryptRaw([]byte(v.pw), []byte(v.salt))
		if got != v.want {
			t.Errorf("md5crypt(%q, %q)\n got %s\nwant %s", v.pw, v.salt, got, v.want)
		}
		if !md5CryptMatches(v.pw, v.want) {
			t.Errorf("stored-hash self-check rejected %q", v.want)
		}
	}
}

// FID-22: the users.1 password variant follows Device.supportsSha512Password
// ((fw_caps & 0x400) == 0x400, Default-0 semantics) — records reporting the
// bit get $6$, the rest get $1$.
func TestUsers1HashBranchesOnFwCaps(t *testing.T) {
	s := New(Config{}, store.NewMemStore(), testLogger())

	sys := mustBuildSys(t, s, u7pg2Record()) // fw_caps 0x0400 seeded
	if pw := systemCfgUsersPassword(t, sys); !sha512BodyRx.MatchString(pw) {
		t.Fatalf("fw_caps 0x400 must pick $6$ sha512: %q", pw)
	}

	rec := u7pg2Record()
	rec.Extra["fw_caps"] = 0.0 // capability reported, bit absent → md5 branch
	sys = mustBuildSys(t, s, rec)
	pw1 := systemCfgUsersPassword(t, sys)
	if !strings.HasPrefix(pw1, "$1$") || len(pw1) != len("$1$")+8+1+22 {
		t.Fatalf("fw_caps 0 must pick $1$ md5crypt: %q", pw1)
	}
	// md5 cache stability: same record builds emit the same $1$ value.
	rec.Extra["ssh_md5passwd"] = pw1
	if pw2 := systemCfgUsersPassword(t, mustBuildSys(t, s, rec)); pw1 != pw2 {
		t.Fatalf("md5 users.1.password not stable: %q vs %q", pw1, pw2)
	}

	rec = u7pg2Record()
	delete(rec.Extra, "fw_caps") // absent field ⇒ capability 0 (X.getInt default)
	if pw := systemCfgUsersPassword(t, mustBuildSys(t, s, rec)); !strings.HasPrefix(pw, "$1$") {
		t.Fatalf("absent fw_caps must fall to the $1$ branch: %q", pw)
	}
}

// ---- FID-23: an unrenderable SSH password fails the provisioning build ----

func TestUsers1PasswordGenerationFailureFailsBuild(t *testing.T) {
	var logs strings.Builder
	s := New(Config{}, store.NewMemStore(), testWarnLogger(&logs))
	rec := u7pg2Record()
	rec.Extra["fw_caps"] = 0.0 // md5 branch so the injectable salt seam applies
	rec.Extra["ssh_md5passwd"] = ""
	prev := randAlphaSalt
	randAlphaSalt = func(int) (string, error) { return "", errors.New("rand unavailable") }
	defer func() { randAlphaSalt = prev }()

	if _, err := s.buildSystemCfg(rec); err == nil {
		t.Fatal("failed salt generation must fail the system_cfg build, not emit an empty users.1.password")
	}
}

// ---- FID-8: an undecryptable inform never produces a pending sighting ----

func TestUnknownMACRottenPayloadNotPending(t *testing.T) {
	h, st := newServerWith(Config{})
	// Encrypted with a non-default key on an unregistered MAC: the broker can
	// only try the factory key at this state, so decryption fails.
	body := encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, "99998888777766665555444433332222"), testIV)
	resp := post(t, h, body)
	if resp.Code != http.StatusBadRequest ||
		!strings.Contains(resp.Body.String(), "unable to decrypt inform payload") {
		t.Fatalf("rotten unknown-MAC payload: want 400, got %d %q", resp.Code, resp.Body.String())
	}
	pending, err := st.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if pending[testMAC] != "" {
		t.Fatalf("MarkPending must not fire before a successful decrypt (FID-8): %v", pending)
	}
}

// ---- FID-35: payload MAC must match the packet header MAC ----

func TestPayloadMACMismatchRejected(t *testing.T) {
	h, st := newServerWith(Config{})
	registerPending(t, st)

	body := infoBody("")
	body["mac"] = "aa:bb:cc:dd:ee:00" // does NOT match the test header MAC aa…ff
	resp := post(t, h, encryptCBC(t, mustJSON(t, body), hexKey(t, testDefaultKey), testIV))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("mac mismatch: want 400, got %d %q", resp.Code, resp.Body.String())
	}
	// Nothing leaked into the record (no RMW cycle ran).
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != store.StatePending || rec.XAuthkey != "" || rec.Model != "" {
		t.Fatalf("mismatched-MAC inform mutated the record: %+v", rec)
	}

	// Missing/invalid mac in the payload body rejects the same way.
	body2 := infoBody("")
	delete(body2, "mac")
	resp = post(t, h, encryptCBC(t, mustJSON(t, body2), hexKey(t, testDefaultKey), testIV))
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("missing payload mac: want 400, got %d", resp.Code)
	}

	// FID-35 applies to UNREGISTERED MACs too (jar privatesuper runs the
	// consistency check before any recording step): no pending sighting.
	h2, st3 := newServerWith(Config{})
	body3 := infoBody("")
	body3["mac"] = "aa:bb:cc:dd:ee:00"
	resp = post(t, h2, encryptCBC(t, mustJSON(t, body3), hexKey(t, testDefaultKey), testIV))
	pending, _ := st3.Pending()
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("unknown-MAC mismatch: want 400, got %d", resp.Code)
	}
	if len(pending) != 0 {
		t.Fatalf("mismatched unknown-MAC inform must not record a pending sighting: %v", pending)
	}
}

// ---- FID-17: unifi.siteid / unifi.reporterid rows ----

func TestSystemCfgIdentityRows(t *testing.T) {
	s := New(Config{}, store.NewMemStore(), testLogger())

	sys := mustBuildSys(t, s, u7pg2Record())
	if want := "\nunifi.siteid=default\n"; !strings.Contains(sys, want) {
		t.Fatalf("missing unifi.siteid row in:\n%s", sys)
	}

	rec := u7pg2Record()
	rec.Extra["anonymous_controller_id"] = "anonctrlid42"
	rec.Extra["anonymous_site_id"] = "anonsiteid42"
	sys = mustBuildSys(t, s, rec)
	for _, want := range []string{
		"unifi.anonymous_controller_id=anonctrlid42\n",
		"unifi.anonymous_site_id=anonsiteid42\n",
		// reporterid mirrors the controller anonymous id (same jar source).
		"unifi.reporterid=anonctrlid42\n",
	} {
		if !strings.Contains(sys, want) {
			t.Fatalf("missing %q in:\n%s", want, sys)
		}
	}
	// String.txt:1851-1897 pair array row order: anonymous_site_id BEFORE
	// reporterid (reporterid was emitted before anonymous_site_id until the
	// order was verified against the decompiled builder).
	ordered := []string{
		"unifi.anonymous_controller_id=anonctrlid42\n",
		"unifi.anonymous_site_id=anonsiteid42\n",
		"unifi.reporterid=anonctrlid42\n",
		"unifi.siteid=default\n",
	}
	last := 0
	for _, w := range ordered {
		i := strings.Index(sys, w)
		if i < 0 || i < last {
			t.Fatalf("unifi row order broken (want %q after offset %d):\n%s", w, last, sys)
		}
		last = i + len(w)
	}

	rec = u7pg2Record()
	rec.Extra["anonymous_controller_id"] = "only-controller-id"
	sys = mustBuildSys(t, s, rec)
	if !strings.Contains(sys, "unifi.reporterid=only-controller-id\n") {
		t.Fatalf("reporterid must ride the controller anonymous id:\n%s", sys)
	}
}

// ---- FID-52: mgmt_url (and unifi.siteid, FID-17) carry the SITE NAME ----

func TestMgmtCfgAndSiteidFollowSiteName(t *testing.T) {
	s := New(Config{ControllerURL: "http://10.0.0.5:8080"}, store.NewMemStore(), testLogger())
	d := u7pg2Record()
	d.SiteID = "building-a"
	got := s.buildMgmtCfg(d, d.XAuthkey)
	if !strings.Contains(got, "mgmt_url=https://10.0.0.5:8443/manage/site/building-a\n") {
		t.Fatalf("mgmt_url must use the site name:\n%s", got)
	}
	if !strings.Contains(got, "inform_url=http://10.0.0.5:8080/inform\n") {
		t.Fatalf("explicit controller URL must emit inform_url:\n%s", got)
	}
	sys := mustBuildSys(t, s, d)
	if !strings.Contains(sys, "unifi.siteid=building-a\n") {
		t.Fatalf("unifi.siteid must use the site name:\n%s", sys)
	}
}

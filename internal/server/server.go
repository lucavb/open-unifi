// Package server hosts the adoption-capable UniFi inform controller.
//
// HTTP semantics per docs/PROTOCOL.md §1–§3; UDP discovery per §4.
// Counter/tabulation realities are logged via slog (no Prometheus here — the
// internal/metrics lane owns that wiring separately).
package server

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lucabecker/open-unifi/internal/inform"
	"github.com/lucabecker/open-unifi/internal/store"
)

// maxInformBody matches the classic controller's 10 MB inform body cap.
const maxInformBody = 10 * 1024 * 1024

// defaultKeyHex is the factory pre-adoption AES key (docs/PROTOCOL.md §2).
const defaultKeyHex = "ba86f2bbe107c7c57eb5f2690775c712"

// Wire-shape constants of the classic controller (FID-54 dedupe: every
// literal here recurs in more than one emission site).
const (
	defaultInformPort   = "8080" // unifi.http.port default
	defaultMgmtPort     = "8443" // manage-port fallback  (mgmt_url)
	defaultStunPort     = "3478" // unifi.stun.port default
	defaultSiteName     = "default"
	defaultTimezone     = "UTC"
	informFactoryNotype = "inform:factory"
)

// informKnownTypes labels the NON-EMPTY request _type values the inform
// state machine processes specially. Real firmware sends its periodic
// status informs with an EMPTY _type (live evidence: U7PG2 on BZ.6.8.2,
// captured during the 2026-09-16 acceptance session), and the jar runs its
// main dispatcher (voidsuper — docs/PROTOCOL-mgmt.md §6.2) on exactly those
// informs: adoption, re-key, and provisioning all ride the empty-_type
// status inform. informTypeGentleNoop therefore lets "" through and only
// noops unknown NON-EMPTY types.
var informKnownTypes = map[string]bool{
	"info": true, "heartbeat": true, "cmd": true,
	"setparam": true, "setparam-ack": true, "cmd-ack": true,
	"alarms": true, "disconnect": true,
}

// informTypeGentleNoop reports whether the request _type falls outside the
// inform state machine: the empty _type IS the main-dispatcher status
// inform (see informKnownTypes), so only unknown NON-EMPTY types get the
// gentle noop.
func informTypeGentleNoop(rtype string) bool {
	return rtype != "" && !informKnownTypes[rtype]
}

// Config describes the runtime configuration of the inform server.
type Config struct {
	// InformListenAddr is the TCP listen address for the inform endpoint (":8080").
	InformListenAddr string

	// DiscoveryListen enables the UDP discovery listener.
	DiscoveryListen bool

	// DiscoveryPort is the UDP port for discovery (classically 10001).
	DiscoveryPort int

	// ControllerURL is the base URL devices are pointed at during adoption,
	// e.g. "http://10.0.0.5:8080".
	ControllerURL string

	// AllowPlainText permits unencrypted JSON inform bodies (classic
	// controllers reject these unless pre-adoption plain text inform is on).
	// Default false.
	AllowPlainText bool

	// WirelessSource supplies the WLAN envelope (admin-API mirror: Wlan
	// struct) that system_cfg provisioning renders and hashes for drift
	// detection. nil ⇒ empty list ⇒ no wlans provisioned.
	WirelessSource func() []Wlan

	// SSHPassword overrides the default SSH password ("ubnt") hashed into
	// system_cfg users.1. SECURITY NOTE: this string lives in server memory
	// and, by protocol design, travels VERBATIM (hashed) inside the
	// provisioned config; the passphrase itself never appears in mgmt_cfg.
	// Treat records/config containing the hash as credentials.
	SSHPassword string
}

// Server serves the UniFi inform protocol used for AP adoption.
type Server struct {
	cfg Config
	st  store.DeviceStore
	lg  *slog.Logger

	seenMu sync.Mutex
	seenAt map[string]time.Time // discovery dedupe per MAC
}

// New builds a Server. A nil logger falls back to slog.Default().
func New(cfg Config, st store.DeviceStore, lg *slog.Logger) *Server {
	if lg == nil {
		lg = slog.Default()
	}
	return &Server{
		cfg:    cfg,
		st:     st,
		lg:     lg,
		seenAt: map[string]time.Time{},
	}
}

// InformHandler returns the HTTP handler implementing POST /inform semantics.
func (s *Server) InformHandler() http.Handler {
	return http.HandlerFunc(s.handleInform)
}

// ---- wire helpers ---------------------------------------------------------

// nowMS is the ms-epoch string always present in every inform response.
func nowMS() string {
	return strconv.FormatInt(time.Now().UnixMilli(), 10)
}

// randKeyChars returns n random lowercase hex characters drawn from the
// alphabet "0123456789abcdef" (crypto/rand), matching the classic controller's
// C.o00000("0123456789abcdef", 32) key generation.
func randKeyChars(n int) (string, error) {
	const alphabet = "0123456789abcdef"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[b%16]
	}
	return string(out), nil
}

// mustKeyChars is gone: rand failures must surface as errors (advance →
// HTTP 500) instead of silently emitting empty authkey=/cfgversion= lines.
// keyChars returns n random lowercase hex chars, logging the (effectively
// impossible) crypto/rand failure as an error.
func (s *Server) keyChars(n int) (string, error) {
	v, err := randKeyChars(n)
	if err != nil {
		s.lg.Error("key generation failed", "err", err)
		return "", fmt.Errorf("key generation: %w", err)
	}
	return v, nil
}

// str fetches a string field from the inform body map.
func str(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// canonMACFromHeader hex-encodes raw 6 header MAC bytes to canonical form.
func canonMACFromHeader(raw []byte) string {
	if len(raw) != 6 {
		return ""
	}
	return strings.ToLower(hex.EncodeToString(raw))
}

// keyCandidates lists lowercase deduped hex keys to try for decryption:
// every record Authkeys entry, then the factory default key.
func keyCandidates(rec store.Device) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range rec.Authkeys {
		k = strings.ToLower(k)
		if k != "" && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	def := defaultKeyHex
	if !seen[def] {
		out = append(out, def)
	}
	return out
}

// addKey appends a lowercase key to the deduped authkey list.
func addKey(keys []string, key string) []string {
	key = strings.ToLower(key)
	for _, k := range keys {
		if strings.ToLower(k) == key {
			return keys
		}
	}
	return append(keys, key)
}

// writeJSONErr writes a plain-JSON error body.
func writeJSONErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ---- HTTP entry ----------------------------------------------------------

func (s *Server) handleInform(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxInformBody+1))
	if err != nil {
		s.lg.Debug("inform: body read error", "err", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(body) > maxInformBody {
		writeJSONErr(w, http.StatusBadRequest, "payload too large")
		return
	}

	if pkt, perr := inform.ParsePacket(body); perr == nil {
		// Plaintext GATE (classic: InformServlet refuses plain informs
		// outside debug builds, docs/PROTOCOL-mgmt.md §5 L262-265 — that
		// check covers framed packets with no encryption flags too, since
		// §5 derives _encrypted from the header):
		if pkt.Flags&(inform.FlagEncCBC|inform.FlagGCM) == 0 && !s.cfg.AllowPlainText {
			writeJSONErr(w, http.StatusBadRequest, "Plain text inform is not supported")
			return
		}
		if pkt.Flags&(inform.FlagEncCBC|inform.FlagGCM) == 0 {
			s.handlePacketPlain(w, pkt)
			return
		}
		s.handlePacket(w, pkt, body)
		return
	}

	// Not a framed packet: maybe a plaintext JSON inform.
	var jm map[string]any
	if jerr := json.Unmarshal(body, &jm); jerr != nil || jm == nil {
		s.lg.Debug("inform: not a packet and not a JSON object")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !s.cfg.AllowPlainText {
		writeJSONErr(w, http.StatusBadRequest, "Plain text inform is not supported")
		return
	}
	mac, merr := store.CanonicalMAC(str(jm, "mac"))
	if merr != nil {
		s.lg.Debug("inform-plain: unparseable mac in body", "err", merr)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.handlePlain(w, mac, jm)
}

// plainGateKeyBytes returns a usable-length AES key for the PLAIN framed
// path: DecryptPayload's no-encryption-flags branch ignores the key entirely
// and only inflates zlib/parses snappy — any valid key works.
func plainGateKeyBytes() ([]byte, error) {
	return inform.DecodeKeyHex(inform.DefaultKeyHex)
}

// handlePacketPlain processes a FRAMED packet that carries no encryption
// flags (plain inform, possibly zlib-compressed). MAC comes from the packet
// header; payload goes through pkt.DecryptPayload so zlib-only (0x02)
// packets are inflated and snappy-flagged ones are rejected with the
// classic error.
func (s *Server) handlePacketPlain(w http.ResponseWriter, pkt *inform.Packet) {
	mac := canonMACFromHeader(pkt.MAC)
	if mac == "" {
		s.lg.Debug("inform-plain: empty MAC in header")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	kb, kerr := plainGateKeyBytes()
	if kerr != nil {
		s.lg.Error("inform-plain: gate key decode failed", "err", kerr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	p, derr := pkt.DecryptPayload(kb)
	if derr != nil {
		s.lg.Debug("inform-plain: payload parse failed", "err", derr)
		writeJSONErr(w, http.StatusBadRequest, "unable to parse inform payload")
		return
	}
	var jm map[string]any
	if uerr := json.Unmarshal(p, &jm); uerr != nil || jm == nil {
		s.lg.Debug("inform-plain: payload not a JSON object")
		writeJSONErr(w, http.StatusBadRequest, "unable to parse inform payload")
		return
	}
	s.handlePlain(w, mac, jm)
}

// handlePacket processes one binary (CBC or GCM) inform.
// informRejectError is a jar-parity protocol rejection that maps to a bare
// HTTP status with no body (InformServlet §143-182: `Object.ÕoÓ000` marker
// → 400, `Object.ÖoÓ000` marker → 404), as opposed to an uncontrolled
// internal error (which FID-69 maps onto a sealed noop response).
type informRejectError struct {
	status int
	reason string
}

func (e *informRejectError) Error() string { return e.reason }

// errMACMismatch (FID-35): the MAC inside the decrypted payload does not
// match the packet header MAC (devmgr §7771-7786, "mac inconsistent in
// header and payload" → Object.ÕoÓ000 → 400).
func errMACMismatch(hdr, payload string) error {
	return &informRejectError{status: http.StatusBadRequest,
		reason: "mac inconsistent in header[" + hdr + "] and payload[" + payload + "]"}
}

// errDefaultKeyRejected (FID-1): an adopted device must never re-authenticate
// with the factory key (devmgr "used default key in X state, reject it" →
// Object.ÖoÓ000 → 404).
var errDefaultKeyRejected = &informRejectError{status: http.StatusNotFound,
	reason: "default key used by an adopted device"}

// decryptPayloadWithKeys runs the candidate-key loop: the first candidate
// whose plaintext parses as a JSON object wins (JSON validation is required
// because the legacy lenient CBC unpad makes wrong-key decrypts "succeed"
// with garbage bytes rather than erroring).
func decryptPayloadWithKeys(pkt *inform.Packet, keys []string) (map[string]any, string, []byte, error) {
	var jm map[string]any
	for _, k := range keys {
		kb, derr := inform.DecodeKeyHex(k)
		if derr != nil {
			continue
		}
		p, derr := pkt.DecryptPayload(kb)
		if derr != nil {
			continue
		}
		if jerr := json.Unmarshal(p, &jm); jerr != nil || jm == nil {
			jm = nil // wrong key (lenient garbage) or malformed payload
			continue
		}
		return jm, strings.ToLower(k), kb, nil
	}
	return nil, "", nil, errors.New("no key produced a valid JSON payload")
}

// payloadMACMatches enforces FID-35: the decrypted body's mac field (when
// present) must canonicalize to the header MAC. The classic controller
// rejects the whole inform otherwise (voidsuper §7771-7786).
func payloadMACMatches(hdrMAC string, jm map[string]any) bool {
	m, ok := jm["mac"].(string)
	if !ok || m == "" {
		return false
	}
	c, err := store.CanonicalMAC(m)
	return err == nil && c == hdrMAC
}

func (s *Server) handlePacket(w http.ResponseWriter, pkt *inform.Packet, body []byte) {
	mac := canonMACFromHeader(pkt.MAC)
	if mac == "" {
		s.lg.Debug("inform: empty MAC in header")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rec, err := s.st.Get(mac)
	if errors.Is(err, store.ErrNotFound) {
		// Un-registered factory device. The classic controller decrypts
		// with the factory key alone (InformServlet §505-531: unknown MAC
		// ⇒ single default-key candidate) and records the sighting — but
		// only AFTER the payload proved decryptable (FID-8) and its MAC
		// matched (FID-35). A garbage/mis-keyed payload touches no state.
		s.lg.Debug("inform: unregistered device", "mac", mac)
		jm, _, _, derr := decryptPayloadWithKeys(pkt, []string{defaultKeyHex})
		if derr != nil {
			s.lg.Debug("inform: no key produced a valid JSON payload", "mac", mac, "tried", 1)
			writeJSONErr(w, http.StatusBadRequest, "unable to decrypt inform payload")
			return
		}
		// FID-35: the jar's MAC-consistency check (privatesuper offsets
		// 13-50) precedes every recording step, unknown devices included.
		if !payloadMACMatches(mac, jm) {
			mm, _ := jm["mac"].(string)
			s.lg.Error("invalid inform (mac inconsistent in header and payload)", "mac", mac, "payloadMac", mm)
			writeJSONErr(w, http.StatusBadRequest, errMACMismatch(mac, mm).Error())
			return
		}
		if merr := s.st.MarkPending(mac, informFactoryNotype); merr != nil {
			s.lg.Warn("inform: mark pending failed", "mac", mac, "err", merr)
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		// FID-69: internal inform failures answer a 200 noop, not 500
		// (classic: devmgr sentinels ØoÓ000/øOÓ000 flow back through the
		// servlet as a real response for everything but the explicit
		// unknown-device marker).
		s.internalNoopResponse(w, pkt, nil, "", false, mac, "store error", err)
		return
	}
	s.lg.Debug("inform: packet", "mac", mac, "flags", fmt.Sprintf("0x%04x", pkt.Flags), "bodyLen", len(body))

	jm, usedKey, keyBytes, derr := decryptPayloadWithKeys(pkt, keyCandidates(rec))
	if derr != nil {
		s.lg.Debug("inform: no key produced a valid JSON payload", "mac", mac, "tried", len(keyCandidates(rec)))
		writeJSONErr(w, http.StatusBadRequest, "unable to decrypt inform payload")
		return
	}
	gcmReq := pkt.Flags&inform.FlagGCM != 0
	if !payloadMACMatches(mac, jm) {
		mm, _ := jm["mac"].(string)
		s.lg.Error("invalid inform (mac inconsistent in header and payload)", "mac", mac, "payloadMac", mm) // FID-35, devmgr §7779
		writeJSONErr(w, http.StatusBadRequest, errMACMismatch(mac, mm).Error())
		return
	}

	// Read-modify-write is serialized per-MAC inside the store: advance
	// never races a concurrent inform rotation or admin mutation for the
	// same device (a lost rotation bricks the device's key).
	// FID-71: UpdateExisting — informs must never create or resurrect
	// device records; a MAC deleted mid-flight lands on the noop path.
	var outcome advanceResult
	uerr := s.st.UpdateExisting(mac, func(rec *store.Device) error {
		resp, kind, aerr := s.advance(mac, rec, jm, usedKey, gcmReq)
		if aerr != nil {
			return aerr
		}
		outcome = advanceResult{resp: resp, kind: kind}
		return nil
	})
	if uerr != nil {
		var rej *informRejectError
		if errors.As(uerr, &rej) {
			s.lg.Debug("inform: rejected", "mac", mac, "reason", rej.reason)
			w.WriteHeader(rej.status)
			return
		}
		// FID-71: UpdateExisting refuses to resurrect records — an
		// ErrNotFound here means the device was deleted (or expired) between
		// the Get and this write. The jar answers an unknown MAC with the
		// ÖoÓ000 marker → servlet 404, so a mid-flight deletion maps onto the
		// same status instead of the internal-error noop.
		if errors.Is(uerr, store.ErrNotFound) {
			s.lg.Debug("inform: device vanished before the RMW cycle", "mac", mac)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.internalNoopResponse(w, pkt, keyBytes, usedKey, gcmReq, mac, "update error", uerr)
		return
	}

	s.writeInformResponse(w, pkt, keyBytes, outcome, mac, usedKey, gcmReq)
}

// advanceResult carries the inform response built inside the store's
// read-modify-write cycle out to the HTTP writer.
type advanceResult struct {
	resp map[string]any
	kind string
}

// plainAdvance is the PLAINTEXT inform state machine. It NEVER rotates
// keys (deviation from the classic debug-build rotation path — we treat
// plaintext claims as assertions, not authenticators):
//
//   - XAuthkey unset  → noop; the record stays StatePending (plaintext can
//     never initiate adoption — rotating/adopting from an unauthenticated
//     channel would let any network observer seed a device's mgmt_cfg with
//     an empty cfgversion/authkey);
//   - claim ≠ XAuthkey → mgmt_cfg-only push carrying the CURRENT XAuthkey
//     via the authkey= line (re-key me), no rotation, no cfgversion regen;
//   - claim == XAuthkey → the normal assigned-key flow (cfgversion match →
//     noop + StateAdopted; mismatch → full provisioning, incl. the wireless
//     drift hash bump).
func (s *Server) plainAdvance(mac string, rec *store.Device, body map[string]any, claim string) (map[string]any, string, error) {
	s.absorbInform(mac, rec, body, time.Now(), false)
	rtype, _ := body["_type"].(string)
	if informTypeGentleNoop(rtype) {
		s.lg.Debug("inform-plain: gentle noop for _type", "mac", mac, "type", rtype)
		return s.noopResp(), "noop", nil
	}

	switch {
	case rec.XAuthkey == "":
		s.lg.Debug("inform-plain: noop without assignment", "mac", mac)
		return s.noopResp(), "noop", nil

	case !strings.EqualFold(rec.XAuthkey, claim):
		s.lg.Debug("inform-plain: re-send current assignment", "mac", mac)
		return s.adoptionPushResp(*rec, claim), "setparam", nil

	default:
		return s.assignedKeyFlow(mac, rec, body)
	}
}

// writeInformResponse renders outcome over the wire: plaintext informs get
// plain JSON; encrypted ones get the classic sealed envelope. If sealing
// fails (rand/cipher errors), a plain-JSON noop rides out under an HTTP 200
// (FID-69: internal failures never surface as 500) rather than leaving the
// socket empty.
func (s *Server) writeInformResponse(w http.ResponseWriter, pkt *inform.Packet, keyBytes []byte, outcome advanceResult, mac, usedKey string, gcmReq bool) {
	out, err := json.Marshal(outcome.resp)
	if err != nil {
		s.internalPlainNoopResponse(w, "response marshal failed", err)
		return
	}

	// Response header (InformServlet._O0 reuse semantics, c_e9bb4be74abe
	// §206-216): the request header object is reused in place. Mutated:
	// flags (0x0009 for GCM responses = GCM|EncCBC, 0x0001 for CBC) and a
	// FRESH RANDOM 16-byte IV for BOTH branches (C.random(16) before the
	// if). Not mutated: magic, packet version, MAC (echoed from the
	// request) and the dataVersion field, which stays at the request's
	// parsed value (= 1).
	rpkt := *pkt
	if gcmReq {
		rpkt.Flags = inform.FlagGCM | inform.FlagEncCBC
	} else {
		rpkt.Flags = inform.FlagEncCBC
	}
	if _, err := rand.Read(rpkt.IV[:]); err != nil {
		s.internalPlainNoopResponse(w, "response IV generation failed", err)
		return
	}
	// Flags are finalized BEFORE encryption: on the GCM path the sealed
	// ciphertext is AAD-bound to the response header's 40 bytes in this
	// exact state (IV/flags/length already mutated), which the device
	// reproduces from the plaintext header it receives.
	if eerr := rpkt.EncryptPayload(keyBytes, out); eerr != nil {
		s.internalPlainNoopResponse(w, "response encryption failed", eerr)
		return
	}
	serialized, serr := rpkt.Serialize()
	if serr != nil {
		s.internalPlainNoopResponse(w, "response serialize failed", serr)
		return
	}
	s.lg.Debug("inform: reply", "mac", mac, "kind", outcome.kind, "key", usedKey, "gcm", gcmReq)
	w.Header().Set("Content-Type", "application/x-binary")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(serialized)
}

// internalNoopResponse answers an internal inform-processing failure with
// HTTP 200 and a noop payload (FID-69, decided: align, not 500). When the
// request was encrypted and the per-device key is known, the noop is sealed
// exactly like a real reply; when no key was established (e.g. the store
// failed before decryption), it falls back to plain JSON.
func (s *Server) internalNoopResponse(w http.ResponseWriter, pkt *inform.Packet, keyBytes []byte, usedKey string, gcmReq bool, mac, cause string, cerr error) {
	s.lg.Error("inform: internal error, answering noop", "mac", mac, "cause", cause, "err", cerr)
	outcome := advanceResult{resp: s.noopResp(), kind: "internal-error"}
	if keyBytes == nil {
		s.internalPlainNoopResponse(w, cause, cerr)
		return
	}
	s.writeInformResponse(w, pkt, keyBytes, outcome, mac, usedKey, gcmReq)
}

// internalPlainNoopResponse is the unsealed fallback of the noop path.
func (s *Server) internalPlainNoopResponse(w http.ResponseWriter, cause string, cerr error) {
	s.lg.Error("inform: falling back to plain noop", "cause", cause, "err", cerr)
	out, merr := json.Marshal(s.noopResp())
	if merr != nil {
		s.lg.Error("inform: noop marshal failed", "err", merr)
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// handlePlain processes a plaintext inform (AllowPlainText only): either an
// unframed JSON body (mac from the body) or a framed no-flags packet
// (mac from the header, section-1 gating upstream in handleInform).
func (s *Server) handlePlain(w http.ResponseWriter, mac string, jm map[string]any) {
	if mac == "" {
		s.lg.Debug("inform-plain: empty MAC")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// FID-35 (payload MAC must match the header MAC) guard: for the framed
	// plain path this is a real cross-check; for an unframed JSON inform
	// the body IS the identity source so the fields coincide.
	if !payloadMACMatches(mac, jm) {
		mm, _ := jm["mac"].(string)
		s.lg.Debug("inform-plain: mac inconsistent between header and payload")
		writeJSONErr(w, http.StatusBadRequest, errMACMismatch(mac, mm).Error())
		return
	}
	_, err := s.st.Get(mac) // existence check only; the RMW cycle runs under store.UpdateExisting
	if errors.Is(err, store.ErrNotFound) {
		s.lg.Debug("inform-plain: unregistered device", "mac", mac)
		if merr := s.st.MarkPending(mac, informFactoryNotype); merr != nil {
			s.lg.Warn("inform-plain: mark pending failed", "mac", mac, "err", merr)
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		// FID-69: internal failure → 200 noop (plain JSON here).
		s.lg.Error("inform-plain: store error", "err", err)
		out, merr := json.Marshal(s.noopResp())
		if merr != nil {
			s.lg.Error("inform-plain: noop marshal failed", "err", merr)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
		return
	}

	// Plaintext devices authenticate via the reported _authkey claim.
	claim := strings.ToLower(str(jm, "_authkey"))
	if claim == "" {
		claim = defaultKeyHex
	}
	var outcome advanceResult
	uerr := s.st.UpdateExisting(mac, func(rec *store.Device) error {
		resp, kind, aerr := s.plainAdvance(mac, rec, jm, claim)
		if aerr != nil {
			return aerr
		}
		outcome = advanceResult{resp: resp, kind: kind}
		return nil
	})
	if uerr != nil {
		// FID-71: a record deleted between the Get and this write answers
		// the jar's unknown-MAC marker (404); any other failure is FID-69's
		// 200 noop.
		if errors.Is(uerr, store.ErrNotFound) {
			s.lg.Debug("inform-plain: device vanished before the RMW cycle", "mac", mac)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.lg.Error("inform-plain: store update error", "mac", mac, "err", uerr)
		out, merr := json.Marshal(s.noopResp())
		if merr != nil {
			s.lg.Error("inform-plain: noop marshal failed", "err", merr)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
		return
	}
	out, merr := json.Marshal(outcome.resp)
	if merr != nil {
		s.lg.Error("inform-plain: response marshal failed", "err", merr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.lg.Debug("inform-plain: reply", "mac", mac, "kind", outcome.kind, "claim", claim)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// advance applies the adoption state machine (docs/PROTOCOL-mgmt.md §6.2) for
// ENCRYPTED informs and returns the response body map plus a response kind
// label (and an error for unrecoverable internal conditions mapped to 500).
// It mutates rec; the caller-side store.Update persists.
//
//		setparam variants (exactly three shapes):
//		  - adoption push:  {"_type":"setparam","mgmt_cfg":...} + server_time
//		    (mgmt_cfg ONLY; fresh 16-hex cfgversion stored on the record first,
//		    carried in the mgmt_cfg "cfgversion=" line).
//		  - full provisioning: {"_type":"setparam","cfgversion":...,\
//		    "system_cfg":...,"blocked_sta":...,"mgmt_cfg":...} + server_time.
//	  - noop: {"_type":"noop","interval":15} + server_time.
//
// usedKey is the lowercase hex key that authenticated the inform.
func (s *Server) advance(mac string, rec *store.Device, body map[string]any, usedKey string, gcmReq bool) (map[string]any, string, error) {
	now := time.Now()
	s.absorbInform(mac, rec, body, now, gcmReq)

	rtype, _ := body["_type"].(string)
	if informTypeGentleNoop(rtype) {
		s.lg.Debug("inform: gentle noop for _type", "mac", mac, "type", rtype)
		return s.noopResp(), "noop", nil
	}

	// Wireless envelope drift (FSM hash bump): BEFORE the cfgversion drift
	// check, compare sha256(canonical wireless envelope) with the stored
	// Extra["wlan_cfg_sha"]. A mismatch regenerates CfgVersion, which the
	// drift check then sees as unknown → full provisioning. The hash is
	// minted together with the cfgversion it belongs to: the adoption push
	// seeds it (rotateKeys case below) and full provisioning refreshes it
	// (assignedKeyFlow). Live finding (2026-09-16 acceptance session, U7PG2
	// on BZ.6.8.2): real firmware echoes the adoption mgmt_cfg's cfgversion
	// back on its first re-keyed inform — matching the jar's equal path
	// (voidsuper bytes 3287-3306 jump to 3549) — so full provisioning never
	// follows adoption on its own, and the drift baseline must NOT depend on
	// assignedKeyFlow having run first. The jar bumps device.cfgversion on
	// operator config saves ("CONFIG changed" log); this hash comparison is
	// open-unifi's equivalent trigger.
	if prev, _ := rec.Extra["wlan_cfg_sha"].(string); prev != "" {
		if cur := wlanListHash(s.currentWireless()); cur != prev {
			nv, kerr := s.keyChars(16)
			if kerr != nil {
				return nil, "", kerr
			}
			rec.CfgVersion = nv
			s.lg.Debug("inform: wireless envelope drift", "mac", mac)
		}
	}

	onAssigned := rec.XAuthkey != "" && strings.EqualFold(rec.XAuthkey, usedKey)
	switch {
	// The factory/default key is still (or again) in use: adopt. Rotate the
	// per-device key AND the config version, respond with a fresh adoption
	// push in the same key the device just sent (classic: send non-default
	// authkey while the device still holds the default — §8 of the doc).
	// FID-1: the shared default key is only ACCEPTED for a device that has
	// not yet authenticated its per-device key — our StatePending stands in
	// for the jar's UNKNOWN(0) pre-adoption record and StateAdopting for the
	// jar's ADOPTING(7) two-phase default-key window (gate ôØ0000, devmgr
	// §11006-11020). An adopted (or lost) device claiming the default key is
	// REJECTED (devmgr "used default key in X state, reject it!" returns the
	// ÖoÓ000 marker → servlet 404). No INFORM_ERROR(9) re-adopt state exists
	// in the store yet — flagged for the store lane.
	case usedKey == defaultKeyHex:
		prev := rec.State
		if prev != store.StatePending && prev != store.StateAdopting {
			return nil, "", errDefaultKeyRejected
		}
		if err := s.rotateKeys(mac, rec); err != nil {
			return nil, "", err
		}
		// Seed the wireless-envelope baseline for the cfgversion just
		// minted (see the drift block above): the device would reach
		// connected-noop on its very next inform (mgmt_cfg echo) without
		// ever seeing system_cfg, and without a baseline a later WLAN
		// change could never be detected as drift. Envelope changes made
		// AFTER this push then mismatch the seed → full provisioning.
		if cur := wlanListHash(s.currentWireless()); cur != "" {
			rec.Extra["wlan_cfg_sha"] = cur
		}
		s.lg.Debug("inform: adoption push (default key)", "mac", mac, "prevState", prev)
		return s.adoptionPushResp(*rec, usedKey), "setparam", nil

	// A non-default key that is neither the default nor our current
	// assignment: a stale or rogue x_authkey. FID-36 (jar §1348 rotation
	// pending path): do NOT rotate — RE-PUSH the existing per-device key in
	// the authkey= line; the device re-keys to the assignment it was given.
	case !onAssigned:
		s.lg.Debug("inform: adoption push (stale/rogue key, re-push existing assignment)", "mac", mac)
		return s.adoptionPushResp(*rec, usedKey), "setparam", nil

	// Authenticated with our per-device key and the config applied → noop.
	case rec.CfgVersion != "" && rec.AppliedCfg == rec.CfgVersion:
		// Self-heal for records without a drift baseline (e.g. adopted
		// before the hash was seeded at adoption time): mint a fresh
		// cfgversion so the NEXT inform mismatches and flows through
		// full provisioning, which captures the hash. Terminates: the
		// provisioning path always stores it.
		if prev, _ := rec.Extra["wlan_cfg_sha"].(string); prev == "" {
			nv, kerr := s.keyChars(16)
			if kerr != nil {
				return nil, "", kerr
			}
			rec.CfgVersion = nv
			s.lg.Debug("inform: no envelope baseline, forcing provisioning", "mac", mac)
			return s.noopResp(), "noop", nil
		}
		rec.State = store.StateAdopted
		s.lg.Debug("inform: connected noop", "mac", mac, "cfg", rec.CfgVersion)
		return s.noopResp(), "noop", nil

	default:
		resp, kind, err := s.assignedKeyFlow(mac, rec, body)
		if err != nil {
			return nil, "", err
		}
		s.lg.Debug("inform: full provisioning", "mac", mac, "ours", rec.CfgVersion, "device", rec.AppliedCfg)
		return resp, kind, nil
	}
}

// assignedKeyFlow is the shared tail of the assigned-key (x_authkey-held)
// path: at CFGVERSION MATCH it is unreachable (handled by the noop branch),
// here it emits FULL PROVISIONING — fresh cfgversion when unset, adopting
// state, ssh password-hash cache, and capture of the emitted wireless
// envelope hash (the next identical-envelope inform after apply must noop).
func (s *Server) assignedKeyFlow(mac string, rec *store.Device, body map[string]any) (map[string]any, string, error) {
	if rec.CfgVersion == "" {
		nv, err := s.keyChars(16)
		if err != nil {
			return nil, "", err
		}
		rec.CfgVersion = nv
	}
	rec.State = store.StateAdopting
	sys, serr := s.buildSystemCfg(*rec)
	if serr != nil {
		// FID-23: provisioning content that cannot be rendered (e.g. an
		// unusable/empty SSH password hash) fails the whole push, like the
		// classic L.ÔO0000 crypt call — it must never silently emit a
		// degraded config. Nothing was persisted (the store cycle aborts).
		return nil, "", serr
	}
	if cur := wlanListHash(s.currentWireless()); cur != "" {
		rec.Extra["wlan_cfg_sha"] = cur
	} else {
		delete(rec.Extra, "wlan_cfg_sha")
	}
	resp := map[string]any{
		"_type":              "setparam",
		"server_time_in_utc": nowMS(),
		"cfgversion":         rec.CfgVersion,
		"system_cfg":         sys,
		"blocked_sta":        "",
		"mgmt_cfg":           s.buildMgmtCfg(*rec, rec.XAuthkey),
	}
	return resp, "setparam", nil
}

// siteRef is the site value the classic builder puts into mgmt_url and
// unifi.siteid (FID-17/FID-52): the site NAME the device belongs to. The
// store's Device.SiteID carries exactly that admin-supplied site name for
// this MVP (no site table yet, so an empty id degrades to "default").
func siteRef(d store.Device) string {
	if d.SiteID == "" {
		return defaultSiteName
	}
	return d.SiteID
}

// rotateKeys assigns a fresh per-device key and config version to rec and
// moves it back into the adopting state. An error here (crypto/rand
// failure, practically impossible) maps the inform to HTTP 500 — the
// caller must never persist half-rotated records.
func (s *Server) rotateKeys(mac string, rec *store.Device) error {
	xk, err := s.keyChars(32)
	if err != nil {
		return err
	}
	cv, err := s.keyChars(16)
	if err != nil {
		return err
	}
	rec.XAuthkey = xk
	rec.CfgVersion = cv
	rec.Authkeys = addKey(rec.Authkeys, xk)
	// Keep only the NEWEST TWO assigned keys: the device might still be
	// finishing one rotation cycle when the next starts, so its previous
	// key must keep decrypting, but everything older is useless ballast.
	// The factory default key is never stored in this list — keyCandidates
	// appends it at decrypt time — so factory-reset recovery is unaffected.
	if len(rec.Authkeys) > 2 {
		rec.Authkeys = rec.Authkeys[len(rec.Authkeys)-2:]
	}
	rec.State = store.StateAdopting
	return nil
}

// Extra preservation classes when an inform body replaces rec.Extra:
//
//	prevWins     — controller-owned caches that must survive ANY inform
//	               (forward/push bookkeeping);
//	fillIfAbsent — device-sided data the device may refresh at any time;
//	               copy from the previous record ONLY when the incoming body
//	               omits the key (a sparse heartbeat must not wipe the
//	               radio_table, but prev-WINS would pin device-side channel
//	               reselection forever);
//	adminOwned   — never sourced from a device body: value comes from the
//	               previous record if present, otherwise the key is DELETED
//	               (the device can never introduce them).
var (
	extraPrevWins     = []string{"wlan_cfg_sha", "ssh_sha512passwd"}
	extraFillIfAbsent = []string{"radio_table"}
	extraAdminOwned   = []string{"system_cfg_extra_lines", "mgmt_dev",
		"anonymous_controller_id", "anonymous_site_id"}
)

// absorbInform copies interesting fields from the inform body into the record.
func (s *Server) absorbInform(mac string, rec *store.Device, body map[string]any, now time.Time, gcmReq bool) {
	rec.Model = str(body, "model")
	rec.Firmware = str(body, "version")
	rec.Serial = str(body, "serial")
	rec.IP = str(body, "ip")
	rec.InformURL = str(body, "inform_url")
	prevExtra := rec.Extra          // caches / admin-owned values live here
	rec.Extra = store.JSONMap(body) // full raw passthrough (freshly unmarshal'd per request)
	if prevExtra == nil {
		prevExtra = store.JSONMap{}
	}
	for _, k := range extraPrevWins {
		if v, ok := prevExtra[k]; ok {
			rec.Extra[k] = v
		}
	}
	for _, k := range extraFillIfAbsent {
		if _, ok := body[k]; !ok {
			if v, ok := prevExtra[k]; ok {
				rec.Extra[k] = v
			}
		}
	}
	for _, k := range extraAdminOwned {
		if v, ok := prevExtra[k]; ok {
			rec.Extra[k] = v
		} else {
			delete(rec.Extra, k)
		}
	}
	if stat, ok := body["stat"].(map[string]any); ok {
		rec.LastUps = store.JSONMap(stat)
	}
	if cfg, ok := body["cfgversion"].(string); ok && cfg != "" {
		rec.AppliedCfg = cfg
	}
	rec.LastSeen = now.Unix()
	if rec.FirstSeen == 0 {
		rec.FirstSeen = now.Unix()
	}
	if gcmReq {
		rec.AESGCM = true
	}
	if v, ok := body["x_aes_gcm"].(bool); ok && v {
		rec.AESGCM = true
	}
}

// ---- config blob builders (docs/PROTOCOL-mgmt.md §2, §3) ------------------

// lineWriter returns the shared INJECTION-GUARDED key=value line writer used
// by every system_cfg/mgmt_cfg emission site. Any VALUE containing \n or \r
// makes the whole row skipped (with a warn) instead of emitted — a newline
// smuggled in from an inform body (forged radio fields, timezone strings,
// cookie comments) would terminate the row early and inject attacker-chosen
// key=value rows into the device's config. "Fail loud, never emit."
// (raw() admin passthrough lines in buildSystemCfg are the ONLY unguarded
// writer: admin-owned by definition.)
func (s *Server) lineWriter(b *strings.Builder, where string) func(k, v string) {
	return func(k, v string) {
		if strings.ContainsAny(v, "\n\r") {
			s.lg.Warn("config blob: row skipped, newline in value", "where", where, "key", k)
			return
		}
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(v)
		b.WriteString("\n")
	}
}

// sshPassword is the effective SSH password ("ubnt" default, cfg override).
func (s *Server) sshPassword() string {
	if s.cfg.SSHPassword != "" {
		return s.cfg.SSHPassword
	}
	return defaultSSHPassword
}

// addrHost extracts the hostname/IP of u, tolerating unparseable input.
func addrHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return ""
	}
	return u.Hostname()
}

// advertHost derives the controller host a device should be pointed back at:
// server.Config.ControllerURL host → the device's reported inform_url host →
// device IP (docs/PROTOCOL-mgmt.md §2, L.o00000 priority).
func (s *Server) advertHost(d store.Device) string {
	if h := addrHost(s.cfg.ControllerURL); h != "" {
		return h
	}
	if h := addrHost(d.InformURL); h != "" {
		return h
	}
	return d.IP
}

// informURLPort is the port embedded into the inform_url line: the
// ControllerURL's explicit port, else the configured listen port, else the
// classic 8080.
func (s *Server) informURLPort() string {
	if u, err := url.Parse(s.cfg.ControllerURL); err == nil && u != nil && u.Port() != "" {
		return u.Port()
	}
	if _, port, err := net.SplitHostPort(strings.TrimSpace(s.cfg.InformListenAddr)); err == nil && port != "" {
		return port
	}
	return defaultInformPort
}

// mgmtPort is the HTTPS manage-port embedded into mgmt_url. The classic
// controller appends the port unless it is 443 (docs/PROTOCOL-mgmt.md §2:
// "https://<host>[:443]/…" vs the 8443-default branch). We cannot know the
// admin HTTPS port from a plain-HTTP ControllerURL, so anything that is not
// an explicit https URL falls back to the classic default 8443.
func (s *Server) mgmtPort() string {
	u, err := url.Parse(s.cfg.ControllerURL)
	if err != nil || u == nil || u.Scheme != "https" {
		return defaultMgmtPort
	}
	if u.Port() == "" {
		return "443"
	}
	return u.Port()
}

// buildMgmtCfg renders the mgmt_cfg blob exactly in the config/B (decompile
// cfr_renamed_0) line order. Every line is terminated with \n (verified in
// com/ubnt/ace/C.o00000(StringBuilder,…): append(key=value).append("\n")).
//
// usedKey is the key the current inform was encrypted with; the authkey=
// rotation line is emitted only when that key differs from the record's
// XAuthkey (x_inform_authkey != x_authkey in the decompile).
func (s *Server) buildMgmtCfg(d store.Device, usedKey string) string {
	host := s.advertHost(d)
	site := siteRef(d)
	var b strings.Builder
	line := s.lineWriter(&b, "mgmt_cfg")

	// AP capabilities: notif + notif-assoc-stat. fastapply-bg is USW-only
	// and is never emitted for an AP (B decompile: "usw".equals(type)).
	line("capability", "notif,notif-assoc-stat")
	// selfrun_guest_mode comes from the site's config.selfrun_guest_mode
	// setting, default "pass"; we have no site table yet — emit the default.
	line("selfrun_guest_mode", "pass")
	line("cfgversion", d.CfgVersion)
	line("led_enabled", "true")
	line("stun_url", "stun://"+host+":"+defaultStunPort+"/")
	if p := s.mgmtPort(); p == "443" {
		line("mgmt_url", "https://"+host+"/manage/site/"+site)
	} else {
		line("mgmt_url", "https://"+host+":"+p+"/manage/site/"+site)
	}
	if d.XAuthkey != "" && !strings.EqualFold(usedKey, d.XAuthkey) {
		line("authkey", d.XAuthkey)
	}
	// FID-16: the inform_url row exists only when the controller URL is
	// explicitly overridden (jar: mgmt.override_inform_host/migrate_inform_url —
	// config L.new() returns null without an override, and the B writer
	// skips the row on null). Devices keep pointing wherever they already
	// point until an admin overrides.
	if s.cfg.ControllerURL != "" && host != "" {
		line("inform_url", "http://"+host+":"+s.informURLPort()+"/inform")
	}
	line("use_aes_gcm", "true")
	line("report_crash", "true")
	return b.String()
}

// buildSystemCfg renders the MINIMAL system_cfg text blob
// (docs/PROTOCOL-mgmt.md §3; builder = com/ubnt/service/config/int).
// Sections are plain "# name" headers followed by key=value lines, each
// line \n-terminated. An error aborts the whole provisioning push (FID-23)
// — the caller must answer the inform with the noop path instead of
// persisting/shipping partial config.
//
// TODO(wireless): see docs/PROTOCOL-systemcfg-wireless.md when it lands —
// the wireless/aaa.<n>, vlan/bridge/netconf, qos/bandsteering, syslog, snmp
// and cron/ntp sections from the real int builder are pending
// reverse-engineering and must NOT be invented here.
func (s *Server) buildSystemCfg(d store.Device) (string, error) {
	var b strings.Builder
	line := s.lineWriter(&b, "system_cfg")
	raw := func(l string) {
		if l != "" {
			b.WriteString(l)
			if !strings.HasSuffix(l, "\n") {
				b.WriteString("\n")
			}
		}
	}

	// 1. # system — timezone rows (system.timezone + locale.timezone,
	//    FID-19: config_String section writer emits BOTH rows with the
	//    same value). analytics thresholds / resetbtn deliberately
	//    deferred with the wireless sections.
	b.WriteString("# system\n")
	tz, _ := d.Extra["timezone"].(string)
	if tz == "" {
		tz = defaultTimezone
	}
	line("system.timezone", tz)
	line("locale.timezone", tz)

	// 2. # unifi — controller identity bits the AP relays back. Anonymous
	//    ids turn on only when present in the record; reporterid mirrors
	//    the controller anonymous id (same R.Øõ0000() source in the jar,
	//    config_String unifi pair list — FID-17); siteid carries the
	//    device's site name (getSiteId always set there; our fallback is
	//    the "default" site). unifi.idp/unifi.key/unifi.mcip depend on the
	//    idp + mgmt settings we do not model yet, and unifi.cfgcap_info on
	//    the capability bitmask — genuinely underivable, left out.
	b.WriteString("# unifi\n")
	line("unifi.version", "0.1.0-dev")
	if v, ok := d.Extra["anonymous_controller_id"].(string); ok && v != "" {
		line("unifi.anonymous_controller_id", v)
		// reporterid = the very same controller anonymous id.
		line("unifi.reporterid", v)
	}
	if v, ok := d.Extra["anonymous_site_id"].(string); ok && v != "" {
		line("unifi.anonymous_site_id", v)
	}
	line("unifi.siteid", siteRef(d))

	// 3. # users — config_String.java §197-206 / PROTOCOL-systemcfg-Config.
	users1pw, uerr := s.usersPasswordHash(d)
	if uerr != nil {
		return "", uerr
	}
	b.WriteString("# users\n")
	line("users.status", "enabled")
	line("users.1.name", "ubnt")
	line("users.1.password", users1pw)
	line("users.1.status", "enabled")
	line("users.2.name", "nobody")
	line("users.2.password", "x")
	line("users.2.shell", "/bin/false")
	line("users.2.status", "enabled")

	// 4. Wireless/VLAN compound (docs/PROTOCOL-systemcfg-wireless.md):
	// `# wlans (radio)` + radio.<n>/virtual + aaa.<n>/wireless.<n> vaps +
	// `# vlan`/`# bridge`/`# netconf`/`# dhcpc` wiring. Real section order
	// per PROTOCOL-mgmt.md §3 puts this before the sshd/syslog ones.
	s.emitWirelessCfg(&b, d, s.currentWireless())

	// sshd rows — config_String.java §309-337 defaults: SSH on, password
	// auth on, wildcard bind off, no injected keys, mgmt interface bound.
	// FID-20: these rows carry NO "# sshd" section header in the classic
	// builder (no such literal exists in int/String). hooksite: real mgmt
	// dev is model-specific (record pass-through Extra["mgmt_dev"] allowed
	// as the admin escape hatch).
	line("sshd.status", "enabled")
	line("sshd.auth.passwd", "enabled")
	line("sshd.1.status", "enabled")
	mgmtDev, _ := d.Extra["mgmt_dev"].(string)
	if mgmtDev == "" {
		mgmtDev = "br0"
	}
	line("sshd.1.ifname", mgmtDev)

	// What is deliberately missing here (bandsteering, airtime, stamgr,
	// qos, mesh, connectivity, syslog, snmp, resolv/route/iptables, cron,
	// ntpclient — config_String/int): no admin-API fields exist yet; the
	// wireless RE doc covers only the emitted set.
	// TODO(wireless): see docs/PROTOCOL-systemcfg-wireless.md §9 when a
	// follow-up RE pass lands. Do NOT invent those rows.

	// 5. The admin "config.system_cfg.<idx>" passthrough lines
	//    (config_String.java §appendix: raw pre-formatted lines). FID-62:
	//    emitted without any "# misc" section header row.
	if extra, ok := d.Extra["system_cfg_extra_lines"].([]any); ok {
		for _, v := range extra {
			if l, ok := v.(string); ok {
				raw(l)
			}
		}
	}
	return b.String(), nil
}

// defaultSSHPassword is the site's default SSH password (docs §7:
// x_ssh_password default "ubnt").
const defaultSSHPassword = "ubnt"

// usersPasswordHash selects and derives the users.1.password value for the
// record (config_String §nine-branch: String.txt §1985-2006):
//
//	supportsSsh() && supportsSha512Password() → $6$ SHA-512 crypt (L.ÔO0000)
//	supportsSsh() && !supportsSha512Password() → $1$ MD5 crypt (L.õ00000)
//	!supportsSsh() → DES crypt — unreachable for our inform-driven model set
//	(fw_caps-bearing APs/switches), deliberately not implemented.
//
// supportsSha512Password() = hasCapability(1024) — `(fw_caps & n) == n`
// with a 0 default when the record doesn't report fw_caps (Device.java) —
// or the UDM/firewall device type, which we don't model (flagged: no
// device-type table in this MVP). The freshly generated hash is cached back
// into the record (the jar writes x_ssh_sha512passwd/x_ssh_md5passwd into
// the site mgmt setting) so repeated pushes are byte-identical.
// FID-23: generation failure or an empty value fails the whole call — the
// classic Crypt.crypt exceptions propagate out of the config build, and a
// degraded/empty row must never ship silently.
func (s *Server) usersPasswordHash(d store.Device) (string, error) {
	pw := s.sshPassword()
	if !supportsSha512Password(d) {
		cached, _ := d.Extra["ssh_md5passwd"].(string)
		if cached != "" && md5CryptMatches(pw, cached) {
			return cached, nil
		}
		fresh, err := md5Crypt(pw)
		if err != nil {
			return "", fmt.Errorf("users.1 md5 password: %w", err)
		}
		if fresh == "" {
			return "", errors.New("users.1 md5 password generated empty")
		}
		d.Extra["ssh_md5passwd"] = fresh
		return fresh, nil
	}
	cached, _ := d.Extra["ssh_sha512passwd"].(string)
	if cached != "" && sha512CryptMatches(pw, cached) {
		return cached, nil
	}
	fresh, err := sha512Crypt(pw)
	if err != nil {
		return "", fmt.Errorf("users.1 sha512 password: %w", err)
	}
	if fresh == "" {
		return "", errors.New("users.1 sha512 password generated empty")
	}
	d.Extra["ssh_sha512passwd"] = fresh
	return fresh, nil
}

// supportsSha512Password mirrors Device.supportsSha512Password(): the
// fw_caps SHA-512 bit (0x0400); a record that does not report the field
// evaluates to capability 0 (jar X.getInt default) → the $1$ branch.
func supportsSha512Password(d store.Device) bool {
	ok, caps := numFromExtra(d.Extra, "fw_caps")
	return ok && caps&0x400 == 0x400
}

// md5Crypt computes the classic $1$ md5crypt (Poul-Henning Kamp's public
// domain algorithm, the same one commons-codec Md5Crypt ports and glibc
// implements), verified byte-exact against
// `openssl passwd -1 -salt <salt> <pw>`.
func md5Crypt(key string) (string, error) {
	salt, err := randAlphaSalt(8)
	if err != nil {
		return "", err
	}
	return "$1$" + salt + "$" + md5CryptRaw([]byte(key), []byte(salt)), nil
}

// md5CryptRaw is md5crypt with a caller-provided salt (max 8 bytes kept),
// faithful to the classic unix md5crypt (Poul-Henning Kamp, verified
// line-for-line against FreeBSD libcrypt crypt-md5.c): the initial digest
// ctx = MD5(key ‖ "$1$" ‖ salt) carries the MAGIC, the "alternation" odd
// iterations append a ZERO byte (the jar's commons-codec-1.11 zeroes the
// alt buffer before the weird loop exactly like FreeBSD's explicit_bzero,
// javap-verified at Md5Crypt crypt() offset 211 before the i&1 loop at
// 223-262), and the output is to64 in the classic
// (0,6,12)(1,7,13)(2,8,14)(3,9,15)(4,10,5) order plus the 2-char final[11]
// tail. Byte-identical to both the controller jar (run directly) and
// `openssl passwd -1`.
func md5CryptRaw(key, salt []byte) string {
	if len(salt) > 8 {
		salt = salt[:8]
	}

	// alt = MD5(key ‖ salt ‖ key)   (NO magic in this digest)
	h := md5.New()
	h.Write(key)
	h.Write(salt)
	h.Write(key)
	alt := h.Sum(nil)

	// ctx = MD5(key ‖ "$1$" ‖ salt ‖ alt×chunks ‖ alternation(zero/key[0]))
	h = md5.New()
	h.Write(key)
	h.Write([]byte("$1$"))
	h.Write(salt)
	for i := len(key); i > 0; i -= 16 {
		if i > 16 {
			h.Write(alt)
		} else {
			h.Write(alt[:i])
		}
	}
	// /* Don't leave anything around in vm i could use. */ — the buffer is
	// zeroed before this loop, so the odd branch appends a literal zero byte.
	zero := []byte{0}
	for i := len(key); i > 0; i >>= 1 {
		if i&1 != 0 {
			h.Write(zero)
		} else if len(key) > 0 {
			h.Write(key[:1])
		}
	}
	final := h.Sum(nil)

	// 1000-iteration burning loop: odd iterations update with key first and
	// final second; even ones final first and key second.
	for i := 0; i < 1000; i++ {
		h = md5.New()
		if i&1 != 0 {
			h.Write(key)
		} else {
			h.Write(final)
		}
		if i%3 != 0 {
			h.Write(salt)
		}
		if i%7 != 0 {
			h.Write(key)
		}
		if i&1 != 0 {
			h.Write(final)
		} else {
			h.Write(key)
		}
		final = h.Sum(nil)
	}

	// Encode 16 bytes in the md5crypt order: 4+4+4+4+4 output groups then a
	// 2-byte tail — "22 chars" (crypto/b64 style, no padding).
	number := func(b1, b2, b3 byte) uint32 {
		return uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)
	}
	out := make([]byte, 0, 22)
	emit := func(v uint32, n int) {
		for i := 0; i < n; i++ {
			out = append(out, b64cryptAlphabet[v&0x3f])
			v >>= 6
		}
	}
	emit(number(final[0], final[6], final[12]), 4)
	emit(number(final[1], final[7], final[13]), 4)
	emit(number(final[2], final[8], final[14]), 4)
	emit(number(final[3], final[9], final[15]), 4)
	emit(number(final[4], final[10], final[5]), 4)
	emit(uint32(final[11]), 2)
	return string(out)
}

// md5CryptMatches verifies a stored $1$ hash against the password (embedded
// salt recomposition), the md5 analog of sha512CryptMatches.
func md5CryptMatches(key, stored string) bool {
	rest, ok := strings.CutPrefix(stored, "$1$")
	if !ok {
		return false
	}
	salt, _, cut := strings.Cut(rest, "$")
	if !cut || salt == "" || len(salt) > 8 {
		return false
	}
	return md5CryptRaw([]byte(key), []byte(salt)) == string(rest[len(salt)+1:])
}

// randAlphaSalt mirrors RandomStringUtils.randomAlphabetic(n) over
// crypto/rand (the jar's md5-branch salt generator, commons-codec B64 set
// aside: letters only). Var so tests can inject failure (FID-23 path).
var randAlphaSalt = randAlphaSaltLive

func randAlphaSaltLive(n int) (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = letters[int(b)%len(letters)]
	}
	return string(out), nil
}

// adoptionPushResp is the §6.2 a/b/c/f setparam variant: mgmt_cfg ONLY,
// with a freshly stored cfgversion carried inside the mgmt_cfg blob. The
// response is encrypted with the key the device just used, so a pending
// authkey= line forwards the rotated key.
func (s *Server) adoptionPushResp(d store.Device, usedKey string) map[string]any {
	return map[string]any{
		"_type":              "setparam",
		"server_time_in_utc": nowMS(),
		"mgmt_cfg":           s.buildMgmtCfg(d, usedKey),
	}
}

// fullProvisionResp was removed: assigned-key full provisioning is now
// assembled inside assignedKeyFlow so a buildSystemCfg error (FID-23) can
// fail the whole push.

// noopResp builds the connected/nothing-to-do response. Interval is a JSON
// NUMBER of seconds (jar: `object.put("interval", nextInterval)` — FID-11),
// 15 here; tiered/load-based intervals are a documented follow-up.
func (s *Server) noopResp() map[string]any {
	return map[string]any{
		"_type":              "noop",
		"server_time_in_utc": nowMS(),
		"interval":           15,
	}
}

// ---- serving --------------------------------------------------------------
//
// The inform endpoint is owned by the caller: cmd/openunifi wires the
// InformHandler into its own http.Server (main.go). The classic jar has no
// inform-side shutdown path of its own, and the former ServeInform/
// Shutdown/httpSrv trio in this file was dead code (FID-55-server).

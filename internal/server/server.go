// Package server hosts the adoption-capable UniFi inform controller.
//
// HTTP semantics per docs/PROTOCOL.md §1–§3; UDP discovery per §4.
// Counter/tabulation realities are logged via slog (no Prometheus here — the
// internal/metrics lane owns that wiring separately).
package server

import (
	"context"
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

	httpSrv *http.Server
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
func (s *Server) handlePacket(w http.ResponseWriter, pkt *inform.Packet, body []byte) {
	mac := canonMACFromHeader(pkt.MAC)
	if mac == "" {
		s.lg.Debug("inform: empty MAC in header")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rec, err := s.st.Get(mac)
	if errors.Is(err, store.ErrNotFound) {
		// Un-registered factory device: classic controller 404s and the AP
		// keeps retrying. Record the sighting for the adoption UI.
		s.lg.Debug("inform: unregistered device", "mac", mac)
		if merr := s.st.MarkPending(mac, "inform:factory"); merr != nil {
			s.lg.Warn("inform: mark pending failed", "mac", mac, "err", merr)
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		s.lg.Error("inform: store error", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.lg.Debug("inform: packet", "mac", mac, "flags", fmt.Sprintf("0x%04x", pkt.Flags), "bodyLen", len(body))

	// Try every candidate key; the first candidate whose plaintext parses as
	// a JSON object wins and selects usedKey. JSON validation is required
	// because the legacy lenient CBC unpad makes wrong-key decrypts
	// "succeed" with garbage bytes rather than erroring.
	gcmReq := pkt.Flags&inform.FlagGCM != 0
	var usedKey string
	var keyBytes []byte
	var jm map[string]any
	for _, k := range keyCandidates(rec) {
		kb, derr := inform.DecodeKeyHex(k)
		if derr != nil {
			continue
		}
		p, derr := pkt.DecryptPayload(kb)
		if derr != nil {
			continue
		}
		if uerr := json.Unmarshal(p, &jm); uerr != nil || jm == nil {
			continue // wrong key (lenient garbage) or malformed payload
		}
		usedKey = strings.ToLower(k)
		keyBytes = kb
		break
	}
	if usedKey == "" {
		s.lg.Debug("inform: no key produced a valid JSON payload", "mac", mac, "tried", len(keyCandidates(rec)))
		writeJSONErr(w, http.StatusBadRequest, "unable to decrypt inform payload")
		return
	}

	// Read-modify-write is serialized per-MAC inside the store: advance
	// never races a concurrent inform rotation or admin mutation for the
	// same device (a lost rotation bricks the device's key).
	var outcome advanceResult
	uerr := s.st.Update(mac, func(rec *store.Device) error {
		resp, kind, aerr := s.advance(mac, rec, jm, usedKey, gcmReq)
		if aerr != nil {
			return aerr
		}
		outcome = advanceResult{resp: resp, kind: kind}
		return nil
	})
	if uerr != nil {
		s.lg.Error("inform: store update error", "mac", mac, "err", uerr)
		w.WriteHeader(http.StatusInternalServerError)
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
	known := map[string]bool{
		"info": true, "heartbeat": true, "cmd": true,
		"setparam": true, "setparam-ack": true, "cmd-ack": true,
		"alarms": true, "disconnect": true,
	}
	rtype, _ := body["_type"].(string)
	if !known[rtype] {
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
// plain JSON; encrypted ones get the classic sealed envelope.
func (s *Server) writeInformResponse(w http.ResponseWriter, pkt *inform.Packet, keyBytes []byte, outcome advanceResult, mac, usedKey string, gcmReq bool) {
	out, err := json.Marshal(outcome.resp)
	if err != nil {
		s.lg.Error("inform: response marshal failed", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
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
		s.lg.Error("inform: response IV generation failed", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// Flags are finalized BEFORE encryption: on the GCM path the sealed
	// ciphertext is AAD-bound to the response header's 40 bytes in this
	// exact state (IV/flags/length already mutated), which the device
	// reproduces from the plaintext header it receives.
	if eerr := rpkt.EncryptPayload(keyBytes, out); eerr != nil {
		s.lg.Error("inform: response encryption failed", "err", eerr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	serialized, serr := rpkt.Serialize()
	if serr != nil {
		s.lg.Error("inform: response serialize failed", "err", serr)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	s.lg.Debug("inform: reply", "mac", mac, "kind", outcome.kind, "key", usedKey, "gcm", gcmReq)
	w.Header().Set("Content-Type", "application/x-binary")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(serialized)
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
	_, err := s.st.Get(mac) // existence check only; the RMW cycle runs under store.Update
	if errors.Is(err, store.ErrNotFound) {
		s.lg.Debug("inform-plain: unregistered device", "mac", mac)
		if merr := s.st.MarkPending(mac, "inform:factory"); merr != nil {
			s.lg.Warn("inform-plain: mark pending failed", "mac", mac, "err", merr)
		}
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err != nil {
		s.lg.Error("inform-plain: store error", "err", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Plaintext devices authenticate via the reported _authkey claim.
	claim := strings.ToLower(str(jm, "_authkey"))
	if claim == "" {
		claim = defaultKeyHex
	}
	var outcome advanceResult
	uerr := s.st.Update(mac, func(rec *store.Device) error {
		resp, kind, aerr := s.plainAdvance(mac, rec, jm, claim)
		if aerr != nil {
			return aerr
		}
		outcome = advanceResult{resp: resp, kind: kind}
		return nil
	})
	if uerr != nil {
		s.lg.Error("inform-plain: store update error", "mac", mac, "err", uerr)
		w.WriteHeader(http.StatusInternalServerError)
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
//	setparam variants (exactly three shapes):
//	  - adoption push:  {"_type":"setparam","mgmt_cfg":...} + server_time
//	    (mgmt_cfg ONLY; fresh 16-hex cfgversion stored on the record first,
//	    carried in the mgmt_cfg "cfgversion=" line).
//	  - full provisioning: {"_type":"setparam","cfgversion":...,\
//	    "system_cfg":...,"blocked_sta":...,"mgmt_cfg":...} + server_time.
//	  - noop: {"_type":"noop","interval":"15"} + server_time.
//
// usedKey is the lowercase hex key that authenticated the inform.
func (s *Server) advance(mac string, rec *store.Device, body map[string]any, usedKey string, gcmReq bool) (map[string]any, string, error) {
	now := time.Now()
	s.absorbInform(mac, rec, body, now, gcmReq)

	known := map[string]bool{
		"info": true, "heartbeat": true, "cmd": true,
		"setparam": true, "setparam-ack": true, "cmd-ack": true,
		"alarms": true, "disconnect": true,
	}
	rtype, _ := body["_type"].(string)
	if !known[rtype] {
		s.lg.Debug("inform: gentle noop for _type", "mac", mac, "type", rtype)
		return s.noopResp(), "noop", nil
	}

	// Wireless envelope drift (FSM hash bump): BEFORE the cfgversion drift
	// check, compare sha256(canonical wireless envelope) with the stored
	// Extra["wlan_cfg_sha"]. A mismatch regenerates CfgVersion, which the
	// drift check then sees as unknown → full provisioning. Adoption
	// pushes leave the hash untouched: the device has not received
	// system_cfg yet, so the hash is first captured by full provisioning
	// (stored below). No stored hash ⇒ nothing to bump.
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
	case usedKey == defaultKeyHex:
		prev := rec.State
		if err := s.rotateKeys(mac, rec); err != nil {
			return nil, "", err
		}
		s.lg.Debug("inform: adoption push (default key)", "mac", mac, "prevState", prev)
		return s.adoptionPushResp(*rec, usedKey), "setparam", nil

	// A non-default key that is neither the default nor our current
	// assignment: a stale or rogue x_authkey. Regenerate and push the new
	// assignment the same way (mgmt_cfg with the authkey= rotation line).
	case !onAssigned:
		if err := s.rotateKeys(mac, rec); err != nil {
			return nil, "", err
		}
		s.lg.Debug("inform: adoption push (stale/rogue key)", "mac", mac)
		return s.adoptionPushResp(*rec, usedKey), "setparam", nil

	// Authenticated with our per-device key and the config applied → noop.
	case rec.CfgVersion != "" && rec.AppliedCfg == rec.CfgVersion:
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
	s.cacheSSHPasswordHash(mac, rec)
	if cur := wlanListHash(s.currentWireless()); cur != "" {
		rec.Extra["wlan_cfg_sha"] = cur
	} else {
		delete(rec.Extra, "wlan_cfg_sha")
	}
	return s.fullProvisionResp(*rec), "setparam", nil
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
	return "8080"
}

// mgmtPort is the HTTPS manage-port embedded into mgmt_url. The classic
// controller appends the port unless it is 443 (docs/PROTOCOL-mgmt.md §2:
// "https://<host>[:443]/…" vs the 8443-default branch). We cannot know the
// admin HTTPS port from a plain-HTTP ControllerURL, so anything that is not
// an explicit https URL falls back to the classic default 8443.
func (s *Server) mgmtPort() string {
	u, err := url.Parse(s.cfg.ControllerURL)
	if err != nil || u == nil || u.Scheme != "https" {
		return "8443"
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
	site := d.SiteID
	if site == "" {
		site = "default"
	}
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
	line("stun_url", "stun://"+host+":3478/")
	if p := s.mgmtPort(); p == "443" {
		line("mgmt_url", "https://"+host+"/manage/site/"+site)
	} else {
		line("mgmt_url", "https://"+host+":"+p+"/manage/site/"+site)
	}
	if d.XAuthkey != "" && !strings.EqualFold(usedKey, d.XAuthkey) {
		line("authkey", d.XAuthkey)
	}
	if host != "" {
		line("inform_url", "http://"+host+":"+s.informURLPort()+"/inform")
	}
	line("use_aes_gcm", "true")
	line("report_crash", "true")
	return b.String()
}

// buildSystemCfg renders the MINIMAL system_cfg text blob
// (docs/PROTOCOL-mgmt.md §3; builder = com/ubnt/service/config/int).
// Sections are plain "# name" headers followed by key=value lines, each
// line \n-terminated.
//
// TODO(wireless): see docs/PROTOCOL-systemcfg-wireless.md when it lands —
// the wireless/aaa.<n>, vlan/bridge/netconf, qos/bandsteering, syslog, snmp
// and cron/ntp sections from the real int builder are pending
// reverse-engineering and must NOT be invented here.
func (s *Server) buildSystemCfg(d store.Device) string {
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

	// 1. # system — timezone only for the MVP (analytics thresholds,
	//    resetbtn etc. deliberately deferred with the wireless sections).
	b.WriteString("# system\n")
	tz, _ := d.Extra["timezone"].(string)
	if tz == "" {
		tz = "UTC"
	}
	line("system.timezone", tz)

	// 2. # unifi — controller identity bits the AP relays back. Anonymous
	//    ids turn on only when present in the record (real controller reads
	//    them from the site row; C.o00000 skips null pair values).
	b.WriteString("# unifi\n")
	line("unifi.version", "0.1.0-dev")
	if v, ok := d.Extra["anonymous_controller_id"].(string); ok && v != "" {
		line("unifi.anonymous_controller_id", v)
	}
	if v, ok := d.Extra["anonymous_site_id"].(string); ok && v != "" {
		line("unifi.anonymous_site_id", v)
	}

	// 3. # users — config_String.java §197-206 / PROTOCOL-systemcfg-Config.
	cached, _ := d.Extra["ssh_sha512passwd"].(string)
	users1pw := cached
	if users1pw == "" || !sha512CryptMatches(s.sshPassword(), users1pw) {
		// empty or stale cache (password changed → self-heals via the
		// crypt self-check, mirroring the controller's site-setting cache
		// semantics at per-device scope)
		nv, gerr := sha512Crypt(s.sshPassword())
		if gerr == nil {
			users1pw = nv
		}
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

	// sshd section — config_String.java §309-337 defaults: SSH on, password
	// auth on, wildcard bind off, no injected keys, mgmt interface
	// bound. hooksite: real mgmt dev is model-specific (record pass-
	// through Extra["mgmt_dev"] allowed as the admin escape hatch).
	b.WriteString("# sshd\n")
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

	// 5. # misc — the admin "config.system_cfg.<idx>" passthrough lines
	//    (config_String.java §appendix: raw pre-formatted lines).
	b.WriteString("# misc\n")
	if extra, ok := d.Extra["system_cfg_extra_lines"].([]any); ok {
		for _, v := range extra {
			if l, ok := v.(string); ok {
				raw(l)
			}
		}
	}
	return b.String()
}

// defaultSSHPassword is the site's default SSH password (docs §7:
// x_ssh_password default "ubnt").
const defaultSSHPassword = "ubnt"

// cacheSSHPasswordHash mirrors the classic L.\u00d4O0000 cache semantics
// (doc §10.3) at per-device scope: self-check the stored
// Extra["ssh_sha512passwd"] (`crypt(pw, stored) == stored`); regenerate a
// fresh random-salt $6$ hash only when the check fails or nothing is
// cached. buildSystemCfg reuses whatever lands in Extra, so repeated
// pushes emit the same users.1.password.
func (s *Server) cacheSSHPasswordHash(mac string, rec *store.Device) {
	if cached, ok := rec.Extra["ssh_sha512passwd"].(string); ok &&
		sha512BodyRx.MatchString(cached) &&
		sha512CryptMatches(s.sshPassword(), cached) {
		return
	}
	fresh, err := sha512Crypt(s.sshPassword())
	if err != nil {
		s.lg.Error("inform: sha512crypt generation failed", "mac", mac, "err", err)
		return
	}
	rec.Extra["ssh_sha512passwd"] = fresh
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

// fullProvisionResp is the §6.2 d setparam variant: all four config keys,
// always (blocked_sta is "" while we have no client block list). Full
// provisioning is only ever reached while the device already holds
// its assigned XAuthkey (= the encrypt key), so buildMgmtCfg takes that as
// usedKey and the authkey= rotation line is correctly omitted.
func (s *Server) fullProvisionResp(d store.Device) map[string]any {
	return map[string]any{
		"_type":              "setparam",
		"server_time_in_utc": nowMS(),
		"cfgversion":         d.CfgVersion,
		"system_cfg":         s.buildSystemCfg(d),
		"blocked_sta":        "",
		"mgmt_cfg":           s.buildMgmtCfg(d, d.XAuthkey),
	}
}

// noopResp builds the connected/nothing-to-do response. Interval is a STRING
// of seconds (classic wire shape), 15 here.
func (s *Server) noopResp() map[string]any {
	return map[string]any{
		"_type":              "noop",
		"server_time_in_utc": nowMS(),
		"interval":           "15",
	}
}

// ---- serving --------------------------------------------------------------

// ServeInform blocks serving the inform endpoint on ln.
func (s *Server) ServeInform(ln net.Listener) error {
	srv := &http.Server{Handler: s.InformHandler()}
	s.httpSrv = srv
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully stops the inform HTTP server and waits for in-flight
// informs to finish (up to ctx).
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// Package server hosts the adoption-capable UniFi inform controller.
//
// HTTP semantics per docs/PROTOCOL.md §1–§3; UDP discovery per §4.
// Counter/tabulation realities are logged via slog (no Prometheus here — the
// internal/metrics lane owns that wiring separately).
package server

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lucabecker/open-unifi/internal/inform"
	"github.com/lucabecker/open-unifi/internal/server/adoption"
	"github.com/lucabecker/open-unifi/internal/server/systemcfg"
	"github.com/lucabecker/open-unifi/internal/store"
	"github.com/lucabecker/open-unifi/internal/wireless"
)

// ErrLiveWLANProvisioningUnsupported is returned for the exact U7PG2
// firmware lane whose system_cfg WLAN template has not been differentially
// verified against the official controller. The caller must not retry this as
// a successful delivery.
type ErrLiveWLANProvisioningUnsupported struct {
	Model    string
	Firmware string
}

func (e *ErrLiveWLANProvisioningUnsupported) Error() string {
	return "live WLAN provisioning is unsupported for " + e.Model + " firmware " + e.Firmware + "; awaiting an official-controller differential fixture"
}

func (e *ErrLiveWLANProvisioningUnsupported) Status() int { return http.StatusNotImplemented }

// Wire-shape constant of the classic controller (FID-54 dedupe): the
// factory-notype pending annotation.
const informFactoryNotype = "inform:factory"

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

	// RegulatoryCountryCode is the ISO 3166-1 numeric country code emitted
	// into wireless system_cfg. Zero selects the conservative US default for
	// backwards compatibility; operators should set this to their jurisdiction.
	RegulatoryCountryCode int

	// AllowPlainText permits unencrypted JSON inform bodies (classic
	// controllers reject these unless pre-adoption plain text inform is on).
	// Default false.
	AllowPlainText bool

	// WirelessSource supplies the WLAN envelope (admin-API mirror: Wlan
	// struct) that system_cfg provisioning renders and hashes for drift
	// detection. nil ⇒ empty list ⇒ no wlans provisioned.
	WirelessSource func() []Wlan

	// AllowGatedLiveWLAN lifts the fail-closed live-WLAN gate for the
	// U7PG2 6.8.2.15592 lane (the typed 501, "live WLAN provisioning
	// gated"). Default false: live WLAN provisioning for that exact
	// model+firmware stays rejected unless a sanctioned live round
	// explicitly opts in — the offline minimal-diff harness gates the
	// push candidate separately, before any bytes reach the AP.
	AllowGatedLiveWLAN bool

	// SSHPassword overrides the default SSH password ("ubnt") hashed into
	// system_cfg users.1. SECURITY NOTE: this string lives in server memory
	// and, by protocol design, travels VERBATIM (hashed) inside the
	// provisioned config; the passphrase itself never appears in mgmt_cfg.
	// Treat records/config containing the hash as credentials.
	SSHPassword string
}

const DefaultRegulatoryCountryCode = 840

// ValidateConfig validates values that affect device addressing or generated
// configuration. ControllerURL may include a path (for deployments using a
// reverse proxy), but must not include query, fragment, or userinfo.
func ValidateConfig(cfg Config) error {
	if cfg.ControllerURL != "" {
		if err := validateBaseURL(cfg.ControllerURL, "controller URL"); err != nil {
			return err
		}
	}
	code := cfg.RegulatoryCountryCode
	if code == 0 {
		code = DefaultRegulatoryCountryCode
	}
	if code < 1 || code > 999 {
		return fmt.Errorf("regulatory country code must be an ISO 3166-1 numeric code from 001 to 999, got %d", code)
	}
	return nil
}

func validateBaseURL(raw, label string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u == nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%s must be an absolute http or https URL with a host", label)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain userinfo", label)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must not contain a query or fragment", label)
	}
	return nil
}

// Server serves the UniFi inform protocol used for AP adoption.
type Server struct {
	cfg Config
	st  store.DeviceStore
	lg  *slog.Logger

	// engine is the adoption decider: every decoded inform's decision logic
	// lives there; this type is the transport adapter around it.
	engine *adoption.Engine

	seenMu sync.Mutex
	seenAt map[string]time.Time // discovery dedupe per MAC

	noopMu     sync.Mutex
	noopTarget map[string]int64 // controller-owned steady-state target, by MAC
}

// New builds a Server. A nil logger falls back to slog.Default().
func New(cfg Config, st store.DeviceStore, lg *slog.Logger) *Server {
	if lg == nil {
		lg = slog.Default()
	}
	s := &Server{
		cfg:        cfg,
		st:         st,
		lg:         lg,
		seenAt:     map[string]time.Time{},
		noopTarget: map[string]int64{},
	}
	// The adoption engine is a pure decider: randomness, key generation and
	// the wireless source are injected, and the system_cfg producer is a
	// thin closure over the pure systemcfg renderer.
	s.engine = adoption.New(adoption.Deps{
		Logger: lg,
		Random: func() float64 { return noopRandom() },
		KeyChars: func(n int) (string, error) {
			return s.keyChars(n)
		},
		Wireless:           s.currentWireless,
		SystemCfg:          s.renderSystemCfg,
		ControllerURL:      cfg.ControllerURL,
		InformListenAddr:   cfg.InformListenAddr,
		AllowGatedLiveWLAN: cfg.AllowGatedLiveWLAN,
	})
	return s
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
	def := inform.DefaultKeyHex
	if !seen[def] {
		out = append(out, def)
	}
	return out
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
	body, err := io.ReadAll(io.LimitReader(r.Body, inform.MaxBodySize+1))
	if err != nil {
		s.lg.Debug("inform: body read error", "err", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(body) > inform.MaxBodySize {
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

// handlePacketPlain processes a FRAMED packet that carries no encryption
// flags (plain inform, possibly zlib-compressed). MAC comes from the packet
// header; the payload goes through the codec's Decode so zlib-only (0x02)
// packets are inflated and snappy-flagged ones are rejected with the
// classic error. Decode's no-encryption-flags branch ignores the key
// entirely and only inflates zlib/parses snappy — any valid key works, the
// factory default is simply the cheapest candidate.
func (s *Server) handlePacketPlain(w http.ResponseWriter, pkt *inform.Packet) {
	mac := canonMACFromHeader(pkt.MAC)
	if mac == "" {
		s.lg.Debug("inform-plain: empty MAC in header")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	d, derr := inform.Decode(pkt, []string{inform.DefaultKeyHex})
	if derr != nil {
		if errors.Is(derr, inform.ErrNotJSONObject) {
			s.lg.Debug("inform-plain: payload not a JSON object")
		} else {
			s.lg.Debug("inform-plain: payload parse failed", "err", derr)
		}
		writeJSONErr(w, http.StatusBadRequest, "unable to parse inform payload")
		return
	}
	s.handlePlain(w, mac, d.Body)
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
		jd, derr := inform.Decode(pkt, []string{inform.DefaultKeyHex})
		if derr != nil {
			s.lg.Debug("inform: no key produced a valid JSON payload", "mac", mac, "tried", 1)
			writeJSONErr(w, http.StatusBadRequest, "unable to decrypt inform payload")
			return
		}
		// FID-35: the jar's MAC-consistency check (privatesuper offsets
		// 13-50) precedes every recording step, unknown devices included.
		if !payloadMACMatches(mac, jd.Body) {
			mm, _ := jd.Body["mac"].(string)
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
		s.internalNoopResponse(w, pkt, nil, "", mac, "store error", err)
		return
	}
	s.lg.Debug("inform: packet", "mac", mac, "flags", fmt.Sprintf("0x%04x", pkt.Flags), "bodyLen", len(body))

	candidates := keyCandidates(rec)
	jd, derr := inform.Decode(pkt, candidates)
	if derr != nil {
		s.lg.Debug("inform: no key produced a valid JSON payload", "mac", mac, "tried", len(candidates))
		writeJSONErr(w, http.StatusBadRequest, "unable to decrypt inform payload")
		return
	}
	jm, usedKey, keyBytes := jd.Body, jd.UsedKey, jd.KeyBytes
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
		now := time.Now()
		s.absorbInform(mac, rec, jm, now, gcmReq)
		out, aerr := s.engine.Decide(adoption.Request{
			Transport:      adoption.TransportEncrypted,
			Device:         *rec,
			Body:           jm,
			UsedKey:        usedKey,
			Now:            now,
			PrevNoopTarget: s.noopTargetSnapshot(mac),
		})
		if aerr != nil {
			return s.mapEngineError(rec, aerr)
		}
		outcome = advanceResult{resp: s.applyOutcome(mac, rec, out), kind: string(out.Kind)}
		return nil
	})
	if uerr != nil {
		var rej *informRejectError
		if errors.As(uerr, &rej) {
			s.lg.Debug("inform: rejected", "mac", mac, "reason", rej.reason)
			w.WriteHeader(rej.status)
			return
		}
		var unsupported *ErrLiveWLANProvisioningUnsupported
		if errors.As(uerr, &unsupported) {
			s.lg.Warn("inform: live WLAN provisioning gated", "mac", mac, "status", unsupported.Status())
			w.WriteHeader(unsupported.Status())
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
		s.internalNoopResponse(w, pkt, keyBytes, usedKey, mac, "update error", uerr)
		return
	}

	s.writeInformResponse(w, pkt, keyBytes, outcome, mac, usedKey)
}

// advanceResult carries the inform response built inside the store's
// read-modify-write cycle out to the HTTP writer.
type advanceResult struct {
	resp map[string]any
	kind string
}

// writeInformResponse renders outcome over the wire: plaintext informs get
// plain JSON; encrypted ones get the classic sealed envelope. If sealing
// fails (rand/cipher errors), a plain-JSON noop rides out under an HTTP 200
// (FID-69: internal failures never surface as 500) rather than leaving the
// socket empty.
func (s *Server) writeInformResponse(w http.ResponseWriter, pkt *inform.Packet, keyBytes []byte, outcome advanceResult, mac, usedKey string) {
	out, err := json.Marshal(outcome.resp)
	if err != nil {
		s.internalPlainNoopResponse(w, "response marshal failed", err)
		return
	}
	serialized, serr := inform.Respond(pkt, keyBytes, out)
	if serr != nil {
		s.internalPlainNoopResponse(w, "response sealing failed", serr)
		return
	}
	// Never log usedKey: it is a live decryption/adoption credential.
	s.lg.Debug("inform: reply", "mac", mac, "kind", outcome.kind,
		"gcm", pkt.Flags&inform.FlagGCM != 0)
	w.Header().Set("Content-Type", "application/x-binary")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(serialized)
}

// internalNoopResponse answers an internal inform-processing failure with
// HTTP 200 and a noop payload (FID-69, decided: align, not 500). When the
// request was encrypted and the per-device key is known, the noop is sealed
// exactly like a real reply; when no key was established (e.g. the store
// failed before decryption), it falls back to plain JSON.
func (s *Server) internalNoopResponse(w http.ResponseWriter, pkt *inform.Packet, keyBytes []byte, usedKey string, mac, cause string, cerr error) {
	s.lg.Error("inform: internal error, answering noop", "mac", mac, "cause", cause, "err", cerr)
	outcome := advanceResult{resp: s.noopResp(), kind: "internal-error"}
	if keyBytes == nil {
		s.internalPlainNoopResponse(w, cause, cerr)
		return
	}
	s.writeInformResponse(w, pkt, keyBytes, outcome, mac, usedKey)
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
		claim = inform.DefaultKeyHex
	}
	var outcome advanceResult
	uerr := s.st.UpdateExisting(mac, func(rec *store.Device) error {
		now := time.Now()
		s.absorbInform(mac, rec, jm, now, false)
		out, aerr := s.engine.Decide(adoption.Request{
			Transport:      adoption.TransportPlaintext,
			Device:         *rec,
			Body:           jm,
			UsedKey:        claim,
			Now:            now,
			PrevNoopTarget: s.noopTargetSnapshot(mac),
		})
		if aerr != nil {
			return s.mapEngineError(rec, aerr)
		}
		outcome = advanceResult{resp: s.applyOutcome(mac, rec, out), kind: string(out.Kind)}
		return nil
	})
	if uerr != nil {
		var unsupported *ErrLiveWLANProvisioningUnsupported
		if errors.As(uerr, &unsupported) {
			s.lg.Warn("inform-plain: live WLAN provisioning gated", "mac", mac, "status", unsupported.Status())
			w.WriteHeader(unsupported.Status())
			return
		}
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
	// Never log the plaintext auth claim.
	s.lg.Debug("inform-plain: reply", "mac", mac, "kind", outcome.kind)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// mapEngineError converts engine error sentinels onto the transport-layer
// protocol rejections they map to (FID-1 default-key rejection → the 404
// marker; the unsupported-live-WLAN lane → the typed 501).
func (s *Server) mapEngineError(rec *store.Device, err error) error {
	if errors.Is(err, adoption.ErrDefaultKeyRejected) {
		return errDefaultKeyRejected
	}
	if errors.Is(err, adoption.ErrLiveWLANProvisioningUnsupported) {
		return &ErrLiveWLANProvisioningUnsupported{Model: rec.Model, Firmware: rec.Firmware}
	}
	return err
}

// noopTargetSnapshot reads the controller-owned steady-state noop target for
// a MAC. The Server.noopMu/noopTarget map stays adapter-owned; the engine
// receives the value in the Request and the outcome carries the new one back.
func (s *Server) noopTargetSnapshot(mac string) int64 {
	s.noopMu.Lock()
	defer s.noopMu.Unlock()
	return s.noopTarget[mac]
}

// applyOutcome applies the engine's record deltas to the adapter's record
// and serializes the outcome into the EXACT response JSON shapes of the
// pre-extraction behavior (adoption push: mgmt_cfg only; full provisioning:
// all four config keys; noop: interval).
func (s *Server) applyOutcome(mac string, rec *store.Device, out adoption.Outcome) map[string]any {
	if out.SetState {
		rec.State = out.State
	}
	if out.SetXAuthkey {
		rec.XAuthkey = out.XAuthkey
	}
	if out.SetCfgVersion {
		rec.CfgVersion = out.CfgVersion
	}
	if out.SetAuthkeys {
		rec.Authkeys = out.Authkeys
	}
	rec.Extra = out.Extra
	// Credential-cache deltas from the pure renderer: the renderer no longer
	// mutates anything, so the adapter applies them at the same point the
	// former in-place mutation landed (same keys, same values, same timing →
	// persisted Extra bytes identical).
	for k, v := range out.CredentialDeltas {
		rec.Extra[k] = v
	}
	if out.PersistNoopTarget {
		s.noopMu.Lock()
		s.noopTarget[mac] = out.NewNoopTarget
		s.noopMu.Unlock()
	}
	switch out.Kind {
	case adoption.KindSetparam:
		if out.FullProvision {
			return map[string]any{
				"_type":              "setparam",
				"server_time_in_utc": nowMS(),
				"cfgversion":         out.CfgVersion,
				"system_cfg":         out.SystemCfg,
				"blocked_sta":        out.BlockedSta,
				"mgmt_cfg":           out.MgmtCfg,
			}
		}
		return map[string]any{
			"_type":              "setparam",
			"server_time_in_utc": nowMS(),
			"mgmt_cfg":           out.MgmtCfg,
		}
	default:
		return map[string]any{
			"_type":              "noop",
			"server_time_in_utc": nowMS(),
			"interval":           out.Interval,
		}
	}
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
//
// extraPrevWins is built from the engine's single-source controller-owned
// key list (adoption.ControllerOwnedKeys) plus the server-side ssh hash
// cache key. absorbInform's iteration is order-independent and JSON map
// marshaling sorts keys, so the copy order carries no byte semantics.
var (
	extraPrevWins     = append(append([]string{}, adoption.ControllerOwnedKeys...), "ssh_sha512passwd")
	extraFillIfAbsent = []string{"radio_table", "wifi_caps", "fw_caps", "if_table", "ethernet_table", "uplink", "has_eth1"}
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

// ---- system_cfg producer wiring (the pure renderer) -----------------------

// renderSystemCfg is the adapter's wiring of the pure systemcfg renderer
// (the D5 producer shape): it assembles SiteFacts from the server config and
// the engine-threaded WLAN snapshot, validates the config exactly like the
// former render path did, and performs the render's observability here —
// the renderer's diagnostics (warn-level alerts with their structured attrs,
// debug-level warnings) and the full-config diagnostic (digest and ordered
// names, never config values; the "unavailable" wording keeps the debug path
// bounded for malformed passthrough input without echoing a key name). All
// logging happens inside the producer call, before Decide returns, restoring
// the pre-extraction relative order (inline-during-render → diagnostic-after).
func (s *Server) renderSystemCfg(d store.Device, wls []wireless.Wlan) (string, map[string]string, error) {
	if err := ValidateConfig(s.cfg); err != nil {
		return "", nil, err
	}
	country := s.cfg.RegulatoryCountryCode
	if country == 0 {
		// R3: defense-in-depth — ValidateConfig already defaults zero to the
		// compatibility value; the renderer takes the code verbatim.
		country = DefaultRegulatoryCountryCode
	}
	res, err := systemcfg.Render(d, systemcfg.SiteFacts{
		ControllerURL: s.cfg.ControllerURL,
		CountryCode:   country,
		SSHPassword:   s.cfg.SSHPassword,
		WLANs:         wls,
	})
	if err != nil {
		return "", nil, err
	}
	for _, warn := range res.Warnings {
		s.lg.Debug(warn)
	}
	for _, alert := range res.Alerts {
		if alert.Where != "" {
			s.lg.Warn(alert.Msg, "where", alert.Where, "key", alert.Key)
			continue
		}
		s.lg.Warn(alert.Msg)
	}
	if diagnostic, derr := systemcfg.Diagnostic(res.Text); derr == nil {
		s.lg.Debug(diagnostic)
	} else {
		s.lg.Debug("system_cfg diagnostic unavailable", "reason", "duplicate-key")
	}
	return res.Text, res.CredentialDeltas, nil
}

// noopRandom is a narrow seam for the jar's per-response random interval.
// It deliberately does not use the process-global math/rand source.
var noopRandom = func() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return float64(binary.LittleEndian.Uint64(b[:])) / float64(^uint64(0))
}

// noopResp is the exception/internal fallback. Record-aware normal noops use
// the adoption engine's noop scheduling (Engine.noopFor, the standard
// non-ubios UAP scheduler).
func (s *Server) noopResp() map[string]any {
	return map[string]any{
		"_type":              "noop",
		"server_time_in_utc": nowMS(),
		"interval":           10,
	}
}

// ---- serving --------------------------------------------------------------
//
// The inform endpoint is owned by the caller: cmd/openunifi wires the
// InformHandler into its own http.Server (main.go). The classic jar has no
// inform-side shutdown path of its own, and the former ServeInform/
// Shutdown/httpSrv trio in this file was dead code (FID-55-server).

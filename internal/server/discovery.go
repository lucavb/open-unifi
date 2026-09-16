// discovery.go implements the UDP :10001 discovery listener
// ("LiteStationQueryServer" — com/ubnt/net/K over base class
// com/super/A/A/G, parser com/super/A/A/O0oO).
//
// Ground truth is the redumped parser class
// tmpwork/javap/regen/O0oO_discovery_redump.txt (class com.super.A.A.O0oO,
// 1733 lines). Cited line map: version dispatch :61-190; TLV loop switch;
// v2 gates :815-862; anti-replay :862-928; debug log :908; cmd dispatch
// :934-946; challenge :1024-1228; site-local :1232-1252; V0 :1331-1461;
// reply builder :1462-1564; sshd :1566-1596; static model blocklist
// :1675-1733. Encoder half: com/super/A/A/oooO builds [ver:1][cmd:1]
// [payloadLen:2 BE] headers and [type:1][len:2 BE][value] TLV entries and
// auto-adds TLV 18 (seq) + TLV 19 (own MAC) on v2 packets.
//
// An earlier revision of this file parsed a fabricated composite layout
// ([ver][mac:6 @1][ip:4 @7][len:2 BE @11][version @13] with a 0x7f mask on
// byte 0). That layout was refuted by bytecode adjudication: byte 0 is the
// EXACT version (never masked — 0x80 alone is "Unknown version (N)" and
// rejected), byte 1 is the command, bytes 2-3 are the BE16 payload length,
// and the MAC lives in TLV 1 on modern packets.
//
// Milestone scope (docs/PROTOCOL.md §4): parse announcing devices, record
// pending candidates for the adoption UI via store.MarkPending, apply the
// jar's v2 gates and anti-replay, and answer V2 cmd-8 beacons with cmd-9.
// Malformed packets
// are logged and dropped, never fatal.
package server

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// discoveryDedupWindow is the anti-replay freshness window (jar:
	// notes last-seen in seconds and drops only when now-last < 5 s
	// AND seq <= lastSeq; O0oO_discovery_redump.txt:862-928).
	discoveryDedupWindow = 5 * time.Second

	// discoveryMinModernLen is the modern header size [ver][cmd][len:2].
	discoveryMinModernLen = 4

	// discoveryMinV0Len is the V0 card minimum (redump:1331-1341).
	discoveryMinV0Len = 15

	// discoveryPruneThreshold bounds the sightings map. DEVIATION: the
	// jar keeps the per-MAC map unbounded; we opportunistically prune
	// entries whose last sighting is older than the window once the map
	// grows past this, to bound memory on hostile networks.
	discoveryPruneThreshold = 4096
)

// Discovery TLV ids (O0oO_discovery_redump.txt TLV loop switch:87-1008;
// encoder/decoder parity mirrored from the oooO builder).
const (
	tlvMAC          byte = 1  // 6-byte device MAC
	tlvAliasIP      byte = 2  // 10-byte interface MAC(6)+IP(4), repeatable
	tlvVersion      byte = 3  // firmware version string
	tlvESSID        byte = 13 // wlan essid string
	tlvWMode        byte = 14 // wlan mode (BE int)
	tlvFingerprint  byte = 16 // fingerprint string (hex)
	tlvSeq          byte = 18 // v2 sequence number (BE int; anti-replay)
	tlvSenderMAC    byte = 19 // sender MAC echo (6-byte)
	tlvModel        byte = 21 // model/shortname string
	tlvShortVersion byte = 22 // short firmware version string
	tlvFactory      byte = 23 // factory-state byte (nonzero = factory)
	tlvSSHDPort     byte = 28 // ssh port (BE int; default 22 server-side)
	tlvPlatform     byte = 12 // platform shortname string
	tlvHostname     byte = 11 // hostname string
	tlvUptime       byte = 10 // uptime seconds (BE int)
)

// discoveryAlias is one TLV 2 entry (interface MAC + IPv4 address).
type discoveryAlias struct {
	mac [6]byte
	ip  [4]byte
}

// discoveryInfo mirrors what O0oO.new (the D-analogue record) contains for
// an accepted datagram. mac is nil when TLV 1 was absent (invalid v2).
type discoveryInfo struct {
	ver         byte
	cmd         byte
	mac         []byte // TLV1 (modern) or card bytes 1-6 (V0)
	senderMAC   []byte // TLV19 (v2 encoder echoes the sender MAC)
	seq         int    // TLV18; -1 when absent
	aliases     []discoveryAlias
	version     string // TLV3 / V0 trailing version string
	hostname    string // TLV11
	platform    string // TLV12
	essid       string // TLV13
	wmode       int    // TLV14 (BE int)
	fingerprint string // TLV16
	model       string // TLV21
	shortVer    string // TLV22
	factory     bool
	hasFactory  bool
	sshdPort    int // TLV28 (BE int)
	uptimeSec   int64
	ip          string // first alias IP, else the UDP source address
}

type discoveryReplyMetadata struct {
	identity, firmware, board, version string
	aliases                            []discoveryAlias
	setup                              bool
	seq                                uint32
}

// ServeDiscovery blocks reading UDP discovery packets on ln until the
// connection is closed. It never crashes on bad packets. G.run reads into
// a fixed 1024-byte window per datagram; longer datagrams contribute only
// their first 1024 bytes (G.run loop, invoked on every selector key).
func (s *Server) ServeDiscovery(ln *net.UDPConn) error {
	buf := make([]byte, 1024)
	for {
		n, src, err := ln.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			s.lg.Debug("discovery: read error", "err", err)
			return err
		}
		s.handleDiscoveryPacketConn(ln, src, buf[:n])
	}
}

// discoveryModelBlocked mirrors the jar's static mFi shortname blocklist
// (intclass; O0oO_discovery_redump.txt:1675-1733): an exact model match
// drops the packet before it ever reaches the pending feed.
func discoveryModelBlocked(model string) bool {
	switch model {
	case "M2M", "M2S", "P8U", "P6E", "P3U", "P3E", "P1U", "P1E", "IWO2U", "IWD1U":
		return true
	}
	return false
}

// discoverySighting is one per-MAC anti-replay record (O0oO$_o: last seq +
// last-seen seconds).
type discoverySighting struct {
	lastSeq  int
	lastSeen time.Time
}

// discoverySightings carries per-Server anti-replay state plus the lazily
// computed own-interface MACs used by the v2 self-guard. It lives here (a
// registry keyed by *Server) so the lane's ownership stays inside
// discovery.go instead of widening server.go's struct.
type discoverySightings struct {
	mu                 sync.Mutex
	byMAC              map[string]discoverySighting
	replySeq           uint32
	replyMeta          *discoveryReplyMetadata
	replyDestination   *net.UDPAddr
	testIdentity       string
	replySourceAllowed func(*net.UDPAddr) bool
	replyWriter        func([]byte, *net.UDPAddr) error
}

// discoveryReplays maps a *Server to its sightings. Never shrinked: one
// entry per constructed Server (tests construct them; production has one).
var discoveryReplays sync.Map

func (s *Server) discoverySightings() *discoverySightings {
	if v, ok := discoveryReplays.Load(s); ok {
		return v.(*discoverySightings)
	}
	v, _ := discoveryReplays.LoadOrStore(s, &discoverySightings{byMAC: map[string]discoverySighting{}})
	return v.(*discoverySightings)
}

// discoverySelfGuard reports whether the packet's TLV 19 echoes one of our
// own interface MACs (jar: drop silently, :815-862 self-guard branch).
func (s *Server) discoverySelfGuard(info discoveryInfo) bool {
	echo := discoveryMACString(info.senderMAC)
	return echo != "" && echo == s.discoveryIdentity()
}

func (s *Server) discoveryIdentity() string {
	st := s.discoverySightings()
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.testIdentity != "" {
		return st.testIdentity
	}
	if st.replyMeta != nil && st.replyMeta.identity != "" {
		return st.replyMeta.identity
	}
	return discoveryHostMetadata().identity
}

func (s *Server) setDiscoveryTestIdentity(identity string) {
	st := s.discoverySightings()
	st.mu.Lock()
	defer st.mu.Unlock()
	st.testIdentity = identity
}

// discoveryMACString formats 6 MAC bytes the way the jar does
// (OOoO.super([B): lower-case colon-separated hex).
func discoveryMACString(mac []byte) string {
	if len(mac) != 6 {
		return ""
	}
	parts := make([]string, 6)
	for i, b := range mac {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return strings.ToLower(strings.Join(parts, ":"))
}

// seeDiscovery is the per-MAC anti-replay decision (jar :862-928, replacing
// the previous plain sighting-dedupe). A packet is dropped IF
//
//	now - lastSeen < discoveryDedupWindow  AND  seq <= lastSeq
//
// a HIGHER seq inside the window is accepted. The recorded state is always
// the packet's own seq/time. The map pruning below stays a documented
// deviation from the jar's unbounded per-MAC map.
func (s *Server) seeDiscovery(info discoveryInfo) bool {
	key := discoveryMACString(info.mac)
	st := s.discoverySightings()
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	prev, ok := st.byMAC[key]
	if ok && now.Sub(prev.lastSeen) < discoveryDedupWindow && info.seq <= prev.lastSeq {
		return false
	}
	st.byMAC[key] = discoverySighting{lastSeq: info.seq, lastSeen: now}
	if len(st.byMAC) > discoveryPruneThreshold {
		for k, v := range st.byMAC {
			if now.Sub(v.lastSeen) >= discoveryDedupWindow {
				delete(st.byMAC, k)
			}
		}
	}
	return true
}

// discoveryCanonicalMAC renders the candidate's MAC as the keyed 12-hex
// (store-side pending map key shape).
func discoveryCanonicalMAC(mac []byte) string {
	return strings.ToLower(hex.EncodeToString(mac))
}

// handleDiscoveryPacket parses one announce datagram and records the sender
// as a pending adoption candidate. Control order mirrors the jar exactly:
// redump:61-190 version dispatch -> TLV/BLE walk -> (v2 only) gates
// :815-862 in order (cmd8 optional-reply, validity, self-guard, model
// blocklist, anti-replay :862-928) -> cmd dispatch :934-946.
func (s *Server) handleDiscoveryPacket(src *net.UDPAddr, b []byte) {
	s.handleDiscoveryPacketConn(nil, src, b)
}

func (s *Server) handleDiscoveryPacketConn(conn *net.UDPConn, src *net.UDPAddr, b []byte) {
	info, ok := s.parseDiscovery(src, b)
	if !ok {
		if info.ver > 2 {
			// Jar parity: warn-level "Unknown version (N) packet,
			// discarding..." (:61-190 default card).
			s.lg.Warn("Unknown version (" + strconv.Itoa(int(info.ver)) + ") packet, discarding...")
		}
		return
	}
	if info.ver == 2 && info.cmd == 8 {
		st := s.discoverySightings()
		st.mu.Lock()
		allowed := discoverySiteLocalIPv4
		if st.replySourceAllowed != nil {
			allowed = st.replySourceAllowed
		}
		st.mu.Unlock()
		if conn != nil && allowed(src) && !s.discoverySelfGuard(info) {
			dst := src
			st := s.discoverySightings()
			st.mu.Lock()
			if st.replyDestination != nil {
				dst = st.replyDestination
			}
			st.mu.Unlock()
			packet := s.discoveryEncodeReply()
			if st.replyWriter != nil {
				_ = st.replyWriter(packet, dst)
			} else {
				_, _ = conn.WriteToUDP(packet, dst)
			}
		}
		return
	}
	// Dispatch (:934-946). Announce = cmd 6 or its 0x80-flagged variant;
	// challenge-resp = cmd 2 or 0x82; everything else is unsupported.
	switch info.cmd {
	case 6, 0x80:
		s.recordDiscoveryCandidate(src, info)
	case 2, 0x82:
		// Challenge flow carries TLV salt/challenge; this jar has no
		// command queue — debug-drop (:1024-1228).
		s.lg.Debug("discovery: challenge response packet dropped (no command queue)")
	default:
		s.lg.Debug("discovery: unsupported command", "cmd", info.cmd, "ver", info.ver)
	}
}

func discoverySiteLocalIPv4(src *net.UDPAddr) bool {
	if src == nil {
		return false
	}
	ip := src.IP.To4()
	if ip == nil {
		return false
	}
	return ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168)
}

func discoveryHostMetadata() discoveryReplyMetadata {
	m := discoveryReplyMetadata{firmware: "unknown", board: "unknown", version: "unknown"}
	ifaces, _ := net.Interfaces()
	for _, ifi := range ifaces {
		if ifi.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 || len(ifi.HardwareAddr) != 6 {
			continue
		}
		var mac [6]byte
		copy(mac[:], ifi.HardwareAddr)
		addrs, _ := ifi.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch a := addr.(type) {
			case *net.IPNet:
				ip = a.IP
			case *net.IPAddr:
				ip = a.IP
			}
			if ip4 := ip.To4(); ip4 != nil && ip4.IsGlobalUnicast() {
				var raw [4]byte
				copy(raw[:], ip4)
				m.aliases = append(m.aliases, discoveryAlias{mac: mac, ip: raw})
			}
		}
	}
	if len(m.aliases) > 0 {
		m.identity = discoveryMACString(m.aliases[0].mac[:])
	}
	return m
}

func (s *Server) discoveryEncodeReply() []byte {
	st := s.discoverySightings()
	st.mu.Lock()
	defer st.mu.Unlock()
	m := discoveryHostMetadata()
	if st.replyMeta != nil {
		m = *st.replyMeta
	}
	if st.testIdentity != "" {
		m.identity = st.testIdentity
	}
	st.replySeq++
	m.seq = st.replySeq
	mac, err := hex.DecodeString(strings.ReplaceAll(m.identity, ":", ""))
	if err != nil || len(mac) != 6 {
		return nil
	}
	var p []byte
	add := func(t byte, v []byte) { p = append(p, t, byte(len(v)>>8), byte(len(v))); p = append(p, v...) }
	seq := make([]byte, 4)
	binary.BigEndian.PutUint32(seq, m.seq)
	add(tlvSeq, seq)
	add(tlvSenderMAC, mac)
	add(tlvMAC, mac)
	for _, a := range m.aliases {
		add(tlvAliasIP, append(append([]byte(nil), a.mac[:]...), a.ip[:]...))
	}
	add(tlvVersion, []byte(m.firmware))
	add(tlvModel, []byte(m.board))
	add(tlvShortVersion, []byte(m.version))
	if m.setup {
		add(tlvFactory, []byte{1})
	} else {
		add(tlvFactory, []byte{0})
	}
	return append([]byte{2, 9, byte(len(p) >> 8), byte(len(p))}, p...)
}

// recordDiscoveryCandidate feeds the pending-adoption map (K's dark path:
// "adopt is not implemented" but the discovery updater feeds X records for
// the UI; open-unifi stores the candidate + a jar-faithful note). V0 cards
// carry no cmd — they are announce-shaped by construction.
func (s *Server) recordDiscoveryCandidate(src *net.UDPAddr, info discoveryInfo) {
	if len(info.mac) != 6 {
		s.lg.Debug("discovery: no candidate MAC", "ver", info.ver)
		return
	}
	mac := discoveryCanonicalMAC(info.mac)
	note := discoveryNote(info)
	if err := s.st.MarkPending(mac, note); err != nil {
		s.lg.Warn("discovery: mark pending failed", "mac", mac, "note", note, "err", err)
		return
	}
	s.lg.Debug("discovery: announced", "mac", mac, "note", note)
	_ = src // (kept for parity with jar's per-source logging)
}

// discoveryNote renders the pending-candidate note from the jar's X-record
// fields (docs/PROTOCOL-discovery.md §2 K feed): model, version, hostname,
// uptime, ip, sshd port, plus extras when present.
func discoveryNote(info discoveryInfo) string {
	var parts []string
	addString := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	addInt := func(k string, v int64) {
		if v > 0 {
			parts = append(parts, k+"="+strconv.FormatInt(v, 10))
		}
	}
	addInt("uptime", info.uptimeSec)
	addString("version", info.version)
	addString("model", info.model)
	addString("hostname", info.hostname)
	if info.sshdPort > 0 {
		addInt("sshd_port", int64(info.sshdPort))
	}
	addString("ip", info.ip)
	addString("shortversion", info.shortVer)
	addString("platform", info.platform)
	addString("essid", info.essid)
	if info.wmode > 0 {
		addInt("wmode", int64(info.wmode))
	}
	if info.hasFactory {
		parts = append(parts, "factory="+strconv.FormatBool(info.factory))
	}
	return "discovery:" + strings.Join(parts, ",")
}

// parseDiscovery extracts the candidate record from one discovery
// datagram. Returns ok=false for every drop gate; the version is surfaced
// in info.ver even on unknown versions so the caller can warn. src may be
// nil in tests (no IP fallback then).
//
// Real layouts (adjudication-verified, redump:61-190 / :1331-1461):
//
//	[ver:1][cmd:1][payloadLen:2 BE][TLV...]     — ver 1/2
//	[ver=0][mac:6][ip:4][len:4 BE][version…]    — V0 (min 15 bytes)
func (s *Server) parseDiscovery(src *net.UDPAddr, b []byte) (discoveryInfo, bool) {
	var info discoveryInfo
	if len(b) == 0 {
		return info, false
	}
	info.ver = b[0]
	switch info.ver {
	case 0:
		return parseDiscoveryV0(src, b)
	case 1, 2:
		return s.parseDiscoveryModern(src, b)
	default:
		return info, false
	}
}

// parseDiscoveryModern walks the [type:1][len:2 BE][value] TLV stream
// (redump TLV switch). Types we do not model (6/7/8/9 challenge bytes,
// 24-27, 33-39, 42, 48/49) are skipped like the jar's default card, with
// the same bound checks.
func (s *Server) parseDiscoveryModern(src *net.UDPAddr, b []byte) (discoveryInfo, bool) {
	var info discoveryInfo
	if len(b) < discoveryMinModernLen {
		return info, false
	}
	info.ver = b[0]
	info.cmd = b[1]
	info.seq = -1
	dataLen := int(binary.BigEndian.Uint16(b[2:4]))
	end := discoveryMinModernLen + dataLen
	if end > len(b) {
		// "Packet reports invalid data length, discarding..." (debug).
		return info, false
	}
	data := b[discoveryMinModernLen:end]
	for i := 0; i < len(data); {
		typ := data[i]
		i++
		if i+2 > len(data) {
			return info, false
		}
		l := int(binary.BigEndian.Uint16(data[i : i+2]))
		i += 2
		if i+l > len(data) {
			// "Invalid length (N) for item T" (debug; jar discards the
			// WHOLE packet, not just the TLV).
			return info, false
		}
		val := data[i : i+l]
		i += l
		switch typ {
		case tlvMAC:
			if l == 6 {
				info.mac = append([]byte(nil), val...)
			}
		case tlvAliasIP:
			if l == 10 {
				var a discoveryAlias
				copy(a.mac[:], val[:6])
				copy(a.ip[:], val[6:])
				info.aliases = append(info.aliases, a)
			}
		case tlvVersion:
			info.version = strings.TrimSpace(discoveryLatin1String(val))
		case tlvUptime:
			if l >= 4 {
				info.uptimeSec = int64(binary.BigEndian.Uint32(val[:4]))
			}
		case tlvHostname:
			info.hostname = strings.TrimSpace(discoveryLatin1String(val))
		case tlvPlatform:
			info.platform = strings.TrimSpace(discoveryLatin1String(val))
		case tlvESSID:
			info.essid = strings.TrimSpace(discoveryLatin1String(val))
		case tlvWMode:
			if l >= 4 {
				info.wmode = int(binary.BigEndian.Uint32(val[:4]))
			}
		case tlvFingerprint:
			info.fingerprint = strings.TrimSpace(discoveryLatin1String(val))
		case tlvSeq:
			if l >= 4 {
				info.seq = int(binary.BigEndian.Uint32(val[:4]))
			}
		case tlvSenderMAC:
			if l == 6 {
				info.senderMAC = append([]byte(nil), val...)
			}
		case tlvModel:
			info.model = strings.TrimSpace(discoveryLatin1String(val))
		case tlvShortVersion:
			info.shortVer = strings.TrimSpace(discoveryLatin1String(val))
		case tlvFactory:
			if l >= 1 {
				info.factory = val[0] != 0
				info.hasFactory = true
			}
		case tlvSSHDPort:
			if l >= 4 {
				info.sshdPort = int(binary.BigEndian.Uint32(val[:4]))
			}
		default:
			// Unknown type: trace-skip (jar default card).
			continue
		}
	}
	info.ip = discoveryCandidateIP(src, info)

	// v2 gates, in jar order (O0oO_discovery_redump.txt:815-928). v1
	// packets skip gates 1-5 entirely. V0 was dispatched before the walk.
	if info.ver == 2 {
		// (1) validity: TLV1 ∧ seq >= 1 ∧ TLV19, else "invalid v2
		// packet" (info level, :830-843).
		if info.mac == nil || info.seq < 1 || info.senderMAC == nil {
			s.lg.Info("discovery: invalid v2 packet")
			return info, false
		}
		// (3) self-guard: own-interface MAC == TLV19 → drop (:844-855).
		if s.discoverySelfGuard(info) {
			return info, false
		}
		// cmd-8 is syntactically valid but reply-only; the receive path
		// consumes it before command dispatch and never records it.
		if info.cmd == 8 {
			return info, true
		}
		// (4) model blocklist — mFi family (:855-862; list :1675-1733).
		if discoveryModelBlocked(info.model) {
			return info, false
		}
		// (5) anti-replay (:862-928): drop iff fresh window AND
		// seq <= lastSeq; a higher seq inside the window IS accepted.
		if !s.seeDiscovery(info) {
			return info, false
		}
	}
	return info, true
}

// discoveryLatin1String decodes TLV string payloads (jar reads the card
// bytes; the encoder writes ISO-8859-1).
func discoveryLatin1String(val []byte) string {
	return string(val)
}

// discoveryCandidateIP picks the candidate IP exactly like the jar's D
// record: first TLV2 alias IP, else the datagram source address.
func discoveryCandidateIP(src *net.UDPAddr, info discoveryInfo) string {
	for _, a := range info.aliases {
		return net.IP(a.ip[:]).String()
	}
	if src != nil {
		return src.IP.String()
	}
	return ""
}

// parseDiscoveryV0 reads the legacy flat card (redump:1331-1461):
//
//	[ver=0][mac:6 @1][ip:4 @7][len:4 BE @11][version-string…]
//
// minimum 15 bytes; shorter cards warn "Malformed V0" and are dropped.
func parseDiscoveryV0(src *net.UDPAddr, b []byte) (discoveryInfo, bool) {
	var info discoveryInfo
	info.ver = 0
	if len(b) < discoveryMinV0Len {
		// "Malformed V0: from [%s]: ip=%s, version=%s"
		return info, false
	}
	info.mac = append([]byte(nil), b[1:7]...)
	var ipBytes [4]byte
	copy(ipBytes[:], b[7:11])
	info.ip = net.IP(ipBytes[:]).String()
	cardLen := binary.BigEndian.Uint32(b[11:15])
	_ = cardLen
	if len(b) > discoveryMinV0Len {
		info.version = strings.TrimSpace(discoveryLatin1String(b[discoveryMinV0Len:]))
	}
	return info, true
}

// discovery.go implements the UDP :10001 discovery listener ("LiteStationQueryServer").
//
// Milestone scope (docs/PROTOCOL.md §4): parse announcing devices, record
// candidates for the adoption UI via store.MarkPending, dedupe sightings
// within 5s per MAC, and respond NOTHING (no discovery reply yet — TODO).
// Malformed packets are logged at debug and dropped, never fatal.
package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// discoveryDedupWindow suppresses repeat announcements per MAC.
const discoveryDedupWindow = 5 * time.Second

// ServeDiscovery blocks reading UDP discovery packets on ln until the
// connection is closed. It never crashes on bad packets.
func (s *Server) ServeDiscovery(ln *net.UDPConn) error {
	buf := make([]byte, 4096)
	for {
		n, _, err := ln.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			s.lg.Debug("discovery: read error", "err", err)
			return err
		}
		s.handleDiscoveryPacket(buf[:n])
	}
}

// handleDiscoveryPacket parses one announce packet ([ver:1][cmd:1][dlen:2 BE][data])
// and records the sender as a discovery-pending candidate.
func (s *Server) handleDiscoveryPacket(b []byte) {
	mac, note, ok := parseDiscovery(b)
	if !ok {
		s.lg.Debug("discovery: unparseable packet", "len", len(b))
		return
	}
	if !s.seeDiscovery(mac) {
		s.lg.Debug("discovery: deduped", "mac", mac)
		return
	}
	if err := s.st.MarkPending(mac, note); err != nil {
		s.lg.Debug("discovery: mark pending failed", "mac", mac, "err", err)
		return
	}
	s.lg.Debug("discovery: announced", "mac", mac, "note", note)
}

// seeDiscovery returns true if this MAC's last sighting was outside the
// dedupe window (and records now as the latest sighting).
func (s *Server) seeDiscovery(mac string) bool {
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	now := time.Now()
	if t, ok := s.seenAt[mac]; ok && now.Sub(t) < discoveryDedupWindow {
		return false
	}
	s.seenAt[mac] = now
	return true
}

// parseDiscovery extracts (canonical MAC, UI note, ok) from a discovery packet.
//
// Layout per §4: [ver:1][cmd:1][dataLen:2 BE][payload TLVs]. Only announces
// (cmd == 6) are recorded this milestone; challenge-resp (cmd 2) is ignored.
// ver 0 uses a legacy fixed form starting with the 6-byte MAC at offset 4
// (15-byte minimum packet); ver 1/2 use the TLV stream.
// TODO(lane-A): reply like O0oO does (mac+ip TLVs type 1/2, 3=ver, 21/22/23)
// so devices can learn the inform URL from broadcast.
func parseDiscovery(b []byte) (mac, note string, ok bool) {
	if len(b) < 5 {
		return "", "", false
	}
	ver, cmd := b[0], b[1]
	if ver > 2 {
		return "", "", false
	}
	dlen := int(binary.BigEndian.Uint16(b[2:4]))
	data := b[4:]
	if dlen > len(data) {
		dlen = len(data) // tolerate trailing truncation rather than dropping
	}
	data = data[:dlen]

	switch {
	case cmd == 6: // announcement
		switch ver {
		case 0:
			// Legacy minimum form: 6-byte MAC first (15-byte min total packet).
			if len(data) < 6 || len(b) < 15 {
				return "", "", false
			}
			m := macHex(data[:6])
			return m, "discovery:platform=unknown", m != ""
		default: // ver 1 / ver 2 TLV stream
			macB, platform := parseTLVs(data)
			if macB == nil {
				return "", "", false
			}
			m := macHex(macB)
			return m, "discovery:platform=" + platform, m != ""
		}
	default:
		return "", "", false
	}
}

// TLV discovery types (docs/PROTOCOL.md §4).
const (
	tlvTypeMAC       = 1  // 6-byte MAC
	tlvTypeFwVer     = 3  // firmware version string
	tlvTypeHostname  = 11 // hostname
	tlvTypePlatform  = 12 // platform / hardware id
	tlvTypeSenderMAC = 19 // sender MAC (authoritative identity)
)

// parseTLVs walks a discovery TLV stream ([type:1][len:2 BE][value]) returning
// the identifying MAC (type 19 preferred, else type 1) and platform (type 12).
func parseTLVs(data []byte) (mac []byte, platform string) {
	for len(data) >= 3 {
		typ := data[0]
		l := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if l > len(data) {
			break // truncated stream; drop remainder
		}
		val := data[:l]
		data = data[l:]
		switch typ {
		case tlvTypeMAC:
			if mac == nil && l == 6 {
				mac = val
			}
		case tlvTypeSenderMAC:
			if l == 6 {
				mac = val // sender MAC wins
			}
		case tlvTypePlatform:
			platform = string(val)
		}
	}
	return mac, platform
}

// macHex renders 6 raw MAC bytes as canonical lowercase 12-hex.
func macHex(raw []byte) string {
	if len(raw) != 6 {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%x", raw))
}

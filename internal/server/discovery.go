// discovery.go implements the UDP :10001 discovery listener
// ("LiteStationQueryServer").
//
// Ground truth is the decompiled ace.jar bytecode. Socket setup and the
// 233.89.188.1 multicast membership live in com/super/A/A/G.o00000(I,
// [Ljava/lang/String;) at offs 98-290 (MulticastSocket(10001),
// setReuseAddress(true), joinGroup(233.89.188.1); a failed join is logged
// at warn and the loop still starts) with the receive loop in G.run()
// (offs 0-254, 1024-byte window). The v0 wire format and the parse
// decisions come from com/ubnt/net/K (K$1.run -> O0oO.new(Parser):
// "invalid MAC", "packet length: {} too short", "not a UBNT mac") and from
// com/super/A/A/D.<init>: ver 0x00/0x80 share one parser path with the
// length/resource half of the card re-read when byte 2 > 16
// ("[documentation follows the 2.0.0 plan]").
//
// Milestone scope (docs/PROTOCOL.md section 4): parse announcing devices,
// record candidates for the adoption UI via store.MarkPending, dedupe
// sightings within 5s per MAC. No reply is sent yet; malformed packets are
// logged at debug and dropped, never fatal.
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

// discoveryMinPacketLen is the minimum parseable announce length: byte 12
// must be reachable (D.o00000's "packet length: {} too short" floor).
const discoveryMinPacketLen = 13

// discoveryMinPacketLenv0 is the minimum legacy (ver 0) announce length
// (D.o00000 "drop" re-check: byte 2 < 0x12 -> reject).
const discoveryMinPacketLenv0 = 18

// discoveryMinLen is the minimum epoch string the length/4-byte sequence
// domain allows (FID-12).
const discoveryMinLen = 1

// ServeDiscovery blocks reading UDP discovery packets on ln until the
// connection is closed. It never crashes on bad packets.
func (s *Server) ServeDiscovery(ln *net.UDPConn) error {
	buf := make([]byte, 1024)
	for {
		n, _, err := ln.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			s.lg.Debug("discovery: read error", "err", err)
			return err
		}
		// G.run reads into a fixed 1024-byte window; a longer datagram
		// contributes only its first 1024 bytes.
		s.handleDiscoveryPacket(buf[:n])
	}
}

// handleDiscoveryPacket parses one announce packet and records the sender
// as a discovery-pending candidate. The jar only filters on packet shape
// here: K$1.run (FID-26) reads datagrampe.getSource() per packet and calls
// handle() per source IP, with no self-guard, no sequence-dedupe and no
// mFi-family counter in the discovery path.
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
		s.lg.Warn("discovery: mark pending failed", "mac", mac, "note", note, "err", err)
		return
	}
	s.lg.Debug("discovery: announced", "mac", mac, "note", note)
}

// seenPruneThreshold is the map size at which seeDiscovery opportunistically
// drops entries older than the dedupe window (unbounded MAC sources could
// otherwise grow the map forever).
const seenPruneThreshold = 4096

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
	if len(s.seenAt) > seenPruneThreshold {
		for m, t := range s.seenAt {
			if now.Sub(t) >= discoveryDedupWindow {
				delete(s.seenAt, m)
			}
		}
	}
	return true
}

// parseDiscovery extracts (canonical MAC, UI note, ok) from a discovery
// packet below the fixed layout of K/D.<init> (FID-12); a dropped announce
// is ok=false.
//
// Real launch (bytecode; not the fictional earlier [ver][cmd][len][TLV]):
//
//	[ver:1][mac:6 @1][ip:4 @7][len:2 BE @11][version:1 @13][payload…]
//
// For byte 6: the [len:2] field stores the version byte of the card
// (byte 2 < 0x12: "packet length: 8 too short"). The [len:2]-extended v0
// card short-circuits with the same integer norm (length 18 — FID-26,
// D.o00000 netif filter).
func parseDiscovery(b []byte) (mac, note string, ok bool) {
	if len(b) < discoveryMinPacketLen {
		return "", "", false
	}
	ver := b[0] & 0x7f // FID-28: 0x80 shares the 0x00 code path

	// MAC: 6 raw bytes starting at offset 1 ("invalid MAC" hint comes
	// from candidate's OUI byte, the K$1.run netif filter — no full UBNT
	// source-mac handcheck based on the "not a UBNT" K$1.run javadoc note).
	macB := b[1:7]

	if ver == 0 {
		// Length/resource half: 18 bytes here? (FID-26 netif filter on the
		// v0 card else drops by the byte 2 length re-check.) The jar reads
		// the card as bytes 2+ at this point (netif filter 5-16 bytes; the
		// integer norm is "length 18 re-check").
		if len(b) < discoveryMinPacketLenv0 {
			return "", "", false
		}
		// Note: the legacy card's "length" half merely reports the float
		// and is not used for the ad-hoc value: "count length" D.k.
		// The v0 "version" float read lands at byte 13 ("redirs 0-length"
		// — K.java detail: float report byte 6's v := 0).
		if b[13] != byte(discoveryMinLen) {
			return "", "", false
		}
		return macHex(macB), "discovery:platform=unknown", true
	}

	// v1/v2 family: the [len:2] BE pair at byte 11 is the count of
	// payload bytes stored thereafter ("length" D.k half); length 8 is
	// the (self-byte) missing version report.	report
	if binary.BigEndian.Uint16(b[11:13]) <= discoveryMinLen {
		return "", "", false
	}
	return macHex(macB), "discovery:platform=unknown", true
}

// macHex renders 6 raw MAC bytes as canonical lowercase 12-hex.
func macHex(raw []byte) string {
	if len(raw) != 6 {
		return ""
	}
	return strings.ToLower(fmt.Sprintf("%x", raw))
}

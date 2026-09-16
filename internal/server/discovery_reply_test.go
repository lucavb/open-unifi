package server

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/lucabecker/open-unifi/internal/store"
)

func TestDiscoveryCmd8ReplyEncoding(t *testing.T) {
	s := New(Config{}, store.NewMemStore(), testLogger())
	st := s.discoverySightings()
	st.mu.Lock()
	st.replyMeta = &discoveryReplyMetadata{identity: "001122334455", firmware: "fw", board: "board", version: "ver", aliases: []discoveryAlias{
		{mac: [6]byte{1, 2, 3, 4, 5, 6}, ip: [4]byte{10, 0, 1, 1}},
		{mac: [6]byte{6, 5, 4, 3, 2, 1}, ip: [4]byte{10, 0, 2, 1}},
	}}
	st.testIdentity = "aa:bb:cc:dd:ee:ff"
	st.mu.Unlock()
	beacon := mkDiscoveryPacket(2, 8, mkTLV(1, []byte{9, 8, 7, 6, 5, 4}), mkTLV(18, []byte{0, 0, 0, 1}), mkTLV(19, []byte{9, 8, 7, 6, 5, 4}))
	info, ok := s.parseDiscovery(&net.UDPAddr{IP: net.ParseIP("10.10.10.20")}, beacon)
	if !ok || info.cmd != 8 {
		t.Fatalf("cmd8 parse: ok=%v info=%+v", ok, info)
	}
	if !discoverySiteLocalIPv4(&net.UDPAddr{IP: net.ParseIP("10.10.10.20")}) {
		t.Fatal("10.10.10.20 must be site-local")
	}
	first := s.discoveryEncodeReply()
	second := s.discoveryEncodeReply()
	if first[0] != 2 || first[1] != 9 || int(binary.BigEndian.Uint16(first[2:4])) != len(first)-4 {
		t.Fatalf("invalid reply header")
	}
	if binary.BigEndian.Uint32(first[7:11]) != 1 || binary.BigEndian.Uint32(second[7:11]) != 2 {
		t.Fatalf("reply sequence did not progress")
	}
	var types []byte
	for _, packet := range [][]byte{first} {
		for i := 4; i < len(packet); {
			typ := packet[i]
			n := int(binary.BigEndian.Uint16(packet[i+1 : i+3]))
			types = append(types, typ)
			i += 3 + n
		}
	}
	want := []byte{18, 19, 1, 2, 2, 3, 21, 22, 23}
	if string(types) != string(want) {
		t.Fatalf("TLV order %v, want %v", types, want)
	}
	if pending, _ := s.st.Pending(); len(pending) != 0 {
		t.Fatalf("cmd8 produced pending candidate: %v", pending)
	}
	for _, ip := range []string{"10.10.10.20", "172.16.1.1", "172.31.255.254", "192.168.1.1"} {
		if !discoverySiteLocalIPv4(&net.UDPAddr{IP: net.ParseIP(ip)}) {
			t.Errorf("site-local rejected: %s", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "169.254.1.1", "8.8.8.8", "224.0.0.1", "::1"} {
		if discoverySiteLocalIPv4(&net.UDPAddr{IP: net.ParseIP(ip)}) {
			t.Errorf("non-site-local accepted: %s", ip)
		}
	}
}

func TestDiscoveryCmd8SocketIntegration(t *testing.T) {
	s := New(Config{}, store.NewMemStore(), testLogger())
	st := s.discoverySightings()
	st.mu.Lock()
	st.testIdentity = "001122334455"
	st.replyMeta = &discoveryReplyMetadata{identity: st.testIdentity, firmware: "unknown", board: "unknown", version: "unknown", aliases: []discoveryAlias{{mac: [6]byte{1, 2, 3, 4, 5, 6}, ip: [4]byte{10, 0, 1, 1}}}}
	st.replySourceAllowed = func(a *net.UDPAddr) bool { return a.IP.IsLoopback() }
	st.mu.Unlock()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	var got []byte
	var gotDst *net.UDPAddr
	st.mu.Lock()
	st.replyWriter = func(p []byte, dst *net.UDPAddr) error { got = append([]byte(nil), p...); gotDst = dst; return nil }
	st.mu.Unlock()
	beacon := mkDiscoveryPacket(2, 8, mkTLV(1, []byte{9, 8, 7, 6, 5, 4}), mkTLV(18, []byte{0, 0, 0, 1}), mkTLV(19, []byte{9, 8, 7, 6, 5, 4}))
	s.handleDiscoveryPacketConn(listener, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: client.LocalAddr().(*net.UDPAddr).Port}, beacon)
	if gotDst.Port != client.LocalAddr().(*net.UDPAddr).Port || got[0] != 2 || got[1] != 9 {
		t.Fatalf("reply destination/header: %v %x", gotDst, got)
	}
	if pending, _ := s.st.Pending(); len(pending) != 0 {
		t.Fatalf("pending mutation: %v", pending)
	}
	_ = listener.Close()
}

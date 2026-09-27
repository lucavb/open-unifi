package server

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
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

// TestDiscoveryCmd8HeaderOnlyReplyGate pins the reply gate against the
// official Android app's probe shape ([02 08 00 00], no TLVs —
// com.ubnt.easyunifi ee4.java:138-140) and the com.ubnt.net.K.while()
// state analogue (review T6): a default-state controller answers the
// header-only probe; once a device record has reached StateAdopting or
// beyond, only DiscoveryDiscoverable keeps the reply armed.
func TestDiscoveryCmd8HeaderOnlyReplyGate(t *testing.T) {
	probe := []byte{2, 8, 0, 0}
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4242}

	setup := func(t *testing.T, cfg Config, st store.DeviceStore) (*Server, *[]byte) {
		t.Helper()
		s := New(cfg, st, testLogger())
		ss := s.discoverySightings()
		var got []byte
		ss.mu.Lock()
		ss.testIdentity = "001122334455"
		ss.replyMeta = &discoveryReplyMetadata{identity: ss.testIdentity, firmware: "unknown", board: "unknown", version: "unknown", aliases: []discoveryAlias{{mac: [6]byte{1, 2, 3, 4, 5, 6}, ip: [4]byte{10, 0, 1, 1}}}}
		ss.replySourceAllowed = func(a *net.UDPAddr) bool { return a.IP.IsLoopback() }
		ss.replyWriter = func(p []byte, dst *net.UDPAddr) error { got = append([]byte(nil), p...); return nil }
		ss.mu.Unlock()
		return s, &got
	}

	t.Run("default state answers the app probe", func(t *testing.T) {
		s, got := setup(t, Config{}, store.NewMemStore())
		s.handleDiscoveryPacketConn(listener, src, probe)
		if *got == nil || (*got)[1] != 9 {
			t.Fatalf("want cmd-9 reply to header-only probe, got %v", *got)
		}
	})
	t.Run("pending candidates keep the default state", func(t *testing.T) {
		st := store.NewMemStore()
		if err := st.MarkPending("112233445566", "discovery:"); err != nil {
			t.Fatal(err)
		}
		s, got := setup(t, Config{}, st)
		s.handleDiscoveryPacketConn(listener, src, probe)
		if *got == nil {
			t.Fatal("pending-only store must still answer")
		}
	})
	t.Run("adopted device silences the reply", func(t *testing.T) {
		st := store.NewMemStore()
		if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StateAdopted}); err != nil {
			t.Fatal(err)
		}
		s, got := setup(t, Config{}, st)
		s.handleDiscoveryPacketConn(listener, src, probe)
		if *got != nil {
			t.Fatalf("provisioned controller must stay silent, got %v", *got)
		}
	})
	t.Run("discoverable override answers with adopted devices", func(t *testing.T) {
		st := store.NewMemStore()
		if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StateAdopted}); err != nil {
			t.Fatal(err)
		}
		s, got := setup(t, Config{DiscoveryDiscoverable: true}, st)
		s.handleDiscoveryPacketConn(listener, src, probe)
		if *got == nil || (*got)[1] != 9 {
			t.Fatal("discoverable override must reply")
		}
	})
	t.Run("v1 probe never replies", func(t *testing.T) {
		s, got := setup(t, Config{}, store.NewMemStore())
		s.handleDiscoveryPacketConn(listener, src, []byte{1, 0, 0, 0})
		if *got != nil {
			t.Fatalf("v1 cmd-0 probe must not reply, got %v", *got)
		}
	})
}

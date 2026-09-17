package inform

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

var (
	testMAC = []byte{0x24, 0xa4, 0x3c, 0x11, 0x22, 0x33}
	testKey = mustKey()
	// A realistic minimal device info JSON.
	testPlain = []byte(`{"_type":"info","mac":"24:a4:3c:11:22:33","state":1,"model":"U7PG2","version":"6.6.55"}`)
)

func mustKey() []byte {
	k, err := DecodeKeyHex(DefaultKeyHex)
	if err != nil || len(k) != 16 {
		panic("test key setup failed")
	}
	return k
}

// parseOrDie is a test helper.
func parseOrDie(t *testing.T, b []byte) *Packet {
	t.Helper()
	p, err := ParsePacket(b)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	return p
}

// TestCBCZlibRoundTrip: encrypt CBC+zlib with the factory key,
// reparse from the wire and decrypt back to the original JSON.
func TestCBCZlibRoundTrip(t *testing.T) {
	zbuf := &bytes.Buffer{}
	zw := zlib.NewWriter(zbuf)
	if _, err := zw.Write(testPlain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	p := NewPacket(testMAC)
	p.Flags = FlagEncCBC | FlagZlib
	if err := p.EncryptPayload(testKey, zbuf.Bytes()); err != nil {
		t.Fatalf("EncryptPayload: %v", err)
	}
	if p.Flags&FlagEncCBC == 0 {
		t.Fatal("CBC flag lost")
	}

	wire, err := p.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !(len(wire) > HeaderLen) {
		t.Fatal("wire too short")
	}

	parsed := parseOrDie(t, wire)
	if !bytes.Equal(parsed.MAC, testMAC) {
		t.Fatalf("MAC round trip: got %x", parsed.MAC)
	}
	got, err := parsed.DecryptPayload(testKey)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if !bytes.Equal(got, testPlain) {
		t.Fatalf("plaintext mismatch: got %q", got)
	}
}

// TestCBCRoundTripPlain checks the plain CBC path (no compression).
func TestCBCRoundTripPlain(t *testing.T) {
	p := NewPacket(testMAC)
	p.Flags = FlagEncCBC
	if err := p.EncryptPayload(testKey, testPlain); err != nil {
		t.Fatal(err)
	}
	if pad := len(p.Payload) - len(testPlain); pad < 1 || pad > blockSize {
		t.Fatalf("PKCS7 padding size %d out of range", pad)
	}
	if len(p.Payload)%16 != 0 {
		t.Fatalf("CBC payload %d not block aligned", len(p.Payload))
	}
	got, err := parseOrDie(t, mustSerialize(t, p)).DecryptPayload(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, testPlain) {
		t.Fatalf("mismatch: %q", got)
	}
}

// TestGCMRoundTripAndAADBinding: standard round trip, then corrupt one
// header byte — decrypt must fail because the ciphertext is AAD-bound to
// the full 40-byte header including the payload-length field.
func TestGCMRoundTripAndAADBinding(t *testing.T) {
	p := NewPacket(testMAC)
	p.Flags = FlagGCM
	if err := p.EncryptPayload(testKey, testPlain); err != nil {
		t.Fatal(err)
	}
	if len(p.Payload) != len(testPlain)+16 {
		t.Fatalf("GCM payload length %d, want plaintext+16 tag", len(p.Payload))
	}
	wire := mustSerialize(t, p)

	// Payload-length field in the header must include the tag size.
	if dl := binary.BigEndian.Uint32(wire[36:40]); dl != uint32(len(testPlain)+16) {
		t.Fatalf("header payload length %d, want %d", dl, len(testPlain)+16)
	}

	got, err := parseOrDie(t, wire).DecryptPayload(testKey)
	if err != nil {
		t.Fatalf("DecryptPayload: %v", err)
	}
	if !bytes.Equal(got, testPlain) {
		t.Fatal("plaintext mismatch")
	}

	// Corrupt a single header byte (mid-IV region) => AAD mismatch.
	tampered := append([]byte(nil), wire...)
	tampered[20] ^= 0x01
	if _, err := parseDecrypt(t, tampered); err == nil {
		t.Fatal("decrypt succeeded despite AAD corruption")
	}

	// Corrupt the payload-length field itself => also AAD-bound.
	tampered = append([]byte(nil), wire...)
	tampered[37] ^= 0x01
	if _, err := parseDecrypt(t, tampered); err == nil {
		t.Fatal("decrypt succeeded despite length-field corruption")
	}
}

// parseDecrypt parses a wire body and decrypts with the factory key.
func parseDecrypt(t *testing.T, body []byte) ([]byte, error) {
	t.Helper()
	p, err := ParsePacket(body)
	if err != nil {
		return nil, err
	}
	return p.DecryptPayload(testKey)
}

func mustSerialize(t *testing.T, p *Packet) []byte {
	t.Helper()
	b, err := p.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return b
}

// TestParsePacketFields builds a minimal valid packet by hand (raw header
// bytes) and asserts every decoded field.
func TestParsePacketFields(t *testing.T) {
	payload := []byte(`{"a":1}`)
	hdr := make([]byte, HeaderLen)
	binary.BigEndian.PutUint32(hdr[0:4], Magic)
	binary.BigEndian.PutUint32(hdr[4:8], PacketVersion)
	copy(hdr[8:14], testMAC)
	binary.BigEndian.PutUint16(hdr[14:16], FlagEncCBC|FlagGCM)
	copy(hdr[16:32], []byte("0123456789abcdef"))
	binary.BigEndian.PutUint32(hdr[32:36], DataVersion)
	binary.BigEndian.PutUint32(hdr[36:40], uint32(len(payload)))

	p := parseOrDie(t, append(hdr, payload...))
	if p.Version != PacketVersion {
		t.Errorf("Version = %d", p.Version)
	}
	if !bytes.Equal(p.MAC, testMAC) {
		t.Errorf("MAC = %x", p.MAC)
	}
	if p.Flags != FlagEncCBC|FlagGCM {
		t.Errorf("Flags = %#x", p.Flags)
	}
	if string(p.IV[:]) != "0123456789abcdef" {
		t.Errorf("IV = %q", p.IV)
	}
	if p.DataVersion != DataVersion {
		t.Errorf("DataVersion = %d", p.DataVersion)
	}
	if !bytes.Equal(p.Payload, payload) {
		t.Errorf("Payload = %q", p.Payload)
	}

	// No flags => payload passes through as plaintext inform.
	pr := parseOrDie(t, append(hdr, payload...))
	pr.Flags = 0
	out, err := pr.DecryptPayload(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, payload) {
		t.Fatal("plaintext passthrough mismatch")
	}
}

// TestParsePacketErrorPaths covers each documented controller error.
func TestParsePacketErrorPaths(t *testing.T) {
	payload := []byte(`{"a":1}`)

	mk := func() []byte {
		hdr := make([]byte, HeaderLen)
		binary.BigEndian.PutUint32(hdr[0:4], Magic)
		binary.BigEndian.PutUint32(hdr[4:8], PacketVersion)
		copy(hdr[8:14], testMAC)
		binary.BigEndian.PutUint32(hdr[32:36], DataVersion)
		binary.BigEndian.PutUint32(hdr[36:40], uint32(len(payload)))
		return append(hdr, payload...)
	}

	cases := []struct {
		name string
		body []byte
		want string
	}{
		// Case bodies are built so each check fires at its jar-verified
		// position (content length < 8 / > 10 MB, magic, header length,
		// data length, data version).
		{"content too short", make([]byte, 7), "Content too short"},
		{"too long", make([]byte, MaxBodySize+1), "Content too long"},
		{"bad magic", func() []byte {
			// 8 bytes so the content-length bound passes but the magic
			// check (which precedes the header-length check in the jar)
			// fires.
			b := make([]byte, 8)
			b[0] = 0xFF
			return b
		}(), "Bad packet magic"},
		{"header too short", func() []byte {
			// Valid magic, truncated header (< 40 bytes).
			return mk()[:HeaderLen-1]
		}(), "Header is too short"},
		{"bad data length", func() []byte {
			b := mk()
			binary.BigEndian.PutUint32(b[36:40], uint32(len(payload)+1))
			return b
		}(), "Bad data length"},
		{"bad data version", func() []byte {
			b := mk()
			binary.BigEndian.PutUint32(b[32:36], 2)
			return b
		}(), "Data version 2 is not supported"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePacket(tc.body)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if err.Error() != tc.want {
				t.Fatalf("error %q, want %q", err.Error(), tc.want)
			}
		})
	}

	// The jar has no dataLen==0 special case: an empty payload parses
	// fine ("Content too short" there only means HTTP content-length < 8).
	empty := mk()
	binary.BigEndian.PutUint32(empty[36:40], 0)
	p, err := ParsePacket(empty)
	if err != nil {
		t.Fatalf("dataLen=0 rejected: %v (jar has no such special case)", err)
	}
	if len(p.Payload) != 0 {
		t.Fatalf("Payload = %q, want empty", p.Payload)
	}
}

// TestIndependentCBCDecrypt: encrypt with the package, then decrypt with
// a fully independent stdlib-only path implemented here (ECB per block +
// XOR chain, no CBC decrypter reuse) and compare.
func TestIndependentCBCDecrypt(t *testing.T) {
	p := NewPacket(testMAC)
	p.Flags = FlagEncCBC
	if err := p.EncryptPayload(testKey, testPlain); err != nil {
		t.Fatal(err)
	}
	wire := mustSerialize(t, p)

	iv := append([]byte(nil), wire[16:32]...)
	ct := wire[HeaderLen:]
	block, err := aes.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	var plain []byte
	prev := append([]byte(nil), iv...)
	buf := make([]byte, blockSize)
	for off := 0; off < len(ct); off += blockSize {
		block.Decrypt(buf, ct[off:off+blockSize])
		for i := 0; i < blockSize; i++ {
			buf[i] ^= prev[i]
		}
		plain = append(plain, buf...)
		prev = append([]byte(nil), ct[off:off+blockSize]...)
	}
	n := int(plain[len(plain)-1])
	if n < 1 || n > blockSize {
		t.Fatalf("padding byte %d invalid", n)
	}
	plain = plain[:len(plain)-n]
	if !bytes.Equal(plain, testPlain) {
		t.Fatalf("independent CBC decrypt mismatch: %q", plain)
	}
}

// TestIndependentGCMDecrypt: decrypt GCM with a raw stdlib path built
// directly from the serialized frame (no shared package code), verifying
// the exact AAD/nonce binding on the wire.
func TestIndependentGCMDecrypt(t *testing.T) {
	p := NewPacket(testMAC)
	p.Flags = FlagGCM
	if err := p.EncryptPayload(testKey, testPlain); err != nil {
		t.Fatal(err)
	}
	wire := mustSerialize(t, p)

	aad := wire[:HeaderLen] // includes payload-length field
	nonce := append([]byte(nil), wire[16:32]...)
	block, err := aes.NewCipher(testKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := aead.Open(nil, nonce, wire[HeaderLen:], aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, testPlain) {
		t.Fatalf("independent GCM decrypt mismatch: %q", plain)
	}

	// Tamper the header once more with the raw path to confirm binding.
	bad := append([]byte(nil), wire...)
	bad[4] ^= 0x20 // packet-version field
	if _, err := aead.Open(nil, nonce, bad[HeaderLen:], bad[:HeaderLen]); err == nil {
		t.Fatal("tampered header accepted by raw GCM path")
	}
}

// TestPacketHeaderRoundTrip mirrors the classic response/envelope path: the
// codec's framing must reproduce the first 40 bytes the device actually
// sent byte-for-byte (same MAC/version/flags/IV/dataVersion and the same
// payload-length field), since the decompiled servlet builds the GCM AAD
// from exactly such a header clone (c_cf8384dbe7ae.java §64-78). Exercise it
// through the public verbs: parse the wire, Serialize it again, compare.
func TestPacketHeaderRoundTrip(t *testing.T) {
	wire := mustSerialize(t, func() *Packet {
		p := NewPacket(testMAC)
		p.Flags = FlagGCM | FlagEncCBC
		if err := p.EncryptPayload(testKey, testPlain); err != nil {
			t.Fatal(err)
		}
		return p
	}())
	re := mustSerialize(t, parseOrDie(t, wire))
	if !bytes.Equal(re, wire) {
		t.Fatalf("header round trip mismatch:\n got %x\nwant %x", re, wire)
	}
}

// TestEncryptPayloadShape pins the verb-level contract of EncryptPayload on
// the GCM path: Flags/DataVersion left untouched, payload = plaintext+16-byte
// tag, nil-error round trip through the standard decrypt path, and bad key
// sizes rejected.
func TestEncryptPayloadShape(t *testing.T) {
	p := NewPacket(testMAC)
	p.Flags = FlagGCM | FlagEncCBC // caller-driven; the verb must not change it
	wantFlags := p.Flags
	p.DataVersion = DataVersion
	if err := p.EncryptPayload(testKey, testPlain); err != nil {
		t.Fatal(err)
	}
	if p.Flags != wantFlags {
		t.Fatal("EncryptPayload mutated Flags")
	}
	if len(p.Payload) != len(testPlain)+gcmTagSize {
		t.Fatalf("payload len %d, want plaintext+16 (tag)", len(p.Payload))
	}
	got, err := parseOrDie(t, mustSerialize(t, p)).DecryptPayload(testKey)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if !bytes.Equal(got, testPlain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
	// Bad key size rejected.
	if err := (&Packet{}).EncryptPayload(make([]byte, 5), testPlain); err == nil {
		t.Fatal("bad key accepted")
	}
}

// TestSnappyUnsupported rejects flag 0x04 even with otherwise valid data.
func TestSnappyUnsupported(t *testing.T) {
	p := parseOrDie(t, mustSerialize(t, func() *Packet {
		pp := NewPacket(testMAC)
		pp.Flags = FlagEncCBC | FlagSnappy
		if err := pp.EncryptPayload(testKey, testPlain); err != nil {
			t.Fatal(err)
		}
		return pp
	}()))
	_, err := p.DecryptPayload(testKey)
	if !errors.Is(err, ErrSnappyUnsupported) {
		t.Fatalf("want ErrSnappyUnsupported, got %v", err)
	}
}

// TestParseMACAndKeyHex covers the formatting helpers and key validation.
func TestParseMACAndKeyHex(t *testing.T) {
	mac := []byte{0x00, 0x11, 0x22, 0xaa, 0xbb, 0xff}
	if got := MACString(mac); got != "00:11:22:aa:bb:ff" {
		t.Fatalf("MACString = %q", got)
	}
	for _, s := range []string{"00:11:22:aa:bb:ff", "001122AABBFF", "00:11:22:AA:BB:FF"} {
		got, err := ParseMACString(s)
		if err != nil {
			t.Fatalf("ParseMACString(%q): %v", s, err)
		}
		if !bytes.Equal(got, mac) {
			t.Fatalf("ParseMACString(%q) = %x", s, got)
		}
	}
	if _, err := ParseMACString("zz:11:22:aa:bb:ff"); err == nil {
		t.Fatal("expected MAC parse error")
	}
	if _, err := ParseMACString("0011"); err == nil {
		t.Fatal("expected MAC length error")
	}

	k, err := DecodeKeyHex(DefaultKeyHex)
	if err != nil || len(k) != 16 {
		t.Fatalf("DecodeKeyHex: %v %x", err, k)
	}
	for _, bad := range []string{"", "ba86f2", strings.ToUpper(DefaultKeyHex), strings.Repeat("g", 32)} {
		if _, err := DecodeKeyHex(bad); err == nil {
			t.Fatalf("DecodeKeyHex(%q) accepted", bad)
		}
	}
}

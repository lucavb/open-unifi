// Package inform is the inform CODEC (CONTEXT.md: decision modules): it
// turns an inform body into a decoded inform and an outcome into response
// bytes. Framing (ParsePacket/Serialize), crypto (crypto_cbc/crypto_gcm)
// and compression (inflateZlib) live only behind the two verbs:
//
//   - Decode: a framed packet → decoded inform (key selection across both
//     key classes, payload decrypt, zlib inflation, JSON-body validation);
//   - Respond: a plaintext response payload → fully framed+encrypted
//     response bytes.
//
// The UniFi "inform" wire protocol itself is per docs/PROTOCOL.md §1 (wire
// format) and §2 (keys).
//
// The header is 40 bytes, all integers big-endian:
//
//	offset  size  field
//	0       4     magic  = 0x544E4255 ("TNBU")
//	4       4     packet version (0)
//	8       6     device MAC (raw 6 bytes)
//	14      2     flags: 0x01 CBC, 0x02 zlib, 0x04 snappy, 0x08 AES-GCM
//	16      16    IV / nonce
//	32      4     data version (must be 1)
//	40      ...   payload (for GCM this includes the trailing 16-byte tag)
package inform

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Wire-format constants (docs/PROTOCOL.md §1).
const (
	// Magic is the first 4 bytes of every inform packet: "TNBU".
	Magic uint32 = 0x544E4255
	// PacketVersion is the packet version field value devices send.
	PacketVersion uint32 = 0
	// DataVersion is the only supported data version.
	DataVersion uint32 = 1
	// MaxBodySize is the controller's 10 MB request-size limit.
	MaxBodySize = 0xA00000
	// HeaderLen is the fixed size of the inform packet header.
	HeaderLen = 40
)

// DefaultKeyHex is the pre-adoption factory AES key (= MD5("ubnt")),
// docs/PROTOCOL.md §2. This is the single canonical literal: the adoption
// engine and the inform adapter alias it.
const DefaultKeyHex = "ba86f2bbe107c7c57eb5f2690775c712"

// Header flag bits.
const (
	FlagEncCBC uint16 = 0x0001
	FlagZlib   uint16 = 0x0002
	FlagSnappy uint16 = 0x0004
	FlagGCM    uint16 = 0x0008
)

// Sentinel errors for unsupported payload encodings.
var (
	// ErrSnappyUnsupported is returned when flag 0x04 is set; snappy is
	// legacy wallet-side and not implemented here.
	ErrSnappyUnsupported = errors.New("inform: snappy-compressed payloads are not supported")
)

// Packet is a framed inform wire packet (the §1 header + payload; Decoded
// in codec.go is the decoded inform built from one).
type Packet struct {
	// Version is the packet version field.
	Version uint32
	// MAC is the 6-byte device MAC.
	MAC []byte
	// Flags holds the header flag bits.
	Flags uint16
	// IV is the 16-byte IV (CBC) / nonce (GCM).
	IV [16]byte
	// DataVersion is the data version field (only 1 is accepted).
	DataVersion uint32
	// Payload is the packet payload. With FlagGCM it is ciphertext||tag;
	// the tag size is included in the serialized payload-length field.
	Payload []byte
}

// Error messages matching classic controller semantics. Exported-style
// capitalization is kept deliberately (reverse-engineered strings).
var (
	errBadMagic  = errors.New("Bad packet magic")
	errTooShort  = errors.New("Header is too short")
	errBadLength = errors.New("Bad data length")
)

// ParsePacket decodes and validates an inform packet body.
//
// Validation closely follows InformServlet semantics, in the jar's exact
// order (InformServlet.super(HttpServletRequest) +
// InformServlet$_O0.super(byte[])): content-length bounds (< 8, > 10 MB),
// magic, minimum header length, payload-length sanity and supported data
// version. Error strings match the controller wording.
func ParsePacket(body []byte) (*Packet, error) {
	if len(body) < 8 {
		return nil, errors.New("Content too short")
	}
	if len(body) > MaxBodySize {
		return nil, errors.New("Content too long")
	}
	if magic := binary.BigEndian.Uint32(body[0:4]); magic != Magic {
		return nil, errBadMagic
	}
	if len(body) < HeaderLen {
		return nil, errTooShort
	}
	dataLen := binary.BigEndian.Uint32(body[36:40])
	if dataLen > uint32(len(body)-HeaderLen) {
		return nil, errBadLength
	}
	dv := binary.BigEndian.Uint32(body[32:36])
	if dv != DataVersion {
		return nil, fmt.Errorf("Data version %d is not supported", dv)
	}

	p := &Packet{
		Version:     binary.BigEndian.Uint32(body[4:8]),
		MAC:         append([]byte(nil), body[8:14]...),
		Flags:       binary.BigEndian.Uint16(body[14:16]),
		DataVersion: dv,
	}
	copy(p.IV[:], body[16:32])
	p.Payload = append([]byte(nil), body[HeaderLen:HeaderLen+int(dataLen)]...)
	return p, nil
}

// Serialize renders the packet as header (40 bytes, BE) + payload. The
// payload-length field is written as len(Payload); callers working with
// GCM must ensure Payload already includes the tag.
func (p *Packet) Serialize() ([]byte, error) {
	if len(p.MAC) != 6 {
		return nil, fmt.Errorf("inform: MAC must be 6 bytes, got %d", len(p.MAC))
	}
	out := make([]byte, HeaderLen, HeaderLen+len(p.Payload))
	putHeader(out, p, uint32(len(p.Payload)))
	return append(out, p.Payload...), nil
}

// putHeader fills the 40-byte header prefix of buf. Caller must guarantee
// len(buf) >= HeaderLen and a valid 6-byte MAC in p.
func putHeader(buf []byte, p *Packet, payloadLen uint32) {
	binary.BigEndian.PutUint32(buf[0:4], Magic)
	binary.BigEndian.PutUint32(buf[4:8], p.Version)
	copy(buf[8:14], p.MAC)
	binary.BigEndian.PutUint16(buf[14:16], p.Flags)
	copy(buf[16:32], p.IV[:])
	binary.BigEndian.PutUint32(buf[32:36], p.DataVersion)
	binary.BigEndian.PutUint32(buf[36:40], payloadLen)
}

// headerBytes returns the canonical 40-byte header for p with the given
// payload-length field value, without mutating anything.
func headerBytes(p *Packet, payloadLen uint32) ([]byte, error) {
	if len(p.MAC) != 6 {
		return nil, fmt.Errorf("inform: MAC must be 6 bytes, got %d", len(p.MAC))
	}
	buf := make([]byte, HeaderLen)
	putHeader(buf, p, payloadLen)
	return buf, nil
}

// NewPacket returns a packet with sane request defaults: packet version 0,
// data version 1 and a random IV. The MAC is copied.
func NewPacket(mac []byte) *Packet {
	p := &Packet{
		Version:     PacketVersion,
		DataVersion: DataVersion,
		MAC:         append([]byte(nil), mac...),
	}
	// crypto/rand never fails on well-behaved platforms; on the
	// theoretical failure leave the zero IV (EncryptPayload will
	// randomize it anyway as a zero check).
	_, _ = rand.Read(p.IV[:])
	return p
}

// DecodeKeyHex decodes a 32-character lowercase-hex string into a 16-byte
// AES-128 key (docs/PROTOCOL.md §2: hex, lowercase).
func DecodeKeyHex(hexKey string) ([]byte, error) {
	if len(hexKey) != 32 {
		return nil, fmt.Errorf("inform: key hex must be 32 characters, got %d", len(hexKey))
	}
	for i := 0; i < len(hexKey); i++ {
		c := hexKey[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return nil, fmt.Errorf("inform: key hex must be 32 lowercase hex characters")
		}
	}
	return hex.DecodeString(hexKey)
}

// checkKey validates that k is a usable AES key size.
func checkKey(k []byte) error {
	switch len(k) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("inform: invalid AES key size %d bytes", len(k))
	}
}

// DecryptPayload decrypts (and, when flagged, zlib-inflates) p.Payload
// into the plaintext JSON body using the supplied AES key.
//
//   - FlagGCM (0x08): AES-GCM, nonce = p.IV (16 bytes), AAD = the 40-byte
//     header with the payload-length field as it was (de)serialized, tag
//     = last 16 bytes of the payload.
//   - FlagEncCBC (0x01): AES-CBC, IV = p.IV, PKCS7 unpad with the lenient
//     legacy fallback (raw + trailing NUL/pad trim).
//   - Neither flag: payload is taken as plaintext (plain inform mode).
//
// Snappy (0x04) is rejected. Zlib (0x02) is decompressed after decrypt.
func (p *Packet) DecryptPayload(key []byte) ([]byte, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	if p.Flags&FlagSnappy != 0 {
		return nil, ErrSnappyUnsupported
	}

	var (
		body []byte
		err  error
	)
	switch {
	case p.Flags&FlagGCM != 0:
		aad, aerr := headerBytes(p, uint32(len(p.Payload)))
		if aerr != nil {
			return nil, aerr
		}
		body, err = decryptGCM(key, p.Payload, p.IV[:], aad)
	case p.Flags&FlagEncCBC != 0:
		body, err = decryptCBC(key, p.Payload, p.IV[:])
	default:
		body = append([]byte(nil), p.Payload...)
	}
	if err != nil {
		return nil, err
	}

	if p.Flags&FlagZlib != 0 {
		body, err = inflateZlib(body)
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}

// EncryptPayload encrypts plaintext into p per its flag settings:
// GCM when FlagGCM is set, CBC otherwise (FlagEncCBC is set in that case
// so the packet round-trips through ParsePacket/DecryptPayload). The IV
// is randomized if the caller left it zero. p.Flags is not otherwise
// modified and p.Payload is replaced wholesale.
func (p *Packet) EncryptPayload(key []byte, plaintext []byte) error {
	if err := checkKey(key); err != nil {
		return err
	}
	if isAllZero(p.IV[:]) {
		if _, err := rand.Read(p.IV[:]); err != nil {
			return fmt.Errorf("inform: generating IV: %w", err)
		}
		if isAllZero(p.IV[:]) { // cannot happen in practice; keep AAD/IV sane
			p.IV[0] = 1
		}
	}
	if p.Flags&FlagGCM != 0 {
		// AAD binds the header including the payload-length field,
		// which must equal plaintext length + 16-byte tag.
		aad, err := headerBytes(p, uint32(len(plaintext)+16))
		if err != nil {
			return err
		}
		p.Payload = encryptGCM(key, plaintext, p.IV[:], aad)
		return nil
	}
	p.Flags |= FlagEncCBC
	pad := pkcs7Pad(plaintext)
	p.Payload = encryptCBC(key, pad, p.IV[:])
	return nil
}

// inflateZlib decompresses a zlib stream. An inflated body larger than
// MaxBodySize is an ERROR (never a silent truncation misreported downstream
// as a decrypt failure) — the classic servlet bounds the inform body the
// same way ("Content too long").
func inflateZlib(body []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("inform: zlib: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, MaxBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("inform: zlib: %w", err)
	}
	if len(out) > MaxBodySize {
		return nil, fmt.Errorf("inform: zlib: inflated body exceeds %d bytes", MaxBodySize)
	}
	return out, nil
}

// isAllZero reports whether every byte of b is zero.
func isAllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// MACString formats a 6-byte MAC as lowercase colon-separated hex
// ("aa:bb:cc:dd:ee:ff"). Non-6-byte input is still rendered byte for byte.
func MACString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*3)
	for i, c := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// ParseMACString parses a MAC from "aa:bb:cc:dd:ee:ff", "AA:BB:.." or
// "AABBCCDDEEFF" form into 6 raw bytes.
func ParseMACString(s string) ([]byte, error) {
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ':' {
			clean = append(clean, s[i])
		}
	}
	if len(clean) != 12 {
		return nil, fmt.Errorf("inform: invalid MAC string %q", s)
	}
	out := make([]byte, 6)
	for i := 0; i < 12; i += 2 {
		hi, ok := hexVal(clean[i])
		lo, ok2 := hexVal(clean[i+1])
		if !ok || !ok2 {
			return nil, fmt.Errorf("inform: invalid MAC string %q", s)
		}
		out[i/2] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

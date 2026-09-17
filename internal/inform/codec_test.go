package inform

// Codec-verb unit tests: Decode (key selection across both key classes,
// zlib, JSON validation, plain-packet contract) and Respond (response
// envelope, both branches). F2 adds the only independent proof that the
// response GCM AAD is the FINALIZED header: a stdlib-only decrypt of the
// Respond output, with no inform helpers involved.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Two distinct valid factory-independent keys (lowercase hex — the only
// form DecodeKeyHex accepts).
const (
	keyWrong = "11112222333344445555666677778888" // candidate 1: wrong key
	keyRight = "aaaabbbbccccddddeeeeffff00001111" // candidate 2: the real one
)

func hexKeyBytes(t *testing.T, hexKey string) []byte {
	t.Helper()
	kb, err := DecodeKeyHex(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	return kb
}

// TestDecodeCandidateOrdering: the FIRST candidate whose plaintext parses
// as a JSON object wins. Candidate 1 (keyWrong) decrypts the CBC payload to
// non-JSON garbage — decryptCBC's lenient legacy fallback accepts ANY
// wrong-key CBC decryption — so JSON validation fails and candidate 2 wins.
func TestDecodeCandidateOrdering(t *testing.T) {
	iv := bytes.Repeat([]byte{0x03}, 16)
	body := []byte(`{"_type":"info","mac":"24:a4:3c:11:22:33"}`)
	p := NewPacket(testMAC)
	p.Flags = FlagEncCBC
	copy(p.IV[:], iv)
	if err := p.EncryptPayload(hexKeyBytes(t, keyRight), body); err != nil {
		t.Fatal(err)
	}

	// Determinism probe (independent stdlib decrypt): the wrong-key
	// plaintext must NOT be a JSON object, so the loop really falls through.
	block, err := aes.NewCipher(hexKeyBytes(t, keyWrong))
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, len(p.Payload))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(raw, p.Payload)
	var probe map[string]any
	if jerr := json.Unmarshal(raw, &probe); jerr == nil && probe != nil {
		t.Fatalf("wrong-key decryption unexpectedly valid JSON: %q", raw)
	}

	d, err := Decode(p, []string{keyWrong, keyRight})
	if err != nil {
		t.Fatal(err)
	}
	if d.UsedKey != keyRight {
		t.Fatalf("UsedKey = %q, want the second candidate %q", d.UsedKey, keyRight)
	}
	if d.Body["_type"] != "info" {
		t.Fatalf("Body = %v, want the second candidate's decoded inform", d.Body)
	}
}

// TestDecodeSentinels: ErrNoValidJSON when every candidate fails to
// decrypt, ErrNotJSONObject when the payload decrypts but is not a JSON
// object.
func TestDecodeSentinels(t *testing.T) {
	// GCM packet sealed under keyRight; the only candidate is keyWrong →
	// tag failure on every candidate → ErrNoValidJSON (wrapping the last
	// decrypt error).
	p := NewPacket(testMAC)
	p.Flags = FlagGCM
	if err := p.EncryptPayload(hexKeyBytes(t, keyRight), testPlain); err != nil {
		t.Fatal(err)
	}
	_, err := Decode(p, []string{keyWrong})
	if !errors.Is(err, ErrNoValidJSON) {
		t.Fatalf("want ErrNoValidJSON, got %v", err)
	}
	// The multi-%w wrap preserves both identities through the chain.
	if !strings.Contains(err.Error(), "no key produced a valid JSON payload") {
		t.Fatalf("wrapped error text missing the sentinel text: %v", err)
	}

	// Empty candidate list: nothing tried at all → plain ErrNoValidJSON.
	_, err = Decode(p, nil)
	if !errors.Is(err, ErrNoValidJSON) || strings.Contains(err.Error(), ":") {
		t.Fatalf("empty-candidate error = %v, want the unwrapped sentinel", err)
	}

	// CBC packet whose plaintext is a valid JSON SCALAR (`6`): decrypts fine,
	// JSON-object validation fails → ErrNotJSONObject.
	p2 := NewPacket(testMAC)
	p2.Flags = FlagEncCBC
	if err := p2.EncryptPayload(hexKeyBytes(t, keyRight), []byte("6")); err != nil {
		t.Fatal(err)
	}
	_, err = Decode(p2, []string{keyRight})
	if !errors.Is(err, ErrNotJSONObject) {
		t.Fatalf("want ErrNotJSONObject, got %v", err)
	}
}

// TestDecodeUsedKeyContract: encrypted packets carry the winning candidate's
// lowercase hex key plus its decoded bytes; plain (no-encryption-flag)
// packets are NOT key-authenticated — UsedKey stays empty and KeyBytes nil.
func TestDecodeUsedKeyContract(t *testing.T) {
	iv := bytes.Repeat([]byte{0x04}, 16)

	// Encrypted (GCM): UsedKey == the candidate, KeyBytes == decoded.
	p := NewPacket(testMAC)
	p.Flags = FlagGCM
	copy(p.IV[:], iv)
	if err := p.EncryptPayload(hexKeyBytes(t, keyRight), testPlain); err != nil {
		t.Fatal(err)
	}
	d, err := Decode(p, []string{keyWrong, keyRight})
	if err != nil {
		t.Fatal(err)
	}
	if d.UsedKey != keyRight {
		t.Fatalf("UsedKey = %q, want %q", d.UsedKey, keyRight)
	}
	if !bytes.Equal(d.KeyBytes, hexKeyBytes(t, keyRight)) {
		t.Fatalf("KeyBytes = %x, want the decoded candidate", d.KeyBytes)
	}

	// Plain (no flags): the key is ignored by DecryptPayload entirely —
	// UsedKey must stay "" and KeyBytes nil.
	pp := NewPacket(testMAC)
	pp.Payload = append([]byte(nil), testPlain...)
	pd, err := Decode(pp, []string{keyRight})
	if err != nil {
		t.Fatal(err)
	}
	if pd.UsedKey != "" || pd.KeyBytes != nil {
		t.Fatalf("plain decode UsedKey=%q KeyBytes=%v, want empty/nil", pd.UsedKey, pd.KeyBytes)
	}
	if pd.Body["_type"] != "info" {
		t.Fatalf("plain Body = %v", pd.Body)
	}
}

// TestDecodeInvalidHexCandidateSkipped: a non-hex candidate is skipped
// without aborting; the valid candidate still wins.
func TestDecodeInvalidHexCandidateSkipped(t *testing.T) {
	iv := bytes.Repeat([]byte{0x05}, 16)
	p := NewPacket(testMAC)
	p.Flags = FlagEncCBC
	copy(p.IV[:], iv)
	if err := p.EncryptPayload(hexKeyBytes(t, keyRight), testPlain); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "tooshort", strings.ToUpper(keyRight)} {
		d, err := Decode(p, []string{bad, keyRight})
		if err != nil {
			t.Fatalf("candidate %q: %v", bad, err)
		}
		if d.UsedKey != keyRight {
			t.Fatalf("candidate %q: UsedKey = %q", bad, d.UsedKey)
		}
	}
}

// TestDecodeWrapsLastDecryptCause: the concrete DecryptPayload/inflate cause
// rides through the ErrNoValidJSON chain (DecodeKeyHex errors are excluded).
func TestDecodeWrapsLastDecryptCause(t *testing.T) {
	// Snappy flag: DecryptPayload rejects with the sentinel before any crypto.
	p := NewPacket(testMAC)
	p.Flags = FlagEncCBC | FlagSnappy
	err := p.EncryptPayload(hexKeyBytes(t, keyRight), testPlain)
	if err != nil {
		t.Fatal(err)
	}
	_, derr := Decode(p, []string{keyRight})
	if !errors.Is(derr, ErrNoValidJSON) {
		t.Fatalf("want ErrNoValidJSON, got %v", derr)
	}
	if !errors.Is(derr, ErrSnappyUnsupported) {
		t.Fatalf("chain must carry the concrete snappy cause, got %v", derr)
	}

	// zlib payload that decrypts but fails to inflate under the only key.
	pz := NewPacket(testMAC)
	pz.Flags = FlagEncCBC | FlagZlib
	if err := pz.EncryptPayload(hexKeyBytes(t, keyRight), []byte("not a zlib stream")); err != nil {
		t.Fatal(err)
	}
	_, derr = Decode(pz, []string{keyRight})
	if !errors.Is(derr, ErrNoValidJSON) {
		t.Fatalf("want ErrNoValidJSON, got %v", derr)
	}
	if !strings.Contains(derr.Error(), "zlib") {
		t.Fatalf("chain must carry the concrete zlib cause, got %v", derr)
	}
}

// TestRespondEnvelope: the GCM branch finalizes flags 0x0009, the CBC branch
// 0x0001; the serialized header reflects them; a round trip through
// ParsePacket/DecryptPayload returns the plaintext; an invalid key size
// surfaces the wrapped error.
func TestRespondEnvelope(t *testing.T) {
	iv := bytes.Repeat([]byte{0x06}, 16)
	cases := []struct {
		name      string
		reqFlags  uint16
		wantFlags uint16
	}{
		{"gcm request", FlagGCM, FlagGCM | FlagEncCBC},
		{"cbc request", FlagEncCBC, FlagEncCBC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := NewPacket(testMAC)
			pkt.Flags = tc.reqFlags
			copy(pkt.IV[:], iv)
			ivBefore := pkt.IV
			resp, err := Respond(pkt, hexKeyBytes(t, keyRight), testPlain)
			if err != nil {
				t.Fatal(err)
			}
			// Header facts, straight off the wire.
			if m := binary.BigEndian.Uint32(resp[0:4]); m != Magic {
				t.Fatalf("magic %08x", m)
			}
			if f := binary.BigEndian.Uint16(resp[14:16]); f != tc.wantFlags {
				t.Fatalf("response flags %04x, want %04x", f, tc.wantFlags)
			}
			if dv := binary.BigEndian.Uint32(resp[32:36]); dv != DataVersion {
				t.Fatalf("dataVersion %d, want %d (reused verbatim)", dv, DataVersion)
			}
			if dl := binary.BigEndian.Uint32(resp[36:40]); uint32(len(resp)-HeaderLen) != dl {
				t.Fatalf("payloadLen %d, body %d", dl, len(resp)-HeaderLen)
			}
			// Round trip through the standard decrypt path.
			parsed, err := ParsePacket(resp)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parsed.DecryptPayload(hexKeyBytes(t, keyRight))
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			if !bytes.Equal(got, testPlain) {
				t.Fatalf("round trip mismatch: %q", got)
			}
			// Respond reuses the request header in a COPY: the caller's
			// packet (flags and IV) must be left unmutated.
			if pkt.Flags != tc.reqFlags {
				t.Fatal("Respond mutated the request packet's Flags")
			}
			if pkt.IV != ivBefore {
				t.Fatal("Respond mutated the request packet's IV")
			}
		})
	}

	// Invalid key size surfaces the wrapped error.
	pkt := NewPacket(testMAC)
	pkt.Flags = FlagEncCBC
	if _, err := Respond(pkt, make([]byte, 5), testPlain); err == nil ||
		!strings.Contains(err.Error(), "response encryption") {
		t.Fatalf("want wrapped response-encryption error, got %v", err)
	}
}

// TestRespondIndependentStdlib is the only independent proof that the
// response AAD is the FINALIZED header: decrypt the Respond output with a
// raw stdlib path only (no inform helpers) — GCM via aead.Open with the
// full 40-byte response header as AAD, CBC via a manual CBC decrypter plus
// PKCS7 strip.
func TestRespondIndependentStdlib(t *testing.T) {
	iv := bytes.Repeat([]byte{0x08}, 16)
	key := hexKeyBytes(t, keyRight)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	// GCM branch: request carries FlagGCM → response 0x0009; the tag binds
	// the finalized header (IV/flags/length already mutated).
	pkt := NewPacket(testMAC)
	pkt.Flags = FlagGCM
	copy(pkt.IV[:], iv)
	resp, err := Respond(pkt, key, testPlain)
	if err != nil {
		t.Fatal(err)
	}
	if f := binary.BigEndian.Uint16(resp[14:16]); f != FlagGCM|FlagEncCBC {
		t.Fatalf("gcm response flags %04x, want 0x0009", f)
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := aead.Open(nil, resp[16:32], resp[40:], resp[:40])
	if err != nil {
		t.Fatalf("independent GCM open failed: %v", err)
	}
	if !bytes.Equal(plain, testPlain) {
		t.Fatalf("independent GCM plaintext mismatch: %q", plain)
	}

	// CBC branch: request carries FlagEncCBC → response 0x0001; strip PKCS7
	// by hand (last byte n ∈ 1..blockSize, all pad bytes equal n).
	pkt2 := NewPacket(testMAC)
	pkt2.Flags = FlagEncCBC
	copy(pkt2.IV[:], iv)
	resp2, err := Respond(pkt2, key, testPlain)
	if err != nil {
		t.Fatal(err)
	}
	if f := binary.BigEndian.Uint16(resp2[14:16]); f != FlagEncCBC {
		t.Fatalf("cbc response flags %04x, want 0x0001", f)
	}
	ct := resp2[HeaderLen:]
	if len(ct) == 0 || len(ct)%blockSize != 0 {
		t.Fatalf("bad CBC ciphertext length %d", len(ct))
	}
	padded := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, resp2[16:32]).CryptBlocks(padded, ct)
	n := int(padded[len(padded)-1])
	if n < 1 || n > blockSize {
		t.Fatalf("bad pad byte %d", n)
	}
	for _, c := range padded[len(padded)-n:] {
		if int(c) != n {
			t.Fatalf("bad pad content %q", padded[len(padded)-n:])
		}
	}
	if !bytes.Equal(padded[:len(padded)-n], testPlain) {
		t.Fatalf("independent CBC plaintext mismatch: %q", padded[:len(padded)-n])
	}
}

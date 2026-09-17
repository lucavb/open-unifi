package inform

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
)

// Decoded is the decoded inform: the decrypted, decompressed,
// JSON-validated body plus the key that authenticated it. (Packet is the
// framed wire packet; Decoded is what the adapter's decision layer sees.)
type Decoded struct {
	// Body is the decoded JSON object (non-nil; Decode rejects non-objects).
	Body map[string]any
	// UsedKey is the lowercase hex key that authenticated the payload.
	// Empty for plain, no-encryption-flag informs: DecryptPayload ignores
	// the key entirely there, so a plain packet is NOT key-authenticated.
	UsedKey string
	// KeyBytes is UsedKey decoded; the response is sealed with it. Nil for
	// plain, no-encryption-flag informs (see UsedKey).
	KeyBytes []byte
}

// ErrNoValidJSON reports that no candidate key produced a decryptable,
// JSON-object payload. When at least one candidate was a valid-length key
// whose DecryptPayload failed, the LAST such error is wrapped so the caller
// sees the concrete cause (zlib/snappy/cipher) through the chain.
var ErrNoValidJSON = errors.New("no key produced a valid JSON payload")

// ErrNotJSONObject reports that at least one candidate decrypted to valid
// bytes that were not a JSON object while the remaining candidates failed
// decryption. Distinct from ErrNoValidJSON so the framed-plain lane can log
// the difference; the encrypted lane treats both as "no key produced a
// valid JSON payload".
var ErrNotJSONObject = errors.New("inform: payload is not a JSON object")

// Decode turns a framed inform packet into a decoded inform: it runs the
// candidate-key loop (both key classes — CBC and GCM — plus the plain
// no-flags branch, where the key is ignored), inflates any zlib payload,
// and validates the body is a JSON object. The FIRST candidate whose
// plaintext parses as a JSON object wins.
//
// keys must be lowercase hex: DecodeKeyHex only accepts 0-9a-f and the
// adapter's candidate lists are pre-lowercased, so UsedKey is reported
// verbatim. Invalid-hex candidates are skipped without aborting.
//
// Plain packets (no FlagEncCBC/FlagGCM — the same condition DecryptPayload
// uses to skip decryption) are not key-authenticated: the winning Decoded
// carries UsedKey="" and KeyBytes=nil.
//
// Errors: ErrNoValidJSON when no candidate decrypts (wrapping the last
// decrypt/inflate error); ErrNotJSONObject when at least one candidate
// decrypted to bytes that were not a JSON object.
func Decode(pkt *Packet, keys []string) (*Decoded, error) {
	plain := pkt.Flags&(FlagEncCBC|FlagGCM) == 0
	var jm map[string]any
	notJSON := false
	var lastErr error
	for _, k := range keys {
		kb, derr := DecodeKeyHex(k)
		if derr != nil {
			continue // not a usable candidate (defensively excluded from wrapping)
		}
		p, derr := pkt.DecryptPayload(kb)
		if derr != nil {
			lastErr = derr
			continue
		}
		if jerr := json.Unmarshal(p, &jm); jerr != nil || jm == nil {
			jm = nil // wrong key (lenient garbage) or malformed payload
			notJSON = true
			continue
		}
		if plain {
			return &Decoded{Body: jm}, nil
		}
		return &Decoded{Body: jm, UsedKey: k, KeyBytes: kb}, nil
	}
	if notJSON {
		return nil, ErrNotJSONObject
	}
	if lastErr != nil {
		// Multi-%w keeps BOTH identities in the chain: errors.Is finds the
		// sentinel AND the concrete last decrypt/inflate cause.
		return nil, fmt.Errorf("%w: %w", ErrNoValidJSON, lastErr)
	}
	return nil, ErrNoValidJSON
}

// Respond seals a plaintext response payload into the classic response
// envelope for the request packet pkt and returns the full response bytes.
// The response branch is derived from the request: a FlagGCM request gets
// the GCM-sealed response, everything else the CBC one.
//
// Response header (InformServlet._O0 reuse semantics, c_e9bb4be74abe
// §206-216): the request header object is reused in place. Mutated:
// flags (0x0009 for GCM responses = GCM|EncCBC, 0x0001 for CBC) and a
// FRESH RANDOM 16-byte IV for BOTH branches (C.random(16) before the
// if). Not mutated: magic, packet version, MAC (echoed from the
// request) and the dataVersion field, which stays at the request's
// parsed value (= 1) — the request packet's DataVersion is reused
// verbatim (caller contract: ParsePacket guarantees dv==1).
//
// Flags are finalized BEFORE encryption: on the GCM path the sealed
// ciphertext is AAD-bound to the response header's 40 bytes in this
// exact state (IV/flags/length already mutated), which the device
// reproduces from the plaintext header it receives.
func Respond(pkt *Packet, key []byte, plaintext []byte) ([]byte, error) {
	rpkt := *pkt
	if pkt.Flags&FlagGCM != 0 {
		rpkt.Flags = FlagGCM | FlagEncCBC
	} else {
		rpkt.Flags = FlagEncCBC
	}
	if _, err := rand.Read(rpkt.IV[:]); err != nil {
		return nil, fmt.Errorf("inform: generating response IV: %w", err)
	}
	if err := rpkt.EncryptPayload(key, plaintext); err != nil {
		return nil, fmt.Errorf("inform: response encryption: %w", err)
	}
	serialized, err := rpkt.Serialize()
	if err != nil {
		return nil, fmt.Errorf("inform: response serialize: %w", err)
	}
	return serialized, nil
}

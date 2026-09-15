package inform

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// gcmTagSize is the fixed 128-bit GCM tag size used by the controller
// (Java AES/GCM/NoPadding with GCMParameterSpec(128, iv)).
const gcmTagSize = 16

// newGCM builds an AES-GCM AEAD that accepts the packet's IV length
// directly as the nonce. Classic controllers hand the full 16-byte IV to
// GCMParameterSpec, so nonces on the wire are 16 bytes; Go supports this
// via NewGCMWithNonceSize (IV lengths other than 12 are GHASH-mixed per
// SP 800-38D, identical to the JCA implementation).
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("inform: GCM: %w", err)
	}
	return cipher.NewGCMWithNonceSize(block, 16)
}

// decryptGCM opens payload (ciphertext||tag) authenticated with aad.
func decryptGCM(key, payload, nonce, aad []byte) ([]byte, error) {
	if len(payload) < gcmTagSize {
		return nil, errors.New("inform: GCM: payload shorter than tag")
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("inform: GCM: invalid nonce length %d", len(nonce))
	}
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, payload, aad)
	if err != nil {
		return nil, fmt.Errorf("inform: GCM: %w", err)
	}
	return plain, nil
}

// encryptGCM seals plaintext into ciphertext||tag.
func encryptGCM(key, plaintext, nonce, aad []byte) []byte {
	aead, err := newGCM(key)
	if err != nil {
		// unreachable for validated key sizes
		panic(fmt.Sprintf("inform: aes: %v", err))
	}
	return aead.Seal(nil, nonce, plaintext, aad)
}

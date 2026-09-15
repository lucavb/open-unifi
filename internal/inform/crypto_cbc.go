package inform

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// blockSize is the AES block size used by CBC paths.
const blockSize = aes.BlockSize

// encryptCBC encrypts (already PKCS7-padded) plaintext with AES-CBC-IV.
// The caller chooses the key (16/24/32 bytes); the default factory key is
// AES-128. No error return on the happy path: invalid key size and
// invalid input are programming errors caught by checkKey earlier and by
// encryptCBC's callers, but we still propagate aes.NewCipher failures.
func encryptCBC(key, plaintext, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		// checkKey already vetted the size; this is unreachable for
		// valid keys but guard against panics anyway.
		panic(fmt.Sprintf("inform: aes: %v", err))
	}
	if len(plaintext)%blockSize != 0 || len(iv) != blockSize {
		panic("inform: encryptCBC: invalid input lengths")
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	return out
}

// decryptCBC implements the controller's lenient CBC path: try PKCS7
// unpad first; on bad padding fall back to the raw buffer with trailing
// NUL / pad bytes trimmed (legacy NoPadding devices).
func decryptCBC(key, ciphertext, iv []byte) ([]byte, error) {
	if len(iv) != blockSize {
		return nil, fmt.Errorf("inform: CBC: invalid IV length %d", len(iv))
	}
	if len(ciphertext) == 0 || len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("inform: CBC: ciphertext length %d is not a multiple of %d",
			len(ciphertext), blockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("inform: CBC: %w", err)
	}
	raw := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(raw, ciphertext)

	if plain, ok := pkcs7Unpad(raw); ok {
		return plain, nil
	}
	return trimLegacyPad(raw), nil
}

// pkcs7Pad pads data to blockSize (RFC 2315 §10.3 / Java "PKCS5" on AES).
func pkcs7Pad(data []byte) []byte {
	n := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+n)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// pkcs7Unpad strips a valid PKCS7 padding; the boolean is false when the
// padding is malformed (caller falls back to lenient handling).
func pkcs7Unpad(b []byte) ([]byte, bool) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, false
	}
	n := int(b[len(b)-1])
	if n < 1 || n > blockSize || n > len(b) {
		return nil, false
	}
	for _, c := range b[len(b)-n:] {
		if byte(n) != c {
			return nil, false
		}
	}
	return b[:len(b)-n], true
}

// trimLegacyPad trims trailing NUL bytes and, failing that performs no
// further stripping: the PKCS7-valid case is already handled in
// decryptCBC, so only legacy zero-padded plaintext reaches here.
func trimLegacyPad(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

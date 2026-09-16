package server

// Tests for the $6$ SHA-512 crypt used by users.1.password. The default
// vectors live in server_test.go (TestSha512CryptVectorTests, OpenSSL
// -generated goldens); this file pins the above-64-byte-block behavior —
// the round-chain P sequence chunk-fill (FID-21). Reference vectors
// generated with OpenSSL 3.6.4 (`openssl passwd -6 -salt abcd1234 <key>`),
// the same generator that produced the default-key goldens.

import "testing"

const longVecSalt = "abcd1234"

func key65k() string {
	b := make([]byte, 65)
	for i := range b {
		b[i] = 'k'
	}
	return string(b)
}

func keyMixed123() string {
	return "LONGKEYbbbccccddddeeeeffffggggghhhhhiiiiijjjjjkkkkklllllmmmmnnnnnooooopppppqqqqqrrrrrssssstttttuuuuuvvvvvwwwwwxxxxxyyyyy720"
}

func keyMixed84() string {
	return "SIXTYFIVE-byte-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaZ"
}

// FID-21: keys longer than one SHA-512 block (64B) must tile the P digest
// chunk-wise into a keyLen-byte sequence (commons-codec Sha2Crypt offsets
// 184-238 fingerprint); slicing the bare 64-byte digest would panic, and
// hashing only the first block of the sequence would mismatch the
// reference crypts.
func TestSha512CryptLongKeyChunkFill(t *testing.T) {
	vv := []struct{ pw, want string }{
		{key65k(), "$6$abcd1234$kfWKnZUUm7uAIVFcqYMgPH393da5ti9hpVDgIfuWFVKAo9KBnUs/FJlmAdDgoERLjw84TWd20lZj3Qzvj.jcm."},
		{keyMixed123(), "$6$abcd1234$M1yjfzSyd/ZMLxLEJw/1FCI8gTFcbH4IkNvT4YkhJwzk1ZEPB01zyzNY8Y/LH5VqpZlTQbR6UAt2FwJFhwKo8/"},
		{keyMixed84(), "$6$abcd1234$wQdQTCyff/LlIQ9SiNUkHq02tpB9TZly3coa8mR0vhyv5lc1zgPfQM7CxFwdH4FYbw9nTwx3G6ZpS4ATW9kLb/"},
	}
	for _, v := range vv {
		if len(v.pw) <= 64 {
			t.Fatalf("golden key %q must exceed one 64-byte block", v.pw)
		}
		got := sha512CryptRaw([]byte(v.pw), []byte(longVecSalt))
		if got != v.want {
			t.Errorf("sha512crypt(<%dB key>, %q)\n got %s\nwant %s", len(v.pw), longVecSalt, got, v.want)
		}
		if !sha512CryptMatches(v.pw, v.want) {
			t.Errorf("cache self-check rejected long-key hash (%d bytes)", len(v.pw))
		}
	}
}

// Sweep across block-boundary key lengths: each must self-check (the
// tiling constructor degenerates to slices below one block, preserving
// the default-vector behavior) and keep the 86-char digest body.
func TestSha512CryptBlockBoundarySweep(t *testing.T) {
	for n := 1; n <= 200; n++ {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte('a' + i%26)
		}
		full := sha512CryptRaw(b, []byte(longVecSalt))
		if !sha512CryptMatches(string(b), full) {
			t.Fatalf("self-check failed for keylen %d", n)
		}
		if body := full[len("$6$"+longVecSalt+"$"):]; len(body) != 86 {
			t.Fatalf("keylen %d: digest body malformed: %s", n, full)
		}
	}
}

// randSalt draws from the crypt B64 alphabet only and honors the length.
func TestRandSaltShape(t *testing.T) {
	s, err := randSalt(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 8 {
		t.Fatalf("salt len %d, want 8", len(s))
	}
	for i := 0; i < len(s); i++ {
		if !containsByte(b64cryptAlphabet, s[i]) {
			t.Fatalf("salt char %q outside crypt alphabet", s[i])
		}
	}
}

func containsByte(alphabet string, c byte) bool {
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == c {
			return true
		}
	}
	return false
}

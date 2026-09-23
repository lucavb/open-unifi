package systemcfg

// glibc SHA-512 crypt ($6$, "SHA-crypt" spec by Ulrich Drepper, the format
// produced by commons-codec Sha2Crypt.sha512Crypt — the JAR the classic
// controller bundles — and used by the classic `users.1.password` emitter,
// docs/PROTOCOL-systemcfg-wireless.md §10.3).
//
// Output shape (default 5000 rounds, no `rounds=` parameter):
//
//	"$6$" + <8 chars of ./0-9A-Za-z> + "$" + <86 chars of ./0-9A-Za-z>
//
// Implementation is the literal translation of the published algorithm:
// A = SHA512(key‖salt‖key); DP/DS expansion digests; 5000 chained rounds with
// P/S/K interleaving per round parity/modulo; final 64-bit digest encoded 21
// full 24-bit groups + a final 8-bit tail (order (0,21,42)…, low-to-high
// base64 from `./0123456789A-Za-z`).

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"regexp"
	"strings"
)

// b64cryptAlphabet is the crypt(3) dot-slash-alphanumeric alphabet
// (commons-codec B64T / glibc's output alphabet), in index order.
const b64cryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// cryptEndian converts three bytes into base64 low-to-high (b64_from_24bit).
func b64From24bit(b1, b2, b3 byte, out []byte) []byte {
	v := uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)
	for i := 0; i < 4; i++ {
		out = append(out, b64cryptAlphabet[v&0x3f])
		v >>= 6
	}
	return out
}

// sha512CryptRaw computes the full "$6$salt$hash" string for key and an
// already-filtered raw salt using the default 5000 rounds. This matches
// commons-codec Crypt.crypt(pw, "$6$salt$") / glibc crypt(key, "$6$salt").
// Algorithm transcribed from libxcrypt lib/crypt-sha512.c (the canonical
// Drepper SHA-crypt implementation).
func sha512CryptRaw(key, salt []byte) string {
	if len(salt) == 0 {
		// Degenerate-input guard (mirror of the md5 side's clamp): an empty
		// salt would ship a "$6$$…" hash; returning "" routes it into the
		// FID-23 empty-value guard instead. Unreachable in production
		// (randSaltLive always yields 8 chars) — reachable only through the
		// test seam.
		return ""
	}
	const defaultRounds = 5000 // fixed; no "rounds=" parameter is emitted

	// Clamp the raw salt to the sha-crypt limit (≤16 chars); normal callers
	// pass the 8-char salt only.
	if len(salt) > 16 {
		salt = salt[:16]
	}

	sumB := func() []byte {
		ctx := sha512.New()
		ctx.Write(key)
		ctx.Write(salt)
		ctx.Write(key)
		return ctx.Sum(nil)
	}()

	// sumA ("prepare for the real work"): key, salt, then sumB repeated to
	// keylen bytes, then key/sumB alternated per the bits of keylen. This
	// digest seeds the round chain (Drepper SHA-crypt step 9-12).
	ctx := sha512.New()
	ctx.Write(key)
	ctx.Write(salt)
	cnt := len(key)
	for ; cnt > 64; cnt -= 64 {
		ctx.Write(sumB)
	}
	ctx.Write(sumB[:cnt])
	for bit := len(key); bit > 0; bit >>= 1 {
		if bit&1 != 0 {
			ctx.Write(sumB)
		} else {
			ctx.Write(key)
		}
	}
	sumA := ctx.Sum(nil)

	// seqP/seqS — the round-chain byte sequences. P = sha512 digest over
	// (the key added keylen times), S = sha512 digest over (salt hashed
	// 16 + sumA[0] times). The SEQUENCES are not bare digest slices: each
	// is the digest tiled chunk-wise into a len(key)/len(salt) buffer
	// (commons-codec Sha2Crypt offsets 184-238 fingerprint: full blocks
	// while remaining > blockSize, then the remainder). Tiling equals a
	// digest[:n] slice only while n ≤ one 64-byte block; slicing beyond a
	// block would panic, so keys over the block size tile instead.
	// Result: a >64B key feeds a >64B P sequence to every round. (FID-21)
	seqFill := func(digest []byte, want int) []byte {
		out := make([]byte, want)
		for i := range out {
			out[i] = digest[i%len(digest)]
		}
		return out
	}
	pSeq := func() []byte {
		ctx := sha512.New()
		for i := 0; i < len(key); i++ { // digest P input: key added keylen times (commons 279-306)
			ctx.Write(key)
		}
		return seqFill(ctx.Sum(nil), len(key))
	}()
	// seqS: salt hashed (16 + sumA[0]) times over → saltlen-byte sequence.
	// Salt is clamped ≤16 so this always stays within one block, but the
	// tiling constructor is shared for symmetry.
	sSeq := func() []byte {
		ctx := sha512.New()
		for i := 0; i < 16+int(sumA[0]); i++ {
			ctx.Write(salt)
		}
		return seqFill(ctx.Sum(nil), len(salt))
	}()

	// Round loop (5000): the recycled P/S byte sequences contribute
	// keylen/saltlen bytes per round (commons offsets 479-572: update(seq,
	// 0, keyLen/saltLen)) — pSeq is already exactly keylen bytes long, so
	// long keys feed the full tiled sequence here.
	for cnt := 0; cnt < defaultRounds; cnt++ {
		ctx = sha512.New()
		if cnt&1 != 0 {
			ctx.Write(pSeq)
		} else {
			ctx.Write(sumA)
		}
		if cnt%3 != 0 {
			ctx.Write(sSeq)
		}
		if cnt%7 != 0 {
			ctx.Write(pSeq)
		}
		if cnt&1 != 0 {
			ctx.Write(sumA)
		} else {
			ctx.Write(pSeq)
		}
		sumA = ctx.Sum(sumA[:0])
	}

	out := make([]byte, 0, 88)
	// 21 full 3-byte groups in the SHA-crypt byte-permutation order, then
	// the final lone byte 63 encoded as two base64 chars: 21*4 + 2 = 86.
	groups := [][3]byte{
		{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45},
		{25, 46, 4}, {47, 5, 26}, {6, 27, 48}, {28, 49, 7},
		{50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32},
		{12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57},
		{37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19},
		{62, 20, 41},
	}
	for _, g := range groups {
		out = b64From24bit(sumA[g[0]], sumA[g[1]], sumA[g[2]], out)
	}
	out = append(out, b64cryptAlphabet[sumA[63]&0x3f])
	out = append(out, b64cryptAlphabet[sumA[63]>>6])

	var s strings.Builder
	s.WriteString("$6$")
	s.Write(salt)
	s.WriteByte('$')
	s.Write(out)
	return s.String()
}

// randSalt returns n random characters drawn from the crypt B64 alphabet
// (byte-drawn, index masked to the alphabet size like commons-codec's
// B64.getRandomSalt). Var seam so tests can inject failure/emptiness (the
// FID-23 path), mirroring md5crypt.go's randAlphaSalt seam.
var randSalt = randSaltLive

func randSaltLive(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = b64cryptAlphabet[int(b)%len(b64cryptAlphabet)]
	}
	return string(out), nil
}

// sha512Crypt computes a fresh "$6$salt$hash" string with a random 8-char
// salt (commons-codec Crypt.crypt(bytes) equivalent).
func sha512Crypt(key string) (string, error) {
	salt, err := randSalt(8)
	if err != nil {
		return "", fmt.Errorf("sha512crypt: salt generation: %w", err)
	}
	return sha512CryptRaw([]byte(key), []byte(salt)), nil
}

// saltBodyRx matches the sha-crypt body of a stored $6$ hash: 8 salt chars,
// then the 86-char digest (the regex the doc's cache self-check requires
// before trusting a cached value).
var sha512BodyRx = regexp.MustCompile(`^\$6\$([./0-9A-Za-z]{1,16})\$([./0-9A-Za-z]{86})$`)

// sha512CryptMatches reproduces the controller cache check
// `stored.equals(Crypt.crypt(pw, stored))`: re-crypt the password using the
// salt from the stored full hash and compare digests.
func sha512CryptMatches(key, stored string) bool {
	m := sha512BodyRx.FindStringSubmatch(stored)
	if m == nil {
		return false
	}
	return sha512CryptRaw([]byte(key), []byte(m[1])) == stored
}

// sha512CacheFormatRx is the VERBATIM-REUSE format gate (the per-device
// unset branch in render.go, the locked contract): only a well-formed
// $6$ crypt string of this controller's own output shape — "$6$" + 8
// chars of [./0-9A-Za-z] + "$" + 86 chars, mirroring the jar's
// SALT_PATTERN family (docs/PROTOCOL-systemcfg-wireless.md §10.7) — may be
// reused unwritten on an unset-password render; anything else falls
// through to the factory-default fresh-hash path.
var sha512CacheFormatRx = regexp.MustCompile(`^\$6\$[./0-9A-Za-z]{8}\$[./0-9A-Za-z]{86}$`)

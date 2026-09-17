package systemcfg

import (
	"crypto/md5"
	"crypto/rand"
	"strings"
)

// md5Crypt computes the classic $1$ md5crypt (Poul-Henning Kamp's public
// domain algorithm, the same one commons-codec Md5Crypt ports and glibc
// implements), verified byte-exact against
// `openssl passwd -1 -salt <salt> <pw>`.
func md5Crypt(key string) (string, error) {
	salt, err := randAlphaSalt(8)
	if err != nil {
		return "", err
	}
	return "$1$" + salt + "$" + md5CryptRaw([]byte(key), []byte(salt)), nil
}

// md5CryptRaw is md5crypt with a caller-provided salt (max 8 bytes kept),
// faithful to the classic unix md5crypt (Poul-Henning Kamp, verified
// line-for-line against FreeBSD libcrypt crypt-md5.c): the initial digest
// ctx = MD5(key ‖ "$1$" ‖ salt) carries the MAGIC, the "alternation" odd
// iterations append a ZERO byte (the jar's commons-codec-1.11 zeroes the
// alt buffer before the weird loop exactly like FreeBSD's explicit_bzero,
// javap-verified at Md5Crypt crypt() offset 211 before the i&1 loop at
// 223-262), and the output is to64 in the classic
// (0,6,12)(1,7,13)(2,8,14)(3,9,15)(4,10,5) order plus the 2-char final[11]
// tail. Byte-identical to both the controller jar (run directly) and
// `openssl passwd -1`.
func md5CryptRaw(key, salt []byte) string {
	if len(salt) > 8 {
		salt = salt[:8]
	}

	// alt = MD5(key ‖ salt ‖ key)   (NO magic in this digest)
	h := md5.New()
	h.Write(key)
	h.Write(salt)
	h.Write(key)
	alt := h.Sum(nil)

	// ctx = MD5(key ‖ "$1$" ‖ salt ‖ alt×chunks ‖ alternation(zero/key[0]))
	h = md5.New()
	h.Write(key)
	h.Write([]byte("$1$"))
	h.Write(salt)
	for i := len(key); i > 0; i -= 16 {
		if i > 16 {
			h.Write(alt)
		} else {
			h.Write(alt[:i])
		}
	}
	// /* Don't leave anything around in vm i could use. */ — the buffer is
	// zeroed before this loop, so the odd branch appends a literal zero byte.
	zero := []byte{0}
	for i := len(key); i > 0; i >>= 1 {
		if i&1 != 0 {
			h.Write(zero)
		} else if len(key) > 0 {
			h.Write(key[:1])
		}
	}
	final := h.Sum(nil)

	// 1000-iteration burning loop: odd iterations update with key first and
	// final second; even ones final first and key second.
	for i := 0; i < 1000; i++ {
		h = md5.New()
		if i&1 != 0 {
			h.Write(key)
		} else {
			h.Write(final)
		}
		if i%3 != 0 {
			h.Write(salt)
		}
		if i%7 != 0 {
			h.Write(key)
		}
		if i&1 != 0 {
			h.Write(final)
		} else {
			h.Write(key)
		}
		final = h.Sum(nil)
	}

	// Encode 16 bytes in the md5crypt order: 4+4+4+4+4 output groups then a
	// 2-byte tail — "22 chars" (crypto/b64 style, no padding).
	number := func(b1, b2, b3 byte) uint32 {
		return uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)
	}
	out := make([]byte, 0, 22)
	emit := func(v uint32, n int) {
		for i := 0; i < n; i++ {
			out = append(out, b64cryptAlphabet[v&0x3f])
			v >>= 6
		}
	}
	emit(number(final[0], final[6], final[12]), 4)
	emit(number(final[1], final[7], final[13]), 4)
	emit(number(final[2], final[8], final[14]), 4)
	emit(number(final[3], final[9], final[15]), 4)
	emit(number(final[4], final[10], final[5]), 4)
	emit(uint32(final[11]), 2)
	return string(out)
}

// md5CryptMatches verifies a stored $1$ hash against the password (embedded
// salt recomposition), the md5 analog of sha512CryptMatches.
func md5CryptMatches(key, stored string) bool {
	rest, ok := strings.CutPrefix(stored, "$1$")
	if !ok {
		return false
	}
	salt, _, cut := strings.Cut(rest, "$")
	if !cut || salt == "" || len(salt) > 8 {
		return false
	}
	return md5CryptRaw([]byte(key), []byte(salt)) == string(rest[len(salt)+1:])
}

// randAlphaSalt mirrors RandomStringUtils.randomAlphabetic(n) over
// crypto/rand (the jar's md5-branch salt generator, commons-codec B64 set
// aside: letters only). Var so tests can inject failure (FID-23 path).
var randAlphaSalt = randAlphaSaltLive

func randAlphaSaltLive(n int) (string, error) {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = letters[int(b)%len(letters)]
	}
	return string(out), nil
}

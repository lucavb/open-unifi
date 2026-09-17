package systemcfg

import "testing"

// Golden vectors from OpenSSL 3.x (`openssl passwd -1 -salt S P`) — the
// glibc/Apache md5crypt the classic controller's commons-codec Md5Crypt
// mirrors byte-for-byte. (Moved from package server with the renderer.)
func TestMD5CryptVectorTests(t *testing.T) {
	vv := []struct{ pw, salt, want string }{
		{"ubnt", "abcd1234", "$1$abcd1234$UPyGHXXYPYzFOkGgbE7uo0"},
		{"ubnt", "testsalt", "$1$testsalt$phdRQ10fojI.hrEiZfZVU/"},
		{"ubnt", "01234567", "$1$01234567$vigV.l7xN3EZbzxgDJoUg."},
		{"ubnt", "/0ab", "$1$/0ab$2Pwalw/7N95C047k71opS0"},
		{"letmeinnow", "abcd1234", "$1$abcd1234$7IaawFGkVaJc9HfqkbLCx."},
		{"letmeinnow", "testsalt", "$1$testsalt$YP2koC9HPVZjUpyIa288z."},
	}
	for _, v := range vv {
		got := "$1$" + v.salt + "$" + md5CryptRaw([]byte(v.pw), []byte(v.salt))
		if got != v.want {
			t.Errorf("md5crypt(%q, %q)\n got %s\nwant %s", v.pw, v.salt, got, v.want)
		}
		if !md5CryptMatches(v.pw, v.want) {
			t.Errorf("stored-hash self-check rejected %q", v.want)
		}
	}
}

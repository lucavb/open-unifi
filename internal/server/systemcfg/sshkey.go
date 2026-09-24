package systemcfg

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
)

// PublicKey is one SSH authorized-key line parsed into the three components
// the firmware's authorized_keys writer needs. The U7PG2 firmware (BZ.
// 6.8.2.15592) regenerates /etc/dropbear/authorized_keys from persisted cfg
// rows on every boot/apply (users/sshd state is rebuilt from cfg rows —
// docs/AP-FIRMWARE-APPLY-PATH.md §192-209; live-confirmed wipe
// docs/WLAN-ACCEPTANCE-6.8.2.15592.md:427-432): the builder string cluster
// at ubntbox 0x0063bd40-0x0063be80 carries the row names
// "sshd.auth.key.%d.status"/".type"/".comment", the default type
// "ssh-rsa", and the bare ".value" suffix at 0x0064ec8c; the key line is
// written with format "%s %s %s\n" (type, value, comment) to
// "/etc/dropbear/authorized_keys" @0x0063f19c. So a key only survives on
// the device when its Type/Value/Comment are carried as cfg rows.
type PublicKey struct {
	// Type is the key-type token as it appears in an authorized_keys line
	// ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", ...).
	Type string
	// Value is the base64 key material (the middle authorized_keys field),
	// carried verbatim — the renderer does not re-encode it.
	Value string
	// Comment is the optional trailing comment ("" when the line had none);
	// the firmware emits the comment row only when non-empty.
	Comment string
}

// publicKeyTypeRe is the fail-closed key-type gate: only the token shapes
// the firmware's type suffix mechanism can carry ("ssh-*" and "ecdsa-*",
// lowercase alnum plus hyphen) pass. Anything else is a parse error — a
// malformed token must never reach the renderer and become a silently
// broken authorized_keys line on the next boot rebuild.
var publicKeyTypeRe = regexp.MustCompile(`^(ssh|ecdsa)-[a-z0-9-]+$`)

// ParsePublicKey parses one authorized_keys line into a PublicKey. The
// accepted shapes are the two firmware-relevant ones: "type value" and
// "type value comment" (exactly 2 or 3 strings.Fields tokens). The type
// token must match ^(ssh|ecdsa)-[a-z0-9-]+$ and the value must be standard
// base64 encoding a structurally valid RFC 4253 §6.6 wire blob: the blob
// begins with its own algorithm name (4-byte BigEndian length + type token)
// and parses as clean length-prefixed fields consuming it EXACTLY, with at
// least 2 fields total (see walkWireBlob). This is a STRUCTURE check, not
// cryptographic validation — a well-formed blob of the wrong key still
// passes; the firmware's own dropbear will reject it at first use.
//
// NOTE: Go's base64 decoder silently skips \n and \r, so strings.Fields
// tokenization is the ONLY newline gate in this parser — keep it that way.
// The base64 charset check guards malformed values, not newlines: a future
// strings.Split refactor would reopen the newline-injection hole the
// lineWriter guards otherwise block. There is no trimming or lenient
// repair: malformed input is an error, so callers fail closed at startup
// instead of provisioning a half-line the next boot rebuild would turn into
// a broken authorized_keys.
func ParsePublicKey(line string) (PublicKey, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || len(fields) > 3 {
		return PublicKey{}, fmt.Errorf("want exactly 2 or 3 fields (type value [comment]), got %d", len(fields))
	}
	if !publicKeyTypeRe.MatchString(fields[0]) {
		return PublicKey{}, fmt.Errorf("unsupported key type %q: want ^(ssh|ecdsa)-[a-z0-9-]+$", fields[0])
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return PublicKey{}, fmt.Errorf("invalid base64 key value: %w", err)
	}
	pk := PublicKey{Type: fields[0], Value: fields[1]}
	if len(fields) == 3 {
		pk.Comment = fields[2]
	}
	if err := walkWireBlob(raw, pk.Type); err != nil {
		return PublicKey{}, err
	}
	return pk, nil
}

// walkWireBlob checks the RFC 4253 §6.6 wire structure of a decoded public
// key blob: the blob must begin with its own algorithm name (4-byte
// BigEndian length + the type token) and parse as clean length-prefixed
// fields that consume the blob EXACTLY — no mid-field overrun, no trailing
// bytes — with at least 2 fields total (the type name plus at least one
// more: no real SSH public key is name-only). Structure only, NOT
// cryptographic validation: a well-formed blob of the wrong key still
// passes (dropbear's first use rejects it).
func walkWireBlob(raw []byte, typ string) error {
	if len(raw) < 4+len(typ) {
		return fmt.Errorf("key blob too short for its %q type name (got %d bytes)", typ, len(raw))
	}
	nameLen := binary.BigEndian.Uint32(raw)
	if int(nameLen) != len(typ) {
		return fmt.Errorf("key blob does not begin with its own type name: value names a %d-byte type, token is %q", nameLen, typ)
	}
	if string(raw[4:4+len(typ)]) != typ {
		return fmt.Errorf("key blob type name does not match its type token: blob %q vs token %q", raw[4:4+len(typ)], typ)
	}
	off := 4 + len(typ)
	fieldCount := 1
	for off < len(raw) {
		if len(raw)-off < 4 {
			return fmt.Errorf("key blob truncated inside a length field at offset %d", off)
		}
		l := int(binary.BigEndian.Uint32(raw[off:]))
		off += 4
		if l > len(raw)-off {
			return fmt.Errorf("key blob field at offset %d overruns the blob: declares %d bytes, %d remain", off-4, l, len(raw)-off)
		}
		off += l
		fieldCount++
	}
	if fieldCount < 2 {
		return fmt.Errorf("key blob carries only its type name: want at least 2 length-prefixed fields")
	}
	return nil
}

func parseDeviceSSHPublicKeys(lines []string) ([]PublicKey, error) {
	if len(lines) == 0 {
		return nil, nil
	}
	out := make([]PublicKey, 0, len(lines))
	for i, line := range lines {
		k, err := ParsePublicKey(line)
		if err != nil {
			return nil, fmt.Errorf("invalid SSH public key #%d: %w", i+1, err)
		}
		out = append(out, k)
	}
	return out, nil
}

package adoption

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// systemCfgDiagnostic returns a bounded representation of cfg. It deliberately
// parses, rather than redacts, the input: only the complete blob's digest and
// section/key names are copied to the result. In particular, never add a
// value, or an error containing a value, to this format.
//
// The format is stable and intentionally plain:
// system_cfg diagnostic sha256=<hex> sections=[a,b] keys=[a.k,b.k]
func systemCfgDiagnostic(cfg string) (string, error) {
	sum := sha256.Sum256([]byte(cfg))
	sections := make([]string, 0)
	keys := make([]string, 0)
	seenSections := make(map[string]bool)
	seenKeys := make(map[string]bool)
	section := ""

	for _, line := range strings.Split(cfg, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# ") {
			section = strings.TrimSpace(strings.TrimPrefix(line, "# "))
			if section != "" && !seenSections[section] {
				sections = append(sections, section)
				seenSections[section] = true
			}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 1 {
			// The builder permits opaque passthrough lines. They are not key
			// names, and must not be copied into diagnostics.
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if key == "" {
			continue
		}
		if !safeDiagnosticName(key) {
			continue
		}
		duplicateID := section + "\x00" + key
		if seenKeys[duplicateID] {
			return "", fmt.Errorf("duplicate system_cfg key %q", key)
		}
		seenKeys[duplicateID] = true
		keys = append(keys, key)
	}

	return fmt.Sprintf("system_cfg diagnostic sha256=%s sections=[%s] keys=[%s]",
		hex.EncodeToString(sum[:]), strings.Join(sections, ","), strings.Join(keys, ",")), nil
}

func safeDiagnosticName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') &&
			(r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

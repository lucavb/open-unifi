package systemcfg

import (
	"strings"
	"testing"
)

func TestSystemCfgDiagnosticContainsNoValues(t *testing.T) {
	const secret = "U7PG2-PSK-secret-marker"
	cfg := "# system\nsystem.timezone=UTC\n# users\nusers.1.password=" + secret + "\n"

	diagnostic, err := Diagnostic(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(diagnostic, secret) {
		t.Fatalf("diagnostic leaked a config value: %q", diagnostic)
	}
	if !strings.Contains(diagnostic, "sections=[system,users]") {
		t.Fatalf("missing ordered sections: %q", diagnostic)
	}
	if !strings.Contains(diagnostic, "keys=[system.timezone,users.1.password]") {
		t.Fatalf("missing ordered keys: %q", diagnostic)
	}
	if !strings.Contains(diagnostic, "sha256=") {
		t.Fatalf("missing digest: %q", diagnostic)
	}
}

func TestSystemCfgDiagnosticRejectsDuplicateKeys(t *testing.T) {
	_, err := Diagnostic("# system\nsystem.timezone=UTC\nsystem.timezone=secret\n")
	if err == nil {
		t.Fatal("expected duplicate key error")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("duplicate-key error leaked a value: %q", err)
	}
}

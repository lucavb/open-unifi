package main

import (
	"strings"
	"testing"
)

func TestDiscoveryPort(t *testing.T) {
	for addr, want := range map[string]struct {
		host string
		port int
	}{
		":10001":         {"", 10001},
		"0.0.0.0:2":      {"0.0.0.0", 2},
		"10001":          {"", 10001},
		"185.99.0.1:100": {"185.99.0.1", 100},
	} {
		host, port, err := discoveryPort(addr)
		if err != nil {
			t.Fatalf("--listen-discovery %q: unexpected error %v", addr, err)
		}
		if host != want.host || port != want.port {
			t.Fatalf("--listen-discovery %q: want (%q,%d), got (%q,%d)", addr, want.host, want.port, host, port)
		}
	}
	for _, addr := range []string{"185.99.0.1", "failhost", ":100001", "host:port99", ":0"} {
		if _, _, err := discoveryPort(addr); err == nil {
			t.Fatalf("unparseable spec %q must hard-fail at startup", addr)
		}
	}
}

func TestValidateRegulatoryCountryCode(t *testing.T) {
	if err := validateRegulatoryCountryCode(840); err != nil {
		t.Fatalf("validateRegulatoryCountryCode(840) = %v, want nil", err)
	}
	if err := validateRegulatoryCountryCode(276); err != nil {
		t.Fatalf("validateRegulatoryCountryCode(276) = %v, want nil", err)
	}
	err := validateRegulatoryCountryCode(0)
	if err == nil {
		t.Fatal("validateRegulatoryCountryCode(0) = nil, want error")
	}
	if !strings.Contains(err.Error(), "omit the flag") {
		t.Fatalf("error should tell the user to omit the flag, got: %v", err)
	}
}

func TestParseLogFormat(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"empty defaults to text", "", "text", false},
		{"text", "text", "text", false},
		{"TEXT uppercase", "TEXT", "text", false},
		{"Text mixed case", "Text", "text", false},
		{"json", "json", "json", false},
		{"JSON uppercase", "JSON", "json", false},
		{"invalid", "xml", "", true},
		{"invalid spaced", "text json", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseLogFormat(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseLogFormat(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("parseLogFormat(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidateAdminExposure(t *testing.T) {
	tests := []struct {
		name                         string
		addr, token                  string
		anonymous, insecure, wantErr bool
	}{
		{"loopback token", "127.0.0.1:8080", "token", false, false, false},
		{"localhost anonymous", "localhost:8080", "", true, false, false},
		{"missing token", "127.0.0.1:8080", "", false, false, true},
		{"public plaintext", "0.0.0.0:8080", "token", false, false, true},
		{"public insecure opt in", "0.0.0.0:8080", "", true, true, false},
		{"malformed address", "8080", "token", false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAdminExposure(tc.addr, tc.token, tc.anonymous, tc.insecure)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateAdminExposure(%q, ...) error = %v, wantErr %v", tc.addr, err, tc.wantErr)
			}
		})
	}
}

// resolveSSHPublicKeys table: the cmd-layer ssh-key startup composition —
// flag/env precedence, the one non-obvious semantic (an explicit empty flag
// value refuses the env and fails the parser), fail-closed key validation
// with the 1-based "#N" error, and the disable-password guard both arms.
// Synthetic key material only (the systemcfg tests' marker'd RFC 4253 blob
// — never a real key).
const testSSHKeyLine = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB second@ap"
const testSSHKeyLine2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB test@ap"

func TestResolveSSHPublicKeys(t *testing.T) {
	cases := []struct {
		name            string
		flagKeys        []string
		envValue        string
		disablePassword bool
		want            []string // resolved key types, nil = error expected
		wantErr         string   // substring when want == nil
	}{
		{name: "flag-only", flagKeys: []string{testSSHKeyLine}, want: []string{"ssh-rsa"}},
		{name: "env-only", envValue: testSSHKeyLine2, want: []string{"ssh-ed25519"}},
		{
			name: "flag-wins-over-env", flagKeys: []string{testSSHKeyLine}, envValue: testSSHKeyLine2,
			want: []string{"ssh-rsa"},
		},
		{
			name: "empty-flag-refuses-env", flagKeys: []string{""}, envValue: testSSHKeyLine2,
			wantErr: "invalid AP SSH public key #1: want exactly 2 or 3 fields",
		},
		{
			name: "malformed-flag-second", flagKeys: []string{testSSHKeyLine2, "ssh-rsa !!!"},
			wantErr: "invalid AP SSH public key #2: ",
		},
		{
			name:            "disable-without-keys",
			disablePassword: true,
			wantErr:         "cannot be disabled without a provisioned public key",
		},
		{
			name: "disable-with-keys", flagKeys: []string{testSSHKeyLine}, disablePassword: true,
			want: []string{"ssh-rsa"},
		},
	}
	for _, c := range cases {
		got, err := resolveSSHPublicKeys(c.flagKeys, c.envValue, c.disablePassword)
		if c.want == nil {
			if err == nil {
				t.Fatalf("%s: unexpectedly succeeded", c.name)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("%s: err %v, want substring %q", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected err %v", c.name, err)
		}
		if len(got) != len(c.want) {
			t.Fatalf("%s: got %d keys, want %d", c.name, len(got), len(c.want))
		}
		for i, typ := range c.want {
			if got[i].Type != typ {
				t.Fatalf("%s: key %d type = %q, want %q", c.name, i, got[i].Type, typ)
			}
		}
	}
}

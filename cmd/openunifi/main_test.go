package main

import (
	"reflect"
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

// effectiveSSHKeyLines table: the cmd-layer ssh-key flag/env composition —
// flag/env precedence and the one non-obvious semantic (an explicit empty
// flag value refuses the env: the flag slice is non-empty, so the env
// fallback never engages — the exact semantic the former cmd-layer resolver
// carried into the seed). The key LINES themselves are validated fail-closed
// at the app record seams (app/site_settings.go: seed + save, the single
// systemcfg.ParsePublicKey parser) — that parse coverage lives in the
// internal/app and internal/adminapi tests and is not duplicated here.
func TestEffectiveSSHKeyLines(t *testing.T) {
	cases := []struct {
		name     string
		flagKeys []string
		envValue string
		want     []string
	}{
		{name: "flag-only", flagKeys: []string{"ssh-rsa AAAAflag first@ap"}, want: []string{"ssh-rsa AAAAflag first@ap"}},
		{name: "env-only", envValue: "ssh-ed25519 AAAAenv second@ap", want: []string{"ssh-ed25519 AAAAenv second@ap"}},
		{name: "flag-wins-over-env", flagKeys: []string{"ssh-rsa AAAAflag first@ap"}, envValue: "ssh-ed25519 AAAAenv second@ap", want: []string{"ssh-rsa AAAAflag first@ap"}},
		{name: "empty-flag-refuses-env", flagKeys: []string{""}, envValue: "ssh-ed25519 AAAAenv second@ap", want: []string{""}},
		{name: "neither-source", want: nil},
	}
	for _, c := range cases {
		got := effectiveSSHKeyLines(c.flagKeys, c.envValue)
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%s: effectiveSSHKeyLines(%q, %q) = %q, want %q", c.name, c.flagKeys, c.envValue, got, c.want)
		}
	}
}

// validateSSHDisableSeed table: the fail-closed disable-without-keys
// startup guard, restored verbatim from the pre-lane cmd-layer resolver
// (both arms — the refusal message and the pass-through) and pinned like
// the composition above, so the lane's deletion of the guard can never
// regress silently again.
func TestValidateSSHDisableSeed(t *testing.T) {
	cases := []struct {
		name            string
		keys            []string
		disablePassword bool
		wantErr         string // substring; "" = must pass
	}{
		{name: "disable-without-keys", keys: nil, disablePassword: true, wantErr: "cannot be disabled without a provisioned public key"},
		{name: "disable-with-keys", keys: []string{"ssh-rsa AAAAflag first@ap"}, disablePassword: true},
		{name: "keys-without-disable", keys: []string{"ssh-rsa AAAAflag first@ap"}},
		{name: "neither"},
	}
	for _, c := range cases {
		err := validateSSHDisableSeed(c.keys, c.disablePassword)
		if c.wantErr == "" {
			if err != nil {
				t.Fatalf("%s: unexpected err %v", c.name, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("%s: unexpectedly succeeded", c.name)
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Fatalf("%s: err %v, want substring %q", c.name, err, c.wantErr)
		}
	}
}

package main

import (
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

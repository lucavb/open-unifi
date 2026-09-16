package main

import "testing"

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

package main

import (
	"flag"
	"io"
	"strings"
	"testing"
	"time"
)

func resolveWith(t *testing.T, env map[string]string, args ...string) (bool, time.Duration, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	h := registerClientHistoryFlags(fs, func(k string) string { return env[k] })
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return h.resolve(fs)
}

func TestClientHistoryDefaultsOff(t *testing.T) {
	on, ret, err := resolveWith(t, nil)
	if err != nil || on || ret != 30*24*time.Hour {
		t.Fatalf("on=%v ret=%v err=%v, want off/30d", on, ret, err)
	}
}

func TestClientHistoryEnvEnables(t *testing.T) {
	on, ret, err := resolveWith(t, map[string]string{envClientHistory: "true", envClientHistoryRetention: "7d"})
	if err != nil || !on || ret != 7*24*time.Hour {
		t.Fatalf("on=%v ret=%v err=%v", on, ret, err)
	}
}

func TestClientHistoryFlagBeatsEnv(t *testing.T) {
	env := map[string]string{envClientHistory: "true", envClientHistoryRetention: "7d"}
	on, ret, err := resolveWith(t, env, "--client-history=false", "--client-history-retention=12h")
	if err != nil || on || ret != 12*time.Hour {
		t.Fatalf("on=%v ret=%v err=%v, flags must win", on, ret, err)
	}
}

func TestClientHistoryInvalidEnvFails(t *testing.T) {
	_, _, err := resolveWith(t, map[string]string{envClientHistory: "yes please"})
	if err == nil || !strings.Contains(err.Error(), envClientHistory) {
		t.Fatalf("err = %v, want an error naming the variable", err)
	}
	_, _, err = resolveWith(t, map[string]string{envClientHistoryRetention: "soon"})
	if err == nil || !strings.Contains(err.Error(), "retention") {
		t.Fatalf("err = %v, want a retention error", err)
	}
}

func TestClientHistoryFlagOverridesInvalidEnv(t *testing.T) {
	on, _, err := resolveWith(t, map[string]string{envClientHistory: "garbage", envClientHistoryRetention: "garbage"},
		"--client-history", "--client-history-retention=1d")
	if err != nil || !on {
		t.Fatalf("on=%v err=%v, explicit flags must override bad env", on, err)
	}
}

func TestClientHistoryInvalidRetentionFlagFails(t *testing.T) {
	if _, _, err := resolveWith(t, nil, "--client-history-retention=0d"); err == nil {
		t.Fatal("zero retention accepted")
	}
}

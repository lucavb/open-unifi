package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lucavb/open-unifi/internal/clientevents"
)

// Environment defaults for the client-history flags, following the
// OPEN_UNIFI_ADMIN_TOKEN pattern: the variable seeds the flag default and
// an explicit flag wins.
const (
	envClientHistory          = "OPEN_UNIFI_CLIENT_HISTORY"
	envClientHistoryRetention = "OPEN_UNIFI_CLIENT_HISTORY_RETENTION"
)

// clientHistoryFlags holds the registered opt-in client-history flags.
type clientHistoryFlags struct {
	enabled   *bool
	retention *string
	// envErr is a malformed $OPEN_UNIFI_CLIENT_HISTORY. It is only fatal
	// when no --client-history flag overrides it, so a bad variable never
	// silently disables history.
	envErr error
}

// registerClientHistoryFlags registers --client-history and
// --client-history-retention on fs, defaulting from the environment.
func registerClientHistoryFlags(fs *flag.FlagSet, getenv func(string) string) *clientHistoryFlags {
	on, envErr := parseEnvBool(envClientHistory, getenv(envClientHistory))
	f := &clientHistoryFlags{envErr: envErr}
	f.enabled = fs.Bool("client-history", on,
		"persist client connect/disconnect/roam events and per-client AP history to <data-dir>/client-events.jsonl (opt-in; defaults to $"+envClientHistory+")")
	retention := strings.TrimSpace(getenv(envClientHistoryRetention))
	if retention == "" {
		retention = "30d"
	}
	f.retention = fs.String("client-history-retention", retention,
		"how long client history is kept, e.g. 30d, 12h (defaults to $"+envClientHistoryRetention+" or 30d)")
	return f
}

// resolve returns the effective settings after fs has been parsed. An
// invalid variable or retention is an error, never a silent default.
func (f *clientHistoryFlags) resolve(fs *flag.FlagSet) (enabled bool, retention time.Duration, err error) {
	explicit := false
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "client-history" {
			explicit = true
		}
	})
	if f.envErr != nil && !explicit {
		return false, 0, f.envErr
	}
	retention, err = clientevents.ParseRetention(*f.retention)
	if err != nil {
		return false, 0, fmt.Errorf("invalid --client-history-retention (or $%s) %q: %w", envClientHistoryRetention, *f.retention, err)
	}
	return *f.enabled, retention, nil
}

// parseEnvBool parses an optional boolean variable: empty means false.
func parseEnvBool(name, value string) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid $%s %q: want true or false", name, value)
	}
	return b, nil
}

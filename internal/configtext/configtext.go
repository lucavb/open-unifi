// Package configtext holds the shared config-blob text helpers used by BOTH
// the adoption engine's mgmt_cfg builder and the system_cfg renderer. It is
// a leaf: it imports only stdlib and internal/store, so neither consumer
// drags the other in.
package configtext

import (
	"strings"

	"github.com/lucabecker/open-unifi/internal/store"
)

// LineWriter returns the shared INJECTION-GUARDED key=value line writer used
// by every system_cfg/mgmt_cfg emission site. Any VALUE containing \n or \r
// makes the whole row skipped — warn(where, key) is called with the skipped
// row's context — instead of emitted: a newline smuggled in from an inform
// body (forged radio fields, timezone strings, cookie comments) would
// terminate the row early and inject attacker-chosen key=value rows into the
// device's config. "Fail loud, never emit." (raw() admin passthrough lines
// in the system_cfg renderer are the ONLY unguarded writer: admin-owned by
// definition.)
//
// The caller owns the logging/warning channel: the adoption engine's builder
// passes a slog-backed sink, the pure system_cfg renderer passes a collector
// that records the skip as a warn-level diagnostic value for its caller to
// log.
func LineWriter(warn func(where, key string), b *strings.Builder, where string) func(k, v string) {
	return func(k, v string) {
		if strings.ContainsAny(v, "\n\r") {
			warn(where, k)
			return
		}
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(v)
		b.WriteString("\n")
	}
}

// SiteRef is the site value the classic builder puts into mgmt_url and
// unifi.siteid (FID-17/FID-52): the site NAME the device belongs to. The
// store's Device.SiteID carries exactly that admin-supplied site name for
// this MVP (no site table yet, so an empty id degrades to "default").
func SiteRef(d store.Device) string {
	if d.SiteID == "" {
		return defaultSiteName
	}
	return d.SiteID
}

const defaultSiteName = "default"

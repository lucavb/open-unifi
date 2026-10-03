// Package configtext holds the shared config-blob text helpers used by BOTH
// the adoption engine's mgmt_cfg builder and the system_cfg renderer. It is
// a leaf: it imports only stdlib and internal/store, so neither consumer
// drags the other in.
package configtext

import (
	"strings"

	"github.com/lucavb/open-unifi/internal/store"
)

// LineWriter returns the shared key=value writer for system_cfg and mgmt_cfg.
// Values containing CR or LF are skipped and reported: otherwise an inform
// value could terminate a row and inject config. Admin-owned raw passthrough
// lines in the system_cfg renderer are the only unguarded writer.
//
// The caller supplies the warning sink; the adoption builder logs directly,
// while the pure renderer collects diagnostics for its caller.
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

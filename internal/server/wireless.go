package server

// The system_cfg emission (and its byte-verified schema contract) moved to
// internal/server/systemcfg in checkpoint 3. What stays here is the WLAN
// type alias and the adapter's configured wireless source.

import (
	"github.com/lucavb/open-unifi/internal/wireless"
)

// Wlan aliases the shared WLAN type (internal/wireless): every existing
// server-side reference (and cmd/openunifi's converter) keeps compiling
// unchanged while the type itself lives in its own package.
type Wlan = wireless.Wlan

// currentWireless resolves the configured source; nil source ⇒ empty list.
func (s *Server) currentWireless() []Wlan {
	if s.cfg.WirelessSource == nil {
		return nil
	}
	return s.cfg.WirelessSource()
}

// currentSiteSettings resolves the configured site-settings source; nil
// source ⇒ zero facts (the four rendering defaults), mirroring
// currentWireless. A non-nil error is the REAL retained settings load error
// (a present-but-unreadable/corrupt/invalid site-settings file): the render
// fails on it (no record mutation, no emission); the gate closure maps it
// to zero facts so the gate stays inert — net fail-closed. Both the gate
// read and the render read go through this live source per call; for the
// two-read residual within one decision (and its recorded remedy) see the
// adoption.Deps.SSHSiteFacts docblock.
func (s *Server) currentSiteSettings() (SiteSettings, error) {
	if s.cfg.SiteSettings == nil {
		return SiteSettings{}, nil
	}
	return s.cfg.SiteSettings()
}

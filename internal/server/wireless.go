package server

// The system_cfg emission (and its byte-verified schema contract) moved to
// internal/server/systemcfg in checkpoint 3. What stays here is the WLAN
// type alias and the adapter's configured wireless source.

import (
	"github.com/lucabecker/open-unifi/internal/wireless"
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

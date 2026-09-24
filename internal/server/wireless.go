package server

// The system_cfg emission (and its byte-verified schema contract) moved to
// internal/server/systemcfg in checkpoint 3. What stays here is the WLAN
// type alias and the adapter's per-device wireless source.

import (
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

// Wlan aliases the shared WLAN type (internal/wireless): every existing
// server-side reference (and cmd/openunifi's converter) keeps compiling
// unchanged while the type itself lives in its own package.
type Wlan = wireless.Wlan

// wirelessForDevice resolves WLAN intent for one device; nil source ⇒ empty list.
func (s *Server) wirelessForDevice(d store.Device) []Wlan {
	if s.cfg.WirelessForDevice == nil {
		return nil
	}
	return s.cfg.WirelessForDevice(d)
}

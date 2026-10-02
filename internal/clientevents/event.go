// Package clientevents turns the per-AP client session transitions the
// inform path derives (internal/store RefreshSessionStations) into
// UniFi-style client events — EVT_WU_Connected, EVT_WU_Disconnected,
// EVT_WU_Roam and EVT_WU_RoamRadio — and fans them out to sinks.
//
// Each AP only ever reports its own station table, so a roam looks like a
// disconnect on one AP and a connect on another, in either order. The
// Tracker correlates them (see tracker.go). Event keys and field names
// mirror the official controller's stat/event documents so a classic-API
// route can be layered on later.
//
// Events always reach the SlogSink; the FileSink (opt-in, filesink.go)
// persists them as an append-only JSON-lines history that the admin API
// queries. Per-client location and IP history is personal data, which is
// why persistence is off unless explicitly enabled.
package clientevents

import (
	"fmt"
	"strings"
	"time"
)

// Event keys, mirroring the official controller.
const (
	KeyConnected    = "EVT_WU_Connected"
	KeyDisconnected = "EVT_WU_Disconnected"
	KeyRoam         = "EVT_WU_Roam"
	KeyRoamRadio    = "EVT_WU_RoamRadio"
)

// Event is one client event. MAC fields are colon-hex. Unknown values are
// omitted from the JSON.
type Event struct {
	Key      string `json:"key"`
	Time     int64  `json:"time"` // unix milliseconds, as in the official API
	Datetime string `json:"datetime"`

	// Client is the client MAC (the official API's "user" field).
	Client   string `json:"client"`
	Hostname string `json:"hostname,omitempty"`
	// IP is the client's IP address as the station table reported it.
	IP string `json:"ip,omitempty"`

	// AP is the AP of a connect/disconnect/radio event; APFrom/APTo are
	// the two sides of a roam. *Name fields are the AP names at event time.
	AP         string `json:"ap,omitempty"`
	APName     string `json:"ap_name,omitempty"`
	APFrom     string `json:"ap_from,omitempty"`
	APFromName string `json:"ap_from_name,omitempty"`
	APTo       string `json:"ap_to,omitempty"`
	APToName   string `json:"ap_to_name,omitempty"`

	SSID        string `json:"ssid,omitempty"`
	Radio       string `json:"radio,omitempty"`
	RadioFrom   string `json:"radio_from,omitempty"`
	RadioTo     string `json:"radio_to,omitempty"`
	Channel     int    `json:"channel,omitempty"`
	ChannelFrom int    `json:"channel_from,omitempty"`
	ChannelTo   int    `json:"channel_to,omitempty"`

	// Duration is the connection time in seconds and Bytes the tx+rx total
	// (disconnect events only).
	Duration int64 `json:"duration,omitempty"`
	Bytes    int64 `json:"bytes,omitempty"`

	// Msg is a human-readable description in the style of the official
	// System Log.
	Msg string `json:"msg"`
}

// At returns the event time.
func (e Event) At() time.Time { return time.UnixMilli(e.Time) }

func (e *Event) setTime(unixSec int64) {
	e.Time = unixSec * 1000
	e.Datetime = time.UnixMilli(e.Time).UTC().Format("2006-01-02T15:04:05Z")
}

// clientLabel is the hostname when known, else the client MAC.
func clientLabel(hostname, mac string) string {
	if hostname != "" {
		return hostname
	}
	return mac
}

// apLabel is the AP name when known, else its MAC.
func apLabel(name, mac string) string {
	if name != "" {
		return name
	}
	return mac
}

func channelLabel(channel int, radio string) string {
	if channel == 0 {
		return "unknown channel"
	}
	if radio == "" {
		return fmt.Sprintf("channel %d", channel)
	}
	return fmt.Sprintf("channel %d (%s)", channel, radio)
}

// FormatDuration renders seconds like the official log: "1h 28m",
// "9m 24s", "30s".
func FormatDuration(sec int64) string {
	if sec < 0 {
		sec = 0
	}
	d, h, m, s := sec/86400, sec%86400/3600, sec%3600/60, sec%60
	switch {
	case d > 0:
		return fmt.Sprintf("%dd %dh", d, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm %ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// FormatBytes renders a byte count with a decimal unit ("1.2 MB").
func FormatBytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}

func (e *Event) buildMsg() {
	who := clientLabel(e.Hostname, e.Client)
	switch e.Key {
	case KeyConnected:
		var b strings.Builder
		fmt.Fprintf(&b, "%s connected", who)
		if e.SSID != "" {
			fmt.Fprintf(&b, " to %s", e.SSID)
		}
		fmt.Fprintf(&b, " on %s.", apLabel(e.APName, e.AP))
		e.Msg = b.String()
	case KeyDisconnected:
		var b strings.Builder
		fmt.Fprintf(&b, "%s disconnected", who)
		if e.SSID != "" {
			fmt.Fprintf(&b, " from %s", e.SSID)
		}
		b.WriteString(".")
		if e.Duration > 0 {
			fmt.Fprintf(&b, " Time Connected: %s.", FormatDuration(e.Duration))
		}
		if e.Bytes > 0 {
			fmt.Fprintf(&b, " Data Used: %s.", FormatBytes(e.Bytes))
		}
		fmt.Fprintf(&b, " Last AP: %s.", apLabel(e.APName, e.AP))
		e.Msg = b.String()
	case KeyRoam:
		e.Msg = fmt.Sprintf("%s roamed from %s to %s.", who, apLabel(e.APFromName, e.APFrom), apLabel(e.APToName, e.APTo))
	case KeyRoamRadio:
		e.Msg = fmt.Sprintf("%s changed from %s to %s on %s.", who,
			channelLabel(e.ChannelFrom, e.RadioFrom), channelLabel(e.ChannelTo, e.RadioTo), apLabel(e.APName, e.AP))
	}
}

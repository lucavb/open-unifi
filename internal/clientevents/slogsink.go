package clientevents

import "log/slog"

// SlogSink logs every event as one structured info line. It is always on:
// the log line is transient, unlike the opt-in persisted history.
type SlogSink struct {
	Logger *slog.Logger
}

// Emit implements Sink.
func (s SlogSink) Emit(e Event) {
	lg := s.Logger
	if lg == nil {
		lg = slog.Default()
	}
	attrs := []any{"key", e.Key, "client", e.Client}
	add := func(k, v string) {
		if v != "" {
			attrs = append(attrs, k, v)
		}
	}
	add("hostname", e.Hostname)
	add("ap", e.AP)
	add("ap_name", e.APName)
	add("ap_from", e.APFrom)
	add("ap_to", e.APTo)
	add("ssid", e.SSID)
	if e.Channel != 0 {
		attrs = append(attrs, "channel", e.Channel)
	}
	if e.ChannelFrom != 0 || e.ChannelTo != 0 {
		attrs = append(attrs, "channel_from", e.ChannelFrom, "channel_to", e.ChannelTo)
	}
	if e.Duration != 0 {
		attrs = append(attrs, "duration_s", e.Duration)
	}
	if e.Bytes != 0 {
		attrs = append(attrs, "bytes", e.Bytes)
	}
	attrs = append(attrs, "msg_text", e.Msg)
	lg.Info("client event", attrs...)
}

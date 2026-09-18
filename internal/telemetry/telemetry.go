// Package telemetry wires opt-in observability into open-unifi:
// log formatting (text by default, JSON opt-in) and OTLP/HTTP tracing.
//
// Opt-in contract:
//
//   - Logging defaults to human-readable text. A --log-format flag
//     (OPEN_UNIFI_LOG_FORMAT) selects "json" for machine consumption.
//   - Tracing is DISABLED by default. It activates only when an OTLP
//     endpoint is supplied (--otlp-endpoint / OPEN_UNIFI_OTLP_ENDPOINT, or
//     the standard OTEL_EXPORTER_OTLP_ENDPOINT(_TRACES) variables). An empty
//     endpoint with the standard env vars unset never produces a provider —
//     the gate IS the opt-in, so nothing is ever exported to a default
//     localhost by accident. OTEL_SDK_DISABLED=true force-disables tracing
//     regardless of any endpoint configuration.
//
// When tracing is enabled, every log record emitted while a span is active
// gains trace_id/span_id fields (snake_case, Grafana/Loki conventions) via
// the traceHandler wrapping the logger.
package telemetry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// NewLogger builds the process logger: text or JSON handler as requested,
// always wrapped so active spans inject trace_id/span_id into every record.
// Anything other than "json" (case-insensitive) selects the text handler;
// main validates the flag value before calling.
func NewLogger(format string, level slog.Level, w io.Writer) *slog.Logger {
	var inner slog.Handler
	if strings.EqualFold(format, "json") {
		inner = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	} else {
		inner = slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	}
	return slog.New(traceHandler{inner: inner})
}

// traceHandler injects the active span's trace context into every record,
// using exactly the field names Loki's JSON stage expects.
type traceHandler struct{ inner slog.Handler }

func (h traceHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h traceHandler) WithGroup(name string) slog.Handler {
	return traceHandler{inner: h.inner.WithGroup(name)}
}

func (h traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	return h.inner.Handle(ctx, r)
}

// noopShutdown is returned when tracing stays disabled: calling it is a
// no-op, so the caller can defer it unconditionally.
func noopShutdown(context.Context) error { return nil }

// otlpTracesPath is the canonical OTLP/HTTP traces path. otlptracehttp
// (v1.45+) uses a WithEndpointURL path AS-IS — the canonical path is NOT
// appended and a bare http://host:port would POST to "/" — so endpoints
// carrying a scheme but no path get it appended here (OTLP base-URL
// semantics, mirroring OTEL_EXPORTER_OTLP_ENDPOINT), while endpoints that
// carry an explicit path stay verbatim.
const otlpTracesPath = "/v1/traces"

// SetupTracing builds the global tracer provider and wires it into otel's
// default globals. The gate IS the opt-in: without an endpoint (flag or
// standard env) — or with OTEL_SDK_DISABLED=true — nothing is constructed
// and a no-op shutdown is returned. A nil-error return always means the
// caller may defer the shutdown function unconditionally.
func SetupTracing(ctx context.Context, endpoint string, lg *slog.Logger) (func(context.Context) error, error) {
	if os.Getenv("OTEL_SDK_DISABLED") == "true" {
		return noopShutdown, nil
	}
	if endpoint == "" && os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		return noopShutdown, nil
	}

	var exp sdktrace.SpanExporter
	var err error
	switch {
	case strings.HasPrefix(endpoint, "https://"), strings.HasPrefix(endpoint, "http://"):
		// Explicit scheme-carrying endpoint from the flag. Parse it so a
		// pathless base URL gains the canonical traces path (the flag
		// mirrors OTEL_EXPORTER_OTLP_ENDPOINT semantics, and a collector
		// listens on /v1/traces); a URL that carries a path keeps it
		// verbatim (collectors behind a reverse proxy).
		u, uerr := url.Parse(endpoint)
		if uerr != nil {
			return nil, fmt.Errorf("otlp endpoint URL: %w", uerr)
		}
		if u.Path == "" || u.Path == "/" {
			u.Path = otlpTracesPath
		}
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(u.String())}
		if u.Scheme == "http" {
			// Plaintext endpoint: WithInsecure disables TLS.
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exp, err = otlptracehttp.New(ctx, opts...)
	case endpoint != "":
		// Scheme-less endpoint (host:port): use WithEndpoint and treat the
		// target as plaintext OTLP/HTTP.
		exp, err = otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint(endpoint),
			otlptracehttp.WithInsecure())
	default:
		// No flag endpoint but OTEL_EXPORTER_OTLP_ENDPOINT(_TRACES) is set:
		// construct with defaults so the SDK reads the env natively — it
		// maps an http:// scheme to an insecure transport itself.
		exp, err = otlptracehttp.New(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(),
		resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceName("openunifi")))
	if err != nil {
		return nil, fmt.Errorf("otel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))
	otel.SetErrorHandler(&throttledHandler{lg: lg, interval: 30 * time.Second})

	return tp.Shutdown, nil
}

// throttledHandler forwards otel-internal errors to slog.Warn at most once
// per interval so a dead collector cannot flood the log.
type throttledHandler struct {
	mu       sync.Mutex
	lg       *slog.Logger
	interval time.Duration
	last     time.Time
}

func (h *throttledHandler) Handle(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.last.IsZero() && time.Since(h.last) < h.interval {
		return
	}
	h.last = time.Now()
	h.lg.Warn("otel: internal error", "err", err)
}

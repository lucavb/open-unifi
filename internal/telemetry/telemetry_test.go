package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name   string
		format string
		check  func(t *testing.T, out string)
	}{
		{
			name:   "empty selects text",
			format: "",
			check: func(t *testing.T, out string) {
				if !strings.Contains(out, "time=") || !strings.Contains(out, "msg=") {
					t.Fatalf("text handler shape expected, got: %s", out)
				}
			},
		},
		{
			name:   "text explicit",
			format: "text",
			check: func(t *testing.T, out string) {
				if !strings.Contains(out, "time=") {
					t.Fatalf("text handler shape expected, got: %s", out)
				}
			},
		},
		{
			name:   "TEXT case-insensitive",
			format: "TEXT",
			check: func(t *testing.T, out string) {
				if strings.Contains(out, "{") {
					t.Fatalf("text handler expected for TEXT, got: %s", out)
				}
			},
		},
		{
			name:   "json",
			format: "json",
			check: func(t *testing.T, out string) {
				var m map[string]any
				if err := json.Unmarshal([]byte(out), &m); err != nil {
					t.Fatalf("json handler output is not valid JSON: %v (%s)", err, out)
				}
				if m["level"] != "INFO" || m["msg"] != "hello" {
					t.Fatalf("json output wrong: %s", out)
				}
			},
		},
		{
			name:   "JSON case-insensitive",
			format: "JSON",
			check: func(t *testing.T, out string) {
				if !strings.HasPrefix(out, "{") {
					t.Fatalf("json handler expected for JSON, got: %s", out)
				}
			},
		},
		{
			name:   "unknown falls back to text",
			format: "logfmt",
			check: func(t *testing.T, out string) {
				if !strings.Contains(out, "time=") {
					t.Fatalf("text fallback expected, got: %s", out)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			lg := NewLogger(tc.format, slog.LevelInfo, &buf)
			lg.Info("hello")
			tc.check(t, strings.TrimSpace(buf.String()))
		})
	}
}

func TestTraceHandlerInjectsSpanContext(t *testing.T) {
	tp := sdktrace.NewTracerProvider()
	defer func() { _ = tp.Shutdown(context.Background()) }()
	tracer := tp.Tracer("telemetry-test")

	ctx, span := tracer.Start(context.Background(), "op")
	defer span.End()
	sc := span.SpanContext()

	// Plain context: no trace_id/span_id attrs.
	var plain bytes.Buffer
	NewLogger("json", slog.LevelInfo, &plain).InfoContext(context.Background(), "msg")
	var pm map[string]any
	if err := json.Unmarshal(plain.Bytes(), &pm); err != nil {
		t.Fatalf("output not JSON: %v (%s)", err, plain.String())
	}
	if _, ok := pm["trace_id"]; ok {
		t.Fatalf("plain context must not carry trace_id: %s", plain.String())
	}

	// Active span: record carries the span's exact IDs.
	var buf bytes.Buffer
	NewLogger("json", slog.LevelInfo, &buf).InfoContext(ctx, "msg")
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("output not JSON: %v (%s)", err, buf.String())
	}
	if m["trace_id"] != sc.TraceID().String() {
		t.Fatalf("trace_id = %v, want %s (%s)", m["trace_id"], sc.TraceID().String(), buf.String())
	}
	if m["span_id"] != sc.SpanID().String() {
		t.Fatalf("span_id = %v, want %s (%s)", m["span_id"], sc.SpanID().String(), buf.String())
	}
}

func TestSetupTracingGate(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{"all unset", map[string]string{}},
		{"sdk disabled beats endpoint", map[string]string{"OTEL_SDK_DISABLED": "true", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range map[string]string{
				"OTEL_SDK_DISABLED":                  "",
				"OTEL_EXPORTER_OTLP_ENDPOINT":        "",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "",
			} {
				t.Setenv(k, v)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			shutdown, err := SetupTracing(context.Background(), "", slog.Default())
			if err != nil {
				t.Fatalf("SetupTracing gate: unexpected error %v", err)
			}
			if err := shutdown(context.Background()); err != nil {
				t.Fatalf("noop shutdown returned %v", err)
			}
		})
	}
}

func TestSetupTracingExportsOTLPHTTP(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string // appended to "http://<server addr>"
		wantPath string // path the fake endpoint must see POSTed
	}{
		{
			// otlptracehttp uses a WithEndpointURL path as-is and does
			// NOT append /v1/traces; the flag endpoint mirrors
			// OTEL_EXPORTER_OTLP_ENDPOINT base-URL semantics, so a bare
			// http://host:port must deliver to the canonical path.
			name:     "bare endpoint posts to canonical /v1/traces",
			endpoint: "",
			wantPath: "/v1/traces",
		},
		{
			// A path supplied in the URL is the operator's routing choice
			// (collector behind a reverse proxy) and must stay verbatim.
			name:     "explicit endpoint path is used verbatim",
			endpoint: "/collector/traces",
			wantPath: "/collector/traces",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var hits int
			recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == tc.wantPath {
					mu.Lock()
					hits++
					mu.Unlock()
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer recv.Close()

			// Sandboxed environments may deny loopback connects outright even to
			// an in-process listener; the gate + handler tests above remain the
			// authoritative coverage, so skip rather than fail there.
			if c, err := net.Dial("tcp", recv.Listener.Addr().String()); err != nil {
				t.Skipf("loopback connect denied by environment: %v", err)
			} else {
				_ = c.Close()
			}

			// Clear env so only the explicit endpoint drives configuration.
			t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
			t.Setenv("OTEL_SDK_DISABLED", "")

			shutdown, err := SetupTracing(context.Background(),
				"http://"+recv.Listener.Addr().String()+tc.endpoint, slog.Default())
			if err != nil {
				t.Fatalf("SetupTracing: %v", err)
			}
			tracer := otel.GetTracerProvider().Tracer("smoke")
			_, span := tracer.Start(context.Background(), "smoke")
			span.End()

			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := shutdown(sctx); err != nil {
				t.Fatalf("shutdown flush: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if hits == 0 {
				t.Fatalf("fake OTLP endpoint received no POST to %s", tc.wantPath)
			}
		})
	}
}

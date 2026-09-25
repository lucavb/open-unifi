package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/telemetry"
	"github.com/lucavb/open-unifi/internal/wireless"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func spanNames(spans tracetest.SpanStubs) []string {
	out := make([]string, len(spans))
	for i, s := range spans {
		out[i] = s.Name
	}
	return out
}

func containsSpan(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func attrString(sp tracetest.SpanStub, key string) (string, bool) {
	for _, a := range sp.Attributes {
		if string(a.Key) == key {
			return a.Value.AsString(), true
		}
	}
	return "", false
}

func TestInformTraceSpanHierarchyPlaintext(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	st := store.NewMemStore()
	if err := st.Put(store.Device{
		MAC: testMAC, State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
		XAuthkey: inform.DefaultKeyHex, Authkeys: []string{inform.DefaultKeyHex},
		Model: "U7PG2", Extra: store.JSONMap{"wlan_cfg_sha": wireless.WlanListHash(nil)},
	}); err != nil {
		t.Fatal(err)
	}
	s := New(Config{AllowPlainText: true}, st, testLogger())

	ctx, parent := tp.Tracer("test").Start(context.Background(), "POST /inform")
	defer parent.End()

	body := mustJSON(t, map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "model": "U7PG2", "_type": "status"})
	req := httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleInform(rec, req)

	names := spanNames(exp.GetSpans())
	for _, want := range []string{"inform.handle", "inform.adoption.decide"} {
		if !containsSpan(names, want) {
			t.Fatalf("missing span %q; got %v", want, names)
		}
	}
	for _, sp := range exp.GetSpans() {
		if sp.Name != "inform.adoption.decide" {
			continue
		}
		mac, ok := attrString(sp, telemetry.AttrDeviceMAC)
		if !ok || mac != "aa:bb:cc:dd:ee:ff" {
			t.Fatalf("decide span device mac = %q ok=%v", mac, ok)
		}
		outcome, ok := attrString(sp, telemetry.AttrAdoptionOutcome)
		if !ok || outcome == "" {
			t.Fatalf("decide span missing adoption outcome")
		}
		return
	}
	t.Fatal("inform.adoption.decide span not found")
}

func TestInformTraceDecodeSpanEncrypted(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		_ = tp.Shutdown(context.Background())
	})

	st := store.NewMemStore()
	xk := strings.Repeat("a", 32)
	if err := st.Put(store.Device{
		MAC: testMAC, State: store.StateAdopted,
		CfgVersion: "aaaa", AppliedCfg: "aaaa",
		XAuthkey: xk, Authkeys: []string{xk},
		Model: "U7PG2", Extra: store.JSONMap{"wlan_cfg_sha": wireless.WlanListHash(nil)},
	}); err != nil {
		t.Fatal(err)
	}
	s := New(Config{}, st, testLogger())

	ctx, parent := tp.Tracer("test").Start(context.Background(), "POST /inform")
	defer parent.End()

	body := infoBody("aaaa")
	pkt := encryptCBC(t, mustJSON(t, body), hexKey(t, xk), testIV)
	req := httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(pkt)).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleInform(rec, req)

	if !containsSpan(spanNames(exp.GetSpans()), "inform.decode") {
		t.Fatalf("missing inform.decode; got %v", spanNames(exp.GetSpans()))
	}
	for _, sp := range exp.GetSpans() {
		if sp.Name != "inform.decode" {
			continue
		}
		enc, ok := attrString(sp, telemetry.AttrInformEncryption)
		if !ok || enc != "cbc" {
			t.Fatalf("decode span encryption = %q ok=%v", enc, ok)
		}
		return
	}
	t.Fatal("inform.decode span not found")
}

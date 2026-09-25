package telemetry

import (
	"context"

	"github.com/lucavb/open-unifi/internal/store"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const serverTracerName = "github.com/lucavb/open-unifi/internal/server"

// AttrDeviceMAC is the canonical device MAC attribute for inform traces.
const AttrDeviceMAC = "openunifi.device.mac"

// AttrInformEncryption classifies the inform wire encoding (gcm, cbc, plain).
const AttrInformEncryption = "openunifi.inform.encryption"

// AttrAdoptionOutcome is the adoption engine outcome kind (noop, setparam, …).
const AttrAdoptionOutcome = "openunifi.adoption.outcome"

// AttrAdoptionFullProvision marks a full-provisioning setparam response.
const AttrAdoptionFullProvision = "openunifi.adoption.full_provision"

// ServerTracer returns the tracer used for inform/adoption manual spans.
func ServerTracer() trace.Tracer {
	return otel.GetTracerProvider().Tracer(serverTracerName)
}

// StartServerSpan starts a child span under ctx using the server tracer scope.
func StartServerSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return ServerTracer().Start(ctx, name, opts...)
}

// SetDeviceMAC sets the colon-form MAC on a span.
func SetDeviceMAC(span trace.Span, mac string) {
	if span == nil || mac == "" {
		return
	}
	span.SetAttributes(attribute.String(AttrDeviceMAC, store.ColonMAC(mac)))
}

// RecordSpanErr records err on the span and marks it failed.
func RecordSpanErr(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// SetInformEncryption sets the wire encoding class on a span.
func SetInformEncryption(span trace.Span, enc string) {
	if span == nil || enc == "" {
		return
	}
	span.SetAttributes(attribute.String(AttrInformEncryption, enc))
}

// SetAdoptionOutcome records the adoption engine response kind on a span.
func SetAdoptionOutcome(span trace.Span, kind string, fullProvision bool) {
	if span == nil {
		return
	}
	span.SetAttributes(
		attribute.String(AttrAdoptionOutcome, kind),
		attribute.Bool(AttrAdoptionFullProvision, fullProvision),
	)
}

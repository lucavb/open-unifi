package server

import (
	"context"

	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/server/adoption"
	"github.com/lucavb/open-unifi/internal/telemetry"
)

func informEncryptionLabel(pkt *inform.Packet) string {
	if pkt == nil {
		return "plain"
	}
	if pkt.Flags&inform.FlagGCM != 0 {
		return "gcm"
	}
	if pkt.Flags&inform.FlagEncCBC != 0 {
		return "cbc"
	}
	return "plain"
}

func (s *Server) decodeInformPacket(ctx context.Context, pkt *inform.Packet, candidates []string) (*inform.Decoded, error) {
	_, span := telemetry.StartServerSpan(ctx, "inform.decode")
	defer span.End()
	telemetry.SetInformEncryption(span, informEncryptionLabel(pkt))
	jd, err := inform.Decode(pkt, candidates)
	if err != nil {
		telemetry.RecordSpanErr(span, err)
	}
	return jd, err
}

func (s *Server) decideInform(ctx context.Context, mac string, req adoption.Request) (adoption.Outcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, span := telemetry.StartServerSpan(ctx, "inform.adoption.decide")
	defer span.End()
	req.Context = ctx
	telemetry.SetDeviceMAC(span, mac)
	out, err := s.engine.Decide(req)
	if err != nil {
		telemetry.RecordSpanErr(span, err)
		return out, err
	}
	telemetry.SetAdoptionOutcome(span, string(out.Kind), out.FullProvision)
	return out, nil
}

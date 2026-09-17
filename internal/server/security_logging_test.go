package server

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/lucabecker/open-unifi/internal/inform"
	"github.com/lucabecker/open-unifi/internal/store"
)

func TestDebugReplyLogsDoNotContainAdoptionOrDecryptionKeys(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	st := store.NewMemStore()
	s := New(Config{}, st, logger)
	registerPending(t, st)

	resp := post(t, s.InformHandler(), encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, inform.DefaultKeyHex), testIV))
	if resp.Code != 200 {
		t.Fatalf("adoption inform status = %d", resp.Code)
	}
	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if rec.XAuthkey == "" {
		t.Fatal("adoption did not create an x_authkey")
	}
	if strings.Contains(logs.String(), inform.DefaultKeyHex) {
		t.Fatalf("debug logs contain factory decryption key: %q", logs.String())
	}
	if strings.Contains(logs.String(), rec.XAuthkey) {
		t.Fatalf("debug logs contain generated adoption key: %q", logs.String())
	}
}

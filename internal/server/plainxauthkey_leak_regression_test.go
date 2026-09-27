package server

// Regression tests for audit run-1 finding C3
// (decidePlain:plaintext-xauthkey-disclosure, ref f839fae), ported from the
// validation fixture plainxauthkey_leak_test.go with the assertions FLIPPED
// to the secure behavior: over the opt-in plaintext lane, a WRONG or OMITTED
// _authkey claim gets the mgmt_cfg re-send WITHOUT any key material — the
// authkey= line is never emitted, and the assigned key can no longer be
// learned from the unencrypted reply. The matching-claim arm keeps the
// healthy full-provisioning shape (config rows — here the ap_base rows —
// come back exactly like before).

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

func TestPlainClaimAuthkeySuppressed(t *testing.T) {
	const xk = "11112222333344445555666677778888"
	st := store.NewMemStore()
	h := New(Config{AllowPlainText: true}, st, testLogger()).InformHandler()
	if err := st.Put(store.Device{
		MAC:        "00156d010001",
		State:      store.StateAdopted,
		CfgVersion: "aaaa",
		AppliedCfg: "aaaa",
		XAuthkey:   xk,
		Authkeys:   []string{xk},
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("wrong _authkey claim carries no key material", func(t *testing.T) {
		body := mustJSON(t, map[string]any{"mac": "00:15:6d:01:00:01", "_authkey": "wrong-claim"})
		resp := post(t, h, body)
		if resp.Code != http.StatusOK {
			t.Fatalf("wrong-claim inform: %d %s", resp.Code, resp.Body.String())
		}
		var jm map[string]any
		if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
			t.Fatalf("plain reply JSON: %v", err)
		}
		mgmt, _ := jm["mgmt_cfg"].(string)
		if mgmt == "" {
			t.Fatalf("wrong-claim reply lost the mgmt_cfg rows: %v", jm)
		}
		if strings.Contains(mgmt, "authkey=") {
			t.Fatalf("wrong-claim reply leaked key material: %q", mgmt)
		}
		if !strings.Contains(mgmt, "cfgversion=aaaa\n") {
			t.Fatalf("wrong-claim reply must keep the config rows: %q", mgmt)
		}
	})

	t.Run("omitted _authkey claim carries no key material", func(t *testing.T) {
		body := mustJSON(t, map[string]any{"mac": "00:15:6d:01:00:01"})
		resp := post(t, h, body)
		if resp.Code != http.StatusOK {
			t.Fatalf("omitted-claim inform: %d %s", resp.Code, resp.Body.String())
		}
		var jm map[string]any
		if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
			t.Fatalf("plain reply JSON: %v", err)
		}
		mgmt, _ := jm["mgmt_cfg"].(string) // defaulted to the factory key by the adapter
		if strings.Contains(mgmt, "authkey=") {
			t.Fatalf("omitted-claim reply leaked key material: %q", mgmt)
		}
		if !strings.Contains(mgmt, "cfgversion=aaaa\n") {
			t.Fatalf("omitted-claim reply must keep the config rows: %q", mgmt)
		}
	})

	t.Run("matching _authkey claim full-provisions without an authkey line", func(t *testing.T) {
		body := mustJSON(t, map[string]any{"mac": "00:15:6d:01:00:01", "_authkey": xk})
		resp := post(t, h, body)
		if resp.Code != http.StatusOK {
			t.Fatalf("matching-claim inform: %d %s", resp.Code, resp.Body.String())
		}
		var jm map[string]any
		if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
			t.Fatalf("plain reply JSON: %v", err)
		}
		sys, ok := jm["system_cfg"].(string)
		if !ok {
			t.Fatalf("matching-claim reply missing system_cfg: %v", jm)
		}
		// No WLAN envelope is configured for this fixture, so the plan's
		// "configured WLAN/RADIUS rows" degenerate to the unconditional
		// base rows (the aaa.*/radius.* rows are radio-conditional and are
		// absent for a radio-less record).
		for _, want := range []string{"netconf.status=enabled\n", "syslog.status=enabled\n"} {
			if !strings.Contains(sys, want) {
				t.Fatalf("full provisioning system_cfg missing %q:\n%s", want, sys)
			}
		}
		if mgmt, _ := jm["mgmt_cfg"].(string); strings.Contains(mgmt, "authkey=") {
			t.Fatalf("matching-claim mgmt_cfg leaked an authkey line: %q", mgmt)
		}
	})
}

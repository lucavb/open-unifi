package server

// blocked_sta trust-policy tests at the adapter boundary: the inform path
// (absorbInform) can neither WRITE nor INTRODUCE the admin-owned
// blocked-client set or the engine's delivery baseline — the plaintext lane
// exercises exactly the absorb code the encrypted lane runs — and the
// assigned-key plaintext lane delivers the set end-to-end in the setparam
// response with the §4 wire shape (docs/PROTOCOL-mgmt.md §4/§6.2(d)).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

func wireHash(wire string) string {
	sum := sha256.Sum256([]byte(wire))
	return hex.EncodeToString(sum[:])
}

func blockedSet(t *testing.T, st store.DeviceStore, mac string) ([]string, store.JSONMap) {
	t.Helper()
	rec, err := st.Get(mac)
	if err != nil {
		t.Fatal(err)
	}
	return store.BlockedClients(rec), rec.Extra
}

// TestInformCannotClobberBlockedSet: a device-supplied body carrying
// blocked_sta / blocked_sta_sha must not overwrite the admin-owned set or
// the engine's delivery baseline.
func TestInformCannotClobberBlockedSet(t *testing.T) {
	h, st := newServerWith(Config{AllowPlainText: true})
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, "aaaa", xkey)
	if err := st.Update(testMAC, func(d *store.Device) error {
		if _, err := store.AddBlockedClient(d, "11:22:33:44:55:66"); err != nil {
			return err
		}
		// Baseline exactly as a prior engine emission stamps it.
		d.Extra["blocked_sta_sha"] = wireHash("11:22:33:44:55:66")
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A hostile/echoing body claims a different set AND a matching-forged
	// baseline (a device that echoed both would suppress or hijack
	// delivery if absorb honored either).
	body := infoBody("aaaa")
	body["_authkey"] = xkey
	body["blocked_sta"] = []any{"ff:ff:ff:ff:ff:ff"}
	body["blocked_sta_sha"] = wireHash("ff:ff:ff:ff:ff:ff")
	resp := post(t, h, mustJSON(t, body))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform status = %d %q", resp.Code, resp.Body.String())
	}

	set, extra := blockedSet(t, st, testMAC)
	if len(set) != 1 || set[0] != "112233445566" {
		t.Fatalf("admin-owned set was clobbered: %v", set)
	}
	if got, _ := extra["blocked_sta_sha"].(string); got != wireHash("11:22:33:44:55:66") {
		t.Fatalf("delivery baseline was clobbered: %v", extra["blocked_sta_sha"])
	}
}

// TestInformCannotIntroduceBlockedKeys: a body carrying blocked_sta /
// blocked_sta_sha for a record that never had either must leave NEITHER
// behind — a forged baseline would suppress the first real delivery.
func TestInformCannotIntroduceBlockedKeys(t *testing.T) {
	h, st := newServerWith(Config{AllowPlainText: true})
	registerPending(t, st)

	body := infoBody("")
	body["blocked_sta"] = []any{"ff:ff:ff:ff:ff:ff"}
	body["blocked_sta_sha"] = "deadbeef"
	resp := post(t, h, mustJSON(t, body))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform status = %d %q", resp.Code, resp.Body.String())
	}
	var jm map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
		t.Fatal(err)
	}
	if jm["_type"] != "noop" {
		t.Fatalf("unassigned plaintext inform = %v, want noop", jm["_type"])
	}

	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rec.Extra["blocked_sta"]; ok {
		t.Fatalf("device body introduced blocked_sta: %v", rec.Extra["blocked_sta"])
	}
	if _, ok := rec.Extra["blocked_sta_sha"]; ok {
		t.Fatalf("device body introduced blocked_sta_sha: %v", rec.Extra["blocked_sta_sha"])
	}
	if set := store.BlockedClients(rec); len(set) != 0 {
		t.Fatalf("introduced set = %v", set)
	}
	if rec.State != store.StatePending {
		t.Fatalf("state = %d, want still pending", rec.State)
	}
}

// TestPlainInformDeliversBlockedSet: end-to-end through the adapter — an
// admin-blocked set rides the assigned-key full provisioning out in the
// setparam response with the exact §4 wire string, and the emission-stamped
// baseline persists in the record.
func TestPlainInformDeliversBlockedSet(t *testing.T) {
	h, st := newServerWith(Config{AllowPlainText: true})
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, "aaaa", xkey)
	if err := st.Update(testMAC, func(d *store.Device) error {
		if _, err := store.AddBlockedClient(d, "AA:BB:CC:DD:EE:FF"); err != nil {
			return err
		}
		_, err := store.AddBlockedClient(d, "00:11:22:33:44:55")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	body := infoBody("aaaa")
	body["_authkey"] = xkey
	resp := post(t, h, mustJSON(t, body))
	if resp.Code != http.StatusOK {
		t.Fatalf("inform status = %d %q", resp.Code, resp.Body.String())
	}
	var jm map[string]any
	if err := json.Unmarshal(resp.Body.Bytes(), &jm); err != nil {
		t.Fatal(err)
	}
	if jm["_type"] != "setparam" {
		t.Fatalf("reply type = %v, want setparam (full provisioning)", jm["_type"])
	}
	const wantWire = "00:11:22:33:44:55\naa:bb:cc:dd:ee:ff"
	if jm["blocked_sta"] != wantWire {
		t.Fatalf("reply blocked_sta = %q, want the exact §4 wire string %q", jm["blocked_sta"], wantWire)
	}
	if jm["cfgversion"] != "aaaa" || jm["system_cfg"] == nil || jm["mgmt_cfg"] == nil {
		t.Fatalf("reply missing full-provisioning fields: %v", jm)
	}

	rec, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := rec.Extra["blocked_sta_sha"].(string); got != wireHash(wantWire) {
		t.Fatalf("record baseline = %v, want hash of the delivered wire", rec.Extra["blocked_sta_sha"])
	}
	if set := store.BlockedClients(rec); len(set) != 2 {
		t.Fatalf("record set after delivery = %v", set)
	}
}

// TestInformBlockedSetSurvivesSparseHeartbeats: the blocked set is an
// admin-owned row — repeated informs with bodies omitting the key (the
// normal case: a device has no idea it exists) must never lose it, unlike
// device-refreshable caps which only survive fill-if-absent.
func TestInformBlockedSetSurvivesSparseHeartbeats(t *testing.T) {
	h, st := newServerWith(Config{AllowPlainText: true})
	const xkey = "11112222333344445555666677778888"
	registerAdopted(t, st, "aaaa", xkey)
	if err := st.Update(testMAC, func(d *store.Device) error {
		_, err := store.AddBlockedClient(d, "11:22:33:44:55:66")
		return err
	}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		body := infoBody("aaaa")
		body["_authkey"] = xkey
		body["uptime"] = 1000 + i // distinct body, still no blocked keys
		resp := post(t, h, mustJSON(t, body))
		if resp.Code != http.StatusOK {
			t.Fatalf("inform #%d status = %d %q", i+1, resp.Code, resp.Body.String())
		}
	}
	set, _ := blockedSet(t, st, testMAC)
	if len(set) != 1 || set[0] != "112233445566" {
		t.Fatalf("blocked set lost across informs: %v", set)
	}
}

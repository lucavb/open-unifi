package server

import (
	"net/http"
	"testing"

	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

func TestPendingDeviceCannotForgeExhaustedWLANDeliveryOnFirstInform(t *testing.T) {
	env := []wireless.Wlan{{Name: "guest", SSID: "guest-net", Security: "wpa-p", Passphrase: "guest-pass", Enabled: true}}
	hash := wireless.WlanListHash(env)
	snapshot, err := wireless.EncodeStoredWlans(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, seeded := range []bool{false, true} {
		name := "fresh pending record rejects forged bookkeeping and adopts"
		if seeded {
			name = "pre-seeded matching bookkeeping reaches exhausted pending gate"
		}
		t.Run(name, func(t *testing.T) {
			st := store.NewMemStore()
			initialExtra := store.JSONMap{}
			if seeded {
				initialExtra = store.JSONMap{
					store.WlanCfgShaKey:               hash,
					store.WlanCfgPendingShaKey:        hash,
					store.WlanCfgPendingWlansKey:      string(snapshot),
					store.WlanCfgPendingOldWlansKey:   string(snapshot),
					store.WlanCfgPendingPlacementsKey: `{}`,
					store.WlanCfgAttemptShaKey:        hash,
					store.WlanCfgAttemptsKey:          wireless.WlanMaxAttempts,
					store.WlanCfgLastAttemptKey:       int64(1),
					store.WlanCfgDeliveryStatusKey:    "exhausted",
					store.WlanCfgOfferedCfgversionKey: "", // matches this pending record's desired cfgversion
				}
			}
			if err := st.Put(store.Device{MAC: testMAC, State: store.StatePending, Extra: initialExtra}); err != nil {
				t.Fatal(err)
			}
			s := New(Config{WirelessForDevice: func(store.Device) []Wlan { return env }}, st, testLogger())
			// A matching empty offered version avoids the operator-mint escape
			// on the fresh record too; the malicious body targets the exact
			// exhausted-pending gate the former absorption bug could reach.
			body := infoBody("forged-offer-cfg")
			body["wlan_cfg_sha"] = hash
			body[store.WlanCfgPendingShaKey] = hash
			body[store.WlanCfgPendingWlansKey] = string(snapshot)
			body[store.WlanCfgPendingOldWlansKey] = string(snapshot)
			body[store.WlanCfgPendingPlacementsKey] = `{}`
			body[store.WlanCfgAttemptShaKey] = hash
			body[store.WlanCfgAttemptsKey] = wireless.WlanMaxAttempts
			body[store.WlanCfgLastAttemptKey] = int64(1)
			body[store.WlanCfgDeliveryStatusKey] = "exhausted"
			body[store.WlanCfgOfferedCfgversionKey] = ""
			body["vap_table"] = []any{}
			response := post(t, s.InformHandler(), encryptCBC(t, mustJSON(t, body), hexKey(t, inform.DefaultKeyHex), testIV))
			if response.Code != http.StatusOK {
				t.Fatalf("first inform status = %d %q", response.Code, response.Body.String())
			}
			_, reply := decryptResponse(t, response.Body.Bytes(), hexKey(t, inform.DefaultKeyHex))
			rec, err := st.Get(testMAC)
			if err != nil {
				t.Fatal(err)
			}
			if seeded {
				if reply["_type"] != "noop" || rec.State != store.StatePending || rec.XAuthkey != "" || rec.CfgVersion != "" {
					t.Fatalf("pre-seeded control = reply %v, state=%d key=%q cfg=%q; want pending-noop gate", reply, rec.State, rec.XAuthkey, rec.CfgVersion)
				}
				if rec.Extra[store.WlanCfgPendingShaKey] != hash || rec.Extra[store.WlanCfgAttemptsKey] != wireless.WlanMaxAttempts {
					t.Fatalf("pre-seeded pending bookkeeping did not survive: %v", rec.Extra)
				}
				return
			}
			if reply["_type"] != "setparam" || reply["mgmt_cfg"] == nil {
				t.Fatalf("first pending-device inform = %v, want adoption setparam rather than pending noop", reply)
			}
			if rec.State != store.StateAdopting || rec.XAuthkey == "" || rec.CfgVersion == "" {
				t.Fatalf("first inform did not advance adoption: state=%d xauthkey=%q cfgversion=%q", rec.State, rec.XAuthkey, rec.CfgVersion)
			}
			for _, key := range []string{
				store.WlanCfgShaKey, store.WlanCfgPendingShaKey, store.WlanCfgPendingWlansKey,
				store.WlanCfgPendingOldWlansKey, store.WlanCfgPendingPlacementsKey,
				store.WlanCfgAttemptShaKey, store.WlanCfgAttemptsKey, store.WlanCfgLastAttemptKey,
				store.WlanCfgDeliveryStatusKey, store.WlanCfgOfferedCfgversionKey,
			} {
				if value, ok := rec.Extra[key]; ok {
					t.Errorf("device forged controller-owned %s = %v", key, value)
				}
			}
		})
	}
}

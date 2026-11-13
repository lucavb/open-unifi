package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/inform"
	"github.com/lucavb/open-unifi/internal/server/adoption"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

func patchSiteRef(t *testing.T, adminH http.Handler, site string) (status int, body []byte) {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{"site_id": site})
	if err != nil {
		t.Fatal(err)
	}
	rec := postAdminBody(t, adminH, http.MethodPatch,
		"/api/v1/devices/"+store.ColonMAC(testMAC), string(encoded))
	return rec.Code, rec.Body.Bytes()
}

func TestFreshWhitelistSiteRefUsesOrdinaryAdoptionPush(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	body := `{"mac":"aa:bb:cc:dd:ee:ff","site_id":"whitelist-site"}`
	rec := postAdminBody(t, adminH, http.MethodPost, "/api/v1/devices", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("manual whitelist create: %d %s", rec.Code, rec.Body.String())
	}
	d, err := st.Get(testMAC)
	if err != nil {
		t.Fatal(err)
	}
	if d.State != store.StatePending || d.CfgVersion != "" || d.SiteID != "whitelist-site" {
		t.Fatalf("fresh whitelist state = %+v, want pending site with no admin-time cfgversion", d)
	}

	resp := post(t, informH, encryptCBC(t, mustJSON(t, infoBody("")), hexKey(t, inform.DefaultKeyHex), testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("factory first inform: %d", resp.Code)
	}
	_, reply := decryptResponse(t, resp.Body.Bytes(), hexKey(t, inform.DefaultKeyHex))
	if reply["_type"] != "setparam" {
		t.Fatalf("first inform = %#v, want ordinary adoption push", reply)
	}
	mgmtCfg, _ := reply["mgmt_cfg"].(string)
	if !strings.Contains(mgmtCfg, "/manage/site/whitelist-site\n") {
		t.Fatalf("adoption mgmt_cfg did not use the fresh whitelist SiteRef:\n%s", mgmtCfg)
	}
}

func TestSiteRefPatchDeliversMgmtAndSystemCfgE2E(t *testing.T) {
	adminH, informH, st := lifecycleFixture(t)
	const cfg = "aaaabbbbccccdddd"
	const xkey = "11112222333344445555666677778888"
	dev := u7pg2Record()
	dev.SiteID = "default"
	dev.CfgVersion, dev.AppliedCfg = cfg, cfg
	dev.XAuthkey, dev.Authkeys = xkey, []string{xkey}
	if err := st.Put(dev); err != nil {
		t.Fatal(err)
	}
	kx := hexKey(t, xkey)

	status, raw := patchSiteRef(t, adminH, "building-a")
	if status != http.StatusOK {
		t.Fatalf("site patch: %d %s", status, raw)
	}
	var saved struct {
		SiteID     string `json:"site_id"`
		CfgVersion string `json:"cfg_version"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.SiteID != "building-a" || saved.CfgVersion == cfg || len(saved.CfgVersion) != 16 {
		t.Fatalf("site patch view = %+v; want new site and minted cfgversion", saved)
	}

	resp := post(t, informH, encryptCBC(t, mustJSON(t, radioBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("site-change inform: %d %s", resp.Code, resp.Body.String())
	}
	_, reply := decryptResponse(t, resp.Body.Bytes(), kx)
	if reply["_type"] != "setparam" || reply["cfgversion"] != saved.CfgVersion {
		t.Fatalf("site-change inform response = %#v, want full setparam with minted version", reply)
	}
	systemCfg, _ := reply["system_cfg"].(string)
	mgmtCfg, _ := reply["mgmt_cfg"].(string)
	if !strings.Contains(systemCfg, "unifi.siteid=building-a\n") {
		t.Fatalf("system_cfg did not retain rendered site behavior:\n%s", systemCfg)
	}
	if !strings.Contains(mgmtCfg, "/manage/site/building-a\n") {
		t.Fatalf("mgmt_cfg did not carry the changed site reference:\n%s", mgmtCfg)
	}
}

func TestSiteRefPatchEscapesExhaustedWLANDeliveryE2E(t *testing.T) {
	e1 := []Wlan{{Name: "old", SSID: "oldnet", Security: "open", Enabled: true}}
	e2 := []Wlan{{Name: "pending", SSID: "pendingnet", Security: "open", Enabled: true}}
	adminH, informH, st := lifecycleFixtureWLANS(t, e2)
	const cfg = "aaaabbbbccccdddd"
	const xkey = "11112222333344445555666677778888"
	dev := u7pg2Record()
	dev.SiteID = "default"
	dev.XAuthkey, dev.Authkeys = xkey, []string{xkey}
	dev.CfgVersion, dev.AppliedCfg = cfg, cfg
	if err := st.Put(dev); err != nil {
		t.Fatal(err)
	}
	kx := hexKey(t, xkey)

	oldSnapshot, err := json.Marshal(e1)
	if err != nil {
		t.Fatal(err)
	}
	pendingSnapshot, err := json.Marshal(e2)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateExisting(testMAC, func(d *store.Device) error {
		d.Extra[store.WlanCfgShaKey] = wireless.WlanListHash(e1)
		d.Extra[store.WlanCfgAppliedWlansKey] = string(oldSnapshot)
		d.Extra[store.WlanCfgPendingShaKey] = wireless.WlanListHash(e2)
		d.Extra[store.WlanCfgPendingWlansKey] = string(pendingSnapshot)
		d.Extra[store.WlanCfgPendingOldWlansKey] = string(oldSnapshot)
		d.Extra[store.WlanCfgAttemptShaKey] = wireless.WlanListHash(e2)
		d.Extra[store.WlanCfgAttemptsKey] = adoption.WlanMaxAttempts
		d.Extra[store.WlanCfgLastAttemptKey] = time.Now().Unix()
		d.Extra[store.WlanCfgOfferedCfgversionKey] = cfg
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Before the site save, the unchanged exhausted WLAN operation holds the
	// next inform at the pending-delivery gate.
	resp := post(t, informH, encryptCBC(t, mustJSON(t, radioBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("pre-save inform: %d", resp.Code)
	}
	_, reply := decryptResponse(t, resp.Body.Bytes(), kx)
	if reply["_type"] != "noop" || reply["system_cfg"] != nil {
		t.Fatalf("pre-save exhausted delivery = %#v, want pending noop", reply)
	}

	status, raw := patchSiteRef(t, adminH, "building-b")
	if status != http.StatusOK {
		t.Fatalf("site patch: %d %s", status, raw)
	}
	var saved struct {
		SiteID     string `json:"site_id"`
		CfgVersion string `json:"cfg_version"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.SiteID != "building-b" || saved.CfgVersion == cfg || len(saved.CfgVersion) != 16 {
		t.Fatalf("site patch view = %+v; want effective operator mint", saved)
	}

	// The new SiteRef mint is the existing operator-mint escape: it must
	// deliver the site rows and the still-pending WLAN envelope together.
	resp = post(t, informH, encryptCBC(t, mustJSON(t, radioBody(cfg)), kx, testIV))
	if resp.Code != http.StatusOK {
		t.Fatalf("post-save inform: %d", resp.Code)
	}
	_, reply = decryptResponse(t, resp.Body.Bytes(), kx)
	if reply["_type"] != "setparam" || reply["cfgversion"] != saved.CfgVersion {
		t.Fatalf("post-save exhausted delivery = %#v, want full setparam with site mint", reply)
	}
	systemCfg, _ := reply["system_cfg"].(string)
	mgmtCfg, _ := reply["mgmt_cfg"].(string)
	for _, want := range []string{"unifi.siteid=building-b\n", "aaa.1.ssid=pendingnet\n"} {
		if !strings.Contains(systemCfg, want) {
			t.Fatalf("full provisioning missing %q:\n%s", want, systemCfg)
		}
	}
	if !strings.Contains(mgmtCfg, "/manage/site/building-b\n") {
		t.Fatalf("mgmt_cfg missing changed SiteRef:\n%s", mgmtCfg)
	}
}

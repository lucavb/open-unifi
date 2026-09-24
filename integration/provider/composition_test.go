package provider_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/app"
	"github.com/lucavb/open-unifi/internal/store"
	tfprovider "github.com/lucavb/terraform-provider-open-unifi/provider"
)

// Contract tests: real adminapi handler through the provider decode layer.

func composeAPI(t *testing.T) (*tfprovider.ContractClient, store.DeviceStore, map[string]int) {
	t.Helper()
	st := store.NewMemStore()
	ap := app.New(st, nil)
	handler := adminapi.New(adminapi.Config{}, ap)

	status := map[string]int{}
	tripper := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		status[req.Method+" "+req.URL.Path] = rec.Code
		return rec.Result(), nil
	})
	c := tfprovider.NewContractClient("http://composition", "", tripper)
	return c, st, status
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProviderDecodesRealServerDevices(t *testing.T) {
	c, st, status := composeAPI(t)
	ctx := context.Background()

	if err := c.CheckConnectivity(ctx); err != nil {
		t.Fatalf("whoami probe against real server failed: %v", err)
	}
	if got := status["GET /api/v1/whoami"]; got != http.StatusOK {
		t.Fatalf("whoami status = %d, want 200", got)
	}

	mac := "78:8a:20:11:22:33"
	body := map[string]string{"mac": mac, "name": "ap-lobby", "site_id": "default"}
	if err := c.Do(ctx, http.MethodPost, "/api/v1/devices", body, nil); err != nil {
		t.Fatalf("real POST /api/v1/devices: %v", err)
	}
	if got := status["POST /api/v1/devices"]; got != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201", got)
	}

	if err := c.Do(ctx, http.MethodPost, "/api/v1/devices", body, nil); err != nil {
		t.Fatalf("duplicate create must be an idempotent upsert, got: %v", err)
	}

	dev, err := c.GetDevice(ctx, mac)
	if err != nil {
		t.Fatalf("real GET /api/v1/devices/{mac}: %v", err)
	}
	if dev.State != store.StatePending || tfprovider.ContractStateName(dev.State) != "pending" {
		t.Fatalf("pending decode: state=%d stateName=%q, want 1/pending", dev.State, tfprovider.ContractStateName(dev.State))
	}
	if dev.LastSeen != 0 || dev.IP != "" {
		t.Fatalf("fresh device wire truth: last_seen=%d ip=%q, want 0/\"\"", dev.LastSeen, dev.IP)
	}

	m := &tfprovider.ContractDeviceModel{
		Mac:      types.StringValue(mac),
		Name:     types.StringValue("ap-lobby"),
		SiteID:   types.StringValue("default"),
		State:    types.StringNull(),
		IP:       types.StringNull(),
		Firmware: types.StringNull(),
		LastSeen: types.StringNull(),
	}
	tfprovider.ContractApplyDevice(m, dev, "default")
	if m.State.ValueString() != "pending" || m.LastSeen.ValueString() != "" || m.IP.ValueString() != "" {
		t.Fatalf("applyDevice fresh: state=%q last_seen=%q ip=%q",
			m.State.ValueString(), m.LastSeen.ValueString(), m.IP.ValueString())
	}
	if m.SiteID.ValueString() != "default" {
		t.Fatalf("site_id must stay configured, got %q", m.SiteID.ValueString())
	}

	if err := st.Put(store.Device{
		MAC:      "788a20001122",
		Name:     "ap-attic",
		Model:    "UAP-AC-Pro-Gen2",
		Firmware: "6.6.55",
		IP:       "192.0.2.9",
		State:    store.StateAdopted,
		LastSeen: 1726432000,
	}); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	dev2, err := c.GetDevice(ctx, "78:8a:20:00:11:22")
	if err != nil {
		t.Fatalf("GET seeded device: %v", err)
	}
	if dev2.State != store.StateAdopted || dev2.LastSeen != 1726432000 {
		t.Fatalf("seeded decode: state=%d last_seen=%d, want 3/1726432000", dev2.State, dev2.LastSeen)
	}
	if got := tfprovider.ContractStateName(dev2.State); got != "adopted" {
		t.Fatalf("stateName(adopted) = %q", got)
	}

	devs, err := c.ListDevices(ctx)
	if err != nil {
		t.Fatalf("real GET /api/v1/devices: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("listDevices decoded %d devices, want 2: %+v", len(devs), devs)
	}
	seen := map[string]int{}
	for _, d := range devs {
		seen[tfprovider.ContractStateName(d.State)]++
	}
	if seen["pending"] != 1 || seen["adopted"] != 1 {
		t.Fatalf("envelope state vocabulary mismatch: %v", seen)
	}
}

func TestProviderDecodesRealServerWireless(t *testing.T) {
	c, _, status := composeAPI(t)
	ctx := context.Background()
	mac := "78:8a:20:11:22:33"
	if err := c.Do(ctx, http.MethodPost, "/api/v1/devices", map[string]string{"mac": mac, "name": "ap-wlan"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, e := range []tfprovider.ContractWirelessEntry{
		{Name: "home", SSID: "home", Security: "wpa-p", Passphrase: "sup3rsecret", VLAN: 42, Enabled: true},
		{Name: "guest", SSID: "guest", Security: "open", VLAN: 1, Enabled: true},
	} {
		if err := c.CreateWireless(ctx, mac, &e); err != nil {
			t.Fatal(err)
		}
	}
	home, err := c.GetWireless(ctx, mac, "home")
	if err != nil || home.VLAN != 42 {
		t.Fatalf("home read: %+v %v", home, err)
	}
	home.VLAN = 100
	if err := c.UpdateWireless(ctx, mac, "home", home); err != nil {
		t.Fatal(err)
	}
	guest, err := c.GetWireless(ctx, mac, "guest")
	if err != nil || guest.Name != "guest" {
		t.Fatalf("guest lost: %+v %v", guest, err)
	}
	if status["POST /api/v1/devices/"+mac+"/wireless"] != http.StatusCreated {
		t.Fatalf("POST status %d", status["POST /api/v1/devices/"+mac+"/wireless"])
	}
}

func TestRealServer404AndIDRoundTrip(t *testing.T) {
	c, _, status := composeAPI(t)
	ctx := context.Background()

	_, err := c.GetDevice(ctx, "aa:bb:cc:dd:ee:ff")
	if err == nil || !tfprovider.ContractErrNotFound(err) {
		t.Fatalf("typed 404 expected, got %T: %v", err, err)
	}
	st, notFound, ok := tfprovider.ContractAPIError(err)
	if !ok || st != http.StatusNotFound || !notFound {
		t.Fatalf("apiError misclassified: %v", err)
	}
	if got := status["GET /api/v1/devices/aa:bb:cc:dd:ee:ff"]; got != http.StatusNotFound {
		t.Fatalf("wire status = %d, want 404", got)
	}
	if want := "not found: device not found: aabbccddeeff"; err.Error() != want {
		t.Fatalf("error message = %q, want %q", err.Error(), want)
	}

	mac := "aa:bb:cc:dd:ee:01"
	if err := c.Do(ctx, http.MethodPost, "/api/v1/devices", map[string]string{"mac": mac, "name": "one-ap"}, nil); err != nil {
		t.Fatal(err)
	}
	entry := &tfprovider.ContractWirelessEntry{
		ID: "srv-1", Name: "one", SSID: "one", Security: "wpa-p",
		Passphrase: "eight+chars", VLAN: 2, Enabled: true,
	}
	if err := c.CreateWireless(ctx, mac, entry); err != nil {
		t.Fatalf("POST: %v", err)
	}
	got, err := c.GetWireless(ctx, mac, "one")
	if err != nil {
		t.Fatalf("GET after PUT: %v", err)
	}
	if got.ID != "srv-1" {
		t.Fatalf("round trip lost server ID: %+v", got)
	}
}

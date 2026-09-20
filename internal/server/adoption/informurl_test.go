package adoption

// informurl_test.go pins the shared inform-URL derivation (InformURL /
// informURLPortFor) — the one source of the URL both the mgmt_cfg
// inform_url row and the controller-side SSH set-inform push lane
// (docs/PROTOCOL-mgmt.md §7) hand a device — and proves the two
// compositions cannot drift.

import (
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

// TestInformURL pins the derivation's port chain and row-shaped output:
// the controller URL's explicit port, else the inform listen port, else
// the classic 8080; scheme and path of the controller URL are ignored
// exactly like the inform_url row ignores them; no host means no URL.
func TestInformURL(t *testing.T) {
	cases := []struct {
		name          string
		controllerURL string
		listenAddr    string
		want          string
	}{
		{"explicit port wins", "http://10.10.10.10:8080", ":9090", "http://10.10.10.10:8080/inform"},
		{"listen port fallback", "http://10.10.10.10", ":9090", "http://10.10.10.10:9090/inform"},
		{"hosted listen addr", "http://10.10.10.10", "0.0.0.0:8081", "http://10.10.10.10:8081/inform"},
		{"classic 8080 when unparseable", "http://10.10.10.10", "nonsense", "http://10.10.10.10:8080/inform"},
		{"no controller url", "", ":8080", ""},
		{"scheme is row-shaped http", "https://ctrl.example.com", ":8080", "http://ctrl.example.com:8080/inform"},
		{"path ignored like the row", "http://10.10.10.10:8080/base", ":8080", "http://10.10.10.10:8080/inform"},
		{"bare host, no listen port", "http://10.10.10.10", "", "http://10.10.10.10:8080/inform"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InformURL(tc.controllerURL, tc.listenAddr); got != tc.want {
				t.Fatalf("InformURL(%q, %q) = %q, want %q", tc.controllerURL, tc.listenAddr, got, tc.want)
			}
		})
	}
}

// TestInformURLMatchesMgmtCfgRow proves the push lane's URL is byte-equal
// to the inform_url row the device later receives in mgmt_cfg: with a
// configured controller URL the row's advertHost IS the controller URL
// host, and both compose it with the same shared port chain.
func TestInformURLMatchesMgmtCfgRow(t *testing.T) {
	const controllerURL = "http://10.0.1.7" // no explicit port: exercise the listen chain
	e := newTestEngine(t)
	e.controllerURL = controllerURL
	e.informListenAddr = ":8080"
	// The device's own IP / reported inform URL must NOT leak into
	// either composition while the controller URL is configured.
	d := store.Device{MAC: engineMAC, IP: "10.9.9.9", InformURL: "http://10.9.9.9:8080/inform"}
	row := "inform_url=" + InformURL(controllerURL, ":8080") + "\n"
	got := e.BuildMgmtCfg(d, "")
	if !strings.Contains(got, row) {
		t.Fatalf("mgmt_cfg inform_url row not derived like InformURL %q:\n%s", row, got)
	}
}

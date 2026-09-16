package metrics

import (
	"math"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var nanConst = math.NaN()

// seriesForMAC counts gathered series whose mac label equals mac, across the
// given family ("" = all per-device families). Raw family counts are not
// usable in assertions because prometheus counters/gauges are process-global
// and accumulate series created by earlier tests in the package.
func seriesForMAC(t *testing.T, mac, family string) int {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range fams {
		if family != "" && f.GetName() != family {
			continue
		}
		for _, m := range f.Metric {
			for _, l := range m.GetLabel() {
				if l.GetName() == "mac" && l.GetValue() == mac {
					n++
					break
				}
			}
		}
	}
	return n
}

// IncAdopt/IncAdoptFail are POLLER-observed transition counters by decided
// semantics; nothing in the admin API layer calls them (the endpoint-level
// no-bump assertions live in internal/adminapi).
func TestInformAndAdoptCounters(t *testing.T) {
	before := testutil.ToFloat64(informsTotal)
	IncInform()
	IncInform()
	if got := testutil.ToFloat64(informsTotal); got != before+2 {
		t.Fatalf("informs_total = %v, want %v", got, before+2)
	}

	bA := testutil.ToFloat64(adoptTotal)
	IncAdopt()
	if got := testutil.ToFloat64(adoptTotal); got != bA+1 {
		t.Fatalf("adopt_total = %v, want %v", got, bA+1)
	}

	bF := testutil.ToFloat64(adoptFailTotal)
	IncAdoptFail()
	if got := testutil.ToFloat64(adoptFailTotal); got != bF+1 {
		t.Fatalf("adopt_fail_total = %v, want %v", got, bF+1)
	}
}

func TestAPICounterSnapshot(t *testing.T) {
	want := `# HELP openunifi_api_requests_total Total admin API requests by status code and route pattern.
# TYPE openunifi_api_requests_total counter
openunifi_api_requests_total{code="200",path="GET /api/v1/devices"} 1
openunifi_api_requests_total{code="400",path="PUT /api/v1/wireless"} 1
openunifi_api_requests_total{code="401",path="GET /api/v1/devices"} 1
`
	ObserveAPIRequest(200, "GET /api/v1/devices")
	ObserveAPIRequest(401, "GET /api/v1/devices")
	ObserveAPIRequest(400, "PUT /api/v1/wireless")

	if n := testutil.CollectAndCount(apiRequestsTotal); n < 3 {
		t.Fatalf("api counter series = %d, want >= 3", n)
	}
	if err := testutil.CollectAndCompare(apiRequestsTotal, strings.NewReader(want)); err != nil {
		t.Fatalf("api counter snapshot mismatch: %v", err)
	}
}

func TestUpdateFromDeviceSnapshots(t *testing.T) {
	const mac = "f0:9f:c2:84:8f:2a"

	UpdateFromDevice(mac, "U7PG2", 3, 1700000000, 7231.5, 12, 1048576, 2097152)

	if got := testutil.ToFloat64(deviceState.WithLabelValues(mac, "U7PG2")); got != 3 {
		t.Fatalf("device_state = %v, want 3", got)
	}
	if got := testutil.ToFloat64(lastInformTimestamp.WithLabelValues(mac)); got != 1700000000 {
		t.Fatalf("last_inform_timestamp = %v", got)
	}
	if got := testutil.ToFloat64(uptimeSeconds.WithLabelValues(mac)); got != 7231.5 {
		t.Fatalf("uptime_seconds = %v", got)
	}
	if got := testutil.ToFloat64(staCount.WithLabelValues(mac)); got != 12 {
		t.Fatalf("sta_count = %v", got)
	}
	if got := testutil.ToFloat64(userTxBytes.WithLabelValues(mac)); got != 1048576 {
		t.Fatalf("user_tx_bytes = %v", got)
	}
	if got := testutil.ToFloat64(userRxBytes.WithLabelValues(mac)); got != 2097152 {
		t.Fatalf("user_rx_bytes = %v", got)
	}
}

func TestUnknownValuesAreHonest(t *testing.T) {
	const mac = "aa:bb:cc:dd:ee:01"

	// Unknown state (-1) and never-seen (0) are recorded as-is.
	UpdateFromDevice(mac, "", -1, 0, nanConst, nanConst, nanConst, nanConst)
	if got := testutil.ToFloat64(deviceState.WithLabelValues(mac, "")); got != -1 {
		t.Fatalf("unknown state = %v, want -1", got)
	}
	if got := testutil.ToFloat64(lastInformTimestamp.WithLabelValues(mac)); got != 0 {
		t.Fatalf("never-seen timestamp = %v, want 0", got)
	}

	// NaN floats must NOT seed zero-faked series: only the two MACs touched
	// with real data above exist for uptime/tx.
	if c := testutil.CollectAndCount(uptimeSeconds); c != 1 {
		t.Fatalf("uptime series = %d, want 1 (NaN must not seed a series)", c)
	}
	if c := testutil.CollectAndCount(userTxBytes); c != 1 {
		t.Fatalf("tx series = %d, want 1 (NaN must not seed a series)", c)
	}
	if c := testutil.CollectAndCount(userRxBytes); c != 1 {
		t.Fatalf("rx series = %d, want 1 (NaN must not seed a series)", c)
	}

	// A genuine 0 uptime IS recorded (not skipped like NaN).
	UpdateFromDevice("aa:bb:cc:dd:ee:02", "", -1, 0, 0, 0, 0, 0)
	if c := testutil.CollectAndCount(uptimeSeconds); c != 2 {
		t.Fatalf("uptime series after genuine 0 = %d, want 2", c)
	}
}

// ForgetDevice must remove EVERY per-device series for the MAC — including
// the (mac, model) pairs of deviceState — and leave other devices untouched.
func TestForgetDevicePrunesAllSeries(t *testing.T) {
	const mac = "de:ad:be:ef:00:01"
	const other = "de:ad:be:ef:00:02"

	UpdateFromDevice(mac, "U7PG2", 3, 1700000001, 1, 2, 3, 4)
	UpdateFromDevice(mac, "U6Lite", 3, 1700000001, 1, 2, 3, 4) // churned repair pair
	UpdateFromDevice(other, "U7PG2", 1, 1700000002, 5, 6, 7, 8)

	// 2 (mac, model) pairs on deviceState + 5 single-label gauges = 7 series.
	if got := seriesForMAC(t, mac, ""); got != 7 {
		t.Fatalf("series for %s = %d, want 7", mac, got)
	}

	ForgetDevice(mac)

	// Pruned device: every per-device series must be gone.
	if got := seriesForMAC(t, mac, ""); got != 0 {
		t.Fatalf("series for %s after forget = %d, want 0", mac, got)
	}
	// ...and the other device is untouched.
	if got := seriesForMAC(t, other, ""); got != 6 {
		t.Fatalf("series for %s = %d, want 6", other, got)
	}
	if got := testutil.ToFloat64(deviceState.WithLabelValues(other, "U7PG2")); got != 1 {
		t.Fatalf("other MAC device_state changed: %v", got)
	}
	if got := testutil.ToFloat64(lastInformTimestamp.WithLabelValues(other)); got != 1700000002 {
		t.Fatalf("other MAC last_inform changed: %v", got)
	}

	// ForgetDevice takes the same label spelling as UpdateFromDevice — a
	// bare (non-colon) MAC must therefore NOT prune the colon-hex series.
	UpdateFromDevice(mac, "U7PG2", 3, 1700000001, 1, 2, 3, 4)
	ForgetDevice("deadbeef0001")
	if got := seriesForMAC(t, mac, ""); got != 6 {
		t.Fatalf("bare-hex ForgetDevice must not match colon-hex series, got %d series", got)
	}
	ForgetDevice(mac) // clean up

	// Idempotent: forgetting a pruned MAC again is a no-op, not a panic.
	ForgetDevice(mac)
	if got := seriesForMAC(t, mac, ""); got != 0 {
		t.Fatalf("re-forget must stay pruned, %d series left", got)
	}
}

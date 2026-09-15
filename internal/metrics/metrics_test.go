package metrics

import (
	"math"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

var nanConst = math.NaN()

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

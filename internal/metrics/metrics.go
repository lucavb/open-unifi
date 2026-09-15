// Package metrics wires Prometheus instrumentation for open-unifi.
//
// Design note: helpers take PLAIN string/int64/float64 arguments (no
// internal/store types) so the metrics package stays decoupled from the
// store contract while the server lane evolves it. The server lane maps
// store.Device fields onto these helpers after each inform.
package metrics

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// informsTotal counts inform packets received by the inform server.
var informsTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "openunifi_informs_total",
	Help: "Total number of inform packets received.",
})

// adoptTotal counts adoption attempts initiated via the admin API.
var adoptTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "openunifi_adopt_total",
	Help: "Total number of adoption attempts initiated.",
})

// adoptFailTotal counts adoption attempts that ended in failure.
var adoptFailTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "openunifi_adopt_fail_total",
	Help: "Total number of adoption attempts that failed.",
})

// apiRequestsTotal counts admin API requests by status code and route pattern.
// "path" is the ServeMux route pattern (e.g. "GET /api/v1/devices/{mac}"),
// never a concrete MAC, to keep label cardinality bounded.
var apiRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "openunifi_api_requests_total",
	Help: "Total admin API requests by status code and route pattern.",
}, []string{"code", "path"})

// deviceState reports the current state of each tracked device as an integer
// matching the store state enum (1=pending, 2=adopting, 3=adopted, 4=lost;
// -1 = unknown). MACs are canonical lowercase colon-hex.
//
// Label caveat: the mac label is the canonical address we track (ours), but
// the model label comes from inform bodies — i.e. DEVICE-influenced data.
// Cardinality is therefore bounded by the set of distinct (mac, model) pairs
// the trust domain ever reports; on a trusted LAN that is "one model per
// device", small, and a churned repair only adds one extra series.
// Documented residual risk: a malicious device on the network could vary its
// reported model per inform to inflate series count until store removal
// prunes stale label pairs.
var deviceState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "openunifi_device_state",
	Help: "Device lifecycle state as an integer (-1 unknown, 1 pending, 2 adopting, 3 adopted, 4 lost).",
}, []string{"mac", "model"})

// lastInformTimestamp tracks the unix-seconds timestamp of the last inform
// heard from each device (0 if never seen).
var lastInformTimestamp = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "openunifi_last_inform_timestamp",
	Help: "Unix seconds of the last inform received from this device (0 = never seen).",
}, []string{"mac"})

// uptimeSeconds reports device-reported uptime in seconds; only set when the
// device's last inform carried a usable uptime value (never pre-seeded with a
// fabricated 0 for devices that have no such statistic yet).
var uptimeSeconds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "openunifi_uptime_seconds",
	Help: "Uptime in seconds as reported by the device's last inform.",
}, []string{"mac"})

// staCount reports the number of associated stations (clients).
//
// Milestone v1: single unlabeled-by-band value. If a future inform carries
// per-band splits ("stat" keys per radio), we may add a "band" label then;
// until data actually contains split keys we omit the label rather than
// emit a fake "all" band. Documented here so the evolution path is explicit.
var staCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "openunifi_sta_count",
	Help: "Number of associated client stations on this device.",
}, []string{"mac"})

// userTxBytes / userRxBytes are cumulative byte counters read from periodic
// informs. They are GAUGES on purpose: a Prometheus Counter would treat a
// controller restart (counter reset to a lower value) as a rate spike, which
// is wrong for restart-prone periodic snapshots. Honest read: gauge — and the
// name must NOT carry the Prometheus "_total" counter suffix, because
// rate()/increase() treat _total series specially and nonsense would result.
// They are absolute snapshot values, not monotonic client-side counters.
var userTxBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "openunifi_user_tx_bytes",
	Help: "Cumulative transmitted bytes (gauge; read from periodic inform snapshots).",
}, []string{"mac"})

var userRxBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Name: "openunifi_user_rx_bytes",
	Help: "Cumulative received bytes (gauge; read from periodic inform snapshots).",
}, []string{"mac"})

func init() {
	prometheus.MustRegister(
		informsTotal,
		adoptTotal,
		adoptFailTotal,
		apiRequestsTotal,
		deviceState,
		lastInformTimestamp,
		uptimeSeconds,
		staCount,
		userTxBytes,
		userRxBytes,
	)
}

// ---- Worker-style helpers (called by the inform/server lane after decoding
// ---- a device snapshot; args are plain values, no store types).

// IncInform increments the inform counter by one.
func IncInform() { informsTotal.Inc() }

// IncAdopt increments the successful-adoption counter by one.
func IncAdopt() { adoptTotal.Inc() }

// IncAdoptFail increments the failed-adoption counter by one.
func IncAdoptFail() { adoptFailTotal.Inc() }

// ObserveAPIRequest records one admin API response. code is the HTTP status;
// route should be a ServeMux pattern like "GET /api/v1/devices/{mac}" or a
// low-cardinality constant — never a raw user-supplied path with MACs in it.
func ObserveAPIRequest(code int, route string) {
	apiRequestsTotal.WithLabelValues(strconv.Itoa(code), route).Inc()
}

// SetDeviceState records a device's lifecycle state. Pass -1 for unknown.
// A model of "" is preserved as an empty label.
func SetDeviceState(mac, model string, state int64) {
	deviceState.WithLabelValues(mac, model).Set(float64(state))
}

// SetLastInform records the last-seen unix seconds for a device
// (0 = never seen, per contract).
func SetLastInform(mac string, lastSeenUnix int64) {
	lastInformTimestamp.WithLabelValues(mac).Set(float64(lastSeenUnix))
}

// SetUptime records the device-reported uptime seconds. NaN means "no data
// in this inform" and is skipped (we do not fabricate a 0). A genuine 0 is
// recorded honestly.
func SetUptime(mac string, uptime float64) {
	if uptime != uptime { // NaN
		return
	}
	uptimeSeconds.WithLabelValues(mac).Set(uptime)
}

// SetStaCount records the associated-station count. NaN = "no data" (skip).
func SetStaCount(mac string, n float64) {
	if n != n { // NaN
		return
	}
	staCount.WithLabelValues(mac).Set(n)
}

// SetUserBytes records cumulative tx/rx byte gauges for a device.
// NaN on either side means "no data in this inform" and skips that series.
func SetUserBytes(mac string, tx, rx float64) {
	if tx == tx { // not NaN
		userTxBytes.WithLabelValues(mac).Set(tx)
	}
	if rx == rx { // not NaN
		userRxBytes.WithLabelValues(mac).Set(rx)
	}
}

// UpdateFromDevice is the one-shot convenience used after decoding an inform:
// it pushes a full snapshot in one call. Use NaN for floats that are absent,
// -1 for an unknown state, and 0 for a never-seen LastSeen.
//
// The sta parameter name must NOT shadow the package-level staCount gauge
// var; use it via the SetStaCount helper instead (named "sta" so the
// compiler would catch any stray naked reference to the var here anyway).
func UpdateFromDevice(mac, model string, state, lastSeenUnix int64, uptime, sta, txBytes, rxBytes float64) {
	SetDeviceState(mac, model, state)
	SetLastInform(mac, lastSeenUnix)
	SetUptime(mac, uptime)
	SetStaCount(mac, sta)
	SetUserBytes(mac, txBytes, rxBytes)
}

// Handler returns the Prometheus HTTP handler (metrics endpoint).
func Handler() http.Handler {
	return promhttp.Handler()
}

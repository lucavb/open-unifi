package metrics

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// deviceStatePairs gathers the openunifi_device_state series reported for one
// MAC (keyed by model label, valued by the gauge) from the default registry.
// It never calls WithLabelValues, so assertions cannot accidentally re-create
// a deleted series.
func deviceStateValues(t *testing.T, mac string) map[string]int64 {
	t.Helper()
	fams, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int64{}
	for _, f := range fams {
		if f.GetName() != "openunifi_device_state" {
			continue
		}
		for _, m := range f.Metric {
			macSeen := false
			model := ""
			for _, l := range m.GetLabel() {
				if l.GetName() == "mac" && l.GetValue() == mac {
					macSeen = true
				}
				if l.GetName() == "model" {
					model = l.GetValue()
				}
			}
			if macSeen {
				out[model] = int64(m.GetGauge().GetValue())
			}
		}
	}
	return out
}

// C6 regression: a MAC that starts reporting a different model must not keep
// its previous (mac, model) series — exactly one device_state series survives
// per known MAC, whichever model was reported last.
func TestDeviceStateLatestModelWins(t *testing.T) {
	const mac = "c6:0a:00:00:00:01" // unique to this file; the Prometheus default registry is process-global

	SetDeviceState(mac, "U7PG2", 3)
	SetDeviceState(mac, "U6Lite", 2)

	values := deviceStateValues(t, mac)
	if len(values) != 1 {
		t.Fatalf("device_state series for %s after model change = %d (models %v), want exactly 1 (latest model wins)", mac, len(values), keys(values))
	}
	if values["U6Lite"] != 2 {
		t.Fatalf("surviving device_state series for %s = %v, want U6Lite=2", mac, values)
	}
}

// C6 regression: a churn loop of 100 distinct models on one MAC must never
// grow the series count — the family stays one series per MAC.
func TestDeviceStateModelChurnBounded(t *testing.T) {
	const mac = "c6:0a:00:00:00:02"

	for i := 0; i < 100; i++ {
		SetDeviceState(mac, fmt.Sprintf("U-CHURN-%03d", i), 3)
	}

	if got := seriesForMAC(t, mac, "openunifi_device_state"); got != 1 {
		t.Fatalf("device_state series for %s after 100-model churn = %d, want 1", mac, got)
	}
}

// C6 regression: ForgetDevice must remove the device_state series AND clear
// the remembered model — otherwise a re-added device reporting its old model
// re-seeds a stale map entry and a later model switch resurrects a second
// series (0 after forget, then 1 series survive the forget → old → new path).
func TestDeviceStateForgetAlsoForgetsModel(t *testing.T) {
	const mac = "c6:0a:00:00:00:03"

	SetDeviceState(mac, "U7PG2", 3)
	SetDeviceState(mac, "U6Lite", 2) // latest model wins: (mac, U7PG2) retired

	ForgetDevice(mac)
	if got := seriesForMAC(t, mac, "openunifi_device_state"); got != 0 {
		t.Fatalf("device_state series for %s after ForgetDevice = %d, want 0", mac, got)
	}

	// Re-added device reports its OLD model again, then churns to a newer
	// one. With lastModel cleared by ForgetDevice this stays exactly one
	// series; a stale map entry (prev "U6Lite" remembered across the forget)
	// would resurrect (mac, U7PG2)-era churn and end at 2.
	SetDeviceState(mac, "U7PG2", 1)
	SetDeviceState(mac, "U6-Pro", 3)

	if got := seriesForMAC(t, mac, "openunifi_device_state"); got != 1 {
		t.Fatalf("device_state series for %s after re-add and model switch = %d, want 1 (forget must clear the remembered model)", mac, got)
	}
	values := deviceStateValues(t, mac)
	if values["U6-Pro"] != 3 {
		t.Fatalf("surviving device_state series for %s = %v, want U6-Pro=3", mac, values)
	}
}

func keys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

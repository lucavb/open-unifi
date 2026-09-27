package app

import (
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

// deviceStateSeriesForMAC counts openunifi_device_state exposition series for
// one MAC, gathered from the process-global default registry (metrics
// registers there via init()).
func deviceStateSeriesForMAC(t *testing.T, mac string) int {
	t.Helper()
	n := 0
	for k := range gatherDefault(t) {
		if strings.HasPrefix(k, "openunifi_device_state{") && strings.Contains(k, "mac="+mac+",") {
			n++
		}
	}
	return n
}

// C6 regression end-to-end: the app poller reports device snapshots via
// metrics.UpdateFromDevice (→ SetDeviceState). A device that keeps its MAC but
// changes its reported Model (reflash, repair) must retire its previous
// (mac, model) gauge series — exactly one openunifi_device_state series per
// known MAC, latest model wins.
//
// The MAC here is UNIQUE to this file: gatherDefault reads the process-global
// Prometheus registry, and sibling app tests seed series for their own MACs
// (a shared MAC polluted a validation run's series count with stale series).
func TestPollOnceDeviceStateLatestModelWins(t *testing.T) {
	a, st := pollerSetup(t)
	const mac = "ca:fe:ba:be:00:02"
	now := time.Now().Unix()

	if err := st.Put(store.Device{MAC: mac, State: store.StateAdopted, Model: "U7PG2", LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	a.PollOnce()
	if got := deviceStateSeriesForMAC(t, mac); got != 1 {
		t.Fatalf("device_state series for %s after first poll = %d, want 1", mac, got)
	}

	// Same MAC, different reported model: the U7PG2 series must be retired,
	// not accumulate alongside the new one.
	d, err := st.Get(mac)
	if err != nil {
		t.Fatal(err)
	}
	d.Model = "U6Lite"
	if err := st.Put(d); err != nil {
		t.Fatal(err)
	}
	a.PollOnce()

	if got := deviceStateSeriesForMAC(t, mac); got != 1 {
		t.Fatalf("device_state series for %s after model change = %d, want 1 (latest model wins)", mac, got)
	}
}

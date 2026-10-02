package inform

import (
	"encoding/json"
	"testing"
)

func TestStationsCarryRowAndVapContext(t *testing.T) {
	body := map[string]any{"vap_table": []any{
		map[string]any{
			"essid": "TNG", "bssid": "aa:bb:cc:00:00:01", "radio": "na", "channel": float64(149),
			"sta_table": []any{
				map[string]any{
					"mac": "aa:2c:3b:5b:b7:10", "hostname": "mohr-trent-900", "ip": "10.13.16.246",
					"rssi": float64(-37), "tx_bytes": float64(100), "rx_bytes": float64(50), "uptime": float64(290),
				},
			},
		},
		map[string]any{"essid": "TNG", "radio": "ng", "channel": float64(6), "sta_table": []any{}},
	}}
	sts, present := Stations(body)
	if !present || len(sts) != 1 {
		t.Fatalf("stations=%v present=%v, want one row", sts, present)
	}
	got := sts[0]
	want := Station{
		MAC: "aa:2c:3b:5b:b7:10", Hostname: "mohr-trent-900", IP: "10.13.16.246",
		Signal: -37, TxBytes: 100, RxBytes: 50, Uptime: 290,
		ESSID: "TNG", BSSID: "aa:bb:cc:00:00:01", Radio: "na", Channel: 149,
	}
	if got != want {
		t.Fatalf("station = %+v, want %+v", got, want)
	}
}

func TestStationsMissingAndOddFieldsAreZero(t *testing.T) {
	body := map[string]any{"vap_table": []any{
		map[string]any{"essid": 42, "channel": "six", "sta_table": []any{
			map[string]any{"mac": "aa:bb:cc:dd:ee:01", "hostname": 7, "rssi": "loud", "tx_bytes": nil},
		}},
	}}
	sts, present := Stations(body)
	if !present || len(sts) != 1 {
		t.Fatalf("stations=%v present=%v", sts, present)
	}
	if sts[0] != (Station{MAC: "aa:bb:cc:dd:ee:01"}) {
		t.Fatalf("station = %+v, want only the MAC populated", sts[0])
	}
}

func TestStationsJSONNumberAndSignalKey(t *testing.T) {
	body := map[string]any{"sta_table": []any{
		map[string]any{"mac": "aa:bb:cc:dd:ee:01", "signal": json.Number("-55"), "tx_bytes": json.Number("12")},
	}}
	sts, present := Stations(body)
	if !present || len(sts) != 1 || sts[0].Signal != -55 || sts[0].TxBytes != 12 {
		t.Fatalf("stations=%+v present=%v", sts, present)
	}
}

func TestStationsAbsentMatchesStationMACs(t *testing.T) {
	sts, present := Stations(map[string]any{"_type": "heartbeat"})
	if present || sts != nil {
		t.Fatalf("stations=%v present=%v, want nil/false", sts, present)
	}
}

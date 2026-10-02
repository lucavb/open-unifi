package wireless

import "testing"

func vapRow(kv ...string) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func TestVapEvidencePresenceAndKnown(t *testing.T) {
	tests := []struct {
		name           string
		table          any
		present, known bool
	}{
		{"absent", nil, false, false},
		{"wrong type", "not-a-table", false, false},
		{"typed nil slice is present but empty", []any(nil), true, false},
		{"empty", []any{}, true, false},
		{"non-map rows only", []any{"x", 1.0}, true, true},
		{"one row", []any{vapRow("state", "RUN")}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := ReadVapEvidence(tt.table)
			if ev.Present() != tt.present || ev.Known() != tt.known {
				t.Fatalf("Present/Known = %v/%v, want %v/%v", ev.Present(), ev.Known(), tt.present, tt.known)
			}
		})
	}
}

func TestVapEvidenceRunRule(t *testing.T) {
	ev := ReadVapEvidence([]any{
		vapRow("state", "RUN", "essid", "primary", "name", "ath0", "radio_name", "wifi0"),
		vapRow("state", "run", "ssid", "fallback", "name", "ath1", "parent", "wifi1"), // case + fallback spellings
		vapRow("status", "RUN", "essid", "status-fallback", "name", "ath2"),           // status fallback
		vapRow("state", "INIT", "essid", "booting", "name", "ath3"),
		vapRow("essid", "no-state", "name", "ath4"),
		vapRow("state", "RUN", "essid", "x", "status", "INIT", "name", "ath5"), // state wins over status
		"junk",
	})
	want := []VapRun{
		{Name: "ath0", SSID: "primary", Radio: "wifi0"},
		{Name: "ath1", SSID: "fallback", Radio: "wifi1"},
		{Name: "ath2", SSID: "status-fallback"},
		{Name: "ath5", SSID: "x"},
	}
	got := ev.Running()
	if len(got) != len(want) {
		t.Fatalf("Running = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Running[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	for _, ssid := range []string{"primary", "fallback", "status-fallback", "x"} {
		if !ev.SSIDRunning(ssid) {
			t.Errorf("SSIDRunning(%q) = false, want true", ssid)
		}
	}
	for _, ssid := range []string{"booting", "no-state", "absent", ""} {
		if ev.SSIDRunning(ssid) {
			t.Errorf("SSIDRunning(%q) = true, want false", ssid)
		}
	}
	for _, name := range []string{"ath0", "ath1", "ath2", "ath5"} {
		if !ev.DevnameRunning(name) {
			t.Errorf("DevnameRunning(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"ath3", "ath4", "ath9", ""} {
		if ev.DevnameRunning(name) {
			t.Errorf("DevnameRunning(%q) = true, want false", name)
		}
	}
}

func TestVapEvidenceZeroValueIsEmpty(t *testing.T) {
	var ev VapEvidence
	if ev.Present() || ev.Known() || len(ev.Running()) != 0 || ev.SSIDRunning("a") || ev.DevnameRunning("ath0") {
		t.Fatalf("zero VapEvidence must read as no evidence: %+v", ev)
	}
}

package wireless

import "strings"

// VapRun is one RUNNING row of a device's reported vap_table.
type VapRun struct {
	Name  string // vap devname ("ath<N>")
	SSID  string // broadcast SSID the row carries
	Radio string // radio_table name the row sits on
}

// VapEvidence is the reading of the vap_table a device reports in one
// inform. It is the only place the vap_table wire shape and the "is this row
// RUN?" rule live; the drift settle, the settled-state watchdogs and the
// admin view all ask it instead of parsing the table themselves.
//
// Wire keys (firmware-verified, mcad FUN_0041cecc; docs/PROTOCOL.md:388,
// docs/AP-FIRMWARE-APPLY-PATH.md): a row reports "state", "essid", "name"
// and "radio_name". The "status", "ssid" and "parent" spellings only ever
// existed in synthetic test fixtures and are kept as fallbacks so in-flight
// fixtures keep working. RUN compares case-insensitively.
//
// Two levels of "no evidence" exist on purpose:
//
//   - Present: the record carries a vap_table at all. An empty-but-present
//     table is real evidence for removal (a device with every WLAN deleted
//     reports one), which is the only thing the drift settle accepts it for.
//   - Known: the table carries at least one row. Anything that would read a
//     table as REGRESSION evidence (the watchdogs, the admin view) requires
//     Known: vap_table is in no trust class, so a sparse heartbeat that omits
//     it drops it, and an absent or empty table says nothing about whether
//     the WLANs run.
type VapEvidence struct {
	present bool
	rows    int
	running []VapRun
}

// ReadVapEvidence parses a raw vap_table value (the []any a record's Extra
// carries, passed through verbatim). Anything else reads as not present.
func ReadVapEvidence(vapTable any) VapEvidence {
	rawList, ok := vapTable.([]any)
	if !ok {
		return VapEvidence{}
	}
	ev := VapEvidence{present: true, rows: len(rawList)}
	for _, raw := range rawList {
		m, ok := raw.(map[string]any)
		if !ok || !strings.EqualFold(JSONStr(m, "state", JSONStr(m, "status", "")), "RUN") {
			continue
		}
		ev.running = append(ev.running, VapRun{
			Name:  JSONStr(m, "name", ""),
			SSID:  JSONStr(m, "essid", JSONStr(m, "ssid", "")),
			Radio: JSONStr(m, "radio_name", JSONStr(m, "parent", "")),
		})
	}
	return ev
}

// Present reports whether a vap_table was reported at all (see the type doc).
func (e VapEvidence) Present() bool { return e.present }

// Known reports whether the table carries at least one row (see the type doc).
func (e VapEvidence) Known() bool { return e.rows > 0 }

// Running returns the RUNNING rows in reported order. The slice is shared;
// callers must not modify it.
func (e VapEvidence) Running() []VapRun { return e.running }

// SSIDRunning reports whether any RUNNING row carries ssid. The empty SSID
// is never running.
func (e VapEvidence) SSIDRunning(ssid string) bool {
	if ssid == "" {
		return false
	}
	for _, r := range e.running {
		if r.SSID == ssid {
			return true
		}
	}
	return false
}

// DevnameRunning reports whether the vap devname ("ath<N>") is RUNNING. The
// empty devname is never running.
func (e VapEvidence) DevnameRunning(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range e.running {
		if r.Name == name {
			return true
		}
	}
	return false
}

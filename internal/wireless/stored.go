package wireless

import "encoding/json"

// The stored WLAN format (Extra["device_wlans"] and the
// wlan_cfg_pending/pending_old/applied snapshots) is the untagged Go-field
// spelling every record has been written with since before Wlan carried the
// admin API's JSON tags. It is deliberately NOT the admin wire: a binary from
// before the tags decodes records written now, and renaming an admin JSON
// tag cannot change what is on disk.

// storedRadiusRow is the stored shape of RadiusServer and RadiusAcctServer.
type storedRadiusRow struct {
	IP   string
	Port int
}

// storedWlanRecord is the stored shape of Wlan: same field names, same
// order, no tags, no omitempty. TestStoredWlanRecordMirrorsWlan keeps it in
// step with Wlan.
type storedWlanRecord struct {
	Name                 string
	SSID                 string
	Security             string
	Passphrase           string
	VLAN                 int
	Enabled              bool
	ID                   string
	Band                 string
	RadiusServers        []storedRadiusRow
	RadiusSecret         string
	RadiusVLANMode       string
	AccountingEnabled    bool
	AcctServers          []storedRadiusRow
	InterimUpdateEnabled bool
	RadiusDASEnabled     bool
}

// EncodeStoredWlans renders a WLAN list in the stored format. It is the only
// writer of stored WLAN blobs. A nil list encodes as null, an empty one as [],
// as json.Marshal of []Wlan did before.
func EncodeStoredWlans(wls []Wlan) ([]byte, error) {
	var out []storedWlanRecord
	if wls != nil {
		out = make([]storedWlanRecord, len(wls))
	}
	for i, w := range wls {
		out[i] = storedWlanRecord{
			Name: w.Name, SSID: w.SSID, Security: w.Security, Passphrase: w.Passphrase,
			VLAN: w.VLAN, Enabled: w.Enabled, ID: w.ID, Band: w.Band,
			RadiusServers:        storedRows(w.RadiusServers, func(s RadiusServer) storedRadiusRow { return storedRadiusRow(s) }),
			RadiusSecret:         w.RadiusSecret,
			RadiusVLANMode:       w.RadiusVLANMode,
			AccountingEnabled:    w.AccountingEnabled,
			AcctServers:          storedRows(w.AcctServers, func(s RadiusAcctServer) storedRadiusRow { return storedRadiusRow(s) }),
			InterimUpdateEnabled: w.InterimUpdateEnabled,
			RadiusDASEnabled:     w.RadiusDASEnabled,
		}
	}
	return json.Marshal(out)
}

// storedRows converts a server list, keeping nil as nil (null) and empty as
// empty ([]).
func storedRows[T any](in []T, conv func(T) storedRadiusRow) []storedRadiusRow {
	if in == nil {
		return nil
	}
	out := make([]storedRadiusRow, len(in))
	for i, s := range in {
		out[i] = conv(s)
	}
	return out
}

// storedWlan reads a WLAN blob in either spelling. Go's JSON matching is
// case-insensitive, so every single-word stored key (Name, SSID, VLAN,
// nested IP and Port, ...) already lands on the tagged Wlan field. Only the
// multi-word fields differ ("RadiusServers" vs "radius_servers") and need
// the explicit stored-spelling twin. The embedded Wlan also accepts the
// snake_case admin spelling, so a blob in that spelling decodes too.
type storedWlan struct {
	Wlan
	StoredRadiusServers        []RadiusServer     `json:"RadiusServers"`
	StoredRadiusSecret         string             `json:"RadiusSecret"`
	StoredRadiusVLANMode       string             `json:"RadiusVLANMode"`
	StoredAccountingEnabled    bool               `json:"AccountingEnabled"`
	StoredAcctServers          []RadiusAcctServer `json:"AcctServers"`
	StoredInterimUpdateEnabled bool               `json:"InterimUpdateEnabled"`
	StoredRadiusDASEnabled     bool               `json:"RadiusDASEnabled"`
}

// DecodeStoredWlans decodes a stored WLAN list in the stored Go-field
// spelling (see EncodeStoredWlans) or the snake_case admin spelling. It is
// the only reader of stored WLAN blobs: the admin wire keeps strict,
// tag-only decoding on Wlan itself. When one blob carries both spellings of
// a field, a non-empty snake_case value wins and the booleans are true if
// either spelling is true (omitempty cannot tell false from absent).
func DecodeStoredWlans(raw []byte) ([]Wlan, error) {
	var in []storedWlan
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	if in == nil {
		return nil, nil
	}
	out := make([]Wlan, len(in))
	for i, s := range in {
		w := s.Wlan
		if len(w.RadiusServers) == 0 {
			w.RadiusServers = s.StoredRadiusServers
		}
		if w.RadiusSecret == "" {
			w.RadiusSecret = s.StoredRadiusSecret
		}
		if w.RadiusVLANMode == "" {
			w.RadiusVLANMode = s.StoredRadiusVLANMode
		}
		w.AccountingEnabled = w.AccountingEnabled || s.StoredAccountingEnabled
		if len(w.AcctServers) == 0 {
			w.AcctServers = s.StoredAcctServers
		}
		w.InterimUpdateEnabled = w.InterimUpdateEnabled || s.StoredInterimUpdateEnabled
		w.RadiusDASEnabled = w.RadiusDASEnabled || s.StoredRadiusDASEnabled
		out[i] = w
	}
	return out, nil
}

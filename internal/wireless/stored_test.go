package wireless

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

// fullWlan sets every field, so a field added to Wlan without a matching
// twin in storedWlan / storedWlanRecord fails the round-trips below.
func fullWlan() Wlan {
	return Wlan{
		Name: "corp", SSID: "Corp", Security: "wpa-eap", Passphrase: "pp-12345678",
		VLAN: 20, Enabled: true, ID: "abc123", Band: "5g",
		RadiusServers:        []RadiusServer{{IP: "10.0.0.1", Port: 1812}, {IP: "10.0.0.2"}},
		RadiusSecret:         "s3cret",
		RadiusVLANMode:       "optional",
		AccountingEnabled:    true,
		AcctServers:          []RadiusAcctServer{{IP: "10.0.0.3", Port: 1813}},
		InterimUpdateEnabled: true,
		RadiusDASEnabled:     true,
	}
}

// legacyBlob reproduces what the pre-tag binary persisted: the untagged
// struct marshalled with its Go field names.
func legacyBlob(t *testing.T, w Wlan) []byte {
	t.Helper()
	type legacyRadius struct {
		IP   string
		Port int
	}
	type legacyWlan struct {
		Name, SSID, Security, Passphrase string
		VLAN                             int
		Enabled                          bool
		ID, Band                         string
		RadiusServers                    []legacyRadius
		RadiusSecret, RadiusVLANMode     string
		AccountingEnabled                bool
		AcctServers                      []legacyRadius
		InterimUpdateEnabled             bool
		RadiusDASEnabled                 bool
	}
	l := legacyWlan{
		Name: w.Name, SSID: w.SSID, Security: w.Security, Passphrase: w.Passphrase,
		VLAN: w.VLAN, Enabled: w.Enabled, ID: w.ID, Band: w.Band,
		RadiusSecret: w.RadiusSecret, RadiusVLANMode: w.RadiusVLANMode,
		AccountingEnabled: w.AccountingEnabled, InterimUpdateEnabled: w.InterimUpdateEnabled,
		RadiusDASEnabled: w.RadiusDASEnabled,
	}
	for _, s := range w.RadiusServers {
		l.RadiusServers = append(l.RadiusServers, legacyRadius(s))
	}
	for _, s := range w.AcctServers {
		l.AcctServers = append(l.AcctServers, legacyRadius(s))
	}
	b, err := json.Marshal([]legacyWlan{l})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fullWlanStoredGolden and fullWlanHashGolden were produced for fullWlan()
// by the binary before this module existed (commit 1090998: json.Marshal of
// the untagged Wlan, and its WlanListHash). They are the on-disk and drift
// contract: changing either breaks rollback or re-provisions every device.
const (
	fullWlanStoredGolden = `[{"Name":"corp","SSID":"Corp","Security":"wpa-eap","Passphrase":"pp-12345678","VLAN":20,"Enabled":true,"ID":"abc123","Band":"5g","RadiusServers":[{"IP":"10.0.0.1","Port":1812},{"IP":"10.0.0.2","Port":0}],"RadiusSecret":"s3cret","RadiusVLANMode":"optional","AccountingEnabled":true,"AcctServers":[{"IP":"10.0.0.3","Port":1813}],"InterimUpdateEnabled":true,"RadiusDASEnabled":true}]`
	fullWlanHashGolden   = "8f51c3a758835741aa8fd9b9eaa7a006f1771b0aa35971d5bdf118b48dba4d59"
)

func TestEncodeStoredWlansIsThePreModuleFormat(t *testing.T) {
	got, err := EncodeStoredWlans([]Wlan{fullWlan()})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != fullWlanStoredGolden {
		t.Fatalf("stored WLAN bytes changed:\n got %s\nwant %s", got, fullWlanStoredGolden)
	}
	for _, tc := range []struct {
		in   []Wlan
		want string
	}{{nil, "null"}, {[]Wlan{}, "[]"}} {
		if b, _ := EncodeStoredWlans(tc.in); string(b) != tc.want {
			t.Fatalf("EncodeStoredWlans(%#v) = %s, want %s", tc.in, b, tc.want)
		}
	}
}

func TestWlanListHashIsPinned(t *testing.T) {
	if got := WlanListHash([]Wlan{fullWlan()}); got != fullWlanHashGolden {
		t.Fatalf("WlanListHash(fullWlan) = %s, want %s", got, fullWlanHashGolden)
	}
}

// TestStoredWlanRecordMirrorsWlan keeps the stored shape in step with Wlan:
// same field names in the same order, so a new Wlan field must be added to
// storedWlanRecord and EncodeStoredWlans before it can be persisted.
func TestStoredWlanRecordMirrorsWlan(t *testing.T) {
	wt, st := reflect.TypeOf(Wlan{}), reflect.TypeOf(storedWlanRecord{})
	if wt.NumField() != st.NumField() {
		t.Fatalf("Wlan has %d fields, storedWlanRecord %d", wt.NumField(), st.NumField())
	}
	for i := 0; i < wt.NumField(); i++ {
		if wt.Field(i).Name != st.Field(i).Name {
			t.Fatalf("field %d: Wlan.%s vs storedWlanRecord.%s", i, wt.Field(i).Name, st.Field(i).Name)
		}
	}
	// Round trip through the real encoder: a field present on the struct
	// but not copied in EncodeStoredWlans comes back zero.
	blob, err := EncodeStoredWlans([]Wlan{fullWlan()})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeStoredWlans(blob)
	if err != nil || len(got) != 1 || !reflect.DeepEqual(got[0], fullWlan()) {
		t.Fatalf("stored round trip = %+v, %v", got, err)
	}
}

func TestDecodeStoredWlansAcceptsBothSpellings(t *testing.T) {
	want := fullWlan()

	snake, err := json.Marshal([]Wlan{want})
	if err != nil {
		t.Fatal(err)
	}
	for name, blob := range map[string][]byte{"snake_case": snake, "stored": legacyBlob(t, want)} {
		got, err := DecodeStoredWlans(blob)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
			t.Fatalf("%s: decoded %+v\nwant %+v\nblob %s", name, got, want, blob)
		}
	}
}

// TestDecodeStoredWlansCoversEveryField fails when Wlan gains a field the
// legacy decoder does not know: it fills every field by reflection, writes
// the legacy spelling by Go field name, and expects the same value back.
func TestDecodeStoredWlansCoversEveryField(t *testing.T) {
	rt := reflect.TypeOf(Wlan{})
	legacy := map[string]any{}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		switch f.Type.Kind() {
		case reflect.String:
			legacy[f.Name] = "v-" + f.Name
		case reflect.Int:
			legacy[f.Name] = 7
		case reflect.Bool:
			legacy[f.Name] = true
		case reflect.Slice:
			legacy[f.Name] = []map[string]any{{"IP": "1.2.3.4", "Port": 99}}
		default:
			t.Fatalf("field %s: unhandled kind %s — extend this test and storedWlan", f.Name, f.Type.Kind())
		}
	}
	blob, _ := json.Marshal([]any{legacy})
	got, err := DecodeStoredWlans(blob)
	if err != nil || len(got) != 1 {
		t.Fatalf("decode: %v %+v", err, got)
	}
	gv := reflect.ValueOf(got[0])
	for i := 0; i < rt.NumField(); i++ {
		if gv.Field(i).IsZero() {
			t.Errorf("legacy field %s was not decoded — add its twin to storedWlan", rt.Field(i).Name)
		}
	}
}

func TestDecodeStoredWlansEdges(t *testing.T) {
	if got, err := DecodeStoredWlans([]byte(`null`)); err != nil || got != nil {
		t.Fatalf("null = %v, %v; want nil, nil", got, err)
	}
	if got, err := DecodeStoredWlans([]byte(`[]`)); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("[] = %#v, %v; want empty non-nil", got, err)
	}
	if _, err := DecodeStoredWlans([]byte(`{bad`)); err == nil {
		t.Fatal("malformed blob must error")
	}
	// A non-empty snake_case value wins over the stored twin on one blob.
	got, err := DecodeStoredWlans([]byte(`[{"ssid":"a","radius_secret":"new","RadiusSecret":"old"}]`))
	if err != nil || got[0].RadiusSecret != "new" {
		t.Fatalf("snake_case spelling must win: %+v %v", got, err)
	}
	got, err = DecodeStoredWlans([]byte(`[{"ssid":"a","radius_servers":[{"ip":"1.1.1.1"}],"RadiusServers":[{"IP":"2.2.2.2"}]}]`))
	if err != nil || len(got[0].RadiusServers) != 1 || got[0].RadiusServers[0].IP != "1.1.1.1" {
		t.Fatalf("snake_case server list must win: %+v %v", got, err)
	}
	// Booleans: true in either spelling is true (omitempty drops false, so
	// an explicit false cannot outvote the other spelling).
	got, err = DecodeStoredWlans([]byte(`[{"ssid":"a","accounting_enabled":false,"AccountingEnabled":true,"interim_update_enabled":true,"InterimUpdateEnabled":false,"RadiusDASEnabled":true}]`))
	if err != nil || !got[0].AccountingEnabled || !got[0].InterimUpdateEnabled || !got[0].RadiusDASEnabled {
		t.Fatalf("mixed-spelling bools = %+v, %v; want all true", got, err)
	}
}

func TestDeviceWLANsReadsLegacyRecord(t *testing.T) {
	want := fullWlan()
	d := store.Device{Extra: store.JSONMap{DeviceWLANsExtraKey: string(legacyBlob(t, want))}}
	got := DeviceWLANs(d)
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("DeviceWLANs over a legacy record = %+v, want %+v", got, want)
	}
	// Writing back keeps the stored format, byte for byte.
	if err := SetDeviceWLANs(&d, got); err != nil {
		t.Fatal(err)
	}
	if d.Extra[DeviceWLANsExtraKey] != fullWlanStoredGolden {
		t.Fatalf("SetDeviceWLANs wrote %v, want the stored format", d.Extra[DeviceWLANsExtraKey])
	}
	if again := DeviceWLANs(d); len(again) != 1 || !reflect.DeepEqual(again[0], want) {
		t.Fatalf("re-read after migrate = %+v", again)
	}
}

// TestWlanListHashIgnoresStoredSpelling: the drift hash reads fields, not
// JSON, so decoding either spelling yields the same hash.
func TestWlanListHashIgnoresStoredSpelling(t *testing.T) {
	want := fullWlan()
	cur, _ := json.Marshal([]Wlan{want})
	a, _ := DecodeStoredWlans(cur)
	b, _ := DecodeStoredWlans(legacyBlob(t, want))
	if WlanListHash(a) != WlanListHash(b) {
		t.Fatal("drift hash differs between current and legacy spellings of one WLAN")
	}
}

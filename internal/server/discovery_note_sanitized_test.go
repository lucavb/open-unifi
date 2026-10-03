package server

// Regression for discovery-note injection: discoveryNote used to comma-join
// TLV-derived values verbatim, so a TLV3 (version) value of ",factory=true"
// injected a standalone "factory=true" part that setInformCandidate honors
// (internal/app/setinform.go). The addString closure in discovery.go now
// strips commas, so a value can only ever compose ONE inert part; the
// app-side parser is deliberately unchanged.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/store"
)

// factoryPartPattern matches a STANDALONE "factory=true" part in the
// comma-joined note — the injected/signature form setInformCandidate
// reacts to — not an embedded "k=factory=true" value.
var factoryPartPattern = regexp.MustCompile(`(^|,)factory=true(,|$)`)

// discoveryPendingNote feeds one crafted v2 discovery beacon through the
// real discovery handler and returns the stored pending note for the
// device MAC that the beacons claim.
func discoveryPendingNote(t *testing.T, extra ...[]byte) string {
	t.Helper()
	st := store.NewMemStore()
	s := New(Config{}, st, testLogger())
	s.setDiscoveryTestIdentity("5a:5a:5a:5a:5a:5a")
	defer func() { s.setDiscoveryTestIdentity("") }()
	s.handleDiscoveryPacket(nil, mkDiscoveryV2(1, [6]byte{0x24, 0xa4, 0x3c, 0xaa, 0xbb, 0xcc},
		[]byte{10, 2, 2, 1}, extra...))
	pending, err := st.Pending()
	if err != nil {
		t.Fatal(err)
	}
	note, ok := pending["00156d010001"]
	if !ok {
		t.Fatalf("no pending note for 00156d010001; pending=%v", pending)
	}
	return note
}

// TestDiscoveryNoteTLV3CommaInjection is the flipped C7 fixture: the
// formerly VULNERABLE scenario (TLV3 value exactly ",factory=true", TLV23
// absent) must now store "version=factory=true" as ONE inert part and must
// NOT contain a standalone "factory=true" part.
func TestDiscoveryNoteTLV3CommaInjection(t *testing.T) {
	note := discoveryPendingNote(t,
		beaconTLV21("BZ2"),
		beaconTLV11("uap-lab"),
		mkTLV(10, []byte{0, 0, 0x0e, 0x10}),
		beaconTLV3(",factory=true"),
	)
	if !strings.Contains(note, "version=factory=true") {
		t.Fatalf("TLV3 value must survive as one inert version= part, note=%q", note)
	}
	if factoryPartPattern.MatchString(note) {
		t.Fatalf("TLV3 comma injection still produced a standalone factory=true part, note=%q", note)
	}
}

// TestDiscoveryNoteGenuineFactoryPart is the positive control: a normal
// beacon with clean TLV values and a real TLV23 factory byte still composes
// the ordinary note including its genuine "factory=true" part.
func TestDiscoveryNoteGenuineFactoryPart(t *testing.T) {
	note := discoveryPendingNote(t,
		beaconTLV21("BZ2"),
		beaconTLV11("uap-lab"),
		mkTLV(10, []byte{0, 0, 0x0e, 0x10}),
		mkTLV(23, []byte{1}),
	)
	if !factoryPartPattern.MatchString(note) {
		t.Fatalf("genuine factory=true part missing from note=%q", note)
	}
	if strings.Contains(note, "version=factory=true") {
		t.Fatalf("factory marker leaked into a value part, note=%q", note)
	}
}

// TestDiscoveryNoteCommaStrippedFromValue: a comma inside an informational
// value (hostname "lab,ap1") is stripped at composition.
func TestDiscoveryNoteCommaStrippedFromValue(t *testing.T) {
	note := discoveryPendingNote(t,
		beaconTLV21("BZ2"),
		beaconTLV11("lab,ap1"),
		mkTLV(10, []byte{0, 0, 0x0e, 0x10}),
	)
	if !strings.Contains(note, "hostname=labap1") {
		t.Fatalf("comma not stripped from hostname value, note=%q", note)
	}
	if strings.Contains(note, "lab,ap1") {
		t.Fatalf("hostname comma leaked into the note, note=%q", note)
	}
}

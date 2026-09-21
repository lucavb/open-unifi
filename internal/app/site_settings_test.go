package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/store"
)

// Valid synthetic authorized_keys lines (the same RFC 4253 shape the
// systemcfg render_test.go table pins — structure-valid synthetic blobs).
const (
	testKeyEd25519Line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB test@ap"
	testKeyRSALine     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB second@ap"
)

// testSettingsApp builds an App whose settings file + seed live in their own
// tempdir, returning all the knobs the site-settings tests need.
func testSettingsApp(t *testing.T, seed SiteSettings) (*App, store.DeviceStore, string) {
	t.Helper()
	st := store.NewMemStore()
	spath := filepath.Join(t.TempDir(), "site-settings.json")
	a := New(st, filepath.Join(t.TempDir(), "wireless.json"), spath, seed, quietLogger())
	return a, st, spath
}

// readSettingsDoc decodes the on-disk site-settings.json (the API document
// shape) for disk-state assertions.
func readSettingsDoc(t *testing.T, path string) adminapi.SiteSettingsDocument {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read settings file: %v", err)
	}
	var doc adminapi.SiteSettingsDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode settings file: %v", err)
	}
	return doc
}

// TestFirstBootSeedPersistsThenFileWins pins the seeding contract: on first
// boot the seed becomes the record AND the disk document; on reopen with a
// DIFFERENT seed, the file wins and the seed is ignored (the flags are
// first-boot seeds only).
func TestFirstBootSeedPersistsThenFileWins(t *testing.T) {
	seed := SiteSettings{
		CountryCode:   276,
		SSHPassword:   "first-boot-password",
		SSHPublicKeys: []string{testKeyEd25519Line},
	}
	a, _, spath := testSettingsApp(t, seed)

	got, err := a.GetSiteSettings(context.Background())
	if err != nil {
		t.Fatalf("get after seed: %v", err)
	}
	if got.RegulatoryCountryCode != 276 || got.APSSHPassword != "first-boot-password" ||
		len(got.APSSHPublicKeys) != 1 || got.APSSHPublicKeys[0] != testKeyEd25519Line || got.APSSHDisablePassword {
		t.Fatalf("seed not served: %+v", got)
	}
	doc := readSettingsDoc(t, spath)
	if doc.RegulatoryCountryCode != 276 || doc.APSSHPassword != "first-boot-password" ||
		len(doc.APSSHPublicKeys) != 1 || doc.APSSHPublicKeys[0] != testKeyEd25519Line || doc.APSSHDisablePassword {
		t.Fatalf("seed not persisted: %+v", doc)
	}

	// Reopen over the same file with a DIFFERENT seed: the file wins.
	reseed := SiteSettings{CountryCode: 840, SSHPassword: "ignored-seed"}
	a2 := New(store.NewMemStore(), filepath.Join(t.TempDir(), "wireless.json"), spath, reseed, quietLogger())
	got2, err := a2.GetSiteSettings(context.Background())
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if got2.RegulatoryCountryCode != 276 || got2.APSSHPassword != "first-boot-password" ||
		len(got2.APSSHPublicKeys) != 1 {
		t.Fatalf("file did not win over seed: %+v", got2)
	}
	if doc2 := readSettingsDoc(t, spath); doc2.APSSHPassword != "first-boot-password" {
		t.Fatalf("reopen rewrote the file: %+v", doc2)
	}
}

// TestPutSiteSettingsMintsProvisionedOnly pins the sweep semantics: an
// effective change re-stamps every device with a non-empty CfgVersion and
// leaves never-provisioned records (CfgVersion "") untouched — adoption
// renders the current facts into their first provisioning.
func TestPutSiteSettingsMintsProvisionedOnly(t *testing.T) {
	a, st, spath := testSettingsApp(t, SiteSettings{})

	// Two provisioned devices + one never-provisioned (pending candidate).
	if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StateAdopted, CfgVersion: "aaaa1111bbbb2222"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(store.Device{MAC: "112233445566", State: store.StateAdopted, CfgVersion: "cccc3333dddd4444"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(store.Device{MAC: "665544332211", State: store.StatePending}); err != nil {
		t.Fatal(err)
	}

	doc := adminapi.SiteSettingsDocument{
		RegulatoryCountryCode: 276,
		APSSHPassword:         "changed-password",
		APSSHPublicKeys:       []string{testKeyEd25519Line},
	}
	before := map[string]string{"aabbccddeeff": "aaaa1111bbbb2222", "112233445566": "cccc3333dddd4444"}
	view, err := a.PutSiteSettings(context.Background(), doc)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if view.RegulatoryCountryCode != 276 || view.APSSHPassword != "changed-password" ||
		len(view.APSSHPublicKeys) != 1 || view.APSSHDisablePassword {
		t.Fatalf("view: %+v", view)
	}
	for mac, old := range before {
		d, err := st.Get(mac)
		if err != nil {
			t.Fatalf("get %s: %v", mac, err)
		}
		if d.CfgVersion == "" || d.CfgVersion == old {
			t.Fatalf("device %s not re-minted: cfgversion %q (was %q)", mac, d.CfgVersion, old)
		}
	}
	d, err := st.Get("665544332211")
	if err != nil {
		t.Fatal(err)
	}
	if d.CfgVersion != "" {
		t.Fatalf("unprovisioned device got a cfgversion: %q", d.CfgVersion)
	}
	// Disk document equals what was applied.
	if doc2 := readSettingsDoc(t, spath); doc2.RegulatoryCountryCode != 276 || doc2.APSSHPassword != "changed-password" {
		t.Fatalf("disk doc: %+v", doc2)
	}
}

// TestPutSiteSettingsNoOpMintsNothing pins that a save carrying the current
// record mints nothing — bookkeeping idempotence, the same rule the
// device-save skeleton teaches.
func TestPutSiteSettingsNoOpMintsNothing(t *testing.T) {
	seed := SiteSettings{
		CountryCode:   840,
		SSHPassword:   "pw",
		SSHPublicKeys: []string{testKeyEd25519Line, testKeyRSALine},
	}
	a, st, _ := testSettingsApp(t, seed)

	docs := []adminapi.SiteSettingsDocument{
		{RegulatoryCountryCode: 840, APSSHPassword: "pw", APSSHPublicKeys: []string{testKeyEd25519Line, testKeyRSALine}},
	}
	if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StateAdopted, CfgVersion: "aaaa1111bbbb2222"}); err != nil {
		t.Fatal(err)
	}

	for i, doc := range docs {
		if _, err := a.PutSiteSettings(context.Background(), doc); err != nil {
			t.Fatalf("put #%d: %v", i, err)
		}
	}
	d, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if d.CfgVersion != "aaaa1111bbbb2222" {
		t.Fatalf("no-change save minted a cfgversion: %q", d.CfgVersion)
	}
}

// TestPutSiteSettingsOrderOnlyDiffMints pins the ORDER-SENSITIVE effective
// rule: swapping two key lines changes the sshd.auth.key.<n> provisioning
// intent and therefore mints one re-provisioning. Content idempotence makes
// this harmless (the device applies identical rows and echoes the new
// cfgversion at the next inform, then noops) — but a reorder must not be
// silently swallowed the way a hash-style comparison would swallow it.
func TestPutSiteSettingsOrderOnlyDiffMints(t *testing.T) {
	seed := SiteSettings{SSHPublicKeys: []string{testKeyEd25519Line, testKeyRSALine}}
	a, st, _ := testSettingsApp(t, seed)
	if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StateAdopted, CfgVersion: "aaaa1111bbbb2222"}); err != nil {
		t.Fatal(err)
	}

	if _, err := a.PutSiteSettings(context.Background(), adminapi.SiteSettingsDocument{
		APSSHPublicKeys: []string{testKeyRSALine, testKeyEd25519Line},
	}); err != nil {
		t.Fatalf("put: %v", err)
	}
	d, err := st.Get("aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	if d.CfgVersion == "" || d.CfgVersion == "aaaa1111bbbb2222" {
		t.Fatalf("order-only diff was not effective: cfgversion %q", d.CfgVersion)
	}
}

// TestPutSiteSettingsValidation pins the verb's fail-closed rule set —
// every failure is an adminapi.ErrInvalid (HTTP 400 via handleBackendErr):
// one malformed authorized_keys line fails the WHOLE save, an explicit
// out-of-range country fails, and disable-without-keys fails.
func TestPutSiteSettingsValidation(t *testing.T) {
	a, _, _ := testSettingsApp(t, SiteSettings{})

	cases := []struct {
		name string
		doc  adminapi.SiteSettingsDocument
	}{
		{
			// render_test.go TestParsePublicKeyTable: single-field line
			// (no type token) is a malformed authorized_keys line.
			name: "malformed key line",
			doc: adminapi.SiteSettingsDocument{
				RegulatoryCountryCode: 840,
				APSSHPublicKeys:       []string{testKeyEd25519Line, "AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"},
			},
		},
		{
			name: "bad key type token",
			doc: adminapi.SiteSettingsDocument{
				RegulatoryCountryCode: 840,
				APSSHPublicKeys:       []string{"opendir3 " + "AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"},
			},
		},
		{
			name: "disable without keys",
			doc: adminapi.SiteSettingsDocument{
				RegulatoryCountryCode: 840,
				APSSHPassword:         "pw",
				APSSHDisablePassword:  true,
			},
		},
		{
			name: "country out of range high",
			doc:  adminapi.SiteSettingsDocument{RegulatoryCountryCode: 1000},
		},
		{
			name: "country out of range low",
			doc:  adminapi.SiteSettingsDocument{RegulatoryCountryCode: -7},
		},
	}
	for _, tc := range cases {
		_, err := a.PutSiteSettings(context.Background(), tc.doc)
		if err == nil {
			t.Fatalf("%s: save unexpectedly accepted", tc.name)
		}
		if !errors.Is(err, adminapi.ErrInvalid) {
			t.Fatalf("%s: want adminapi.ErrInvalid, got %v", tc.name, err)
		}
	}
}

// TestSiteSettingsRuleEquivalenceAcrossLayers pins the Gate A finding #5
// follow-up: the adminapi pre-backend fence (ValidateSiteSettings) and the
// app save verb's internal validation (validateSiteSettingsChange)
// accept/reject the SAME inputs — one rule set, two layers
// (defense-in-depth). Both are pure syntax rules (country range, per-line
// key parse, disable-without-keys); list ORDER is deliberately out of
// scope here — order is a semantics rule (an order-only diff mints one
// harmless re-provisioning), not a rejection rule. The seam is legal
// because internal/app already imports internal/adminapi (the Backend
// interface assertion); adminapi can never import app back, so the pin
// lives beside the verb it cross-checks.
func TestSiteSettingsRuleEquivalenceAcrossLayers(t *testing.T) {
	cases := []struct {
		name   string
		doc    adminapi.SiteSettingsDocument
		reject bool
		keyIdx int // 1-based position both layers must name (0 = n/a)
	}{
		{
			name: "valid document",
			doc: adminapi.SiteSettingsDocument{
				RegulatoryCountryCode: 840,
				APSSHPassword:         "pw",
				APSSHPublicKeys:       []string{testKeyEd25519Line, testKeyRSALine},
			},
		},
		{
			name: "valid document, empty keys accepted",
			doc: adminapi.SiteSettingsDocument{
				RegulatoryCountryCode: 276,
				APSSHPassword:         "pw",
			},
		},
		{
			name: "valid document, country unset (0)",
			doc: adminapi.SiteSettingsDocument{
				APSSHPassword:   "pw",
				APSSHPublicKeys: []string{testKeyEd25519Line},
			},
		},
		{
			name: "invalid second key line names #2",
			doc: adminapi.SiteSettingsDocument{
				RegulatoryCountryCode: 840,
				APSSHPublicKeys: []string{
					testKeyEd25519Line,
					// render_test.go TestParsePublicKeyTable: a typeless
					// line (no type token) is a malformed authorized_keys
					// line.
					"AAAAC3NzaC1lZDI1NTE5AAAAIHRlc3RrZXlBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB",
				},
			},
			reject: true,
			keyIdx: 2,
		},
		{
			name: "disable without keys",
			doc: adminapi.SiteSettingsDocument{
				RegulatoryCountryCode: 840,
				APSSHPassword:         "pw",
				APSSHDisablePassword:  true,
			},
			reject: true,
		},
		{
			name:   "country out of range high",
			doc:    adminapi.SiteSettingsDocument{RegulatoryCountryCode: 1000},
			reject: true,
		},
	}
	for _, tc := range cases {
		msg := adminapi.ValidateSiteSettings(&tc.doc)
		err := validateSiteSettingsChange(siteSettingsFromDoc(tc.doc))
		if (msg == "") != (err == nil) {
			t.Errorf("%s: layer disagreement: adminapi fence %q, app verb error %v", tc.name, msg, err)
			continue
		}
		if !tc.reject {
			continue
		}
		// Rejection parity extends to the #N position: both layers report
		// the FIRST failing key line with its 1-based index.
		if tc.keyIdx != 0 {
			pos := fmt.Sprintf("#%d", tc.keyIdx)
			if !strings.Contains(msg, pos) {
				t.Errorf("%s: adminapi fence message missing %s: %q", tc.name, pos, msg)
			}
			if !strings.Contains(err.Error(), pos) {
				t.Errorf("%s: app verb error missing %s: %v", tc.name, pos, err)
			}
		}
	}
}

// TestRecordAbsorptionCannotTouchSiteSettings pins the structural immunity:
// record absorption (store trust policy) folds a decoded inform body into a
// DEVICE record only. The site-settings record sits entirely outside
// Absorb, so an inform body carrying keys named exactly like the settings
// fields changes neither the cached record nor the on-disk document.
func TestRecordAbsorptionCannotTouchSiteSettings(t *testing.T) {
	seed := SiteSettings{
		CountryCode:   840,
		SSHPassword:   "seed-password",
		SSHPublicKeys: []string{testKeyEd25519Line},
	}
	a, st, spath := testSettingsApp(t, seed)
	before, err := a.GetSiteSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	beforeDoc := readSettingsDoc(t, spath)

	if err := st.Put(store.Device{MAC: "aabbccddeeff", State: store.StateAdopted}); err != nil {
		t.Fatal(err)
	}
	// A poisoned full-inform body, fields named like the site-settings
	// fields (the Absorb shape is (map[string]any, now, gcm) per
	// store/trustpolicy.go:165).
	body := map[string]any{
		"ip":                      "10.0.0.9",
		"regulatory_country_code": float64(1),
		"ap_ssh_password":         "poison-password",
		"ap_ssh_public_keys":      []any{"ssh-rsa AAAA poison"},
		"ap_ssh_disable_password": true,
	}
	err = st.UpdateExisting("aabbccddeeff", func(d *store.Device) error {
		d.Absorb(body, time.Now(), true)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	after, err := a.GetSiteSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("site settings changed by record absorption: %+v -> %+v", before, after)
	}
	// The poisoned body was also deliberately NOT an effective record
	// write: absorption changed the device record, never the site
	// settings record — but if it had, the mint sweep would have been
	// dishonest. The DeepEqual guards are the pin.
	if doc := readSettingsDoc(t, spath); !reflect.DeepEqual(doc, beforeDoc) {
		t.Fatalf("settings file changed by record absorption: %+v -> %+v", beforeDoc, doc)
	}
}

// TestGetSiteSettingsIsDetachedCopy pins the read-path discipline: the
// returned view's key list is a copy, so a caller mutating it never aliases
// the cache (the wireless cloneWireless rule, shape-for-shape).
func TestGetSiteSettingsIsDetachedCopy(t *testing.T) {
	seed := SiteSettings{
		SSHPassword:   "pw",
		SSHPublicKeys: []string{testKeyEd25519Line},
	}
	a, _, _ := testSettingsApp(t, seed)

	v, err := a.GetSiteSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.APSSHPublicKeys) != 1 {
		t.Fatalf("seed view: %+v", v)
	}
	v.APSSHPublicKeys[0] = "mutated-line"
	v.APSSHPublicKeys = append(v.APSSHPublicKeys, "extra-line")

	v2, err := a.GetSiteSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(v2.APSSHPublicKeys) != 1 || v2.APSSHPublicKeys[0] != testKeyEd25519Line {
		t.Fatalf("view mutated the cache: %+v", v2)
	}
}

// TestSiteSettingsLoadAndSeedErrorRefusal pins the load-error surface (the
// wireless mirrored-real-error discipline, on all three legs):
//
//  1. a corrupt settings file on disk: New succeeds structurally (same as
//     a corrupt wireless.json), CurrentSiteSettings retains the REAL
//     error, GetSiteSettings and PutSiteSettings both refuse — and the
//     bad file is NOT overwritten (the fix-it-on-disk posture);
//  2. an invalid seed (malformed key line) with no file: same retention,
//     GET/PUT refuse, and NOTHING is persisted (a bad seed never becomes
//     a record);
//  3. happy contrast: a valid seed surfaces a nil error and the seeded
//     file on disk.
func TestSiteSettingsLoadAndSeedErrorRefusal(t *testing.T) {
	corruptBytes := []byte(`{"regulatory_country_code": 840`)
	validSeed := SiteSettings{
		CountryCode:   840,
		SSHPassword:   "pw",
		SSHPublicKeys: []string{testKeyEd25519Line},
	}
	badSeed := SiteSettings{SSHPublicKeys: []string{"not-a-key-line"}}

	cases := []struct {
		name     string
		seed     SiteSettings
		prep     func(t *testing.T, path string)
		wantErr  bool
		wantFile func(t *testing.T, path string)
	}{
		{
			name: "corrupt file on disk is retained and never overwritten",
			prep: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, corruptBytes, 0o600); err != nil {
					t.Fatalf("prep: %v", err)
				}
			},
			wantErr: true,
			wantFile: func(t *testing.T, path string) {
				t.Helper()
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read back: %v", err)
				}
				if !bytes.Equal(raw, corruptBytes) {
					t.Fatalf("corrupt file was overwritten: %q", raw)
				}
			},
		},
		{
			name:    "invalid seed persists nothing",
			seed:    badSeed,
			wantErr: true,
			wantFile: func(t *testing.T, path string) {
				t.Helper()
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("settings file persisted from a bad seed: %v", err)
				}
			},
		},
		{
			name:    "valid seed surfaces a nil error",
			seed:    validSeed,
			wantErr: false,
			wantFile: func(t *testing.T, path string) {
				t.Helper()
				if _, err := os.Stat(path); err != nil {
					t.Fatalf("seeded file missing: %v", err)
				}
			},
		},
	}

	// A valid effective document for the PUT-refusal assertions.
	putDoc := adminapi.SiteSettingsDocument{
		RegulatoryCountryCode: 276,
		APSSHPassword:         "changed",
		APSSHPublicKeys:       []string{testKeyEd25519Line},
	}
	ctx := context.Background()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spath := filepath.Join(t.TempDir(), "site-settings.json")
			if tc.prep != nil {
				tc.prep(t, spath)
			}
			a := New(store.NewMemStore(), filepath.Join(t.TempDir(), "wireless.json"), spath, tc.seed, quietLogger())

			if _, err := a.CurrentSiteSettings(); tc.wantErr != (err != nil) {
				t.Fatalf("CurrentSiteSettings err = %v, wantErr %v", err, tc.wantErr)
			}
			if _, err := a.GetSiteSettings(ctx); tc.wantErr != (err != nil) {
				t.Fatalf("GetSiteSettings err = %v, wantErr %v", err, tc.wantErr)
			}
			if _, err := a.PutSiteSettings(ctx, putDoc); tc.wantErr != (err != nil) {
				t.Fatalf("PutSiteSettings err = %v, wantErr %v", err, tc.wantErr)
			}
			tc.wantFile(t, spath)
		})
	}
}

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestViewToModelUnsetEchoMapsToNull pins the unset-echo mapping in
// viewToModel. The attributes are Optional-only (no Computed, no
// schema default), so Terraform enforces plan-vs-state equality on them:
// writing the server's concrete unset echo (0, "", []) into state
// under a null plan would diff forever ("will be null" every plan). The
// mapping mirrors applyDevice (empty name → null) and entryToModel (empty
// passphrase → null): unset echo → null, set echo → verbatim value.
//
// terraform-CLI end-to-end acceptance runs are not possible in the nono
// sandbox (plugin unix sockets are denied); composition_test.go pins the
// CRUD paths through the real handler instead.
func TestViewToModelUnsetEchoMapsToNull(t *testing.T) {
	ctx := context.Background()

	// The zero view (controller defaults): everything maps to null except
	// the fixed singleton id.
	m := &siteSettingsModel{}
	viewToModel(ctx, &siteSettings{}, m)
	if m.ID.ValueString() != siteSettingsID {
		t.Fatalf("id = %q, want %q", m.ID.ValueString(), siteSettingsID)
	}
	if !m.RegulatoryCountryCode.IsNull() {
		t.Fatalf("country 0 must map to null, got %d", m.RegulatoryCountryCode.ValueInt64())
	}
	if !m.DeviceSSHPublicKeys.IsNull() || len(m.DeviceSSHPublicKeys.Elements()) != 0 {
		t.Fatalf("empty key list must map to null, got %v", m.DeviceSSHPublicKeys)
	}

	// A set view passes through verbatim, keys in slice order. (The

	view := &siteSettings{
		RegulatoryCountryCode: 840,
		DeviceSSHPublicKeys:   []string{"ssh-ed25519 AAAA a@ap", "ssh-ed25519 AAAA b@ap"},
	}
	m = &siteSettingsModel{}
	viewToModel(ctx, view, m)
	if m.RegulatoryCountryCode.ValueInt64() != 840 {
		t.Fatalf("country = %d, want 840", m.RegulatoryCountryCode.ValueInt64())
	}
	var keys []string
	m.DeviceSSHPublicKeys.ElementsAs(ctx, &keys, false)
	if len(keys) != 2 || keys[0] != "ssh-ed25519 AAAA a@ap" || keys[1] != "ssh-ed25519 AAAA b@ap" {
		t.Fatalf("keys = %v, want the two lines in order", keys)
	}
}

// TestSiteSettingsFromModelZeroMapsToZeroDocument pins the model→document
// direction: null/unknown plan values map to the record's zero values (the
// whole-document PUT body always carries both fields, and the empty key
// list marshals as [] — never null, which the strict server decode would
// reject as a missing field). The historical ap_ssh_password wire name is
// inert: it maps to nothing on the wire (see resource_site_settings.go).
func TestSiteSettingsFromModelZeroMapsToZeroDocument(t *testing.T) {
	ctx := context.Background()
	m := &siteSettingsModel{
		ID:                    types.StringValue(siteSettingsID),
		RegulatoryCountryCode: types.Int64Null(),
		DeviceSSHPublicKeys:   types.ListNull(types.StringType),
	}
	var diags diag.Diagnostics
	doc := siteSettingsFromModel(ctx, m, &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if doc.RegulatoryCountryCode != 0 {
		t.Fatalf("zero mapping mismatch: %+v", doc)
	}
	if doc.DeviceSSHPublicKeys == nil || len(doc.DeviceSSHPublicKeys) != 0 {
		t.Fatalf("empty key list must marshal as [], got %#v", doc.DeviceSSHPublicKeys)
	}

	// Set values pass through verbatim.
	m = &siteSettingsModel{
		ID:                    types.StringValue(siteSettingsID),
		RegulatoryCountryCode: types.Int64Value(840),
	}
	list, _ := types.ListValueFrom(ctx, types.StringType, []string{"ssh-ed25519 AAAA a@ap"})
	m.DeviceSSHPublicKeys = list
	doc = siteSettingsFromModel(ctx, m, &diags)
	if doc.RegulatoryCountryCode != 840 ||
		len(doc.DeviceSSHPublicKeys) != 1 || doc.DeviceSSHPublicKeys[0] != "ssh-ed25519 AAAA a@ap" {
		t.Fatalf("set mapping mismatch: %+v", doc)
	}
}

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = (*siteSettingsResource)(nil)
var _ resource.ResourceWithConfigure = (*siteSettingsResource)(nil)
var _ resource.ResourceWithImportState = (*siteSettingsResource)(nil)

// siteSettingsID is the singleton resource's fixed Terraform id. The
// controller carries exactly one site-settings record — there is nothing
// else the id could distinguish.
const siteSettingsID = "site-settings"

// siteSettingsResource manages the controller's single site-settings record:
// the four AP-intent site facts (regulatory country code, AP SSH password,
// provisioned SSH public keys, SSH password-login disable). A save replaces
// the whole document wholesale (the wireless-envelope doctrine) and —
// server-side — mints cfgversion across provisioned devices on effective
// change, so adopted APs receive the new sshd rows at their next inform.
type siteSettingsResource struct {
	client *apiClient
}

func (r *siteSettingsResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_site_settings"
}

func (r *siteSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		if c, ok := req.ProviderData.(*apiClient); ok {
			r.client = c
		}
	}
}

func (r *siteSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The singleton site-settings record of the open-unifi control plane: the four " +
			"AP-intent site facts. A change re-provisions every adopted AP at its next inform (cfgversion mint). " +
			"Deleting the resource restores the controller defaults. Caveat on default-gated deployments " +
			"(U7PG2 firmware 6.8.2.15592): a save carrying SSH public keys or the password-disable knob " +
			"succeeds, but every subsequent server-side full provisioning is rejected with the typed 501 " +
			"live-provisioning gate until the sshd facts are cleared (an effective save of the defaults) or " +
			"the controller restarts with --allow-gated-live-wlan (a startup-only flag); the rejected " +
			"devices then go stale in the console until one of those remedies. See " +
			"docs/PROTOCOL-systemcfg-wireless.md §13.",
		Attributes: map[string]schema.Attribute{
			"regulatory_country_code": schema.Int64Attribute{
				MarkdownDescription: "ISO 3166-1 numeric country code (1..999). Unset (null/omitted) = the " +
					"controller's persisted-first-boot default, rendered server-side as 840 (US). " +
					"Pass-through: no schema default is injected; set values round-trip verbatim, and the " +
					"unset echo (0) maps back to null so an omitted attribute never shows plan drift. A " +
					"literal 0 cannot be held in state (the echo maps it back to null, breaking " +
					"plan/state equality) — write null or omit the attribute instead.",
				Optional: true,
			},
			"ap_ssh_password": schema.StringAttribute{
				MarkdownDescription: "AP SSH login password. Unset (null/omitted) = the site default (`ubnt`). " +
					"Shown as `(sensitive value)` in plan diffs. Set values round-trip verbatim; a literal " +
					"empty string cannot be held in state (the unset echo maps back to null, mirroring " +
					"the wlan passphrase) — write null or omit the attribute instead.",
				Optional:  true,
				Sensitive: true,
			},
			"ap_ssh_public_keys": schema.ListAttribute{
				MarkdownDescription: "Provisioned AP SSH public keys, one authorized_keys line per element. ORDER " +
					"MATTERS: system_cfg emits one `sshd.auth.key.<n>` row family per line in slice order, so an " +
					"order-only change re-provisions every AP (one harmless full provisioning). Every line is " +
					"validated fail-closed against RFC 4253 server-side; an invalid line is a 400 at apply time. " +
					"This is a list, not a set — duplicates are preserved verbatim. A literal empty list " +
					"cannot be held in state (the empty echo maps back to null); to provision zero keys " +
					"write null or omit the attribute instead.",
				ElementType: types.StringType,
				Optional:    true,
			},
			"ap_ssh_disable_password": schema.BoolAttribute{
				MarkdownDescription: "Disable AP SSH password login (dropbear -s). Requires a non-empty " +
					"`ap_ssh_public_keys` list: the API rejects disable-without-keys with a 400 at apply time " +
					"(SSH lockout guard). Unset (null/omitted) = password login enabled. A literal `false` " +
					"cannot be held in state (the unset echo maps back to null) — write null or omit the " +
					"attribute instead; `true` round-trips verbatim.",
				Optional: true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Resource id, fixed to `site-settings` (one record per controller).",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// siteSettingsModel is the Terraform state shape for the site-settings
// resource.
type siteSettingsModel struct {
	ID                    types.String `tfsdk:"id"`
	RegulatoryCountryCode types.Int64  `tfsdk:"regulatory_country_code"`
	APSSHPassword         types.String `tfsdk:"ap_ssh_password"`
	APSSHPublicKeys       types.List   `tfsdk:"ap_ssh_public_keys"`
	APSSHDisablePassword  types.Bool   `tfsdk:"ap_ssh_disable_password"`
}

func (r *siteSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var plan siteSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	doc := siteSettingsFromModel(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// PUT the whole document once; no retry (see client.go).
	if _, err := r.client.putSiteSettings(ctx, doc); err != nil {
		resp.Diagnostics.AddError("Create site settings", err.Error())
		return
	}

	// Read-back makes the state match the server's view (notably the
	// unset echo 0/""/[]/false mapping back to null — viewToModel).
	if err := readSiteSettingsInto(ctx, r.client, &plan); err != nil {
		resp.Diagnostics.AddError("Create site settings: post-create read", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *siteSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var state siteSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The singleton ALWAYS serves: GET never 404s, so there is no
	// RemoveResource branch here (contrast the wlan/device Read paths).
	view, err := r.client.getSiteSettings(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Read site settings", err.Error())
		return
	}
	viewToModel(ctx, view, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *siteSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var plan siteSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	doc := siteSettingsFromModel(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.client.putSiteSettings(ctx, doc); err != nil {
		resp.Diagnostics.AddError("Update site settings", err.Error())
		return
	}
	// The PUT view echoes the document verbatim, so the plan IS server
	// truth; setting state from the plan (wlan Update's shape) keeps the
	// pass-through contract without a second request.
	plan.ID = types.StringValue(siteSettingsID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *siteSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	// Delete RESTORES THE CONTROLLER DEFAULTS. The site-settings record is
	// a controller-level singleton that always exists server-side (the
	// renderer needs its facts on every cfg render), so there is no
	// server-side deletion. Terraform-side deletion therefore PUTs the zero
	// document — country 0 (unset → the server renders 840/US), empty
	// password (→ the site default "ubnt"), empty key list (→ no sshd key
	// rows), password login re-enabled — and removes the resource from
	// state. Like every save, this is an effective change that mints
	// cfgversion across the provisioned devices, so adopted APs pick the
	// defaults up at their next inform.
	doc := siteSettings{APSSHPublicKeys: []string{}}
	if _, err := r.client.putSiteSettings(ctx, doc); err != nil {
		resp.Diagnostics.AddError("Delete site settings", err.Error())
		return
	}
	resp.State.RemoveResource(ctx)
}

// ImportState accepts only the fixed singleton id; any other id names no
// record (there is exactly one).
func (r *siteSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if req.ID != siteSettingsID {
		resp.Diagnostics.AddError("Invalid site settings import ID",
			fmt.Sprintf("expected import ID %q (the singleton), got %q", siteSettingsID, req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), siteSettingsID)...)
}

// --- helpers -------------------------------------------------------------

// siteSettingsFromModel converts Terraform state into the whole-document PUT
// body. Every attribute is Optional without a schema default, so a
// null/unknown plan value maps to the record's zero value (0, "", [], false)
// — the controller's unset semantics. The key list is preserved in slice
// order: order-only changes re-provision APs (one harmless full
// provisioning), mirroring the server's order-sensitive echo.
func siteSettingsFromModel(ctx context.Context, m *siteSettingsModel, d *diag.Diagnostics) siteSettings {
	doc := siteSettings{APSSHPublicKeys: []string{}}
	if !m.RegulatoryCountryCode.IsNull() && !m.RegulatoryCountryCode.IsUnknown() {
		doc.RegulatoryCountryCode = int(m.RegulatoryCountryCode.ValueInt64())
	}
	if !m.APSSHPassword.IsNull() && !m.APSSHPassword.IsUnknown() {
		doc.APSSHPassword = m.APSSHPassword.ValueString()
	}
	if !m.APSSHPublicKeys.IsNull() && !m.APSSHPublicKeys.IsUnknown() {
		var keys []string
		d.Append(m.APSSHPublicKeys.ElementsAs(ctx, &keys, false)...)
		doc.APSSHPublicKeys = keys
	}
	if !m.APSSHDisablePassword.IsNull() && !m.APSSHDisablePassword.IsUnknown() {
		doc.APSSHDisablePassword = m.APSSHDisablePassword.ValueBool()
	}
	return doc
}

// viewToModel copies the server's read view into the model. The four
// attributes are Optional-only (no Computed, no schema default), so the
// unset echo must map back to null to keep an omitted config drift-free —
// the same empty-to-null mapping applyDevice (name) and entryToModel
// (passphrase) use, for the same reason: Terraform enforces plan-vs-state
// equality on non-Computed optionals, and writing a concrete zero into
// state under a null plan would diff forever. Set values pass through
// verbatim. Mapping detail: 0→null country, ""→null password, empty
// key list→null, false→null disable.
func viewToModel(ctx context.Context, v *siteSettings, m *siteSettingsModel) {
	m.ID = types.StringValue(siteSettingsID)
	if v.RegulatoryCountryCode != 0 {
		m.RegulatoryCountryCode = types.Int64Value(int64(v.RegulatoryCountryCode))
	} else {
		m.RegulatoryCountryCode = types.Int64Null()
	}
	if v.APSSHPassword != "" {
		m.APSSHPassword = types.StringValue(v.APSSHPassword)
	} else {
		m.APSSHPassword = types.StringNull()
	}
	if len(v.APSSHPublicKeys) > 0 {
		// []string elements cannot fail conversion; diags are always empty.
		list, _ := types.ListValueFrom(ctx, types.StringType, v.APSSHPublicKeys)
		m.APSSHPublicKeys = list
	} else {
		m.APSSHPublicKeys = types.ListNull(types.StringType)
	}
	if v.APSSHDisablePassword {
		m.APSSHDisablePassword = types.BoolValue(true)
	} else {
		m.APSSHDisablePassword = types.BoolNull()
	}
}

// readSiteSettingsInto refreshes the model from the controller's view.
func readSiteSettingsInto(ctx context.Context, c *apiClient, m *siteSettingsModel) error {
	view, err := c.getSiteSettings(ctx)
	if err != nil {
		return err
	}
	viewToModel(ctx, view, m)
	return nil
}

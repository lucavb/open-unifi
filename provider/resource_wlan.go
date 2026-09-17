package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = (*wlanResource)(nil)
var _ resource.ResourceWithConfigure = (*wlanResource)(nil)
var _ resource.ResourceWithImportState = (*wlanResource)(nil)

// wlanResource manages one WLAN inside the controller's wireless config.
type wlanResource struct {
	client *apiClient
}

func (r *wlanResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wlan"
}

func (r *wlanResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		if c, ok := req.ProviderData.(*apiClient); ok {
			r.client = c
		}
	}
}

func (r *wlanResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A WLAN (wifi network) on the open-unifi control plane, keyed by `name`. " +
			"Plan diffs for `passphrase` render as `(sensitive value)`.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "Unique name of this wlan; doubles as the resource's `id` (slug). Immutable.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ssid": schema.StringAttribute{
				MarkdownDescription: "Broadcast SSID. Required; must also be unique among wlans.",
				Required:            true,
			},
			"security": schema.StringAttribute{
				MarkdownDescription: "One of `open` or `wpa-p` (WPA2 personal, needs passphrase).",
				Required:            true,
			},
			"passphrase": schema.StringAttribute{
				MarkdownDescription: "Pre-shared key for `wpa-p`. Required to be nonempty and >= 8 chars " +
					"when security != `open`; ignored otherwise. Shown as `(sensitive value)` in plan diffs.",
				Optional:  true,
				Sensitive: true,
			},
			"vlan": schema.Int64Attribute{
				MarkdownDescription: "Tagged VLAN id, 1..4094. Unset defaults to 1 (native).",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(1),
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the wlan broadcasts. Defaults to true.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"band": schema.StringAttribute{MarkdownDescription: "Radio band: `2g`, `5g`, or `both`.", Optional: true, Computed: true, Default: stringdefault.StaticString("both")},
			"id": schema.StringAttribute{
				MarkdownDescription: "Resource id = the wlan name.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// wlanModel is the Terraform state shape for the wlan resource.
type wlanModel struct {
	ID         types.String `tfsdk:"id"`
	Name       types.String `tfsdk:"name"`
	SSID       types.String `tfsdk:"ssid"`
	Security   types.String `tfsdk:"security"`
	Passphrase types.String `tfsdk:"passphrase"`
	VLAN       types.Int64  `tfsdk:"vlan"`
	Enabled    types.Bool   `tfsdk:"enabled"`
	Band       types.String `tfsdk:"band"`
}

// checkWlanConflicts enforces the name/ssid uniqueness rules the envelope
// (and every PUT) depends on: one resource per wlan `name`, globally unique
// SSIDs. selfIdx (the entry currently being updated; -1 on Create) is
// excluded so an update does not collide with itself.
func (r *wlanResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var plan wlanModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.validateWlan(&plan, &resp.Diagnostics) {
		return
	}

	entry := wlanEntryFromModel(&plan)
	if err := r.client.createWireless(ctx, &entry); err != nil {
		resp.Diagnostics.AddError("Create wlan", err.Error())
		return
	}

	// Read-back makes the state match server-normalized truth.
	if err := readWlanInto(ctx, r.client, &plan); err != nil {
		resp.Diagnostics.AddError("Create wlan: post-create read", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *wlanResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var state wlanModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	entry, err := r.client.getWireless(ctx, state.Name.ValueString())
	if errNotFound(err) {
		// Missing = gone: remove from state so Terraform plans re-create.
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Read wlan", err.Error())
		return
	}
	entryToModel(entry, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *wlanResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var plan wlanModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.validateWlan(&plan, &resp.Diagnostics) {
		return
	}
	entry := wlanEntryFromModel(&plan)
	plan.ID = types.StringValue(plan.Name.ValueString())
	if err := r.client.updateWireless(ctx, plan.Name.ValueString(), &entry); err != nil {
		resp.Diagnostics.AddError("Update wlan", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *wlanResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var state wlanModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.deleteWireless(ctx, state.Name.ValueString()); err != nil && !errNotFound(err) {
		resp.Diagnostics.AddError("Delete wlan", err.Error())
		return
	}
}

// --- helpers ------------------------------------------------------------

// wlanEntryFromModel converts Terraform state into a server entry. When
// security is "open" the passphrase is dropped: the server rejects any PUT
// with "passphrase must be empty when security is open".
func wlanEntryFromModel(m *wlanModel) wirelessEntry {
	e := wirelessEntry{
		Name:     m.Name.ValueString(),
		SSID:     m.SSID.ValueString(),
		Security: m.Security.ValueString(),
		Enabled:  true,
		Band:     m.Band.ValueString(),
	}
	if !m.VLAN.IsNull() && !m.VLAN.IsUnknown() {
		e.VLAN = int(m.VLAN.ValueInt64())
	}
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		e.Enabled = m.Enabled.ValueBool()
	}
	if !m.Passphrase.IsNull() && !m.Passphrase.IsUnknown() && m.Passphrase.ValueString() != "" {
		e.Passphrase = m.Passphrase.ValueString()
	}
	if e.Security == "open" {
		e.Passphrase = ""
	}
	return e
}

// entryToModel copies a server entry into the model. The server DOES echo
// passphrase contents back (they are part of the stored whole-document
// wireless config), so server truth wins: a non-empty server passphrase
// replaces the model's sensitive value; an empty one (security=open, or the
// operator cleared it) renders as null. The framework rewrites `sensitive`
// in plan diffs; state round-trips the real value.
func entryToModel(e *wirelessEntry, m *wlanModel) {
	m.ID = types.StringValue(e.Name)
	m.Name = types.StringValue(e.Name)
	m.SSID = types.StringValue(e.SSID)
	m.Security = types.StringValue(e.Security)
	if e.VLAN != 0 {
		m.VLAN = types.Int64Value(int64(e.VLAN))
	} else {
		m.VLAN = types.Int64Value(1)
	}
	m.Enabled = types.BoolValue(e.Enabled)
	if e.Band == "" {
		e.Band = "both"
	}
	m.Band = types.StringValue(e.Band)
	if e.Passphrase != "" {
		m.Passphrase = types.StringValue(e.Passphrase)
	} else {
		m.Passphrase = types.StringNull()
	}
}

// readWlanInto refreshes plan/state from the server for the wlan named by m.
func readWlanInto(ctx context.Context, c *apiClient, m *wlanModel) error {
	entry, err := c.getWireless(ctx, m.Name.ValueString())
	if err != nil {
		return err
	}
	entryToModel(entry, m)
	return nil
}

// validateWlan mirrors the server's rules (internal/adminapi/helpers.go
// validateWlan: security enum, ssid length 1..32, vlan 1..4094, passphrase
// empty for open / >=8 chars otherwise) so clients get an attribute-level
// error at plan/validate time instead of a mid-apply HTTP 400. Deliberately
// NOT full lockstep: the server additionally rejects control characters in
// ssid/name/passphrase and unsafe wlan IDs (defense-in-depth against
// system_cfg row injection, helpers.go hasControlChar/validateWlanID) —
// those checks stay server-side-only.
func (r *wlanResource) validateWlan(m *wlanModel, d *diag.Diagnostics) bool {
	band := m.Band.ValueString()
	if band != "2g" && band != "5g" && band != "both" {
		d.AddAttributeError(path.Root("band"), "Invalid band", "band must be one of 2g|5g|both")
		return false
	}
	sec := m.Security.ValueString()
	switch sec {
	case "open", "wpa-p":
	default:
		d.AddAttributeError(path.Root("security"),
			"Invalid security value",
			fmt.Sprintf("security must be one of open|wpa-p, got %q", sec))
		return false
	}
	name := m.Name.ValueString()
	if strings.TrimSpace(name) == "" {
		d.AddAttributeError(path.Root("name"), "Invalid name", "wlan name must be non-empty")
		return false
	}
	if n := len(m.SSID.ValueString()); n < 1 || n > 32 {
		d.AddAttributeError(path.Root("ssid"), "Invalid ssid",
			fmt.Sprintf("ssid length must be 1..32, got %d", n))
		return false
	}
	if !m.VLAN.IsNull() && !m.VLAN.IsUnknown() {
		v := m.VLAN.ValueInt64()
		if v < 1 || v > 4094 {
			d.AddAttributeError(path.Root("vlan"), "Invalid vlan",
				fmt.Sprintf("vlan must be in 1..4094, got %d", v))
			return false
		}
	}
	psk := ""
	if !m.Passphrase.IsNull() && !m.Passphrase.IsUnknown() {
		psk = m.Passphrase.ValueString()
	}
	if sec == "open" {
		if psk != "" {
			d.AddAttributeError(path.Root("passphrase"),
				"Invalid passphrase",
				"passphrase must be empty when security is open")
			return false
		}
		return true
	}
	if len(psk) < 8 {
		d.AddAttributeError(path.Root("passphrase"),
			"Invalid passphrase",
			fmt.Sprintf("passphrase must be nonempty and at least 8 characters for security=%s", sec))
		return false
	}
	return true
}

func (r *wlanResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	if !resp.Diagnostics.HasError() {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	}
}

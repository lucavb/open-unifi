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

// wlanResource manages one WLAN on a single device (PUT/GET/DELETE
// /api/v1/devices/{mac}/wireless/{name}).
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
		MarkdownDescription: "A WLAN on one open-unifi device, keyed by `device_mac` and wlan `name`. " +
			"WLAN intent is per AP (`/api/v1/devices/{mac}/wireless`). Plan diffs for `passphrase` render as `(sensitive value)`.",
		Attributes: map[string]schema.Attribute{
			"device_mac": schema.StringAttribute{
				MarkdownDescription: "MAC of the device that owns this WLAN, lowercase colon format. Immutable.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Unique wlan name on this device; doubles as the import slug. Immutable.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"ssid": schema.StringAttribute{
				MarkdownDescription: "Broadcast SSID. Required; must be unique among wlans on this device.",
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
				MarkdownDescription: "Resource id = `{device_mac}/{name}`.",
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

type wlanModel struct {
	ID         types.String `tfsdk:"id"`
	DeviceMac  types.String `tfsdk:"device_mac"`
	Name       types.String `tfsdk:"name"`
	SSID       types.String `tfsdk:"ssid"`
	Security   types.String `tfsdk:"security"`
	Passphrase types.String `tfsdk:"passphrase"`
	VLAN       types.Int64  `tfsdk:"vlan"`
	Enabled    types.Bool   `tfsdk:"enabled"`
	Band       types.String `tfsdk:"band"`
}

func wlanID(mac, name string) string {
	return mac + "/" + name
}

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

	mac := plan.DeviceMac.ValueString()
	entry := wlanEntryFromModel(&plan)
	if err := r.client.createWireless(ctx, mac, &entry); err != nil {
		resp.Diagnostics.AddError("Create wlan", err.Error())
		return
	}

	if err := readWlanInto(ctx, r.client, mac, &plan); err != nil {
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
	mac := state.DeviceMac.ValueString()
	entry, err := r.client.getWireless(ctx, mac, state.Name.ValueString())
	if errNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Read wlan", err.Error())
		return
	}
	entryToModel(mac, entry, &state)
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
	mac := plan.DeviceMac.ValueString()
	entry := wlanEntryFromModel(&plan)
	plan.ID = types.StringValue(wlanID(mac, plan.Name.ValueString()))
	if err := r.client.updateWireless(ctx, mac, plan.Name.ValueString(), &entry); err != nil {
		resp.Diagnostics.AddError("Update wlan", err.Error())
		return
	}
	if err := readWlanInto(ctx, r.client, mac, &plan); err != nil {
		resp.Diagnostics.AddError("Update wlan: post-update read", err.Error())
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
	if err := r.client.deleteWireless(ctx, state.DeviceMac.ValueString(), state.Name.ValueString()); err != nil && !errNotFound(err) {
		resp.Diagnostics.AddError("Delete wlan", err.Error())
		return
	}
}

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

func entryToModel(mac string, e *wirelessEntry, m *wlanModel) {
	m.ID = types.StringValue(wlanID(mac, e.Name))
	m.DeviceMac = types.StringValue(mac)
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

func readWlanInto(ctx context.Context, c *apiClient, mac string, m *wlanModel) error {
	entry, err := c.getWireless(ctx, mac, m.Name.ValueString())
	if err != nil {
		return err
	}
	entryToModel(mac, entry, m)
	return nil
}

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
	parts := strings.Split(req.ID, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError(
			"Invalid import id",
			"Import id must be {device_mac}/{wlan_name}, e.g. fc:ec:da:a9:60:75/dummy",
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("device_mac"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}

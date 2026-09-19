package provider

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = (*accessPointResource)(nil)
var _ resource.ResourceWithConfigure = (*accessPointResource)(nil)
var _ resource.ResourceWithImportState = (*accessPointResource)(nil)

// accessPointResource manages one registered access point, keyed by MAC
// address (lowercase, colon separated, e.g. "78:8a:20:00:00:01"). The MAC
// format's lowercase form is a client-side convention documented in the
// schema; use lowercase HCL so plan/apply stays deterministic.
type accessPointResource struct {
	client *apiClient
}

func (r *accessPointResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_access_point"
}

func (r *accessPointResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		if c, ok := req.ProviderData.(*apiClient); ok {
			r.client = c
		}
	}
}

func (r *accessPointResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An access point registered with the open-unifi control plane, identified by MAC address. " +
			"`mac` must be lowercase colon-separated (e.g. `78:8a:20:11:22:33`).",
		Attributes: map[string]schema.Attribute{
			"mac": schema.StringAttribute{
				MarkdownDescription: "Device MAC address, lowercase colon format. Required and immutable.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Human-friendly device name.",
				Optional:            true,
			},
			"site_id": schema.StringAttribute{
				MarkdownDescription: "Site the device is created in. Defaults to `default`.",
				Optional:            true,
				Computed:            true,
			},
			"state": schema.StringAttribute{
				MarkdownDescription: "Computed device state: `pending`, `adopting`, `adopted`, or `lost`.",
				Computed:            true,
			},
			"ip": schema.StringAttribute{
				MarkdownDescription: "Computed IP address reported by the device, if any.",
				Computed:            true,
			},
			"firmware": schema.StringAttribute{
				MarkdownDescription: "Computed firmware version string.",
				Computed:            true,
			},
			"last_seen": schema.StringAttribute{
				MarkdownDescription: "Computed last-seen timestamp as reported by the server.",
				Computed:            true,
			},
			"cfg_version": schema.StringAttribute{
				MarkdownDescription: "Computed desired configuration version last sent by the server, if available.",
				Computed:            true,
			},
			"applied_cfg": schema.StringAttribute{
				MarkdownDescription: "Computed configuration version last reported by the device, if available.",
				Computed:            true,
			},
			"in_sync": schema.BoolAttribute{
				MarkdownDescription: "Computed runtime WLAN synchronization status. True only when the latest AP VAP report proves enabled desired WLANs are RUN and deletions are gone; null when runtime evidence is unavailable.",
				Computed:            true,
			},
			"wlan_delivery_status": schema.StringAttribute{MarkdownDescription: "Computed WLAN delivery status: pending, exhausted, or confirmed.", Computed: true},
			"wlan_delivery_count":  schema.Int64Attribute{MarkdownDescription: "Computed number of WLAN configuration delivery attempts.", Computed: true},
			"wlan_last_attempt":    schema.Int64Attribute{MarkdownDescription: "Computed Unix timestamp of the last WLAN delivery attempt.", Computed: true},
		},
	}
}

// apDevice mirrors the JSON of GET /api/v1/devices/{mac}
// (adminapi.DeviceView). The server encodes `state` as a JSON number and
// `last_seen` as a unix-seconds int64; site_id is request-only and never
// appears in a response body, so it is deliberately absent here.
type apDevice struct {
	Mac                string `json:"mac"`
	Name               string `json:"name"`
	Model              string `json:"model,omitempty"`
	State              int    `json:"state"`
	IP                 string `json:"ip,omitempty"`
	Firmware           string `json:"firmware,omitempty"`
	LastSeen           int64  `json:"last_seen,omitempty"`
	CfgVersion         string `json:"cfg_version,omitempty"`
	AppliedCfg         string `json:"applied_cfg,omitempty"`
	InSync             *bool  `json:"in_sync,omitempty"`
	WLANDeliveryStatus string `json:"wlan_delivery_status,omitempty"`
	WLANDeliveryCount  int    `json:"wlan_delivery_count,omitempty"`
	WLANLastAttempt    int64  `json:"wlan_last_attempt,omitempty"`
	SiteID             string `json:"site_id,omitempty"`
	LEDOverride        string `json:"led_override,omitempty"`
	PendingCommand     string `json:"pending_command,omitempty"`
}

func (r *accessPointResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var plan apModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	site := "default"
	if !plan.SiteID.IsNull() && !plan.SiteID.IsUnknown() {
		site = plan.SiteID.ValueString()
	}
	body := map[string]string{"mac": plan.Mac.ValueString(), "site_id": site}
	if !plan.Name.IsNull() && !plan.Name.IsUnknown() {
		body["name"] = plan.Name.ValueString()
	}

	// POST once; no retry (see client.go). If the create succeeded but the
	// read below fails, the next plan/apply reconciles via the Read path.
	if err := r.client.do(ctx, http.MethodPost, "/api/v1/devices", body, nil); err != nil {
		resp.Diagnostics.AddError("Create access point", err.Error())
		return
	}

	// Read the created device to populate computed fields (state, ip,
	// firmware, last_seen).
	dev, err := r.client.getDevice(ctx, plan.Mac.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Create access point: post-create read", err.Error())
		return
	}
	applyDevice(&plan, dev, site)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *accessPointResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var state apModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	dev, err := r.client.getDevice(ctx, state.Mac.ValueString())
	switch {
	case err == nil:
		applyDevice(&state, dev, state.SiteID.ValueString())
	case errNotFound(err):
		// Device is gone server-side: remove from state so Terraform
		// plans a re-create.
		resp.State.RemoveResource(ctx)
		return
	default:
		resp.Diagnostics.AddError("Read access point", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *accessPointResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var plan apModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state apModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := accessPointUpdateBody(plan, state)
	if len(body) > 0 {
		if err := r.client.do(ctx, http.MethodPatch, "/api/v1/devices/"+url.PathEscape(state.Mac.ValueString()), body, nil); err != nil {
			resp.Diagnostics.AddError("Update access point", err.Error())
			return
		}
	}
	dev, err := r.client.getDevice(ctx, state.Mac.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Update access point", err.Error())
		return
	}
	applyDevice(&state, dev, state.SiteID.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *accessPointResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.client == nil {
		notConfiguredErr(&resp.Diagnostics)
		return
	}
	var state apModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// The MAC is path-escaped (getDevice does the same for GET reads) so an
	// unvalidated state value cannot add path segments to the DELETE URL.
	if err := r.client.do(ctx, http.MethodDelete, "/api/v1/devices/"+url.PathEscape(state.Mac.ValueString()), nil, nil); err != nil {
		// 404 => already gone: treat as success (deletion is idempotent).
		if !errNotFound(err) {
			resp.Diagnostics.AddError("Delete access point", err.Error())
			return
		}
	}
}

// apModel is the Terraform state shape for the access point resource.
type apModel struct {
	Mac                types.String `tfsdk:"mac"`
	Name               types.String `tfsdk:"name"`
	SiteID             types.String `tfsdk:"site_id"`
	State              types.String `tfsdk:"state"`
	IP                 types.String `tfsdk:"ip"`
	Firmware           types.String `tfsdk:"firmware"`
	LastSeen           types.String `tfsdk:"last_seen"`
	CfgVersion         types.String `tfsdk:"cfg_version"`
	AppliedCfg         types.String `tfsdk:"applied_cfg"`
	InSync             types.Bool   `tfsdk:"in_sync"`
	WLANDeliveryStatus types.String `tfsdk:"wlan_delivery_status"`
	WLANDeliveryCount  types.Int64  `tfsdk:"wlan_delivery_count"`
	WLANLastAttempt    types.Int64  `tfsdk:"wlan_last_attempt"`
}

func notConfiguredErr(d interface {
	AddError(summary, detail string)
}) {
	d.AddError("Provider not configured", "Configure must set the API client before resource use.")
}

// applyDevice copies server truth into the Terraform model, mapping the
// server's numeric state into the TF vocabulary via stateName. Empty
// strings are tolerated (a pending/standalone device may not yet report an
// IP). `site` is the configured/request-only site_id: the server never
// echoes it back, so state keeps the configured value.
func applyDevice(m *apModel, dev *apDevice, site string) {
	if dev.SiteID != "" {
		site = dev.SiteID
	}
	m.SiteID = types.StringValue(site)
	m.State = types.StringValue(stateName(dev.State))
	m.IP = types.StringValue(dev.IP)
	m.Firmware = types.StringValue(dev.Firmware)
	if dev.LastSeen > 0 {
		m.LastSeen = types.StringValue(strconv.FormatInt(dev.LastSeen, 10))
	} else {
		m.LastSeen = types.StringValue("")
	}
	if dev.CfgVersion != "" {
		m.CfgVersion = types.StringValue(dev.CfgVersion)
	} else {
		m.CfgVersion = types.StringNull()
	}
	if dev.AppliedCfg != "" {
		m.AppliedCfg = types.StringValue(dev.AppliedCfg)
	} else {
		m.AppliedCfg = types.StringNull()
	}
	if dev.InSync != nil {
		m.InSync = types.BoolValue(*dev.InSync)
	} else {
		m.InSync = types.BoolNull()
	}
	m.WLANDeliveryStatus = types.StringValue(dev.WLANDeliveryStatus)
	m.WLANDeliveryCount = types.Int64Value(int64(dev.WLANDeliveryCount))
	m.WLANLastAttempt = types.Int64Value(dev.WLANLastAttempt)
	// "name" is Optional and NOT Computed (no ModifyPlan), so Terraform
	// enforces plan-vs-state equality on it. The server omits empty names
	// from DeviceView ("name,omitempty"), so an unset name round-trips as
	// ""; writing that back as types.StringValue("") would turn a null in
	// the plan into "" in state and trip terraform's "Provider produced
	// inconsistent result after apply" error. Map empty to null instead —
	// matching the null-vs-empty distinction the update body already makes.
	// NOTE: terraform-CLI end-to-end acceptance runs are not possible in the
	// nono sandbox (plugin unix sockets are denied); TODO(live-gate): cover the
	// create-without-name acceptance case in a networked environment.
	if dev.Name == "" {
		m.Name = types.StringNull()
	} else {
		m.Name = types.StringValue(dev.Name)
	}
}

func accessPointUpdateBody(plan, state apModel) map[string]string {
	body := map[string]string{}
	if !plan.Name.IsUnknown() && plan.Name.ValueString() != state.Name.ValueString() {
		// A null optional value means the configuration removed the name. The
		// PATCH API distinguishes an omitted name from an explicit empty name.
		body["name"] = plan.Name.ValueString()
	}
	if !plan.SiteID.IsNull() && !plan.SiteID.IsUnknown() && plan.SiteID.ValueString() != state.SiteID.ValueString() {
		body["site_id"] = plan.SiteID.ValueString()
	}
	return body
}

func (r *accessPointResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mac, err := normalizeMAC(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid access point import ID", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("mac"), mac)...)
}

func normalizeMAC(value string) (string, error) {
	m, err := net.ParseMAC(value)
	if err != nil || len(m) != 6 {
		return "", fmt.Errorf("%q is not a valid MAC address", value)
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]), nil
}

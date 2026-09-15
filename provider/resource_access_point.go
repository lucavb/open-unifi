package provider

import (
	"context"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = (*accessPointResource)(nil)
var _ resource.ResourceWithConfigure = (*accessPointResource)(nil)

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
				MarkdownDescription: "Human-friendly device name. " +
					"NOTE: the server has no PATCH today, so `name` is updatable_at_next_release — " +
					"changing it currently plans a change but applies no server-side rename.",
				Optional: true,
			},
			"site_id": schema.StringAttribute{
				MarkdownDescription: "Site the device is created in. Defaults to `default`.",
				Optional:            true,
				Computed:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
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
		},
	}
}

// apDevice mirrors the JSON of GET /api/v1/devices/{mac}
// (adminapi.DeviceView). The server encodes `state` as a JSON number and
// `last_seen` as a unix-seconds int64; site_id is request-only and never
// appears in a response body, so it is deliberately absent here.
type apDevice struct {
	Mac      string `json:"mac"`
	Name     string `json:"name"`
	Model    string `json:"model,omitempty"`
	State    int    `json:"state"`
	IP       string `json:"ip,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	LastSeen int64  `json:"last_seen,omitempty"`
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

// Update is a deliberate no-op rename: the admin API has no PATCH on
// devices, and emulating rename via DELETE+POST would destroy the device's
// adoption state. `_ = plan` keeps the framework contract; the live device
// state re-pulls server truth so computed fields stay fresh. The `name`
// attribute is documented as updatable_at_next_release in the schema.
//
// TODO(morning): implement rename via PATCH (or PUT) /api/v1/devices/{mac}
// once the server lane ships it; remove this comment then.
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
	_ = plan // name is updatable_at_next_release; see TODO above
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
	if err := r.client.do(ctx, http.MethodDelete, "/api/v1/devices/"+state.Mac.ValueString(), nil, nil); err != nil {
		// 404 => already gone: treat as success (deletion is idempotent).
		if !errNotFound(err) {
			resp.Diagnostics.AddError("Delete access point", err.Error())
			return
		}
	}
}

// apModel is the Terraform state shape for the access point resource.
type apModel struct {
	Mac      types.String `tfsdk:"mac"`
	Name     types.String `tfsdk:"name"`
	SiteID   types.String `tfsdk:"site_id"`
	State    types.String `tfsdk:"state"`
	IP       types.String `tfsdk:"ip"`
	Firmware types.String `tfsdk:"firmware"`
	LastSeen types.String `tfsdk:"last_seen"`
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
	m.SiteID = types.StringValue(site)
	m.State = types.StringValue(stateName(dev.State))
	m.IP = types.StringValue(dev.IP)
	m.Firmware = types.StringValue(dev.Firmware)
	if dev.LastSeen > 0 {
		m.LastSeen = types.StringValue(strconv.FormatInt(dev.LastSeen, 10))
	} else {
		m.LastSeen = types.StringValue("")
	}
	if dev.Name != "" {
		m.Name = types.StringValue(dev.Name)
	} else if m.Name.IsUnknown() {
		m.Name = types.StringNull()
	}
}

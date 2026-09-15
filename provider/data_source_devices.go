package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSource = (*devicesDataSource)(nil)
var _ datasource.DataSourceWithConfigure = (*devicesDataSource)(nil)

// devicesDataSource exposes the full device list as
// `data "open-unifi_devices" "all" {}`.
type devicesDataSource struct {
	client *apiClient
}

func (d *devicesDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_devices"
}

func (d *devicesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
	if req.ProviderData != nil {
		if c, ok := req.ProviderData.(*apiClient); ok {
			d.client = c
		}
	}
}

func (d *devicesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "All devices known to the open-unifi control plane, including pending " +
			"(not-yet-adopted) ones shown in `state = \"pending\"`.",
		Attributes: map[string]schema.Attribute{
			"devices": schema.ListNestedAttribute{
				MarkdownDescription: "Device list as reported by GET /api/v1/devices.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"mac": schema.StringAttribute{
							MarkdownDescription: "Device MAC address.",
							Computed:            true,
						},
						"name": schema.StringAttribute{
							MarkdownDescription: "Device name (may be empty for pending devices).",
							Computed:            true,
						},
						"model": schema.StringAttribute{
							MarkdownDescription: "Device model string, e.g. `UAP-AC-Pro-Gen2`.",
							Computed:            true,
						},
						"ip": schema.StringAttribute{
							MarkdownDescription: "Device IP address if reported.",
							Computed:            true,
						},
						"state": schema.StringAttribute{
							MarkdownDescription: "One of `pending`, `adopting`, `adopted`, `lost`.",
							Computed:            true,
						},
					},
				},
			},
		},
	}
}

type deviceItemModel struct {
	Mac   types.String `tfsdk:"mac"`
	Name  types.String `tfsdk:"name"`
	Model types.String `tfsdk:"model"`
	IP    types.String `tfsdk:"ip"`
	State types.String `tfsdk:"state"`
}

type devicesDataModel struct {
	Devices []deviceItemModel `tfsdk:"devices"`
}

func (d *devicesDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.client == nil {
		resp.Diagnostics.AddError("Provider not configured", "Configure must set the API client before data source use.")
		return
	}
	devs, err := d.client.listDevices(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Read devices data source", err.Error())
		return
	}
	var model devicesDataModel
	for _, dev := range devs {
		model.Devices = append(model.Devices, deviceItemModel{
			Mac:   types.StringValue(dev.Mac),
			Name:  types.StringValue(dev.Name),
			Model: types.StringValue(dev.Model),
			IP:    types.StringValue(dev.IP),
			State: types.StringValue(stateName(dev.State)),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

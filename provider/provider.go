// Package provider implements the open-unifi Terraform provider on top of
// terraform-plugin-framework. It talks to the minimal control plane's admin
// API (docs/PROTOCOL.md §6 "internal/adminapi (lane D)"): a plain JSON REST
// surface under /api/v1 with optional bearer-token auth.
package provider

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	provschema "github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure interfaces.
var (
	_ provider.Provider = (*openUnifiProvider)(nil)
)

type openUnifiProvider struct{}

func New() provider.Provider { return &openUnifiProvider{} }

func (p *openUnifiProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "open-unifi"
}

func (p *openUnifiProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = provschema.Schema{
		MarkdownDescription: "Terraform provider for the open-unifi minimal UniFi control plane (UAP-AC-Pro-Gen2).",
		Attributes: map[string]provschema.Attribute{
			"url": schema.StringAttribute{
				MarkdownDescription: "Base URL of the open-unifi admin API, e.g. `https://192.168.1.2`.",
				Required:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "Bearer token matching the server's `--admin-token`. Omit when the server runs anonymous.",
				Optional:            true,
				Sensitive:           true,
			},
			"insecure_skip_verify": schema.BoolAttribute{
				MarkdownDescription: "Skip TLS certificate verification against the controller (dev/self-signed setups).",
				Optional:            true,
			},
		},
	}
}

func (p *openUnifiProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg struct {
		URL                types.String `tfsdk:"url"`
		Token              types.String `tfsdk:"token"`
		InsecureSkipVerify types.Bool   `tfsdk:"insecure_skip_verify"`
	}
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if cfg.URL.IsUnknown() || cfg.URL.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("url"),
			"Missing controller URL",
			"The provider attribute `url` must be set, e.g. `url = \"https://192.168.1.2\"`.",
		)
		return
	}

	token := ""
	if !cfg.Token.IsNull() && !cfg.Token.IsUnknown() {
		token = cfg.Token.ValueString()
	}
	// Environment escape hatch for CI so tokens never land in state files.
	if token == "" {
		token = os.Getenv("OPEN_UNIFI_ADMIN_TOKEN")
	}
	insecure := false
	if !cfg.InsecureSkipVerify.IsNull() && !cfg.InsecureSkipVerify.IsUnknown() {
		insecure = cfg.InsecureSkipVerify.ValueBool()
	}

	client := newAPIClient(cfg.URL.ValueString(), token, insecure)

	// Configure-time connectivity/auth probe: GET /api/v1/whoami always
	// exists on an open-unifi admin API, so this catches unreachable
	// controllers, wrong ports, missing/renamed API routes (404), auth
	// rejections (401), and protocol mismatches (decode errors) up front.
	// The authConfigured result is logged only — token validity against a
	// token-less server is the operator's call; resources will error if a
	// real request is rejected.
	if err := client.checkConnectivity(ctx); err != nil {
		resp.Diagnostics.AddError(
			"Unreachable open-unifi admin API",
			fmt.Sprintf("probing %s/api/v1/whoami failed: %s", strings.TrimRight(cfg.URL.ValueString(), "/"), err.Error()),
		)
		return
	}

	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *openUnifiProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		func() resource.Resource { return &accessPointResource{} },
		func() resource.Resource { return &wlanResource{} },
	}
}

func (p *openUnifiProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		func() datasource.DataSource { return &devicesDataSource{} },
	}
}

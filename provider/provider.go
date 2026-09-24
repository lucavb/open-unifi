// Package provider implements the open-unifi Terraform provider on top of
// terraform-plugin-framework. It talks to the minimal control plane's admin
// API (docs/PROTOCOL.md §6 "internal/adminapi (lane D)"): a plain JSON REST
// surface under /api/v1 with optional bearer-token auth.
package provider

import (
	"context"
	"fmt"
	"net/url"
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

func validateProviderURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u == nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("must be an absolute http or https URL with a host")
	}
	if u.User != nil {
		return fmt.Errorf("must not contain userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("must not contain a query or fragment")
	}
	if strings.Trim(u.Path, "/") != "" && strings.Trim(u.Path, "/") != "api" {
		return fmt.Errorf("must be a controller base URL, not an API resource path")
	}
	return nil
}

func New() provider.Provider { return &openUnifiProvider{} }

func (p *openUnifiProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "open-unifi"
}

func (p *openUnifiProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = provschema.Schema{
		MarkdownDescription: "Terraform provider for the open-unifi minimal UniFi control plane (UAP-AC-Pro-Gen2).",
		Attributes: map[string]provschema.Attribute{
			"url": schema.StringAttribute{
				MarkdownDescription: "Base URL of the open-unifi admin API, e.g. `http://192.168.1.2:8443` (plain HTTP: no TLS yet — front-load TLS via a reverse proxy if needed).",
				Required:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "Bearer token matching the server's `--admin-token`. Omit when the server runs anonymous.",
				Optional:            true,
				Sensitive:           true,
			},
			"insecure_skip_verify": schema.BoolAttribute{
				MarkdownDescription: "Skip TLS certificate verification against the controller (only relevant for `https://` URLs; the controller serves plain HTTP today). Dev/self-signed setups.",
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
			"The provider attribute `url` must be set, e.g. `url = \"http://192.168.1.2:8443\"`.",
		)
		return
	}
	if err := validateProviderURL(cfg.URL.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(path.Root("url"), "Invalid controller URL", fmt.Sprintf("The provider attribute `url` %s.", err))
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
		func() resource.Resource { return &deviceResource{} },
		func() resource.Resource { return &wlanResource{} },
	}
}

func (p *openUnifiProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		func() datasource.DataSource { return &devicesDataSource{} },
	}
}

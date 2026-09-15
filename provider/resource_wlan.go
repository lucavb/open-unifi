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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = (*wlanResource)(nil)
var _ resource.ResourceWithConfigure = (*wlanResource)(nil)

// wlanResource manages one WLAN inside the controller's wireless config.
//
// IMPORTANT server constraint: the admin API exposes wireless as a
// WHOLE-document upsert (GET/PUT /api/v1/wireless with {"wlans":[...]}).
// To keep per-resource semantics safe, this resource uses a
// single-source-of-truth strategy built on read-modify-write of the
// envelope:
//
//   - id := the wlan `name` (the slug / key within the envelope)
//   - Create: GET envelope; if a wlan with the same name OR ssid already
//     exists -> error (a name-clone of a wifi resource is fine, but two
//     resources claiming the same wlan would fight on every PUT); else
//     append and PUT.
//   - Read: GET envelope; match by name; missing -> resource is gone, drop
//     from state.
//   - Update: GET envelope; replace the matching entry in place; PUT.
//   - Delete: GET envelope; drop the matching entry; PUT.
//
// Serialized applies are expected (normal Terraform behavior); concurrent
// non-Terraform writers of the envelope will race with the read-modify-
// write, which is why idempotent-retry guidance in client.go forbids
// retrying PUTs.
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
		MarkdownDescription: "A WLAN (wifi network) on the open-unifi control plane.\n\n" +
			"The server models wireless configuration as a single document, so each " +
			"`open-unifi_wlan` resource maps to exactly one entry in that document, keyed by `name`. " +
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
				MarkdownDescription: "One of `open`, `wpa-p` (WPA2 personal, needs passphrase), `wpa-eap` (enterprise; RADIUS handled server-side).",
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

	env, err := r.client.getWireless(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Create wlan: read envelope", err.Error())
		return
	}
	for i := range env.Wlans {
		if env.Wlans[i].Name == plan.Name.ValueString() {
			resp.Diagnostics.AddError("Create wlan",
				fmt.Sprintf("wlan %q already exists on the controller (id %q); import it instead of re-creating",
					plan.Name.ValueString(), env.Wlans[i].ID))
			return
		}
		if env.Wlans[i].SSID == plan.SSID.ValueString() {
			resp.Diagnostics.AddError("Create wlan",
				fmt.Sprintf("ssid %q is already broadcast by wlan %q; SSIDs must be unique",
					plan.SSID.ValueString(), env.Wlans[i].Name))
			return
		}
	}

	entry := wlanEntryFromModel(&plan)
	env.Wlans = append(env.Wlans, entry)

	// No retry on PUT: a blind replay could clobber concurrent envelope
	// writers (see wlanResource doc comment).
	if err := r.client.putWireless(ctx, env); err != nil {
		resp.Diagnostics.AddError("Create wlan: PUT envelope", err.Error())
		return
	}

	// Read-back makes the state match server-normalized truth.
	if err := readWlanInto(ctx, r.client, &plan); err != nil {
		resp.Diagnostics.AddError("Create wlan: post-PUT read", err.Error())
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
	env, err := r.client.getWireless(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Read wlan", err.Error())
		return
	}
	idx := findWlan(env, state.Name.ValueString())
	if idx < 0 {
		// Missing = gone: remove from state so Terraform plans re-create.
		resp.State.RemoveResource(ctx)
		return
	}
	entryToModel(&env.Wlans[idx], &state, true /*keepPassphrase*/)
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
	env, err := r.client.getWireless(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Update wlan: read envelope", err.Error())
		return
	}
	idx := findWlan(env, plan.Name.ValueString())
	if idx < 0 {
		resp.Diagnostics.AddError("Update wlan",
			fmt.Sprintf("wlan %q disappeared from the controller; re-apply to re-create it", plan.Name.ValueString()))
		return
	}
	// Replace in place, preserving the server-assigned id slot.
	plan.ID = types.StringValue(plan.Name.ValueString())
	env.Wlans[idx] = wlanEntryFromModel(&plan)
	if err := r.client.putWireless(ctx, env); err != nil {
		resp.Diagnostics.AddError("Update wlan: PUT envelope", err.Error())
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
	env, err := r.client.getWireless(ctx)
	if err != nil {
		// If the whole envelope is gone/unreachable with 404 semantics,
		// deletion has nothing left to remove.
		if errNotFound(err) {
			return
		}
		resp.Diagnostics.AddError("Delete wlan: read envelope", err.Error())
		return
	}
	idx := findWlan(env, state.Name.ValueString())
	if idx < 0 {
		return // already gone: idempotent delete
	}
	env.Wlans = append(env.Wlans[:idx], env.Wlans[idx+1:]...)
	if err := r.client.putWireless(ctx, env); err != nil {
		resp.Diagnostics.AddError("Delete wlan: PUT envelope", err.Error())
		return
	}
}

// --- helpers ------------------------------------------------------------

func findWlan(env *wirelessEnvelope, name string) int {
	for i := range env.Wlans {
		if env.Wlans[i].Name == name {
			return i
		}
	}
	return -1
}

// wlanEntryFromModel converts Terraform state into a server entry. An
// unset/unknown passphrase is dropped so the server never stores placeholder
// secrets for open networks.
func wlanEntryFromModel(m *wlanModel) wirelessEntry {
	e := wirelessEntry{
		Name:     m.Name.ValueString(),
		SSID:     m.SSID.ValueString(),
		Security: m.Security.ValueString(),
		Enabled:  true,
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
	return e
}

// entryToModel copies a server entry into the model. When keepPassphrase is
// true the model's existing (sensitive) passphrase is kept if the server
// returns an empty one — the server never echoes psk contents back for
// wpa-p entries, so treat "server said nothing" as "unchanged".
func entryToModel(e *wirelessEntry, m *wlanModel, keepPassphrase bool) {
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
	if e.Passphrase != "" {
		m.Passphrase = types.StringValue(e.Passphrase)
	} else if m.Passphrase.IsUnknown() || (!keepPassphrase) {
		m.Passphrase = types.StringNull()
	}
}

// readWlanInto refreshes plan/state from the server for the wlan named by m.
func readWlanInto(ctx context.Context, c *apiClient, m *wlanModel) error {
	env, err := c.getWireless(ctx)
	if err != nil {
		return err
	}
	idx := findWlan(env, m.Name.ValueString())
	if idx < 0 {
		return fmt.Errorf("wlan %q not present in envelope after PUT", m.Name.ValueString())
	}
	entryToModel(&env.Wlans[idx], m, true)
	return nil
}

// validateWlan enforces client-side invariants the server does not reject
// politely today (bad security enum, too-short psk, out-of-range vlan).
func (r *wlanResource) validateWlan(m *wlanModel, d *diag.Diagnostics) bool {
	sec := m.Security.ValueString()
	switch sec {
	case "open", "wpa-p", "wpa-eap":
	default:
		d.AddAttributeError(path.Root("security"),
			"Invalid security value",
			fmt.Sprintf("security must be one of open|wpa-p|wpa-eap, got %q", sec))
		return false
	}
	name := m.Name.ValueString()
	if strings.TrimSpace(name) == "" {
		d.AddAttributeError(path.Root("name"), "Invalid name", "wlan name must be non-empty")
		return false
	}
	if sec == "wpa-p" {
		psk := ""
		if !m.Passphrase.IsNull() && !m.Passphrase.IsUnknown() {
			psk = m.Passphrase.ValueString()
		}
		if len(psk) < 8 {
			d.AddAttributeError(path.Root("passphrase"),
				"Invalid passphrase",
				"passphrase must be nonempty and at least 8 characters for security=wpa-p")
			return false
		}
	}
	if !m.VLAN.IsNull() && !m.VLAN.IsUnknown() {
		v := m.VLAN.ValueInt64()
		if v < 1 || v > 4094 {
			d.AddAttributeError(path.Root("vlan"), "Invalid vlan",
				fmt.Sprintf("vlan must be in 1..4094, got %d", v))
			return false
		}
	}
	return true
}

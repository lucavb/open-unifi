package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestApplyDeviceNameEmptyMapsToNull pins the empty-name mapping in
// applyDevice. The server's DeviceView omits empty names
// (json:"name,omitempty"), so a device registered without a name decodes to
// dev.Name == "". Since "name" is Optional and NOT Computed, Terraform
// compares plan and state strictly: writing "" into state when the plan had
// null trips "Provider produced inconsistent result after apply" (terraform
// 1.16 enforcement strings). The mapping must therefore emit StringNull for
// an empty server name, in every path that shares applyDevice (Create
// post-read, Read refresh, Update post-read, import re-read).
//
// terraform-CLI end-to-end acceptance coverage is not runnable in the nono
// sandbox (plugin unix sockets are denied); TODO(live-gate): add the
// create-without-name acceptance case in a networked environment.
func TestApplyDeviceNameEmptyMapsToNull(t *testing.T) {
	tests := []struct {
		name    string
		devName string
		want    types.String
	}{
		{name: "empty server name maps to null", devName: "", want: types.StringNull()},
		{name: "set server name maps to value", devName: "ap-lobby", want: types.StringValue("ap-lobby")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := apModel{Name: types.StringNull()} // plan/config had no name
			dev := &apDevice{Mac: "78:8a:20:11:22:33", Name: tt.devName}
			applyDevice(&m, dev, "default")
			if tt.want.IsNull() != m.Name.IsNull() {
				t.Fatalf("Name nullness = %v, want %v (value: %q)", m.Name.IsNull(), tt.want.IsNull(), m.Name.ValueString())
			}
			if !m.Name.IsNull() && m.Name.ValueString() != tt.want.ValueString() {
				t.Fatalf("Name = %q, want %q", m.Name.ValueString(), tt.want.ValueString())
			}
		})
	}
}

// TestAccessPointUpdateBodyPreservesNullName guards the pre-existing
// null-vs-empty distinction in the PATCH body: with the null name mapping
// in place, a null plan name against a null state name must still produce
// no PATCH (the value comparison is unchanged), and an explicitly set name
// still produces a name field.
func TestAccessPointUpdateBodyPreservesNullName(t *testing.T) {
	plan := apModel{Name: types.StringNull(), SiteID: types.StringNull()}
	state := apModel{Name: types.StringNull(), SiteID: types.StringNull()}
	if body := accessPointUpdateBody(plan, state); len(body) != 0 {
		t.Fatalf("null plan + null state: body = %v, want empty", body)
	}

	plan.Name = types.StringValue("renamed")
	body := accessPointUpdateBody(plan, state)
	if body["name"] != "renamed" {
		t.Fatalf("set plan name: body = %v, want name=renamed", body)
	}
}

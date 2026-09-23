package provider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func deviceTestPlan(t *testing.T, m deviceModel) tfsdk.Plan {
	t.Helper()
	r := &deviceResource{}
	var sr resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &sr)
	p := tfsdk.Plan{Schema: sr.Schema}
	if diags := p.Set(context.Background(), &m); diags.HasError() {
		t.Fatalf("build plan: %v", diags)
	}
	return p
}

func deviceTestState(t *testing.T, m deviceModel) tfsdk.State {
	t.Helper()
	r := &deviceResource{}
	var sr resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &sr)
	s := tfsdk.State{Schema: sr.Schema}
	if diags := s.Set(context.Background(), &m); diags.HasError() {
		t.Fatalf("build state: %v", diags)
	}
	return s
}

func TestDeviceCreateSSHPasswordLifecycleAgainstFakeBackend(t *testing.T) {
	for _, tc := range []struct {
		name     string
		password types.String
		want     string
	}{
		{name: "configured", password: types.StringValue("secret"), want: "secret"},
		{name: "absent clears", password: types.StringNull(), want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fb := newFakeBackend("")
			c := clientFor(fb, "")
			r := &deviceResource{client: c}
			mac := "78:8a:20:11:22:33"
			plan := deviceTestPlan(t, deviceModel{Mac: types.StringValue(mac), Name: types.StringValue("lab"), SiteID: types.StringValue("default"), SSHPassword: tc.password})
			resp := resource.CreateResponse{State: tfsdk.State{Schema: plan.Schema}}
			r.Create(context.Background(), resource.CreateRequest{Plan: plan}, &resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("create diagnostics: %v", resp.Diagnostics)
			}
			if got, want := fb.deviceEvents, []string{"POST", "PATCH", "GET"}; !equalStrings(got, want) {
				t.Fatalf("events = %v, want %v", got, want)
			}
			if _, ok := fb.deviceBodies[0]["ssh_password"]; ok {
				t.Fatal("registration POST included ssh_password")
			}
			var got string
			if err := json.Unmarshal(fb.deviceBodies[1]["ssh_password"], &got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("PATCH password = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDeviceUpdateSSHPasswordLifecycleAgainstFakeBackend(t *testing.T) {
	fb := newFakeBackend("")
	mac := "788a20112233"
	fb.devices[mac] = deviceJSON(mac, "lab")
	c := clientFor(fb, "")
	r := &deviceResource{client: c}
	stateModel := deviceModel{Mac: types.StringValue("78:8a:20:11:22:33"), Name: types.StringValue("lab"), SiteID: types.StringValue("default"), SSHPassword: types.StringValue("secret")}
	state := deviceTestState(t, stateModel)
	plan := deviceTestPlan(t, deviceModel{Mac: stateModel.Mac, Name: stateModel.Name, SiteID: stateModel.SiteID, SSHPassword: types.StringNull()})
	r.Update(context.Background(), resource.UpdateRequest{Plan: plan, State: state}, &resource.UpdateResponse{State: tfsdk.State{Schema: plan.Schema}})
	if len(fb.deviceEvents) != 2 || fb.deviceEvents[0] != "PATCH" || fb.deviceEvents[1] != "GET" {
		t.Fatalf("clear events = %v", fb.deviceEvents)
	}
	var cleared string
	if err := json.Unmarshal(fb.deviceBodies[0]["ssh_password"], &cleared); err != nil || cleared != "" {
		t.Fatalf("clear PATCH = %q, want empty", cleared)
	}

	fb.deviceEvents = nil
	fb.deviceBodies = nil
	unchanged := deviceTestPlan(t, deviceModel{Mac: stateModel.Mac, Name: stateModel.Name, SiteID: stateModel.SiteID, SSHPassword: types.StringValue("secret")})
	r.Update(context.Background(), resource.UpdateRequest{Plan: unchanged, State: deviceTestState(t, stateModel)}, &resource.UpdateResponse{State: tfsdk.State{Schema: unchanged.Schema}})
	if len(fb.deviceEvents) != 1 || fb.deviceEvents[0] != "GET" || len(fb.deviceBodies) != 0 {
		t.Fatalf("unchanged events=%v bodies=%v", fb.deviceEvents, fb.deviceBodies)
	}
}

func TestApplyDeviceSSHPasswordEchoMapsNullAndValue(t *testing.T) {
	for _, tc := range []struct {
		echo string
		null bool
	}{{"secret", false}, {"", true}} {
		m := deviceModel{}
		applyDevice(&m, &deviceView{SSHPassword: tc.echo}, "default")
		if m.SSHPassword.IsNull() != tc.null {
			t.Fatalf("echo %q null=%v, want %v", tc.echo, m.SSHPassword.IsNull(), tc.null)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

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
			m := deviceModel{Name: types.StringNull()} // plan/config had no name
			dev := &deviceView{Mac: "78:8a:20:11:22:33", Name: tt.devName}
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

// TestDeviceUpdateBodyPreservesNullName guards the pre-existing
// null-vs-empty distinction in the PATCH body: with the null name mapping
// in place, a null plan name against a null state name must still produce
// no PATCH (the value comparison is unchanged), and an explicitly set name
// still produces a name field.
func TestDeviceUpdateBodyPreservesNullName(t *testing.T) {
	plan := deviceModel{Name: types.StringNull(), SiteID: types.StringNull()}
	state := deviceModel{Name: types.StringNull(), SiteID: types.StringNull()}
	if body := deviceUpdateBody(plan, state); len(body) != 0 {
		t.Fatalf("null plan + null state: body = %v, want empty", body)
	}

	plan.Name = types.StringValue("renamed")
	body := deviceUpdateBody(plan, state)
	if body["name"] != "renamed" {
		t.Fatalf("set plan name: body = %v, want name=renamed", body)
	}
}

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func TestDeviceAndSiteSettingsRegistrationContract(t *testing.T) {
	p := New()
	var resources []resource.Resource
	for _, factory := range p.Resources(context.Background()) {
		resources = append(resources, factory())
	}
	seenDevice := false
	seenOldDevice := false
	for _, r := range resources {
		var metadata resource.MetadataResponse
		r.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "open-unifi"}, &metadata)
		var sr resource.SchemaResponse
		r.Schema(context.Background(), resource.SchemaRequest{}, &sr)
		if metadata.TypeName == "open-unifi_device" {
			seenDevice = true
			if _, ok := sr.Schema.Attributes["ssh_password"].(schema.StringAttribute); !ok {
				t.Fatal("device ssh_password is not a string attribute")
			}
			attr := sr.Schema.Attributes["ssh_password"].(schema.StringAttribute)
			if !attr.Optional || !attr.Sensitive {
				t.Fatalf("device ssh_password flags = optional:%v sensitive:%v", attr.Optional, attr.Sensitive)
			}
		}
		if metadata.TypeName == "open-unifi_access_point" {
			seenOldDevice = true
		}
		if metadata.TypeName == "open-unifi_site_settings" {
			if _, ok := sr.Schema.Attributes["device_ssh_public_keys"]; !ok {
				t.Fatal("site settings lacks device_ssh_public_keys")
			}
			for _, name := range []string{"ap_ssh_public_keys", "ap_ssh_password"} {
				if _, ok := sr.Schema.Attributes[name]; ok {
					t.Fatalf("site settings still contains removed attribute %q", name)
				}
			}
		}
	}
	if !seenDevice || seenOldDevice {
		t.Fatalf("device registration: new=%v old=%v", seenDevice, seenOldDevice)
	}
}

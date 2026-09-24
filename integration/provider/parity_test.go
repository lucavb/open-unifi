package provider_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/lucavb/open-unifi/internal/adminapi"
	tfprovider "github.com/lucavb/terraform-provider-open-unifi/provider"
)

func TestDeviceStructParityWithServer(t *testing.T) {
	serverOnly := map[string]bool{
		"actions": true,
	}

	serverFields := map[string]reflect.StructField{}
	st := reflect.TypeOf(adminapi.DeviceView{})
	for i := 0; i < st.NumField(); i++ {
		f := st.Field(i)
		key := strings.Split(f.Tag.Get("json"), ",")[0]
		serverFields[key] = f
	}

	listType, viewType := tfprovider.ContractDeviceWireTypes()
	provFields := map[string]map[string]string{}
	for _, pair := range []struct {
		name string
		typ  reflect.Type
	}{
		{"device", listType},
		{"deviceView", viewType},
	} {
		m := map[string]string{}
		for i := 0; i < pair.typ.NumField(); i++ {
			f := pair.typ.Field(i)
			tag := f.Tag.Get("json")
			key := strings.Split(tag, ",")[0]
			if prev, dup := m[key]; dup {
				t.Fatalf("%s: duplicate JSON key %q (%q and %q)", pair.name, key, prev, tag)
			}
			m[key] = tag

			sf, ok := serverFields[key]
			if !ok {
				t.Fatalf("%s: JSON key %q missing in adminapi.DeviceView", pair.name, key)
			}
			if f.Type != sf.Type {
				t.Fatalf("%s: field %q type drift: provider %v vs adminapi.DeviceView %v", pair.name, key, f.Type, sf.Type)
			}
			pOpts := map[string]bool{}
			for _, o := range strings.Split(tag, ",")[1:] {
				if o != "" {
					pOpts[o] = true
				}
			}
			sOpts := map[string]bool{}
			for _, o := range strings.Split(sf.Tag.Get("json"), ",")[1:] {
				if o != "" {
					sOpts[o] = true
				}
			}
			for o := range pOpts {
				if !sOpts[o] {
					t.Fatalf("%s: field %q tag option %q not in adminapi.DeviceView tag %q", pair.name, key, o, sf.Tag.Get("json"))
				}
			}
		}
		provFields[pair.name] = m
	}

	for key := range serverFields {
		if !serverOnly[key] {
			if _, ok := provFields["device"][key]; !ok {
				t.Fatalf("adminapi.DeviceView field %q missing in provider.device", key)
			}
			if _, ok := provFields["deviceView"][key]; !ok {
				t.Fatalf("adminapi.DeviceView field %q missing in provider.deviceView", key)
			}
		}
	}

	if len(provFields["device"]) != len(provFields["deviceView"]) {
		t.Fatalf("device (%d fields) and deviceView (%d fields) diverged", len(provFields["device"]), len(provFields["deviceView"]))
	}
	for key, tag := range provFields["device"] {
		if t2, ok := provFields["deviceView"][key]; !ok || t2 != tag {
			t.Fatalf("device field %q (%s) missing/changed in deviceView (%q)", key, tag, t2)
		}
	}
}

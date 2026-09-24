package wireless

import (
	"encoding/json"

	"github.com/lucavb/open-unifi/internal/store"
)

// DeviceWLANsExtraKey is the admin-owned per-device WLAN envelope stored in
// Device.Extra (JSON array of Wlan objects, same encoding as wlan_cfg_pending_wlans).
const DeviceWLANsExtraKey = "device_wlans"

// DeviceWLANs reads the admin-owned WLAN list from a device record. Missing or
// invalid data yields nil (no WLANs configured).
func DeviceWLANs(d store.Device) []Wlan {
	if d.Extra == nil {
		return nil
	}
	raw, ok := d.Extra[DeviceWLANsExtraKey].(string)
	if !ok || raw == "" {
		return nil
	}
	var out []Wlan
	if json.Unmarshal([]byte(raw), &out) != nil {
		return nil
	}
	return out
}

// SetDeviceWLANs writes the admin-owned WLAN list onto d.Extra (nil or empty
// clears the key). Caller must persist the device record.
func SetDeviceWLANs(d *store.Device, wlans []Wlan) error {
	if d.Extra == nil {
		d.Extra = store.JSONMap{}
	}
	if len(wlans) == 0 {
		delete(d.Extra, DeviceWLANsExtraKey)
		return nil
	}
	b, err := json.Marshal(wlans)
	if err != nil {
		return err
	}
	d.Extra[DeviceWLANsExtraKey] = string(b)
	return nil
}

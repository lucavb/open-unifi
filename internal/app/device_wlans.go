package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/wireless"
)

// DeviceWLANs returns the provisioned WLAN envelope for one device record
// (inform-side wiring).
func DeviceWLANs(d store.Device) []wireless.Wlan {
	return wireless.DeviceWLANs(d)
}

func adminWlansFromDevice(d store.Device) adminapi.WlansEnvelope {
	wls := wireless.DeviceWLANs(d)
	out := make([]adminapi.Wlan, 0, len(wls))
	for _, w := range wls {
		out = append(out, wirelessWlanToAdmin(w))
	}
	return adminapi.WlansEnvelope{Wlans: out}
}

func wirelessWlanToAdmin(w wireless.Wlan) adminapi.Wlan {
	aw := adminapi.Wlan{
		Name:                 w.Name,
		SSID:                 w.SSID,
		Security:             w.Security,
		Passphrase:           w.Passphrase,
		VLAN:                 w.VLAN,
		Enabled:              w.Enabled,
		ID:                   w.ID,
		Band:                 w.Band,
		RadiusSecret:         w.RadiusSecret,
		RadiusVLANMode:       w.RadiusVLANMode,
		AccountingEnabled:    w.AccountingEnabled,
		InterimUpdateEnabled: w.InterimUpdateEnabled,
		RadiusDASEnabled:     w.RadiusDASEnabled,
	}
	for _, s := range w.RadiusServers {
		aw.RadiusServers = append(aw.RadiusServers, adminapi.RadiusServer{IP: s.IP, Port: s.Port})
	}
	for _, s := range w.AcctServers {
		aw.AcctServers = append(aw.AcctServers, adminapi.RadiusAcctServer{IP: s.IP, Port: s.Port})
	}
	return aw
}

func adminWlanToWireless(w adminapi.Wlan) wireless.Wlan {
	wl := wireless.Wlan{
		Name:                 w.Name,
		SSID:                 w.SSID,
		Security:             w.Security,
		Passphrase:           w.Passphrase,
		VLAN:                 w.VLAN,
		Enabled:              w.Enabled,
		ID:                   w.ID,
		Band:                 w.Band,
		RadiusSecret:         w.RadiusSecret,
		RadiusVLANMode:       w.RadiusVLANMode,
		AccountingEnabled:    w.AccountingEnabled,
		InterimUpdateEnabled: w.InterimUpdateEnabled,
		RadiusDASEnabled:     w.RadiusDASEnabled,
	}
	for _, s := range w.RadiusServers {
		wl.RadiusServers = append(wl.RadiusServers, wireless.RadiusServer{IP: s.IP, Port: s.Port})
	}
	for _, s := range w.AcctServers {
		wl.AcctServers = append(wl.AcctServers, wireless.RadiusAcctServer{IP: s.IP, Port: s.Port})
	}
	return wl
}

func wlanID(w adminapi.Wlan) string {
	if w.ID != "" {
		return w.ID
	}
	sum := sha256.Sum256([]byte(w.Name + w.SSID))
	return fmt.Sprintf("%x", sum[:12])
}

func validateDeviceWlans(env *adminapi.WlansEnvelope) error {
	names, ssids, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range env.Wlans {
		w := &env.Wlans[i]
		if msg := adminapi.ValidateWlanName(w.Name); msg != "" {
			return fmt.Errorf("%w: wlan[%d]: %s", adminapi.ErrConflict, i, msg)
		}
		if msg := adminapi.ValidateWlan(w); msg != "" {
			return fmt.Errorf("%w: wlan[%d]: %s", adminapi.ErrConflict, i, msg)
		}
		if names[w.Name] || ssids[w.SSID] || (w.ID != "" && ids[w.ID]) {
			return fmt.Errorf("%w: duplicate wlan", adminapi.ErrConflict)
		}
		names[w.Name], ssids[w.SSID], ids[w.ID] = true, true, w.ID != ""
	}
	return nil
}

func normalizeDeviceWlanEnvelope(env *adminapi.WlansEnvelope) {
	if env.Wlans == nil {
		env.Wlans = []adminapi.Wlan{}
	}
	for i := range env.Wlans {
		if env.Wlans[i].ID == "" {
			env.Wlans[i].ID = wlanID(env.Wlans[i])
		}
	}
}

func (a *App) persistDeviceWLANs(d *store.Device, env adminapi.WlansEnvelope) error {
	normalizeDeviceWlanEnvelope(&env)
	if err := validateDeviceWlans(&env); err != nil {
		return err
	}
	wls := make([]wireless.Wlan, 0, len(env.Wlans))
	for _, w := range env.Wlans {
		wls = append(wls, adminWlanToWireless(w))
	}
	return wireless.SetDeviceWLANs(d, wls)
}

// GetDeviceWireless returns the whole WLAN document for one device.
func (a *App) GetDeviceWireless(_ context.Context, mac string) (adminapi.WlansEnvelope, error) {
	canon, err := store.CanonicalMAC(mac)
	if err != nil {
		return adminapi.WlansEnvelope{}, unknownDevice(mac)
	}
	rec, err := a.st.Get(canon)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return adminapi.WlansEnvelope{}, unknownDevice(canon)
		}
		return adminapi.WlansEnvelope{}, err
	}
	return adminWlansFromDevice(rec), nil
}

// PutDeviceWireless replaces the whole WLAN document on one device.
func (a *App) PutDeviceWireless(_ context.Context, mac string, env adminapi.WlansEnvelope) error {
	_, err := saveIntent(a, mac, saveExisting, func(d *store.Device) (bool, error) {
		if err := a.persistDeviceWLANs(d, env); err != nil {
			return false, err
		}
		return false, nil
	}, func(d *store.Device) struct{} { return struct{}{} })
	return err
}

// CreateDeviceWlan adds one WLAN on a device.
func (a *App) CreateDeviceWlan(_ context.Context, mac string, wlan adminapi.Wlan) (adminapi.Wlan, error) {
	if msg := adminapi.ValidateWlanName(wlan.Name); msg != "" {
		return adminapi.Wlan{}, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
	}
	wlan.ID = wlanID(wlan)
	out, err := saveIntent(a, mac, saveExisting, func(d *store.Device) (bool, error) {
		env := adminWlansFromDevice(*d)
		env.Wlans = append(append([]adminapi.Wlan(nil), env.Wlans...), wlan)
		if err := a.persistDeviceWLANs(d, env); err != nil {
			return false, err
		}
		return false, nil
	}, func(d *store.Device) adminapi.Wlan {
		for _, w := range adminWlansFromDevice(*d).Wlans {
			if w.Name == wlan.Name {
				return w
			}
		}
		return wlan
	})
	if err != nil {
		return adminapi.Wlan{}, err
	}
	return out, nil
}

// GetDeviceWlan returns one WLAN on a device.
func (a *App) GetDeviceWlan(_ context.Context, mac, name string) (adminapi.Wlan, error) {
	env, err := a.GetDeviceWireless(context.Background(), mac)
	if err != nil {
		return adminapi.Wlan{}, err
	}
	for _, w := range env.Wlans {
		if w.Name == name {
			return w, nil
		}
	}
	return adminapi.Wlan{}, fmt.Errorf("%w: wlan %s", adminapi.ErrNotFound, name)
}

// UpdateDeviceWlan replaces one WLAN on a device.
func (a *App) UpdateDeviceWlan(_ context.Context, mac, name string, wlan adminapi.Wlan) (adminapi.Wlan, error) {
	if msg := adminapi.ValidateWlanName(name); msg != "" {
		return adminapi.Wlan{}, fmt.Errorf("%w: %s", adminapi.ErrConflict, msg)
	}
	if wlan.Name != "" && wlan.Name != name {
		return adminapi.Wlan{}, fmt.Errorf("%w: name must match path", adminapi.ErrConflict)
	}
	wlan.Name = name
	out, err := saveIntent(a, mac, saveExisting, func(d *store.Device) (bool, error) {
		env := adminWlansFromDevice(*d)
		found := false
		for i := range env.Wlans {
			if env.Wlans[i].Name == name {
				wlan.ID = env.Wlans[i].ID
				env.Wlans[i] = wlan
				found = true
				break
			}
		}
		if !found {
			return false, fmt.Errorf("%w: wlan %s", adminapi.ErrNotFound, name)
		}
		if err := a.persistDeviceWLANs(d, env); err != nil {
			return false, err
		}
		return false, nil
	}, func(d *store.Device) adminapi.Wlan { return wlan })
	if err != nil {
		return adminapi.Wlan{}, err
	}
	return out, nil
}

// DeleteDeviceWlan removes one WLAN from a device.
func (a *App) DeleteDeviceWlan(_ context.Context, mac, name string) error {
	_, err := saveIntent(a, mac, saveExisting, func(d *store.Device) (bool, error) {
		env := adminWlansFromDevice(*d)
		out := make([]adminapi.Wlan, 0, len(env.Wlans))
		found := false
		for _, w := range env.Wlans {
			if w.Name == name {
				found = true
			} else {
				out = append(out, w)
			}
		}
		if !found {
			return false, fmt.Errorf("%w: wlan %s", adminapi.ErrNotFound, name)
		}
		env.Wlans = out
		if err := a.persistDeviceWLANs(d, env); err != nil {
			return false, err
		}
		return false, nil
	}, func(d *store.Device) struct{} { return struct{}{} })
	return err
}

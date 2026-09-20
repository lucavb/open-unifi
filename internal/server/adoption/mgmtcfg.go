package adoption

import (
	"net"
	"net/url"
	"strings"

	"github.com/lucavb/open-unifi/internal/configtext"
	"github.com/lucavb/open-unifi/internal/store"
)

// Wire-shape constants of the classic controller (FID-54 dedupe: every
// literal here recurs in more than one emission site).
const (
	defaultInformPort = "8080" // unifi.http.port default
	defaultMgmtPort   = "8443" // manage-port fallback  (mgmt_url)
	defaultStunPort   = "3478" // unifi.stun.port default
)

// buildMgmtCfg renders the mgmt_cfg blob exactly in the config/B (decompile
// cfr_renamed_0) line order. Every line is terminated with \n (verified in
// com/ubnt/ace/C.o00000(StringBuilder,…): append(key=value).append("\n")).
//
// usedKey is the key the current inform was encrypted with; the authkey=
// rotation line is emitted only when that key differs from the record's
// XAuthkey (x_inform_authkey != x_authkey in the decompile).
func (e *Engine) BuildMgmtCfg(d store.Device, usedKey string) string {
	host := e.advertHost(d)
	site := configtext.SiteRef(d)
	var b strings.Builder
	line := configtext.LineWriter(func(where, key string) {
		e.lg.Warn("config blob: row skipped, newline in value", "where", where, "key", key)
	}, &b, "mgmt_cfg")

	// AP capabilities: notif + notif-assoc-stat. fastapply-bg is USW-only
	// and is never emitted for an AP (B decompile: "usw".equals(type)).
	line("capability", "notif,notif-assoc-stat")
	// selfrun_guest_mode comes from the site's config.selfrun_guest_mode
	// setting, default "pass"; we have no site table yet — emit the default.
	line("selfrun_guest_mode", "pass")
	line("cfgversion", d.CfgVersion)
	line("led_enabled", ledEnabledValue(d))
	line("stun_url", "stun://"+host+":"+defaultStunPort+"/")
	if p := e.mgmtPort(); p == "443" {
		line("mgmt_url", "https://"+host+"/manage/site/"+site)
	} else {
		line("mgmt_url", "https://"+host+":"+p+"/manage/site/"+site)
	}
	if d.XAuthkey != "" && !strings.EqualFold(usedKey, d.XAuthkey) {
		line("authkey", d.XAuthkey)
	}
	// FID-16: the inform_url row exists only when the controller URL is
	// explicitly overridden (jar: mgmt.override_inform_host/migrate_inform_url —
	// config L.new() returns null without an override, and the B writer
	// skips the row on null). Devices keep pointing wherever they already
	// point until an admin overrides.
	if e.controllerURL != "" && host != "" {
		line("inform_url", "http://"+host+":"+informURLPortFor(e.controllerURL, e.informListenAddr)+"/inform")
	}
	line("use_aes_gcm", "true")
	line("report_crash", "true")
	return b.String()
}

// ledEnabledValue computes the mgmt_cfg led_enabled row EXACTLY like the
// classic controller's B writer (docs/PROTOCOL-mgmt.md §2, com/ubnt/service/
// config/B.cfr_renamed_0 — the decompile is normative for the value):
//
//	boolean disabled = "uap".equals(device.getType()) && device.is("disabled", false);
//	String ledOverride = device.getString("led_override","default");
//	boolean ledOn = !disabled && ("on".equals(ledOverride) || "default".equals(ledOverride)
//	                && settings("mgmt").is("led_enabled", true));
//	C.o00000(sb, "led_enabled", ledOn ? "true":"false");
//
// Mapping of the jar reads onto our record:
//   - device.is("disabled"): the admin-owned typed record field
//     store.Device.Disabled (a device body can neither write nor introduce
//     it). The "uap".equals(type) gate is constant-true here: every device
//     this controller manages is a uap-class AP (U7PG2), and the B writer
//     only renders for AP beans.
//   - device.getString("led_override","default"): the admin-owned typed
//     record field store.Device.LEDOverride, where "" ≡ the jar default
//     "default" (the record stores "" as the canonical unset).
//   - settings("mgmt").is("led_enabled", true): the SITE default LED
//     setting — the jar default is true. We have no site table yet, so the
//     site default IS the jar default, the same policy selfrun_guest_mode
//     follows above. When a site settings table lands, thread its
//     mgmt.led_enabled value in here instead of widening this function's
//     inputs ad hoc.
//
// Byte values are exactly "true"/"false" (§2's ternary), emitted by the
// shared line writer in the fixed §2 row position.
func ledEnabledValue(d store.Device) string {
	const siteLEDEnabledDefault = true // settings("mgmt").is("led_enabled", true)
	override := d.LEDOverride
	if override == "" {
		override = "default" // device.getString("led_override","default")
	}
	ledOn := !d.Disabled &&
		(override == "on" || (override == "default" && siteLEDEnabledDefault))
	if ledOn {
		return "true"
	}
	return "false"
}

// addrHost extracts the hostname/IP of u, tolerating unparseable input.
func addrHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return ""
	}
	return u.Hostname()
}

// advertHost derives the controller host a device should be pointed back at:
// controller URL host → the device's reported inform_url host →
// device IP (docs/PROTOCOL-mgmt.md §2, L.o00000 priority).
func (e *Engine) advertHost(d store.Device) string {
	if h := addrHost(e.controllerURL); h != "" {
		return h
	}
	if h := addrHost(d.InformURL); h != "" {
		return h
	}
	return d.IP
}

// informURLPortFor is the port chain shared by the mgmt_cfg inform_url
// row and the controller-side SSH set-inform push lane's URL: the
// ControllerURL's explicit port, else the configured inform listen port,
// else the classic 8080.
func informURLPortFor(controllerURL, informListenAddr string) string {
	if u, err := url.Parse(controllerURL); err == nil && u != nil && u.Port() != "" {
		return u.Port()
	}
	if _, port, err := net.SplitHostPort(strings.TrimSpace(informListenAddr)); err == nil && port != "" {
		return port
	}
	return defaultInformPort
}

// InformURL derives the inform URL the controller hands a device over the
// SSH set-inform push lane (docs/PROTOCOL-mgmt.md §7): the controller
// URL's host plus the shared port chain, always http and always the
// /inform path — exactly the URL the mgmt_cfg inform_url row carries for
// a configured controller URL (the row ignores the URL's scheme and path
// the same way). Unlike the row's advertHost chain there is no device
// fallback here — a push target is a pending candidate with no device
// record — so an empty or hostless controller URL yields "" and the lane
// must refuse to fire.
func InformURL(controllerURL, informListenAddr string) string {
	host := addrHost(controllerURL)
	if host == "" {
		return ""
	}
	return "http://" + host + ":" + informURLPortFor(controllerURL, informListenAddr) + "/inform"
}

// mgmtPort is the HTTPS manage-port embedded into mgmt_url. The classic
// controller appends the port unless it is 443 (docs/PROTOCOL-mgmt.md §2:
// "https://<host>[:443]/…" vs the 8443-default branch). We cannot know the
// admin HTTPS port from a plain-HTTP ControllerURL, so anything that is not
// an explicit https URL falls back to the classic default 8443.
func (e *Engine) mgmtPort() string {
	u, err := url.Parse(e.controllerURL)
	if err != nil || u == nil || u.Scheme != "https" {
		return defaultMgmtPort
	}
	if u.Port() == "" {
		return "443"
	}
	return u.Port()
}

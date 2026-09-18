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
	line("led_enabled", "true")
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
		line("inform_url", "http://"+host+":"+e.informURLPort()+"/inform")
	}
	line("use_aes_gcm", "true")
	line("report_crash", "true")
	return b.String()
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

// informURLPort is the port embedded into the inform_url line: the
// ControllerURL's explicit port, else the configured listen port, else the
// classic 8080.
func (e *Engine) informURLPort() string {
	if u, err := url.Parse(e.controllerURL); err == nil && u != nil && u.Port() != "" {
		return u.Port()
	}
	if _, port, err := net.SplitHostPort(strings.TrimSpace(e.informListenAddr)); err == nil && port != "" {
		return port
	}
	return defaultInformPort
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

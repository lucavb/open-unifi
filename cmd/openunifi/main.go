// Command openunifi is an open-source UniFi controller replacement.
//
// It serves the UniFi inform protocol for AP adoption (POST /inform),
// a UDP :10001 discovery listener, the admin HTTP API + web console,
// and Prometheus metrics.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/app"
	"github.com/lucavb/open-unifi/internal/metrics"
	"github.com/lucavb/open-unifi/internal/server"
	"github.com/lucavb/open-unifi/internal/server/systemcfg"
	"github.com/lucavb/open-unifi/internal/store"
	"github.com/lucavb/open-unifi/internal/telemetry"
	"github.com/lucavb/open-unifi/internal/wireless"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "openunifi: fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	listenInform := flag.String("listen-inform", ":8080", "listen address for the inform protocol server")
	listenAdmin := flag.String("listen-admin", "127.0.0.1:8443", "listen address for the admin API server")
	listenDiscovery := flag.String("listen-discovery", ":10001", "UDP listen address for discovery")
	discovery := flag.Bool("discovery", true, "enable the UDP discovery listener")
	dataDir := flag.String("data-dir", "data", "directory for devices.json / wireless.json")
	controllerURL := flag.String("controller-url", "", "base URL devices are pointed at during adoption (e.g. http://10.0.0.5:8080)")
	regulatoryCountryCode := flag.Int("regulatory-country-code", server.DefaultRegulatoryCountryCode, "ISO 3166-1 numeric regulatory country code (001-999); first-boot seed only — managed at runtime via the site-settings API")
	apSSHPassword := flag.String("ap-ssh-password", os.Getenv("OPEN_UNIFI_AP_SSH_PASSWORD"),
		"SSH password for adopted APs (required on first boot — the seed; falls back to $OPEN_UNIFI_AP_SSH_PASSWORD); first-boot seed only — managed at runtime via the site-settings API")
	apSSHKeys := &keyList{}
	flag.Var(apSSHKeys, "ap-ssh-key", "LAB ONLY: SSH authorized public key for adopted APs, one authorized_keys line per flag (repeatable; falls back to a single $OPEN_UNIFI_AP_SSH_KEY); first-boot seed only — managed at runtime via the site-settings API. Parsed and validated fail-closed at startup; provisioned as sshd.auth.key.<n>.* rows — firmware-derived but NOT yet live-bench-validated, pushes gated behind --allow-gated-live-wlan (docs/PROTOCOL-systemcfg-wireless.md §13)")
	apSSHDisablePassword := flag.Bool("ap-ssh-disable-password", false,
		"LAB ONLY: render sshd.auth.passwd=disabled (dropbear -s: no remote password logins); requires at least one --ap-ssh-key; first-boot seed only — managed at runtime via the site-settings API. Applies at adoption or the next config push; flipping it alone does not re-provision adopted devices (docs/PROTOCOL-systemcfg-wireless.md §13)")
	allowDefaultAPSSH := flag.Bool("allow-default-ap-ssh-password", false, "LAB ONLY: permit the insecure AP SSH password \"ubnt\" when --ap-ssh-password is empty")
	// Default from the provider's token env var; --admin-token overrides it.
	adminToken := flag.String("admin-token", os.Getenv("OPEN_UNIFI_ADMIN_TOKEN"),
		"admin API bearer token (required; defaults to $OPEN_UNIFI_ADMIN_TOKEN)")
	allowAnonymousAdmin := flag.Bool("allow-anonymous-admin", false, "LAB ONLY: allow anonymous admin API and metrics")
	allowInsecureAdmin := flag.Bool("allow-insecure-admin", false, "LAB ONLY: allow non-loopback plaintext admin HTTP (normally use an HTTPS reverse proxy)")
	allowPlainText := flag.Bool("allow-plaintext-inform", false, "accept unencrypted JSON inform bodies")
	allowGatedLiveWLAN := flag.Bool("allow-gated-live-wlan", false,
		"LAB ONLY: lift the fail-closed live WLAN provisioning gate for U7PG2 fw 6.8.2.15592 (typed 501 without this flag); requires a push candidate pre-cleared by the offline minimal-diff harness")
	allowSSHSetInformPush := flag.Bool("allow-ssh-set-inform-push", false,
		"LAB ONLY: arm the controller-side SSH set-inform push lane — the console Adopt action on a factory announce candidate dials ubnt@<candidate-ip> with the factory default password and runs mca-cli-op set-inform (explicit admin-action opt-in, never on by default; requires --controller-url)")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	logFormat := flag.String("log-format", os.Getenv("OPEN_UNIFI_LOG_FORMAT"), "log format: text (default) or json")
	otlpEndpoint := flag.String("otlp-endpoint", os.Getenv("OPEN_UNIFI_OTLP_ENDPOINT"), "OTLP/HTTP trace endpoint (e.g. http://127.0.0.1:4318); empty = tracing off unless OTEL_EXPORTER_OTLP_ENDPOINT(_TRACES) is set")
	flag.Parse()
	if err := validateAdminExposure(*listenAdmin, *adminToken, *allowAnonymousAdmin, *allowInsecureAdmin); err != nil {
		return err
	}
	// settingsExisted reports whether a site-settings record was already on
	// disk BEFORE app.New runs. Both the seed-flag guards below and the
	// ignored-flags warn are conditioned on this pre-New determination:
	// app.New seeds AND persists the record inside the call, and a post-New
	// stat could never tell a preexisting record apart from the one this
	// boot just wrote. A missing file (first boot, including the
	// deleted-file re-seed flow — app.New treats a missing file as first
	// boot) stats ENOENT → false. A non-ENOENT stat error also counts as
	// false, conservative: the guards stay on and any real file problem
	// surfaces via loadSettingsFile/CurrentSiteSettings startup refusal.
	_, settingsStatErr := os.Stat(filepath.Join(*dataDir, "site-settings.json"))
	settingsExisted := settingsStatErr == nil
	// Seed-flag validation posture: on FIRST BOOT (!settingsExisted) the
	// seed flags are validated fail-closed — the key lines by app.New's
	// seed validation (the single parser), the disable-without-keys combo
	// by the cmd guard below, an explicit --regulatory-country-code 0 by
	// the guard further down. Once the record exists the flags are dead
	// seeds: warned as ignored (below), never validated — one consistent
	// posture for every equally-dead input (the password guard above
	// narrows the same way). app's seed validation applies the same
	// save-verb rule (it rejects the combo too — the seed is admin
	// intent); the deliberately-accepting rule is the DISK-LOAD one, so
	// a hand-edited record cannot brick startup. The cmd guard is the
	// one the CLI boot honors.
	if !settingsExisted && *apSSHPassword == "" && !*allowDefaultAPSSH {
		return errors.New("AP SSH password is required; set --ap-ssh-password or explicitly opt in with --allow-default-ap-ssh-password for lab use")
	}
	// Fail-closed guard: disabling password auth without a provisioned
	// public key risks locking SSH out — the next boot's cfg rebuild
	// leaves no authorized_keys entry and dropbear starts with -s.
	// Recovery, even then, does NOT need SSH: an effective admin device
	// save re-provisions the record on the next inform (the controller
	// channel), re-rendering the sshd rows.
	sshSeedKeys := effectiveSSHKeyLines(apSSHKeys.keys, os.Getenv("OPEN_UNIFI_AP_SSH_KEY"))
	if !settingsExisted {
		if err := validateSSHDisableSeed(sshSeedKeys, *apSSHDisablePassword); err != nil {
			return err
		}
		// The flag default is nonzero, so a zero here can only come from an
		// explicitly supplied --regulatory-country-code 0. Reject it before the
		// server-side coercion silently maps 0 to the 840 default. Once the
		// record exists ALL flag values (including 0 and out-of-range ones
		// such as 1000) are dead seeds — warned as ignored, never validated.
		if err := validateRegulatoryCountryCode(*regulatoryCountryCode); err != nil {
			return err
		}
	}
	if err := server.ValidateConfig(server.Config{ControllerURL: *controllerURL}); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	level, err := parseLevel(*logLevel)
	if err != nil {
		return fmt.Errorf("invalid --log-level %q: %w", *logLevel, err)
	}
	format, err := parseLogFormat(*logFormat)
	if err != nil {
		return fmt.Errorf("invalid --log-format %q: %w", *logFormat, err)
	}
	logger := telemetry.NewLogger(format, level, os.Stdout)
	slog.SetDefault(logger)

	// Opt-in tracing: the gate inside SetupTracing decides whether a real
	// provider is built; without an endpoint nothing is ever constructed.
	tracerShutdown, err := telemetry.SetupTracing(context.Background(), *otlpEndpoint, logger)
	if err != nil {
		return fmt.Errorf("tracing setup: %w", err)
	}
	// Every return path (graceful, server error, fatal) flushes the batcher
	// once on the way out.
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tracerShutdown(sctx); err != nil {
			logger.Warn("otel: flush failed", "err", err)
		}
	}()

	dhost, dport, err := discoveryPort(*listenDiscovery)
	if err != nil {
		return fmt.Errorf("invalid --listen-discovery %q: %w", *listenDiscovery, err)
	}

	// ---- store + app wiring ----------------------------------------------
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir %s: %w", *dataDir, err)
	}
	lock, err := acquireDataDirLock(*dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	st, err := store.NewJSONStore(filepath.Join(*dataDir, "devices.json"))
	if err != nil {
		return fmt.Errorf("open device store: %w", err)
	}
	ap := app.New(st, filepath.Join(*dataDir, "wireless.json"), filepath.Join(*dataDir, "site-settings.json"), siteSettingsSeed(*regulatoryCountryCode, *apSSHPassword, sshSeedKeys, *apSSHDisablePassword), logger)
	// The wireless document is loaded ONCE in app.New; a corrupt
	// wireless.json must refuse startup here (same as a corrupt
	// devices.json already does) — otherwise the provisioning side would
	// degrade to zero WLANs and, on the next TF plan PUT, wipe every other
	// WLAN off every AP.
	if _, err := ap.CurrentWireless(); err != nil {
		return fmt.Errorf("wireless config: %w", err)
	}
	// Same discipline for the site-settings record: a present-but-bad
	// file (or a failed first-boot seed persist) is retained as a REAL
	// error in app.New and refuses the launch here. On first boot the
	// flags seeded it — the flags' values already passed the validators
	// above, so this check is the belt to their suspenders. The loaded
	// record is also the single source of truth for the startup log and
	// the sshd-facts warn below (the flags are seeds only).
	siteSettings, serr := ap.CurrentSiteSettings()
	if serr != nil {
		return fmt.Errorf("site settings: %w", serr)
	}
	// The four AP-intent inputs are first-boot seeds only. Warn that they
	// were ignored ONLY when a record existed before this boot (the pre-New
	// settingsExisted determination — after app.New the file always exists,
	// because the call seeds and persists it) AND at least one flag was
	// actually supplied. On the seeding first boot the flags were honored:
	// the default flow is the happy path, not a warning.
	if apIntentSupplied() && settingsExisted {
		logger.Warn("site settings exist; --regulatory-country-code/--ap-ssh-password/--ap-ssh-key/--ap-ssh-disable-password ignored (first-boot seeds only — managed at runtime via the site-settings API)")
	}
	adminH := adminapi.New(adminapi.Config{AdminToken: *adminToken}, ap)

	if *allowAnonymousAdmin {
		// Prominent, not debug: without a token any LAN peer can read WLAN
		// passphrases through the admin API and adopt devices through the
		// metrics side of the house.
		logger.Warn("admin API and metrics are ANONYMOUS (LAB ONLY)")
	}

	// WirelessSource feeds the admin-API WLAN envelope into inform-side
	// provisioning (system_cfg wireless/VLAN emission + drift hash). After
	// the CurrentWireless check above the error branch is nil in practice —
	// the envelope is served from App's cache, which cannot fail — but it
	// stays as the documented behavior before startup.
	wirelessSource := func() []server.Wlan {
		env, err := ap.CurrentWireless()
		if err != nil {
			logger.Warn("wireless envelope read failed; provisioning without wlans", "err", err)
			return nil
		}
		out := make([]server.Wlan, 0, len(env.Wlans))
		for _, w := range env.Wlans {
			wl := server.Wlan{
				Name:       w.Name,
				SSID:       w.SSID,
				Security:   w.Security,
				Passphrase: w.Passphrase,
				VLAN:       w.VLAN,
				Enabled:    w.Enabled,
				ID:         w.ID,
				Band:       w.Band,
				// Inline RADIUS profile (wpa-eap): the slices must be
				// rebuilt, not aliased — env.Wlans belongs to App's
				// cached envelope and out outlives this call.
				RadiusSecret:   w.RadiusSecret,
				RadiusVLANMode: w.RadiusVLANMode,
				// Accounting fields (§12 rows 1013-1014): same no-alias
				// rebuild for acct_servers; the booleans pass through.
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
			out = append(out, wl)
		}
		return out
	}

	// SiteSettingsSource feeds the app's site-settings record into inform-
	// side provisioning (the four managed AP-intent facts) and into the
	// adoption engine's live-provisioning gate. The record stores RAW
	// authorized_keys lines; this seam is where the parse lands — every
	// line through the single fail-closed parser (systemcfg.ParsePublicKey),
	// same as the app did at seed and at every save (a line that reached the
	// record unvalidated would be a trust-policy breach, not a parse-time
	// concern here). The closure reads the record LIVE per call, so a
	// site-settings save is visible on the device's next inform. On a load
	// error the error propagates: the render fails before anything
	// persists (the store cycle aborts — in-memory record writes are
	// discarded with it), and the gate reads zero facts and stays inert
	// (net fail-closed — startup already refused on this error, so it is
	// embedder-only).
	siteSettingsSource := func() (server.SiteSettings, error) {
		rec, err := ap.CurrentSiteSettings()
		if err != nil {
			return server.SiteSettings{}, err
		}
		keys := make([]systemcfg.PublicKey, 0, len(rec.SSHPublicKeys))
		for i, line := range rec.SSHPublicKeys {
			k, perr := systemcfg.ParsePublicKey(line)
			if perr != nil {
				return server.SiteSettings{}, fmt.Errorf("invalid AP SSH public key #%d: %w", i+1, perr)
			}
			keys = append(keys, k)
		}
		return server.SiteSettings{
			CountryCode:        rec.CountryCode,
			SSHPassword:        rec.SSHPassword,
			SSHPublicKeys:      keys,
			SSHDisablePassword: rec.SSHDisablePassword,
		}, nil
	}

	srv := server.New(server.Config{
		InformListenAddr:   *listenInform,
		DiscoveryListen:    *discovery,
		DiscoveryPort:      dport,
		ControllerURL:      *controllerURL,
		AllowPlainText:     *allowPlainText,
		AllowGatedLiveWLAN: *allowGatedLiveWLAN,
		WirelessSource:     wirelessSource,
		SiteSettings:       siteSettingsSource,
		// Client-session transition observations ride the same ownership
		// seam as IncInform: the transport stays Prometheus-free and main
		// wires the hook (post-commit, exactly-once per persisted
		// transition).
		OnSessionEvents: metrics.IncClientSessionEvents,
	}, st, logger)
	if *allowGatedLiveWLAN {
		logger.Warn("live WLAN provisioning gate LIFTED for U7PG2 6.8.2.15592 (--allow-gated-live-wlan): live WLAN pushes are enabled — bench use only, candidate must be pre-cleared by the offline minimal-diff harness")
	}
	// Source the condition from the RECORD (the loaded siteSettings, the
	// single source of truth for the four facts — not the seed flags,
	// which are ignored whenever the record file exists): the warn's
	// operative content is "live pushes stay gated", and that depends on
	// the facts the gate will actually read.
	if len(siteSettings.SSHPublicKeys) > 0 || siteSettings.SSHDisablePassword {
		// Prominent, not debug: the sshd site facts are already gated
		// behind the same live-WLAN opt-in at the engine choke point, but
		// an admin with provisioned sshd facts in the record must SEE
		// that pushes will not go live until the bench validation lands.
		logger.Warn("ssh site facts configured in the site-settings record: the sshd.auth.key rows and auth.passwd knob are firmware-derived but NOT yet live-bench-validated — live pushes stay gated behind --allow-gated-live-wlan (docs/PROTOCOL-systemcfg-wireless.md §13, bench use only)")
	}
	// The SSH set-inform push lane (internal/app/setinform.go): armed here
	// so the console Adopt action can hand never-informed factory pending
	// candidates an inform URL over SSH. EnableSetInformPush fails startup
	// when no inform URL is derivable (empty or hostless --controller-url):
	// fail fast like the other flag validations, before any listener binds.
	if *allowSSHSetInformPush {
		if err := ap.EnableSetInformPush(*controllerURL, *listenInform); err != nil {
			return fmt.Errorf("--allow-ssh-set-inform-push: %w", err)
		}
		logger.Warn("ssh set-inform push lane ARMED (LAB ONLY): console Adopt on a factory announce candidate pushes mca-cli-op set-inform over SSH with factory default credentials")
	}
	if *controllerURL == "" {
		logger.Warn("no --controller-url configured: discovery/adopt replies cannot point the device at an inform URL; prefer SSH 'set-inform <this controller>/inform'")
	}

	// Every inform request increments the inform counter, then the server
	// lane handler takes over. InformHandler() is fetched ONCE here — the
	// bare per-request call in the wrapper would allocate a fresh handler
	// on the hot path of every inform. The completion log uses the request
	// context so traceHandler injects trace_id/span_id when tracing is on.
	inform := srv.InformHandler()
	informH := otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics.IncInform()
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		inform.ServeHTTP(sw, r)
		logger.InfoContext(r.Context(), "inform: request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.code,
			"duration_ms", float64(time.Since(start).Microseconds())/1000,
		)
	}), "openunifi: inform")

	// ---- serving ---------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	informLn, err := net.Listen("tcp", *listenInform)
	if err != nil {
		return fmt.Errorf("bind inform %s: %w", *listenInform, err)
	}
	// The jar terminates its bounded reading/writing listener sockets on a
	// per-connection deadline (com/ubnt/ace/J.ø00000)); mirror that with
	// explicit http.Server timeouts here (FID-10).
	adminSrv := &http.Server{
		Addr: *listenAdmin,
		// otelhttp is OUTERMOST: the adminapi auth (requireToken) and its
		// metrics wrapper stay inside so the span covers the full request.
		Handler:           otelhttp.NewHandler(adminH, "openunifi: admin"),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	// Admin TLS is intentionally terminated by a separately managed HTTPS
	// reverse proxy. Native TLS is not implemented; non-loopback plaintext is
	// refused unless the explicit lab-only opt-in was supplied.
	adminLn, err := net.Listen("tcp", *listenAdmin)
	if err != nil {
		_ = informLn.Close()
		return fmt.Errorf("bind admin %s: %w", *listenAdmin, err)
	}

	var udp *net.UDPConn
	if *discovery {
		// FID-7: the jar's discovery socket is a MulticastSocket that JOINS
		// the 233.89.188.1 group (G.O0oO's bindMulticast(O0oO) — the
		// setReuseAddress(true) + joinGroup(233.89.188.1:10001) call; join
		// failures are only logged: the broadcast listener still starts,
		// mirrored by the fallback below).
		gaddr := &net.UDPAddr{IP: net.IPv4(233, 89, 188, 1), Port: dport}
		var ifi *net.Interface
		if dhost != "" {
			ifi, err = net.InterfaceByName(dhost)
			if err != nil {
				_ = informLn.Close()
				_ = adminLn.Close()
				return fmt.Errorf("discovery interface %q: %w", dhost, err)
			}
		}
		udp, err = net.ListenMulticastUDP("udp", ifi, gaddr)
		if err != nil {
			logger.Warn("discovery multicast join failed; falling back to plain UDP listener",
				"group", gaddr.IP.String(), "host", dhost, "err", err)
			udp, err = net.ListenUDP("udp", &net.UDPAddr{Port: dport})
		}
		if err != nil {
			_ = informLn.Close()
			_ = adminLn.Close()
			return fmt.Errorf("bind discovery udp :%d: %w (is another controller running?)", dport, err)
		}
	}
	// closeUDP closes the discovery socket (nil-safe so both the error and
	// the graceful shutdown path share one exit).
	closeUDP := func() {
		if udp != nil {
			_ = udp.Close()
		}
	}

	logger.Info("open-unifi starting",
		"inform", *listenInform,
		"admin", *listenAdmin,
		"discovery", *discovery,
		"discovery_port", dport,
		"data_dir", *dataDir,
		// The site facts are the RECORD's values now (the flags seeded it on
		// first boot and are ignored thereafter).
		"ssh_password_configured", siteSettings.SSHPassword != "",
		"ssh_public_keys", len(siteSettings.SSHPublicKeys),
		"ssh_disable_password", siteSettings.SSHDisablePassword,
		"auth", *adminToken != "",
		"plaintext_inform", *allowPlainText,
		"controller_url", *controllerURL,
		"store", filepath.Join(*dataDir, "devices.json"),
	)

	// Serving goroutines; a running-server error tears everything down.
	errCh := make(chan error, 3)

	// informSrv owns the inform TCP listener: the metrics middleware happens
	// HERE (main owns the HTTP plumbing), directly onto srv.InformHandler().
	// Inform state machine still lives in internal/server.
	// FID-10: same bounded-socket timeouts as adminSrv above.
	informSrv := &http.Server{
		Addr:              *listenInform,
		Handler:           informH,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		if err := informSrv.Serve(informLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("inform server: %w", err)
		}
	}()

	if udp != nil {
		go func() {
			if err := srv.ServeDiscovery(udp); err != nil {
				errCh <- fmt.Errorf("discovery listener: %w", err)
			}
		}()
	}
	go func() {
		if err := adminSrv.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("admin server: %w", err)
		}
	}()
	pollDone := make(chan struct{})
	go func() {
		ap.RunPoller(ctx, 15*time.Second)
		close(pollDone)
	}()

	select {
	case err := <-errCh:
		logger.Error("server error", "err", err)
		drainShutdown(adminSrv, informSrv)
		closeUDP()
		return err
	case <-ctx.Done(): // SIGINT/SIGTERM
	}

	// Shutdown order: admin API → inform server → discovery UDP close →
	// poller (already stopped via ctx cancel) → exit 0.
	actx, acancel := shutdownCtx()
	defer acancel()
	aerr := adminSrv.Shutdown(actx)
	ictx, icancel := shutdownCtx()
	defer icancel()
	ierr := informSrv.Shutdown(ictx)
	closeUDP() // nil-safe single discovery-socket close (shared with the error path)
	if aerr != nil || ierr != nil {
		logger.Warn("incomplete shutdown", "admin_err", aerr, "inform_err", ierr)
	}
	<-pollDone
	logger.Info("open-unifi stopped")
	return nil
}

// shutdownCtx yields the bounded 5s graceful-drain context (caller cancels).
func shutdownCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// keyList is a REPEATABLE flag.Value: every --ap-ssh-key occurrence appends
// one authorized_keys line. The env fallback ($OPEN_UNIFI_AP_SSH_KEY, a
// single key) consults the environment — passed in by run() AFTER
// flag.Parse so this stays pure — only when the flag never appeared, the
// --ap-ssh-password/env fallback pattern, so an explicitly supplied flag
// wins over the environment.
type keyList struct {
	keys []string
}

func (l *keyList) String() string { return strings.Join(l.keys, "\n") }

func (l *keyList) Set(v string) error {
	l.keys = append(l.keys, v)
	return nil
}

// siteSettingsSeed builds the first-boot site-settings seed from the four
// AP-intent flags. The key lines are passed RAW (the composition ran above
// through effectiveSSHKeyLines; app.New runs the single fail-closed parser;
// nothing is pre-parsed here). The saved record preserves what the flags
// say, verbatim: on the first-boot path main's pre-New seed-flag guards
// (password guard, disable-without-keys guard, explicit-0 country
// rejection) and app.New's seed validation (the save-verb rule, key parse
// among them) already gated this boot. Once the record exists the flags
// are dead seeds and this value is ignored by app.New anyway.
func siteSettingsSeed(countryCode int, password string, keys []string, disablePassword bool) app.SiteSettings {
	return app.SiteSettings{
		CountryCode:        countryCode,
		SSHPassword:        password,
		SSHPublicKeys:      keys,
		SSHDisablePassword: disablePassword,
	}
}

// effectiveSSHKeyLines is the flag/env source composition feeding the
// first-boot SSH key seed (its single consumer): the flag occurrences win;
// the env fallback ($OPEN_UNIFI_AP_SSH_KEY, a single key line) supplies
// only when the flag never appeared — the --ap-ssh-password/env fallback
// pattern, so an explicitly supplied flag wins over the environment.
func effectiveSSHKeyLines(flagKeys []string, envValue string) []string {
	keys := flagKeys
	if len(keys) == 0 && envValue != "" {
		return []string{envValue}
	}
	return keys
}

// apIntentSupplied reports whether at least one of the four AP-intent
// inputs was explicitly supplied — the seed the "site settings exist"
// warning actually refers to. Two sources count: flag.Visit over the four
// flag names (explicit occurrences on the command line), and the env
// fallbacks OPEN_UNIFI_AP_SSH_PASSWORD / OPEN_UNIFI_AP_SSH_KEY — those feed
// the flag DEFAULTS, so flag.Visit alone misses them. Must run AFTER
// flag.Parse (flag.Visit walks parsed flags).
func apIntentSupplied() bool {
	names := map[string]bool{
		"regulatory-country-code": true,
		"ap-ssh-password":         true,
		"ap-ssh-key":              true,
		"ap-ssh-disable-password": true,
	}
	supplied := false
	flag.Visit(func(f *flag.Flag) {
		if names[f.Name] {
			supplied = true
		}
	})
	if os.Getenv("OPEN_UNIFI_AP_SSH_PASSWORD") != "" || os.Getenv("OPEN_UNIFI_AP_SSH_KEY") != "" {
		supplied = true
	}
	return supplied
}

// validateSSHDisableSeed is the fail-closed disable-without-keys guard
// for the first-boot seed (the pre-lane cmd-layer semantics, restored
// verbatim): disabling password auth without a provisioned public key
// risks locking SSH out — the next boot's cfg rebuild leaves no
// authorized_keys entry and dropbear starts with -s. Recovery, even then,
// does NOT need SSH: an effective admin device save re-provisions the
// record on the next inform (the controller channel), re-rendering the
// sshd rows. This guard and app's seed rule (the save-verb rule — the
// seed is admin intent) both reject the combo; the deliberately
// accepting rule is the DISK-LOAD one (a hand-edited record cannot
// brick startup — the API is the validator going forward). The engine's live
// gate is NOT a fail-closed backstop for this combo: it is scoped to
// U7PG2 firmware 6.8.2.15592 ONLY, and other models/firmware deliver the
// combo ungated. The honest invariant is that every admin-reachable
// WRITER rejects the combo (the API fence, the app save verb, app's seed
// validation for the CLI seed path); a hand-edited disk file deliberately
// still boots, and recovery goes through an API PUT — no SSH needed.
func validateSSHDisableSeed(keys []string, disablePassword bool) error {
	if disablePassword && len(keys) == 0 {
		return errors.New("AP SSH password auth cannot be disabled without a provisioned public key; set --ap-ssh-key (or $OPEN_UNIFI_AP_SSH_KEY) or SSH access will be locked out")
	}
	return nil
}

// drainShutdown tears both HTTP servers down with a fresh 5s deadline.
func drainShutdown(servers ...*http.Server) {
	ctx, cancel := shutdownCtx()
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
}

// statusWriter captures the response code for the inform request-completion
// log (same pattern as internal/adminapi.statusWriter).
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// parseLevel maps a flag string onto a slog level.
func parseLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, errors.New("want debug|info|warn|error")
	}
}

// parseLogFormat maps a flag string onto the logger format; an empty value
// (the flag default) selects text.
func parseLogFormat(s string) (string, error) {
	switch strings.ToLower(s) {
	case "", "text":
		return "text", nil
	case "json":
		return "json", nil
	default:
		return "", errors.New("want text|json")
	}
}

// discoveryPort resolves a --listen-discovery spec. Accepted forms are
// "host:port", ":port" and a bare "port"; anything unparseable is an
// error (FID-41: the spec must hard-fail at startup instead of silently
// defaulting).
func discoveryPort(addr string) (host string, port int, err error) {
	if p, perr := strconv.Atoi(addr); perr == nil {
		if p <= 0 || p > 65535 {
			return "", 0, errors.New("want numeric UDP port in 1..65535")
		}
		return "", p, nil
	}
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, errors.New("want host:port, :port or bare port (e.g. :10001)")
	}
	n, aerr := strconv.Atoi(p)
	if aerr != nil || n <= 0 || n > 65535 {
		return "", 0, errors.New("want numeric UDP port, got " + p)
	}
	return host, n, nil
}

// validateRegulatoryCountryCode rejects an explicitly supplied 0 before the
// server-side coercion would silently map it to the 840 default; the flag
// default is nonzero, so a zero here always means the user passed 0.
// Called only on the first-boot seed path (no site-settings record yet);
// once the record exists every flag value is a dead seed — warned as
// ignored, never validated.
func validateRegulatoryCountryCode(code int) error {
	if code == 0 {
		return errors.New("--regulatory-country-code 0 is not a valid ISO 3166-1 numeric code; omit the flag to use the default")
	}
	return nil
}

func validateAdminExposure(addr, token string, anonymous, insecure bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --listen-admin %q: want host:port", addr)
	}
	loopback := false
	if ip := net.ParseIP(host); ip != nil {
		loopback = ip.IsLoopback()
	} else if strings.EqualFold(host, "localhost") {
		loopback = true
	}
	if token == "" && !anonymous {
		return errors.New("admin token is required; set --admin-token or explicitly opt in with --allow-anonymous-admin for lab use")
	}
	if !loopback && !insecure {
		return errors.New("non-loopback admin binding is plaintext; put it behind an HTTPS reverse proxy or explicitly opt in with --allow-insecure-admin for lab use")
	}
	return nil
}

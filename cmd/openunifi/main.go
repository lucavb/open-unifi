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
	"syscall"
	"time"

	"github.com/lucabecker/open-unifi/internal/adminapi"
	"github.com/lucabecker/open-unifi/internal/app"
	"github.com/lucabecker/open-unifi/internal/metrics"
	"github.com/lucabecker/open-unifi/internal/server"
	"github.com/lucabecker/open-unifi/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "openunifi: fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	listenInform := flag.String("listen-inform", ":8080", "listen address for the inform protocol server")
	listenAdmin := flag.String("listen-admin", ":8443", "listen address for the admin API server")
	listenDiscovery := flag.String("listen-discovery", ":10001", "UDP listen address for discovery")
	discovery := flag.Bool("discovery", true, "enable the UDP discovery listener")
	dataDir := flag.String("data-dir", "data", "directory for devices.json / wireless.json")
	controllerURL := flag.String("controller-url", "", "base URL devices are pointed at during adoption (e.g. http://10.0.0.5:8080)")
	apSSHPassword := flag.String("ap-ssh-password", "", "SSH password for adopted APs (empty uses the built-in site default \"ubnt\")")
	// Default from the provider's token env var; --admin-token overrides it.
	adminToken := flag.String("admin-token", os.Getenv("OPEN_UNIFI_ADMIN_TOKEN"),
		"admin API bearer token (empty disables auth; defaults to $OPEN_UNIFI_ADMIN_TOKEN)")
	allowPlainText := flag.Bool("allow-plaintext-inform", false, "accept unencrypted JSON inform bodies")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	level, err := parseLevel(*logLevel)
	if err != nil {
		return fmt.Errorf("invalid --log-level %q: %w", *logLevel, err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	dport, err := discoveryPort(*listenDiscovery)
	if err != nil {
		return fmt.Errorf("invalid --listen-discovery %q: %w", *listenDiscovery, err)
	}

	// ---- store + app wiring ----------------------------------------------
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir %s: %w", *dataDir, err)
	}
	st, err := store.NewJSONStore(filepath.Join(*dataDir, "devices.json"))
	if err != nil {
		return fmt.Errorf("open device store: %w", err)
	}
	ap := app.New(st, filepath.Join(*dataDir, "wireless.json"), logger)
	// The wireless document is loaded ONCE in app.New; a corrupt
	// wireless.json must refuse startup here (same as a corrupt
	// devices.json already does) — otherwise the provisioning side would
	// degrade to zero WLANs and, on the next TF plan PUT, wipe every other
	// WLAN off every AP.
	if _, err := ap.CurrentWireless(); err != nil {
		return fmt.Errorf("wireless config: %w", err)
	}
	adminH := adminapi.New(adminapi.Config{AdminToken: *adminToken}, ap)

	if *adminToken == "" {
		// Prominent, not debug: without a token any LAN peer can read WLAN
		// passphrases through the admin API and adopt devices through the
		// metrics side of the house.
		logger.Warn("admin API and metrics are UNAUTHENTICATED: any LAN peer can read WLAN passphrases and adopt devices; set --admin-token or $OPEN_UNIFI_ADMIN_TOKEN")
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
			out = append(out, server.Wlan{
				Name:       w.Name,
				SSID:       w.SSID,
				Security:   w.Security,
				Passphrase: w.Passphrase,
				VLAN:       w.VLAN,
				Enabled:    w.Enabled,
				ID:         w.ID,
			})
		}
		return out
	}

	srv := server.New(server.Config{
		InformListenAddr: *listenInform,
		DiscoveryListen:  *discovery,
		DiscoveryPort:    dport,
		ControllerURL:    *controllerURL,
		SSHPassword:      *apSSHPassword,
		AllowPlainText:   *allowPlainText,
		WirelessSource:   wirelessSource,
	}, st, logger)
	if *controllerURL == "" {
		logger.Warn("no --controller-url configured: discovery/adopt replies cannot point the device at an inform URL; prefer SSH 'set-inform <this controller>/inform'")
	}

	// Every inform request increments the inform counter, then the server
	// lane handler takes over. InformHandler() is fetched ONCE here — the
	// bare per-request call in the wrapper would allocate a fresh handler
	// on the hot path of every inform.
	inform := srv.InformHandler()
	informH := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics.IncInform()
		inform.ServeHTTP(w, r)
	})

	// ---- serving ---------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	informLn, err := net.Listen("tcp", *listenInform)
	if err != nil {
		return fmt.Errorf("bind inform %s: %w", *listenInform, err)
	}
	adminSrv := &http.Server{Addr: *listenAdmin, Handler: adminH}
	// TODO(TLS): the classic controller terminates HTTPS on 8443; we serve
	// plain HTTP on --listen-admin for the current milestone (same-host/
	// trusted-lab setups). Front-load TLS via a reverse proxy, or wire
	// crypto/tls + cert/key flags here.
	adminLn, err := net.Listen("tcp", *listenAdmin)
	if err != nil {
		_ = informLn.Close()
		return fmt.Errorf("bind admin %s: %w", *listenAdmin, err)
	}

	var udp *net.UDPConn
	if *discovery {
		udp, err = net.ListenUDP("udp", &net.UDPAddr{Port: dport})
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
		"ssh_password_configured", *apSSHPassword != "",
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
	informSrv := &http.Server{Addr: *listenInform, Handler: informH}
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

// drainShutdown tears both HTTP servers down with a fresh 5s deadline.
func drainShutdown(servers ...*http.Server) {
	ctx, cancel := shutdownCtx()
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
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
		return slog.LevelInfo, fmt.Errorf("want debug|info|warn|error")
	}
}

// discoveryPort extracts the UDP port from an address like ":10001".
// Portless addresses default to 10001.
func discoveryPort(addr string) (int, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return 10001, nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return 0, fmt.Errorf("want numeric UDP port, got %q", port)
	}
	return n, nil
}

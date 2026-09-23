//go:build acceptance

// Package acceptance contains the black-box Terraform acceptance harness. It
// intentionally builds and runs the two real commands; no provider or server
// internals are imported by these tests.
package acceptance

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const providerAddress = "registry.terraform.io/lucavb/open-unifi"

func TestTerraformAcceptance(t *testing.T) {
	if os.Getenv("TF_ACC") != "1" {
		t.Skip("TF_ACC=1 is required")
	}
	for _, tool := range []string{"terraform", "go"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("acceptance prerequisite %s: %v", tool, err)
		}
	}

	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	goRun(t, "build", "-o", filepath.Join(bin, "openunifi"), "./cmd/openunifi")
	goRun(t, "build", "-o", filepath.Join(bin, "terraform-provider-open-unifi"), "./cmd/tfprovider")

	data := filepath.Join(root, "data")
	token := "acceptance-token-7f3c"
	controllerAddr := freeTCPAddr(t)
	controller := startController(t, filepath.Join(bin, "openunifi"), controllerAddr, data, token)
	// Closure, not a method value: the receiver `controller` is reassigned
	// after the restart below, and the deferred call must stop whatever
	// instance is current at exit.
	defer func() { controller.stop() }()
	controller.waitReady(t)

	// All Terraform invocations use this file, so the test cannot accidentally
	// load a developer's global plugin mirror or credentials.
	cliConfig := filepath.Join(root, "terraform.tfrc")
	if err := os.WriteFile(cliConfig, []byte(fmt.Sprintf(`provider_installation {
  dev_overrides {
    %q = %q
  }
  direct {}
}
`, providerAddress, bin)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Setenv("TF_CLI_CONFIG_FILE", cliConfig); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("TF_CLI_CONFIG_FILE")

	// A proxy whose first accepted connection deterministically times out. The
	// provider has a two-second request deadline; all later connections forward
	// normally, allowing the next apply to prove safe convergence.
	proxy := newForwardProxy(t, controllerAddr)
	defer proxy.close()

	work := filepath.Join(root, "terraform")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, work, proxy.addr())
	tf := newTerraform(t, work, cliConfig, token)

	if out, err := tf.runAllowFailure("apply", "-auto-approve", "-input=false"); err == nil {
		t.Fatalf("failure injection unexpectedly succeeded:\n%s", out)
	} else {
		t.Logf("expected injected timeout (complete output):\n%s", out)
	}
	tf.run("apply", "-auto-approve", "-input=false")

	// Update both resource kinds, then exercise refresh and an out-of-band
	// deletion. The next plan must propose recreation of the missing WLAN.
	writeConfigUpdated(t, work, proxy.addr())
	tf.run("plan", "-input=false", "-out=update.tfplan")
	tf.run("apply", "-auto-approve", "-input=false")
	deleteWLAN(t, controllerAddr, token, "guest")
	tf.run("refresh", "-input=false")
	plan := tf.run("plan", "-input=false")
	if !strings.Contains(plan, "open-unifi_wlan.guest") {
		t.Fatalf("plan after out-of-band deletion did not mention guest recreation:\n%s", plan)
	}

	// Restarting with the same data directory verifies persistence across the
	// real process boundary, rather than merely reusing an in-process handler.
	controller.stop()
	controller = startController(t, filepath.Join(bin, "openunifi"), controllerAddr, data, token)
	controller.waitReady(t)
	tf.run("refresh", "-input=false")

	// Import both an AP and WLAN into a clean state file. This also covers the
	// normalization of AP import IDs and WLAN's name-as-ID contract.
	tf.run("state", "rm", "open-unifi_access_point.lab", "open-unifi_wlan.main")
	tf.run("import", "open-unifi_access_point.lab", "AA:BB:CC:DD:EE:01")
	tf.run("import", "open-unifi_wlan.main", "main")
	tf.run("plan", "-input=false")

	// The admin token is supplied through the runner environment, never HCL or state.
	writeConfigSecretChange(t, work, proxy.addr())
	human := tf.run("plan", "-input=false")
	if strings.Contains(human, "correct-horse-battery") || strings.Contains(human, "new-secret-value") {
		t.Fatalf("human plan leaked a passphrase:\n%s", human)
	}
	if strings.Contains(human, token) {
		t.Fatalf("human plan leaked the admin token")
	}
	state := tf.run("state", "pull")
	if strings.Contains(state, token) {
		t.Fatalf("raw state leaked the admin token")
	}
	tf.run("destroy", "-auto-approve", "-input=false")
}

type terraform struct {
	t                  *testing.T
	dir, config, token string
}

func newTerraform(t *testing.T, dir, config, token string) terraform {
	return terraform{t: t, dir: dir, config: config, token: token}
}
func (tf terraform) run(args ...string) string {
	out, err := tf.runAllowFailure(args...)
	if err != nil {
		tf.t.Fatalf("terraform %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}
func (tf terraform) runAllowFailure(args ...string) (string, error) {
	cmd := exec.Command("terraform", args...)
	cmd.Dir, cmd.Env = tf.dir, append(os.Environ(), "TF_CLI_CONFIG_FILE="+tf.config, "OPEN_UNIFI_ADMIN_TOKEN="+tf.token)
	buf, err := commandOutput(cmd)
	return buf, err
}

func commandOutput(cmd *exec.Cmd) (string, error) {
	b, err := cmd.CombinedOutput()
	return string(b), err
}
func goRun(t *testing.T, args ...string) {
	cmd := exec.Command("go", args...)
	cmd.Dir = repoRoot(t)
	if out, err := commandOutput(cmd); err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}
func repoRoot(t *testing.T) string {
	d, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if info, statErr := os.Stat(filepath.Join(d, "go.mod")); statErr == nil && !info.IsDir() {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			t.Fatalf("could not discover repository root from %q: no go.mod found", d)
		}
		d = parent
	}
}

type controllerProcess struct {
	t           *testing.T
	cmd         *exec.Cmd
	output      strings.Builder
	mu          sync.Mutex
	addr        string
	data, token string
	binary      string
	stopped     bool
}

func startController(t *testing.T, binary, addr, data, token string) *controllerProcess {
	c := &controllerProcess{t: t, addr: addr, data: data, token: token, binary: binary}
	// Discovery is disabled, but the controller still validates its port
	// argument. Use a valid, otherwise unused port instead of :0 (the flag
	// deliberately rejects zero).
	c.cmd = exec.Command(binary, "--listen-inform", "127.0.0.1:0", "--listen-admin", addr, "--listen-discovery", "127.0.0.1:10001", "--discovery=false", "--data-dir", data, "--admin-token", token, "--allow-plaintext-inform")
	c.cmd.Stdout, c.cmd.Stderr = &lockedWriter{c: c}, &lockedWriter{c: c}
	if err := c.cmd.Start(); err != nil {
		t.Fatalf("start controller: %v", err)
	}
	return c
}

type lockedWriter struct{ c *controllerProcess }

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.c.mu.Lock()
	defer w.c.mu.Unlock()
	return w.c.output.Write(p)
}
func (c *controllerProcess) waitReady(t *testing.T) {
	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, "http://"+c.addr+"/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			lastErr = fmt.Errorf("healthz returned %s", resp.Status)
		} else {
			lastErr = err
		}
		time.Sleep(25 * time.Millisecond)
	}
	c.stop()
	t.Fatalf("controller did not become ready (%v); output:\n%s", lastErr, c.logs())
}
func (c *controllerProcess) stop() {
	if c == nil || c.cmd == nil || c.cmd.Process == nil {
		return
	}
	// Idempotent: the explicit restart below and the deferred cleanup both
	// call stop; a second stop must be a no-op, not a signal/Wait on an
	// already-reaped process.
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	c.mu.Unlock()
	_ = c.cmd.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- c.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
		<-done
	}
}
func (c *controllerProcess) logs() string { c.mu.Lock(); defer c.mu.Unlock(); return c.output.String() }

func freeTCPAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

type forwardProxy struct {
	ln     net.Listener
	target string
	first  bool
	mu     sync.Mutex
	done   chan struct{}
}

func newForwardProxy(t *testing.T, target string) *forwardProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &forwardProxy{ln: ln, target: target, first: true, done: make(chan struct{})}
	go p.serve()
	return p
}
func (p *forwardProxy) addr() string { return p.ln.Addr().String() }
func (p *forwardProxy) serve() {
	defer close(p.done)
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		fail := p.first
		p.first = false
		p.mu.Unlock()
		go p.handle(c, fail)
	}
}
func (p *forwardProxy) handle(c net.Conn, fail bool) {
	defer c.Close()
	if fail {
		time.Sleep(2500 * time.Millisecond)
		return
	}
	dst, err := net.DialTimeout("tcp", p.target, time.Second)
	if err != nil {
		return
	}
	defer dst.Close()
	go io.Copy(dst, c)
	_, _ = io.Copy(c, dst)
}
func (p *forwardProxy) close() { _ = p.ln.Close(); <-p.done }

func writeConfig(t *testing.T, dir, url string) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}
	writeHCL(t, dir, fmt.Sprintf(`terraform {
  required_providers {
    open-unifi = {
      source = %q
    }
  }
}

provider "open-unifi" {
  url = %q
}

resource "open-unifi_access_point" "lab" {
  mac  = "aa:bb:cc:dd:ee:01"
  name = "lab-ap"
}

resource "open-unifi_wlan" "main" {
  name       = "main"
  ssid       = "MainNet"
  security   = "wpa-p"
  passphrase = "correct-horse-battery"
  vlan       = 42
}

resource "open-unifi_wlan" "guest" {
  name     = "guest"
  ssid     = "GuestNet"
  security = "open"
  vlan     = 1
}
`, providerAddress, url))
}
func writeConfigUpdated(t *testing.T, dir, url string) {
	writeConfig(t, dir, url)
	b, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(b), `name = "lab-ap"`, `name = "lab-ap-updated"`, 1)
	updated = strings.Replace(updated, `vlan = 42`, `vlan = 43`, 1)
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
}
func writeConfigSecretChange(t *testing.T, dir, url string) {
	writeConfig(t, dir, url)
	b, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(strings.Replace(string(b), "correct-horse-battery", "new-secret-value", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}
func writeHCL(t *testing.T, dir, content string) {
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	terraformInit(t, dir)
}
func terraformInit(t *testing.T, dir string) {
	cmd := exec.Command("terraform", "init", "-input=false")
	cmd.Dir = dir
	if out, err := commandOutput(cmd); err != nil {
		t.Fatalf("terraform init: %v\n%s", err, out)
	}
}

func deleteWLAN(t *testing.T, addr, token, name string) {
	req, err := http.NewRequest(http.MethodDelete, "http://"+addr+"/api/v1/wireless/"+name, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("out-of-band WLAN delete: %s: %s", resp.Status, b)
	}
}

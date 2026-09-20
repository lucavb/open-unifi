package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/store"
	"golang.org/x/crypto/ssh"
)

// armInformPush arms the set-inform push lane with an injectable runner
// pointing at the same URL derivation the flag wiring uses in main.
func armInformPush(t *testing.T, a *App) {
	t.Helper()
	if err := a.EnableSetInformPush("http://10.10.10.10:8080", ":8080"); err != nil {
		t.Fatalf("arm: %v", err)
	}
}

type pushCall struct {
	ip   string
	port int
	url  string
	ctx  context.Context
}

// countingRunner returns a runSetInformSSH-shaped runner recording every
// call (context included) and optionally failing.
func countingRunner(fail error) (func(ctx context.Context, ip string, port int, informURL string) error, *[]pushCall) {
	calls := &[]pushCall{}
	return func(ctx context.Context, ip string, port int, informURL string) error {
		*calls = append(*calls, pushCall{ip: ip, port: port, url: informURL, ctx: ctx})
		return fail
	}, calls
}

const factoryNote = "discovery:uptime=43,version=BZ.4.3.20,model=U7PG2,ip=10.10.10.20,factory=true"

// ---- lane gating -----------------------------------------------------------

// TestAdoptPendingWithoutLaneNeverPushes pins the flag-off refusal: the
// default New() has no armed lane, adopts keep working (state 1), and
// nothing pushes.
func TestAdoptPendingWithoutLaneNeverPushes(t *testing.T) {
	a, st, _ := testApp(t)
	if a.informPush != nil {
		t.Fatal("default New must leave the lane disarmed (nil)")
	}
	if err := st.MarkPending("a040a0aabbcc", factoryNote); err != nil {
		t.Fatal(err)
	}
	dv, err := a.AdoptPending(context.Background(), "a0:40:a0:aa:bb:cc")
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if dv.State != store.StatePending {
		t.Fatalf("adopt view state: %+v", dv)
	}
}

// TestAdoptPendingWithLanePushesFactoryCandidate pins the armed happy
// path: exactly one push with the note's ip, the jar-default sshd port 22
// and the derived inform URL; the adopt still returns the state-1 view.
func TestAdoptPendingWithLanePushesFactoryCandidate(t *testing.T) {
	a, st, _ := testApp(t)
	armInformPush(t, a)
	run, calls := countingRunner(nil)
	a.informPush.run = run
	if err := st.MarkPending("a040a0aabbcc", factoryNote); err != nil {
		t.Fatal(err)
	}
	dv, err := a.AdoptPending(context.Background(), "a0:40:a0:aa:bb:cc")
	if err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if dv.MAC != "a0:40:a0:aa:bb:cc" || dv.State != store.StatePending {
		t.Fatalf("adopt view: %+v", dv)
	}
	if len(*calls) != 1 {
		t.Fatalf("push call count: %d", len(*calls))
	}
	c := (*calls)[0]
	if c.ip != "10.10.10.20" {
		t.Fatalf("push ip: %q", c.ip)
	}
	if c.port != 22 {
		t.Fatalf("push port: %d (want the absent-key default 22)", c.port)
	}
	if c.url != "http://10.10.10.10:8080/inform" {
		t.Fatalf("push url: %q", c.url)
	}
}

// TestAdoptPendingRespectsSshdPortNote pins the note-transported port:
// sshd_port=2222 (discovery TLV 28) must reach the runner verbatim.
func TestAdoptPendingRespectsSshdPortNote(t *testing.T) {
	a, st, _ := testApp(t)
	armInformPush(t, a)
	run, calls := countingRunner(nil)
	a.informPush.run = run
	if err := st.MarkPending("a040a0aabbcc",
		"discovery:model=U7PG2,ip=10.10.10.20,sshd_port=2222,factory=true"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AdoptPending(context.Background(), "a0:40:a0:aa:bb:cc"); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0].port != 2222 {
		t.Fatalf("push calls: %+v", *calls)
	}
}

// TestAdoptPendingGating pins the NOT-APPLICABLE shapes (never pushed,
// never an error): a non-factory discovery announce, a factory key absent
// (TLV 23 missing), the inform lane's note, and a manually created PENDING
// record with no pending-map entry at all.
func TestAdoptPendingGating(t *testing.T) {
	t.Run("factory=false", func(t *testing.T) {
		a, st, _ := testApp(t)
		armInformPush(t, a)
		run, calls := countingRunner(nil)
		a.informPush.run = run
		if err := st.MarkPending("a040a0aabbcc", "discovery:ip=10.10.10.20,factory=false"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.AdoptPending(context.Background(), "a0:40:a0:aa:bb:cc"); err != nil {
			t.Fatalf("adopt: %v", err)
		}
		if len(*calls) != 0 {
			t.Fatalf("pushed non-factory candidate: %+v", *calls)
		}
	})
	t.Run("factory-key-absent", func(t *testing.T) {
		a, st, _ := testApp(t)
		armInformPush(t, a)
		run, calls := countingRunner(nil)
		a.informPush.run = run
		if err := st.MarkPending("a040a0aabbcc", "discovery:ip=10.10.10.20,model=U7PG2"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.AdoptPending(context.Background(), "a0:40:a0:aa:bb:cc"); err != nil {
			t.Fatalf("adopt: %v", err)
		}
		if len(*calls) != 0 {
			t.Fatalf("pushed TLV23-absent candidate: %+v", *calls)
		}
	})
	t.Run("inform-factory-note", func(t *testing.T) {
		a, st, _ := testApp(t)
		armInformPush(t, a)
		run, calls := countingRunner(nil)
		a.informPush.run = run
		if err := st.MarkPending("a040a0aabbcc", "inform:factory"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.AdoptPending(context.Background(), "a0:40:a0:aa:bb:cc"); err != nil {
			t.Fatalf("adopt: %v", err)
		}
		if len(*calls) != 0 {
			t.Fatalf("pushed inform-lane candidate: %+v", *calls)
		}
	})
	t.Run("pending-record-without-map-entry", func(t *testing.T) {
		a, st, _ := testApp(t)
		armInformPush(t, a)
		run, calls := countingRunner(nil)
		a.informPush.run = run
		// Manual CreateDevice shape: a whitelist row (state PENDING)
		// that never came from discovery — no note to parse.
		if err := st.Put(store.Device{MAC: "f09fc2848f2a", State: store.StatePending, FirstSeen: 1700000000}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.AdoptPending(context.Background(), "f0:9f:c2:84:8f:2a"); err != nil {
			t.Fatalf("adopt: %v", err)
		}
		if len(*calls) != 0 {
			t.Fatalf("pushed record-only candidate: %+v", *calls)
		}
	})
}

// TestAdoptPendingPushRetryIsOneShotPerClick pins the failure contract:
// a failed push wraps adminapi.ErrSetInformPushFailed, the whitelist
// promotion STANDS (state 1 in the store), and the SECOND AdoptPending
// re-attempts (exactly two runner calls total — no background loop).
func TestAdoptPendingPushRetryIsOneShotPerClick(t *testing.T) {
	a, st, _ := testApp(t)
	armInformPush(t, a)
	boom := errors.New("mca-cli-op set-inform: exit status 1: permission denied")
	run, calls := countingRunner(boom)
	a.informPush.run = run
	if err := st.MarkPending("a040a0aabbcc", factoryNote); err != nil {
		t.Fatal(err)
	}
	_, err := a.AdoptPending(context.Background(), "a0:40:a0:aa:bb:cc")
	if !errors.Is(err, adminapi.ErrSetInformPushFailed) {
		t.Fatalf("adopt error: want ErrSetInformPushFailed wrap, got %v", err)
	}
	rec, rerr := st.Get("a040a0aabbcc")
	if rerr != nil || rec.State != store.StatePending {
		t.Fatalf("promotion must stand: rec=%+v err=%v", rec, rerr)
	}
	// Second click: one fresh push attempt, not zero, not another two.
	if _, err := a.AdoptPending(context.Background(), "a0:40:a0:aa:bb:cc"); !errors.Is(err, adminapi.ErrSetInformPushFailed) {
		t.Fatalf("second adopt error: %v", err)
	}
	if len(*calls) != 2 {
		t.Fatalf("runner called %d times, want exactly 2", len(*calls))
	}
}

// TestSetInformCandidateParser is the pure parser table: applicable+error
// shapes vs non-applicable vs the port bounds.
func TestSetInformCandidateParser(t *testing.T) {
	cases := []struct {
		note       string
		applicable bool
		wantErr    bool
		wantIP     string
		wantPort   int
	}{
		{note: factoryNote, applicable: true, wantIP: "10.10.10.20", wantPort: 22},
		{note: "discovery:model=U7PG2,ip=10.0.9.9,sshd_port=22,factory=true", applicable: true, wantIP: "10.0.9.9", wantPort: 22},
		{note: "discovery:ip=10.10.10.20,sshd_port=0,factory=true", applicable: true, wantErr: true},
		{note: "discovery:ip=10.10.10.20,sshd_port=70000,factory=true", applicable: true, wantErr: true},
		{note: "discovery:ip=10.10.10.20,sshd_port=-1,factory=true", applicable: true, wantErr: true},
		{note: "discovery:factory=true", applicable: true, wantErr: true}, // no ip=
		{note: "discovery:ip=10.10.10.20,factory=false", applicable: false},
		{note: "discovery:ip=10.10.10.20,factory=True", applicable: false}, // exact match only
		{note: "discovery:ip=10.10.10.20,model=U7PG2", applicable: false},  // TLV23 absent
		{note: "inform:factory", applicable: false},
		{note: "discovery:", applicable: false},
		{note: "", applicable: false},
	}
	for _, tc := range cases {
		tgt, ok, err := setInformCandidate(tc.note)
		if ok != tc.applicable {
			t.Errorf("%q: applicable=%v want %v", tc.note, ok, tc.applicable)
		}
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: err=%v wantErr=%v", tc.note, err, tc.wantErr)
		}
		if tc.applicable && !tc.wantErr {
			if tgt.ip != tc.wantIP || tgt.sshdPort != tc.wantPort {
				t.Errorf("%q: target ip=%q port=%d want ip=%q port=%d", tc.note, tgt.ip, tgt.sshdPort, tc.wantIP, tc.wantPort)
			}
		}
	}
}

// TestAdoptPendingPushDeadlinePinsTimeoutWindow pins the timeout wiring:
// the runner's context carries a deadline at most 10s out (the admin
// server write budget is 30s), and a runner that blocks until ctx.Done()
// fails the adopt with the sentinel.
func TestAdoptPendingPushDeadlinePinsTimeoutWindow(t *testing.T) {
	a, st, _ := testApp(t)
	armInformPush(t, a)
	a.informPush.run = func(ctx context.Context, ip string, port int, informURL string) error {
		dl, ok := ctx.Deadline()
		if !ok {
			return errors.New("test: runner ctx has no deadline")
		}
		// The push lane's own budget: 10s out (test clock slop allowed).
		if out := time.Until(dl); out > 10*time.Second || out <= 0 {
			return fmt.Errorf("test: runner deadline=%v (%v from now)", dl, out)
		}
		// Block until the budget fires, then surface it: the deadline is
		// enforced by pushSetInform's context; the runner follows the same
		// ctx instead of a private timer.
		<-ctx.Done()
		return ctx.Err()
	}
	if err := st.MarkPending("a040a0aabbcc", factoryNote); err != nil {
		t.Fatal(err)
	}
	_, err := a.AdoptPending(context.Background(), "a0:40:a0:aa:bb:cc")
	if !errors.Is(err, adminapi.ErrSetInformPushFailed) {
		t.Fatalf("adopt error: want ErrSetInformPushFailed wrap, got %v", err)
	}
	if !strings.Contains(fmt.Sprint(err), context.DeadlineExceeded.Error()) {
		t.Fatalf("adopt error should carry deadline-exceeded context, got %v", err)
	}
}

// TestEnableSetInformPushControllerURLRefusal pins the fail-fast: an empty
// controller URL cannot derive an inform URL, so arming must fail (main
// turns this into startup refusal).
func TestEnableSetInformPushControllerURLRefusal(t *testing.T) {
	a, _, _ := testApp(t)
	if err := a.EnableSetInformPush("", ":8080"); err == nil {
		t.Fatal("arming with an empty controller URL must fail")
	}
}

// ---- production SSH runner against an in-process sshd ----------------------
//
// A full session-exec channel server (newChannel "session" → pty-req →
// exec → output → exit status), so runSetInformSSH's real client
// exercises handshake, the pty request, the command transport and
// CombinedOutput end to end — not just auth.

// loopbackConnectable probes whether the OS lets this process CONNECT to
// its own loopback listener. The nono sandbox (Seatbelt profile) allows
// binding/listening but denies connect with EPERM — an environment trait,
// not a code bug — so socket-bound SSH tests skip in that case.
func loopbackConnectable(t *testing.T) bool {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	port := ln.Addr().(*net.TCPAddr).Port
	c, cerr := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if cerr == nil {
		_ = c.Close()
	}
	_ = ln.Close()
	return cerr == nil || !strings.Contains(cerr.Error(), "operation not permitted")
}

// TestSetInformCommandComposition is the environment-independent assertion
// of the exact command string handed to the device (the TCP-bound sshd
// tests re-assert it end to end where sockets are allowed).
func TestSetInformCommandComposition(t *testing.T) {
	if setInformCommandPrefix != "mca-cli-op set-inform " {
		t.Fatalf("prefix drift: %q", setInformCommandPrefix)
	}
	if got := setInformCommand("http://10.10.10.10:8080/inform"); got != "mca-cli-op set-inform http://10.10.10.10:8080/inform" {
		t.Fatalf("command: %q", got)
	}
}

// testServerState records what the server saw.
type testServerState struct {
	commands []string
	rejects  int
}

// startTestSSHServer spins an in-process SSH server on 127.0.0.1 that
// accepts ONLY the factory credentials (unless rejectAuth), handles the
// session/newChannel exec shape exactly like the device's sshd, and
// records every executed command.
func startTestSSHServer(t *testing.T, rejectAuth bool) (host string, port int, rec *testServerState) {
	t.Helper()
	rec = &testServerState{}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if rejectAuth {
				rec.rejects++
				return nil, errors.New("rejected")
			}
			if conn.User() == factorySSHUser && string(password) == factorySSHPassword {
				return nil, nil
			}
			rec.rejects++
			return nil, errors.New("rejected")
		},
	}
	cfg.AddHostKey(testSigner(t, t.TempDir()))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ssh listen: %v", err)
	}
	port = ln.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSSHConn(c, cfg, rec, rejectAuth)
		}
	}()
	return "127.0.0.1", port, rec
}

// serveSSHConn performs the handshake and services channels of one
// connection: session channels reply true to pty-req, record the exec
// command, print device-style success output, send exit-status 0 (or 1
// for an auth-rejected test... auth rejection never reaches here) and
// close.
func serveSSHConn(c net.Conn, cfg *ssh.ServerConfig, rec *testServerState, rejectAuth bool) {
	defer func() { _ = c.Close() }()
	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return // rejected auth lands here (expected in the wrong-password test)
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs) // global requests (hostkeys, keepalives)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReq, err := newCh.Accept()
		if err != nil {
			continue
		}
		go serveSession(ch, chReq, rec)
	}
}

// serveSession mirrors a device-side minimal sshd session: accept pty-req,
// accept exec, record the command, answer with output + exit status 0.
func serveSession(ch ssh.Channel, chReq <-chan *ssh.Request, rec *testServerState) {
	for req := range chReq {
		switch req.Type {
		case "pty-req":
			// Mirroring the proven recovery lane: the client asks for a
			// pty; grant it (payload layout irrelevant to us).
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			// [uint32 len][cmd bytes]
			if len(req.Payload) < 4 {
				_ = req.Reply(false, nil)
				continue
			}
			cmdLen := binary.BigEndian.Uint32(req.Payload[:4])
			if int(cmdLen) > len(req.Payload[4:]) {
				_ = req.Reply(false, nil)
				continue
			}
			cmd := string(req.Payload[4 : 4+cmdLen])
			rec.commands = append(rec.commands, cmd)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			// Device behavior: on success the CLI prints
			// "Adoption request sent to '<url>'".
			_, _ = ch.Write([]byte("Adoption request sent to 'the-url'\n"))
			// Exit status packet, then EOF + close → CombinedOutput
			// unblocks with err == nil.
			st := make([]byte, 4)
			binary.BigEndian.PutUint32(st, 0)
			_, _ = ch.SendRequest("exit-status", false, st)
			_ = ch.Close()
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// TestRunSetInformSSHFullExec pins the production runner against the
// in-process sshd: exact command composition, factory-credential auth and
// zero error on a well-behaved device session.
//
// The nono sandbox of the current dev environment denies arbitrary
// loopback connects at the OS level (listen works, connect → EPERM), so
// these three tests SKIP when the dial is refused by the sandbox and run
// for real wherever loopback sockets are allowed (bench/CI).
func TestRunSetInformSSHFullExec(t *testing.T) {
	if !loopbackConnectable(t) {
		t.Skip("sandbox denies loopback connect (EPERM); TCP SSH tests need a socket-enabled environment")
	}
	host, port, rec := startTestSSHServer(t, false)
	err := runSetInformSSH(context.Background(), host, port, "http://10.10.10.10:8080/inform")
	if err != nil {
		t.Fatalf("runSetInformSSH: %v", err)
	}
	if len(rec.commands) != 1 {
		t.Fatalf("exec count: %d commands=%v", len(rec.commands), rec.commands)
	}
	want := "mca-cli-op set-inform http://10.10.10.10:8080/inform"
	if rec.commands[0] != want {
		t.Fatalf("command: got %q want %q", rec.commands[0], want)
	}
}

// TestRunSetInformSSHAuthRejects pins the false-negative direction: the
// factory password must be verified, wrong credentials are an error AND
// no exec ever runs on the device.
func TestRunSetInformSSHAuthRejects(t *testing.T) {
	if !loopbackConnectable(t) {
		t.Skip("sandbox denies loopback connect (EPERM); TCP SSH tests need a socket-enabled environment")
	}
	host, port, rec := startTestSSHServer(t, true)
	err := runSetInformSSH(context.Background(), host, port, "http://10.10.10.10:8080/inform")
	if err == nil {
		t.Fatal("wrong-password session must fail")
	}
	if len(rec.commands) != 0 {
		t.Fatalf("rejected auth must never exec: %v", rec.commands)
	}
	if !strings.Contains(err.Error(), "ssh handshake") {
		t.Fatalf("error should name the handshake: %v", err)
	}
}

// TestRunSetInformSSHFactoryCredentialsAccepted proves the runner cannot
// pass auth with anything OTHER than the factory pair (it is hardwired;
// the site --ap-ssh-password must not leak into the factory lane).
func TestRunSetInformSSHFactoryCredentialsAccepted(t *testing.T) {
	if !loopbackConnectable(t) {
		t.Skip("sandbox denies loopback connect (EPERM); TCP SSH tests need a socket-enabled environment")
	}
	host, port, _ := startTestSSHServer(t, false)
	// Sanity: the runner hardwires the factory pair, so this call succeeds
	// precisely when those are the credentials the server demands —
	// exercised above; here we only pin that the constants are the
	// canonical "ubnt"/"ubnt" pair.
	if factorySSHUser != "ubnt" || factorySSHPassword != "ubnt" {
		t.Fatal("factory credentials must stay ubnt/ubnt (docs/PROTOCOL-mgmt.md §7)")
	}
	if err := runSetInformSSH(context.Background(), host, port, "http://10.10.10.10:8080/inform"); err != nil {
		t.Fatalf("factory credentials must authenticate: %v", err)
	}
}

// testSigner mints a throwaway in-memory host key for the test sshd (no
// disk persistence needed).
func testSigner(t *testing.T, _ string) ssh.Signer { // dir arg ignored
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

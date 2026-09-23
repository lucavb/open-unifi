// Controller-side SSH set-inform push lane (docs/PROTOCOL-mgmt.md §7).
//
// Purpose and scope: a pending candidate that reached the controller ONLY
// through the discovery announce (never through an inform) shows up in the
// console's pending list. Promoting it via AdoptPending arms the adoption —
// but a never-informed device does not know WHERE to inform, so the
// whitelist arming alone never fires. This lane closes that gap for lab
// use: when the operator opts in with --allow-ssh-set-inform-push, a
// successful adopt of a FACTORY ANNOUNCE candidate additionally dials the
// device over SSH with the factory default password and runs
//
//	mca-cli-op set-inform <inform-url>
//
// — the proven 2026-09-20 round-2 recovery lane (WLAN-ACCEPTANCE runbook:
// `mca-cli-op <command> [args]`, `set-inform http://…/inform` →
// "Adoption request sent to '<url>'"; a bare `mca-cli-op` invocation enters
// an interactive CLI and hangs a non-tty, which is why the command prefix
// always carries arguments).
package app

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lucavb/open-unifi/internal/adminapi"
	"github.com/lucavb/open-unifi/internal/server/adoption"
	"github.com/lucavb/open-unifi/internal/store"
	"golang.org/x/crypto/ssh"
)

// setInformPushTimeout is the TOTAL budget (dial + SSH handshake +
// command I/O) of a single push attempt. It must stay under the admin
// server's 30s WriteTimeout (cmd/openunifi/main.go:248) for the Adopt
// HTTP request to still receive a body instead of a truncated connection.
const setInformPushTimeout = 10 * time.Second

const (
	// factorySSHUser / factorySSHPassword are the FACTORY default
	// credentials of a factory-state device (docs/PROTOCOL-mgmt.md §7: site
	// mgmt x_ssh_password defaults to "ubnt"; the device has never received
	// a rendered config, so no provisioned SSH password can have reached
	// it yet). Deliberately NOT the per-device ssh_password row
	// (store.Device.SSHPassword): that row hashes into system_cfg for
	// ADOPTED devices, while this push targets a candidate that has never
	// been provisioned. The whole lane is --allow-ssh-set-inform-push
	// gated for that reason.
	factorySSHUser     = "ubnt"
	factorySSHPassword = "ubnt"
)

// setInformCommandPrefix is the proven one-shot form of the device-side
// command: `mca-cli-op <command> [args]` (WLAN-ACCEPTANCE-6.8.2.15592.md
// runbook). A bare `mca-cli-op` invocation enters an interactive CLI and
// hangs a non-tty session — we always append `set-inform <url>`, so the
// interactive path is never taken.
const setInformCommandPrefix = "mca-cli-op set-inform "

// setInformPush is the armed push lane. The run function is injectable so
// tests can replace the SSH leg entirely.
type setInformPush struct {
	url     string        // derived inform URL (adoption.InformURL)
	timeout time.Duration // per-attempt total budget
	run     func(ctx context.Context, ip string, port int, informURL string) error
}

// setInformTarget is the parsed dial target of one factory-announce note.
type setInformTarget struct {
	ip       string
	sshdPort int
}

// setInformCandidate parses a pending-candidate note into a push target.
//
// ok=false means the lane must NEVER fire for this candidate (not an
// error): the note is not even a discovery note (covers the inform lane's
// "inform:factory" — internal/server/server.go:48 — that candidate already
// informs, so the whitelist arming from AdoptPending is sufficient), or
// the discovery note's factory key is not EXACTLY "factory=true" (TLV 23
// absent or false: internal/server/discovery.go discoveryNote appends the
// key ONLY when TLV23 was present, so "factory=False"/typo casing
// legitimately parse as "not marked" rather than malformed).
//
// ok=true, err!=nil means the note APPLIES (factory announce) but cannot
// be dialied as-is — no ip= part, or an sshd_port= part outside 1..65535 —
// and is refused loudly instead of silently defaulting to port 22.
//
// Note shape (discoveryNote, internal/server/discovery.go:447): a
// "discovery:" prefix, then comma-joined order-independent k=v parts
// where each part splits on the FIRST '=' only. sshd_port absent means 22
// (docs/PROTOCOL-mgmt.md §7: device.getInt("sshd_port", 22) = discovery
// TLV 28). An expected note looks like
//
//	discovery:uptime=43,version=BZ.…,model=U7PG2,ip=10.10.10.20,factory=true
//
// (ordering not guaranteed by discoveryNote above).
func setInformCandidate(note string) (setInformTarget, bool, error) {
	tgt := setInformTarget{sshdPort: 22} // jar default for an absent sshd_port
	const prefix = "discovery:"
	if !strings.HasPrefix(note, prefix) {
		return tgt, false, nil
	}
	body := note[len(prefix):]
	applicable := false
	partCount := 0
	for len(body) > 0 {
		partCount++
		part := body
		if i := strings.IndexByte(body, ','); i >= 0 {
			part = body[:i]
			body = body[i+1:]
		} else {
			body = ""
		}
		// Split on the FIRST '=' only (values may contain '=' in theory).
		key := part
		val := ""
		if i := strings.IndexByte(part, '='); i >= 0 {
			key, val = part[:i], part[i+1:]
		}
		switch key {
		case "factory":
			if val == "true" {
				// Exact match: discoveryNote only emits the key when
				// TLV23 was present, and FormatBool only emits "true"
				// then; anything else is a device that never marked
				// itself factory — not our candidate.
				applicable = true
			}
		case "ip":
			tgt.ip = val
		case "sshd_port":
			n, perr := strconv.Atoi(val)
			if perr != nil || n < 1 || n > 65535 {
				return tgt, true, fmt.Errorf("refusing non-dialable sshd_port=%q", val)
			}
			tgt.sshdPort = n
		default:
			// version/model/hostname/uptime/… : informational only.
			continue
		}
	}
	if partCount == 0 {
		return tgt, false, nil // bare "discovery:" note: nothing known at all
	}
	if applicable && tgt.ip == "" {
		return tgt, true, fmt.Errorf("refusing factory note without an ip= part")
	}
	return tgt, applicable, nil
}

// EnableSetInformPush arms the controller-side SSH set-inform push lane
// (--allow-ssh-set-inform-push, cmd/openunifi/main.go). The inform URL is
// derived via adoption.InformURL from the validated --controller-url flag
// and the inform listen address: http://<host>:<port>/inform, the same URL
// the mgmt_cfg inform_url row carries (internal/server/adoption/
// mgmtcfg.go). An empty derivation (empty or hostless controller URL)
// returns an error — cmd/openunifi refuses startup, fail-fast like the
// other flag validations — because a push that hands the device a blank
// URL is worse than no push.
//
// Calling this twice re-arms with fresh values (main only calls it once).
func (a *App) EnableSetInformPush(controllerURL, informListenAddr string) error {
	url := adoption.InformURL(controllerURL, informListenAddr)
	if url == "" {
		return fmt.Errorf("cannot derive an inform URL from controller URL %q: a host is required", controllerURL)
	}
	a.informPush = &setInformPush{
		url:     url,
		timeout: setInformPushTimeout,
		run:     runSetInformSSH,
	}
	a.lg.Info("set-inform push lane armed", "inform_url", url)
	return nil
}

// pushSetInform runs ONE set-inform push attempt for an already-promoted
// pending candidate, immediately after AdoptPending committed the store
// whitelist promotion.
//
// The contract is strictly one-shot per operator click: no background
// retry loop exists. On failure the promotion STANDS (it was already
// committed by the store Update) and the operator's next Adopt click
// re-attempts the push.
//
// Every attempt logs the same mac/ip/outcome triple the discovery
// listener's per-candidate "discovery: announced" discipline
// (internal/server/discovery.go) logs, so the operator can always tell
// whether the push went out and to whom.
func (a *App) pushSetInform(ctx context.Context, mac string) error {
	if a.informPush == nil {
		// The --allow-ssh-set-inform-push opt-in was not supplied: the
		// lane never fires and AdoptPending keeps its
		// whitelist-arming-only semantics.
		return nil
	}
	pend, err := a.st.Pending()
	if err != nil {
		return fmt.Errorf("pending read for set-inform: %w", err)
	}
	target, applicable, cerr := setInformCandidate(pend[mac])
	if !applicable {
		a.lg.Debug("set-inform: not a factory announce candidate", "mac", store.ColonMAC(mac))
		return nil
	}
	if cerr != nil {
		a.lg.Warn("set-inform: candidate refused", "mac", store.ColonMAC(mac), "ip", target.ip, "outcome", "refused", "err", cerr)
		return fmt.Errorf("%w: %v", adminapi.ErrSetInformPushFailed, cerr)
	}
	cctx, cancel := context.WithTimeout(ctx, a.informPush.timeout)
	defer cancel()
	rerr := a.informPush.run(cctx, target.ip, target.sshdPort, a.informPush.url)
	if rerr == nil {
		a.lg.Info("set-inform: pushed", "mac", store.ColonMAC(mac), "ip", target.ip, "outcome", "pushed", "url", a.informPush.url)
		return nil
	}
	a.lg.Warn("set-inform: push failed", "mac", store.ColonMAC(mac), "ip", target.ip, "outcome", "failed", "err", rerr)
	return fmt.Errorf("%w: %v", adminapi.ErrSetInformPushFailed, rerr)
}

// setInformCommand composes the exact command string handed to the device:
// `mca-cli-op set-inform http://<host>:<port>/inform` — no quoting, no
// extra shell wrapping (the URL charset is constrained: it comes from the
// validated --controller-url flag). Split out pure so the composition is
// directly testable even where a socket dial is not.
func setInformCommand(informURL string) string {
	return setInformCommandPrefix + informURL
}

// runSetInformSSH is the production runner: one SSH session over the
// factory credentials, running `mca-cli-op set-inform <url>`.
//
// HostKeyCallback is ssh.InsecureIgnoreHostKey() — accepted deliberately
// and documented honestly: that is the jar's own fallback when no TLV-16
// ssh_key fingerprint was pre-seeded (docs/PROTOCOL-mgmt.md §7 — "host key
// pre-seeded from discovery TLV-16 fingerprint, else accept-all"), and we
// cannot do better: the TLV-16 fingerprint's exact SHA-256 input is
// UNRESOLVED (docs/PROTOCOL-discovery.md §4) so the fingerprint cannot be
// verified. The entire lane is --allow-ssh-set-inform-push gated lab-only,
// and the credentials in play are factory defaults, not site secrets.
func runSetInformSSH(ctx context.Context, ip string, port int, informURL string) error {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	// ssh.NewClientConn and the session I/O are NOT context-aware, so the
	// 10s context budget has to be enforced on the TCP connection itself:
	// one deadline covers the SSH handshake AND all session reads/writes —
	// everything rides this same conn.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	cfg := &ssh.ClientConfig{
		User: factorySSHUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(factorySSHPassword),
			// Some factory sshd builds gate auth through a keyboard-
			// interactive prompt instead of a plain password packet;
			// answering every question with the same factory password
			// covers both shapes.
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = factorySSHPassword
				}
				return answers, nil
			}),
		},
		// Their fallback, our fallback — see the function comment above.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer func() { _ = client.Close() }() // closes the underlying conn too
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("ssh session: %w", err)
	}
	defer func() { _ = sess.Close() }()
	// Best effort deliberately: the proven recovery lane ran through a
	// pty-bearing session, so requesting one mirrors it; the one-shot
	// `mca-cli-op <command> [args]` form does not require a tty (only a
	// BARE mca-cli-op would hang — we never send one), so a refused pty
	// request is not fatal.
	_ = sess.RequestPty("dumb", 80, 40, nil)
	out, err := sess.CombinedOutput(setInformCommand(informURL))
	if err != nil {
		// The device's output is part of the evidence (success prints
		// "Adoption request sent to '<url>'"; failure prints error text),
		// so it must ride into the returned error.
		return fmt.Errorf("mca-cli-op set-inform: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

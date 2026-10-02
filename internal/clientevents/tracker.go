package clientevents

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

// DefaultGrace is how long a disconnect is held back waiting for the same
// client to appear on another AP (about three inform intervals).
const DefaultGrace = 30 * time.Second

// Sink receives finished events. Emit must not block for long: the tracker
// calls it in event order under its own lock.
type Sink interface {
	Emit(Event)
}

// Config configures a Tracker. The zero value is usable.
type Config struct {
	// Grace is the disconnect hold-back window (default DefaultGrace).
	Grace time.Duration
	// Now is the clock (default time.Now); tests inject one.
	Now func() time.Time
	// APName resolves a colon-hex AP MAC to its display name ("" = unknown).
	APName func(apMAC string) string
	// Sinks receive every event.
	Sinks []Sink
}

// presence is where the tracker currently believes a client is.
type presence struct {
	ap      string // colon-hex AP MAC
	session store.ClientSession
}

// pendingDisconnect is a disconnect held back during the grace window.
type pendingDisconnect struct {
	ap       string
	session  store.ClientSession
	at       int64 // inform time of the disconnect (unix seconds)
	deadline time.Time
}

// Tracker correlates per-AP session transitions into client events.
//
// A roam appears as a disconnect on the old AP and a connect on the new
// one, in either order, because every AP reports only its own station
// table:
//   - connect first: the client is still recorded on the old AP, so the
//     connect is a roam, and the old AP's late disconnect is dropped as
//     stale (the client is no longer recorded there);
//   - disconnect first: the disconnect is held for the grace window; a
//     connect elsewhere inside it is a roam, otherwise the window expiring
//     (Flush) emits the disconnect.
//
// A radio/channel change on the AP the client is on is EVT_WU_RoamRadio.
type Tracker struct {
	cfg Config

	mu      sync.Mutex
	current map[string]presence          // canonical client MAC -> presence
	pending map[string]pendingDisconnect // canonical client MAC -> held disconnect
}

// NewTracker builds a Tracker.
func NewTracker(cfg Config) *Tracker {
	if cfg.Grace <= 0 {
		cfg.Grace = DefaultGrace
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Tracker{
		cfg:     cfg,
		current: map[string]presence{},
		pending: map[string]pendingDisconnect{},
	}
}

// Seed primes the current-AP index from persisted session rows, without
// emitting events, so a controller restart neither re-announces connected
// clients nor misreads their next roam as a fresh connect. When a client
// is recorded connected on several devices, the freshest row wins.
func (t *Tracker) Seed(devices []store.Device) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, d := range devices {
		ap := store.ColonMAC(d.MAC)
		for _, s := range store.ClientSessions(d) {
			if !s.Connected {
				continue
			}
			if cur, ok := t.current[s.MAC]; ok && cur.session.LastSeen >= s.LastSeen {
				continue
			}
			t.current[s.MAC] = presence{ap: ap, session: s}
		}
	}
}

// Observe feeds the transitions one committed inform on AP apMAC (colon-hex)
// produced. Call it after the store cycle commits.
func (t *Tracker) Observe(apMAC string, ts []store.Transition) {
	if len(ts) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, tr := range ts {
		switch tr.Kind {
		case store.TransitionConnect:
			t.connect(apMAC, tr)
		case store.TransitionDisconnect:
			t.disconnect(apMAC, tr)
		case store.TransitionRadioChange:
			t.radioChange(apMAC, tr)
		}
	}
}

func (t *Tracker) connect(ap string, tr store.Transition) {
	c := tr.MAC
	if pend, ok := t.pending[c]; ok {
		delete(t.pending, c)
		if pend.ap == ap {
			// Same AP within the grace window: a genuine reconnect.
			t.emit(t.disconnectEvent(pend))
			t.emit(t.connectEvent(ap, tr))
		} else {
			t.emit(t.roamEvent(pend.ap, pend.session, ap, tr))
		}
		t.current[c] = presence{ap: ap, session: tr.Session}
		return
	}
	if cur, ok := t.current[c]; ok {
		if cur.ap == ap {
			// Already believed here (e.g. seeded): refresh, no event.
			t.current[c] = presence{ap: ap, session: tr.Session}
			return
		}
		t.emit(t.roamEvent(cur.ap, cur.session, ap, tr))
		t.current[c] = presence{ap: ap, session: tr.Session}
		return
	}
	t.emit(t.connectEvent(ap, tr))
	t.current[c] = presence{ap: ap, session: tr.Session}
}

func (t *Tracker) disconnect(ap string, tr store.Transition) {
	c := tr.MAC
	cur, ok := t.current[c]
	if !ok || cur.ap != ap {
		// The client already moved on (roam seen from the new AP first) or
		// was never tracked here: a stale report, not a disconnect.
		return
	}
	if _, held := t.pending[c]; held {
		return
	}
	t.pending[c] = pendingDisconnect{
		ap: ap, session: tr.Session, at: tr.At,
		deadline: t.cfg.Now().Add(t.cfg.Grace),
	}
}

func (t *Tracker) radioChange(ap string, tr store.Transition) {
	c := tr.MAC
	cur, ok := t.current[c]
	if !ok || cur.ap != ap {
		return
	}
	if _, held := t.pending[c]; held {
		return
	}
	e := Event{
		Key: KeyRoamRadio, Client: store.ColonMAC(c), Hostname: tr.Session.Hostname,
		IP: tr.Session.IP,
		AP: ap, APName: t.apName(ap), SSID: tr.Session.ESSID,
		Radio: tr.Session.Radio, RadioFrom: tr.Prev.Radio, RadioTo: tr.Session.Radio,
		Channel: tr.Session.Channel, ChannelFrom: tr.Prev.Channel, ChannelTo: tr.Session.Channel,
	}
	e.setTime(tr.At)
	e.buildMsg()
	t.emit(e)
	t.current[c] = presence{ap: ap, session: tr.Session}
}

// Flush emits the held disconnects whose grace window has elapsed at now.
func (t *Tracker) Flush(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var due []string
	for c, p := range t.pending {
		if !now.Before(p.deadline) {
			due = append(due, c)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		pi, pj := t.pending[due[i]], t.pending[due[j]]
		if pi.at != pj.at {
			return pi.at < pj.at
		}
		return due[i] < due[j]
	})
	for _, c := range due {
		p := t.pending[c]
		delete(t.pending, c)
		if cur, ok := t.current[c]; ok && cur.ap == p.ap {
			delete(t.current, c)
		}
		t.emit(t.disconnectEvent(p))
	}
}

// Run flushes expired disconnects periodically until ctx is done.
func (t *Tracker) Run(ctx context.Context) {
	every := t.cfg.Grace / 3
	if every < time.Second {
		every = time.Second
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			t.Flush(t.cfg.Now())
		}
	}
}

func (t *Tracker) apName(ap string) string {
	if t.cfg.APName == nil {
		return ""
	}
	return t.cfg.APName(ap)
}

func (t *Tracker) emit(e Event) {
	for _, s := range t.cfg.Sinks {
		s.Emit(e)
	}
}

func (t *Tracker) connectEvent(ap string, tr store.Transition) Event {
	e := Event{
		Key: KeyConnected, Client: store.ColonMAC(tr.MAC), Hostname: tr.Session.Hostname,
		IP: tr.Session.IP,
		AP: ap, APName: t.apName(ap), SSID: tr.Session.ESSID,
		Radio: tr.Session.Radio, Channel: tr.Session.Channel,
	}
	e.setTime(tr.At)
	e.buildMsg()
	return e
}

func (t *Tracker) disconnectEvent(p pendingDisconnect) Event {
	s := p.session
	e := Event{
		Key: KeyDisconnected, Client: store.ColonMAC(s.MAC), Hostname: s.Hostname,
		IP: s.IP,
		AP: p.ap, APName: t.apName(p.ap), SSID: s.ESSID,
		Radio: s.Radio, Channel: s.Channel, Bytes: s.Bytes,
	}
	if s.Since > 0 && s.LastSeen >= s.Since {
		e.Duration = s.LastSeen - s.Since
	}
	e.setTime(p.at)
	e.buildMsg()
	return e
}

func (t *Tracker) roamEvent(fromAP string, from store.ClientSession, toAP string, tr store.Transition) Event {
	to := tr.Session
	e := Event{
		Key: KeyRoam, Client: store.ColonMAC(tr.MAC), Hostname: firstNonEmpty(to.Hostname, from.Hostname),
		IP:     firstNonEmpty(to.IP, from.IP),
		APFrom: fromAP, APFromName: t.apName(fromAP), APTo: toAP, APToName: t.apName(toAP),
		SSID:      firstNonEmpty(to.ESSID, from.ESSID),
		Radio:     to.Radio,
		RadioFrom: from.Radio, RadioTo: to.Radio,
		Channel: to.Channel, ChannelFrom: from.Channel, ChannelTo: to.Channel,
	}
	e.setTime(tr.At)
	e.buildMsg()
	return e
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

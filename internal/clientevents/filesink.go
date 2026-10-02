package clientevents

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lucavb/open-unifi/internal/store"
)

const (
	// DefaultRetention is the default history retention.
	DefaultRetention = 30 * 24 * time.Hour
	// DefaultMaxEvents is the default hard cap on retained events.
	DefaultMaxEvents = 200_000
	// compactEvery is the periodic compaction interval.
	compactEvery = 24 * time.Hour
)

// ParseRetention parses a retention duration. It accepts everything
// time.ParseDuration does plus a whole-number "d" (days) suffix: "30d",
// "12h", "90m". The value must be positive.
func ParseRetention(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseUint(days, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}

// FileSinkOptions tunes a FileSink. Zero values select the defaults.
type FileSinkOptions struct {
	Retention time.Duration
	MaxEvents int
	Now       func() time.Time
	Logger    *slog.Logger
}

// FileSink is the opt-in persisted history: an append-only JSON-lines file
// (mode 0600) plus an in-memory copy that serves queries. Retention and the
// hard event cap are enforced at load, on a daily compaction, and on
// Compact; compaction rewrites through a temp file and rename.
type FileSink struct {
	path string
	opts FileSinkOptions

	mu     sync.Mutex
	events []Event // chronological, oldest first
	f      *os.File
}

// NewFileSink opens (creating it if needed) the history file at path, loads
// the retained events and compacts the file.
func NewFileSink(path string, opts FileSinkOptions) (*FileSink, error) {
	if opts.Retention <= 0 {
		opts.Retention = DefaultRetention
	}
	if opts.MaxEvents <= 0 {
		opts.MaxEvents = DefaultMaxEvents
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &FileSink{path: path, opts: opts}
	if err := s.load(); err != nil {
		return nil, err
	}
	if err := s.Compact(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileSink) load() error {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("client history: open %s: %w", s.path, err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if json.Unmarshal(line, &e) != nil || e.Key == "" || e.Time == 0 {
			continue // a torn or foreign line never blocks startup
		}
		s.events = append(s.events, e)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("client history: read %s: %w", s.path, err)
	}
	// Appends are chronological by construction, but a clock step or a
	// hand-edited file must not break the oldest-first invariant.
	sort.SliceStable(s.events, func(i, j int) bool { return s.events[i].Time < s.events[j].Time })
	return nil
}

// Emit implements Sink: it records the event in memory and appends it to
// the file. A write error is logged, never returned: history must not
// disturb the inform path.
func (s *FileSink) Emit(e Event) {
	line, err := json.Marshal(e)
	if err != nil {
		s.opts.Logger.Warn("client history: marshal event", "err", err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Keep oldest-first by event time: a disconnect released after its grace
	// window carries the (earlier) time it was observed. The file stays in
	// emission order; load re-sorts.
	s.events = append(s.events, e)
	for i := len(s.events) - 1; i > 0 && s.events[i-1].Time > s.events[i].Time; i-- {
		s.events[i-1], s.events[i] = s.events[i], s.events[i-1]
	}
	if len(s.events) > s.opts.MaxEvents+s.opts.MaxEvents/10 {
		// Bounded memory between compactions; the file is trimmed on the
		// next Compact.
		s.events = s.events[len(s.events)-s.opts.MaxEvents:]
	}
	if s.f == nil {
		if err := s.openLocked(); err != nil {
			s.opts.Logger.Warn("client history: open file", "err", err)
			return
		}
	}
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		s.opts.Logger.Warn("client history: append event", "err", err)
	}
}

func (s *FileSink) openLocked() error {
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	s.f = f
	return nil
}

// pruneLocked applies retention and the hard cap to the in-memory events.
func (s *FileSink) pruneLocked() {
	cutoff := s.opts.Now().Add(-s.opts.Retention).UnixMilli()
	i := sort.Search(len(s.events), func(i int) bool { return s.events[i].Time >= cutoff })
	s.events = s.events[i:]
	if over := len(s.events) - s.opts.MaxEvents; over > 0 {
		s.events = s.events[over:]
	}
}

// Compact enforces retention and the cap, then rewrites the file with the
// retained events (temp file, fsync, rename).
func (s *FileSink) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()

	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("client history: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("client history: chmod: %w", err)
	}
	w := bufio.NewWriter(tmp)
	enc := json.NewEncoder(w)
	for _, e := range s.events {
		if err := enc.Encode(e); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("client history: encode: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("client history: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("client history: fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("client history: close: %w", err)
	}
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("client history: rename: %w", err)
	}
	tmpName = ""
	return s.openLocked()
}

// Run compacts daily until ctx is done.
func (s *FileSink) Run(ctx context.Context) {
	tick := time.NewTicker(compactEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := s.Compact(); err != nil {
				s.opts.Logger.Warn("client history: compact", "err", err)
			}
		}
	}
}

// Close releases the file handle.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// Filter selects events. Zero fields match everything.
type Filter struct {
	// Client is a client MAC in any spelling.
	Client string
	// AP is an AP MAC in any spelling; it matches ap, ap_from and ap_to.
	AP string
	// Key restricts to one event key.
	Key   string
	Since time.Time
	Until time.Time
	// Limit caps the result (0 = no cap).
	Limit int
}

func canonOrRaw(mac string) string {
	if mac == "" {
		return ""
	}
	if c, err := store.CanonicalMAC(mac); err == nil {
		return c
	}
	return strings.ToLower(mac)
}

func (f Filter) match(e Event, client, ap string) bool {
	if client != "" && canonOrRaw(e.Client) != client {
		return false
	}
	if ap != "" && canonOrRaw(e.AP) != ap && canonOrRaw(e.APFrom) != ap && canonOrRaw(e.APTo) != ap {
		return false
	}
	if f.Key != "" && e.Key != f.Key {
		return false
	}
	if !f.Since.IsZero() && e.Time < f.Since.UnixMilli() {
		return false
	}
	if !f.Until.IsZero() && e.Time > f.Until.UnixMilli() {
		return false
	}
	return true
}

// Query returns the matching events, newest first.
func (s *FileSink) Query(f Filter) []Event {
	client, ap := canonOrRaw(f.Client), canonOrRaw(f.AP)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Event{}
	for i := len(s.events) - 1; i >= 0; i-- {
		if !f.match(s.events[i], client, ap) {
			continue
		}
		out = append(out, s.events[i])
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out
}

// Len reports the number of retained events.
func (s *FileSink) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// Interval is one stretch a client spent on one AP. To is zero while the
// stretch is ongoing.
type Interval struct {
	AP      string `json:"ap"`
	APName  string `json:"ap_name,omitempty"`
	SSID    string `json:"ssid,omitempty"`
	Channel int    `json:"channel,omitempty"`
	From    int64  `json:"from"` // unix milliseconds
	To      int64  `json:"to,omitempty"`
}

// History folds a client's events into its AP assignment intervals,
// oldest first.
func (s *FileSink) History(client string) []Interval {
	c := canonOrRaw(client)
	s.mu.Lock()
	var evs []Event
	for _, e := range s.events {
		if canonOrRaw(e.Client) == c {
			evs = append(evs, e)
		}
	}
	s.mu.Unlock()
	return FoldHistory(evs)
}

// FoldHistory folds one client's chronological events into intervals.
// Connect opens an interval, roam closes the open one and opens one on the
// new AP, disconnect closes it, and a radio change updates the open
// interval's channel in place (the assignment is to the AP).
func FoldHistory(events []Event) []Interval {
	out := []Interval{}
	open := -1
	closeOpen := func(at int64) {
		if open >= 0 {
			out[open].To = at
			open = -1
		}
	}
	openAt := func(ap, name string, e Event) {
		out = append(out, Interval{AP: ap, APName: name, SSID: e.SSID, Channel: e.Channel, From: e.Time})
		open = len(out) - 1
	}
	for _, e := range events {
		switch e.Key {
		case KeyConnected:
			closeOpen(e.Time)
			openAt(e.AP, e.APName, e)
		case KeyRoam:
			closeOpen(e.Time)
			openAt(e.APTo, e.APToName, e)
		case KeyRoamRadio:
			if open >= 0 && out[open].AP == e.AP {
				out[open].Channel = e.Channel
			}
		case KeyDisconnected:
			closeOpen(e.Time)
		}
	}
	return out
}

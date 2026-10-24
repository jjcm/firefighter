package broadcast

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/jjcm/firefighter/internal/intel"
)

type ScheduledSource struct {
	Name        string
	Every       time.Duration
	Fingerprint string
	Source      intel.Source
}
type missingSource struct{}

var errNotConfigured = errors.New("source not configured")

func (missingSource) Name() string { return "unconfigured" }
func (missingSource) Poll(context.Context, string) (intel.Result, error) {
	return intel.Result{}, errNotConfigured
}

type Hub struct {
	mu        sync.RWMutex
	config    Config
	state     diskState
	key       ed25519.PrivateKey
	lock      *os.File
	pollLocks sync.Map
	now       func() time.Time
}

func Open(cfg Config) (*Hub, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := secureDir(cfg.StateDir); err != nil {
		return nil, err
	}
	lock, err := privateFile(filepath.Join(cfg.StateDir, "lock"), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("another hub owns this state directory")
	}
	fail := func(err error) (*Hub, error) {
		syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		return nil, err
	}
	key, err := readKey(cfg.StateDir)
	if err != nil {
		return fail(err)
	}
	state, err := readState(cfg.StateDir)
	if err != nil {
		return fail(err)
	}
	return &Hub{config: cfg, state: state, key: key, lock: lock, now: time.Now}, nil
}
func (h *Hub) Close() error {
	if h.lock == nil {
		return nil
	}
	syscall.Flock(int(h.lock.Fd()), syscall.LOCK_UN)
	return h.lock.Close()
}

// PollOnce commits all new notices and their upstream cursor in the same atomic
// checkpoint. On disk failure the live state is also unchanged; the next attempt
// asks the upstream source for the same cursor. Upstream errors are health data.
func (h *Hub) PollOnce(ctx context.Context, source ScheduledSource) error {
	if !sourceName.MatchString(source.Name) || source.Source == nil || source.Every <= 0 {
		return errors.New("invalid scheduled hub source")
	}
	lock, _ := h.pollLocks.LoadOrStore(source.Name, &sync.Mutex{})
	pollMu := lock.(*sync.Mutex)
	pollMu.Lock()
	defer pollMu.Unlock()
	h.mu.RLock()
	previous := h.state.Sources[source.Name]
	h.mu.RUnlock()
	if previous.Fingerprint != source.Fingerprint {
		previous.Cursor = ""
		previous.NextPoll = time.Time{}
	}
	if h.now().Before(previous.NextPoll) {
		return nil
	}
	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(h.config.PollTimeoutSeconds)*time.Second)
	result, fetchErr := source.Source.Poll(pollCtx, previous.Cursor)
	cancel()
	if ctx.Err() != nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	next := h.state
	next.Sources = make(map[string]sourceState, len(h.state.Sources)+1)
	for k, v := range h.state.Sources {
		next.Sources[k] = v
	}
	next.Notices = append([]storedNotice(nil), h.state.Notices...)
	now := h.now().UTC()
	ss := previous
	ss.Fingerprint = source.Fingerprint
	ss.LastAttempt = now
	ss.NextPoll = now.Add(source.Every)
	if fetchErr != nil {
		ss.Failures++
		ss.ErrorCode = "upstream_unavailable"
		if errors.Is(fetchErr, errNotConfigured) {
			ss.ErrorCode = "not_configured"
		}
		delay := source.Every
		for i := 1; i < ss.Failures && delay < 30*time.Minute; i++ {
			delay *= 2
		}
		if delay > 30*time.Minute {
			delay = 30 * time.Minute
		}
		ss.NextPoll = now.Add(delay)
	} else {
		seen := make(map[string]bool, len(next.Notices))
		for _, entry := range next.Notices {
			seen[entry.Hash] = true
		}
		for _, item := range result.Items {
			item.Source = source.Name
			raw, err := json.Marshal(item)
			if err != nil {
				return errors.New("cannot encode upstream notice")
			}
			fingerprint := hash(raw)
			if seen[fingerprint] {
				continue
			}
			seen[fingerprint] = true
			if next.Sequence == ^uint64(0)-1 {
				return errors.New("hub sequence exhausted")
			}
			notice := publicNotice(item, source.Name, now)
			next.Sequence++
			notice.Seq = next.Sequence
			next.Notices = append(next.Notices, storedNotice{Notice: notice, Hash: fingerprint})
			ss.Published++
		}
		ss.Cursor = result.Cursor
		ss.LastSuccess = now
		ss.Failures = 0
		ss.ErrorCode = ""
	}
	next.Sources[source.Name] = ss
	cutoff := now.Add(-time.Duration(h.config.RetentionDays) * 24 * time.Hour)
	remove := 0
	for remove < len(next.Notices) && (len(next.Notices)-remove > h.config.MaxNotices || next.Notices[remove].Notice.ObservedAt.Before(cutoff)) {
		remove++
	}
	if remove > 0 {
		next.Notices = append([]storedNotice(nil), next.Notices[remove:]...)
	}
	if err := writeState(h.config.StateDir, &next); err != nil {
		return err
	}
	h.state = next
	return nil
}

func (h *Hub) Run(ctx context.Context, sources []ScheduledSource) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, len(sources))
	var wg sync.WaitGroup
	for _, source := range sources {
		source := source
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				if err := h.PollOnce(ctx, source); err != nil {
					select {
					case errs <- err:
					case <-ctx.Done():
					}
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	defer func() { cancel(); wg.Wait() }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}

func (h *Hub) Batch(after uint64, limit int) (Batch, error) {
	if limit < 1 || limit > 500 {
		return Batch{}, errors.New("limit must be 1..500")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	latest := h.state.Sequence
	oldest := uint64(0)
	if len(h.state.Notices) > 0 {
		oldest = h.state.Notices[0].Notice.Seq
	} else if latest > 0 {
		oldest = latest + 1
	}
	b := Batch{Version: 1, Kind: "notices", After: after, Oldest: oldest, Latest: latest, NextCursor: after, ServerTime: h.now().UTC(), Notices: []Notice{}}
	if after > latest || (oldest > 0 && after < oldest-1) {
		b.ResetRequired = true
		if oldest > 0 {
			b.ResetTo = oldest - 1
		}
		return b, nil
	}
	index := sort.Search(len(h.state.Notices), func(i int) bool { return h.state.Notices[i].Notice.Seq > after })
	payloadBytes := 1024 // Reserve bounded batch metadata; stay under client envelope limits.
	for ; index < len(h.state.Notices) && len(b.Notices) < limit; index++ {
		notice := h.state.Notices[index].Notice
		encoded, _ := json.Marshal(notice)
		if payloadBytes+len(encoded)+1 > 1<<20 && len(b.Notices) > 0 {
			break
		}
		payloadBytes += len(encoded) + 1
		notice.CVEs = append([]string{}, notice.CVEs...)
		b.Notices = append(b.Notices, notice)
		b.NextCursor = notice.Seq
	}
	b.HasMore = b.NextCursor < latest
	return b, nil
}

// Recent is an informational board view, deliberately separate from the signed
// sequential client feed. Reordering this view never changes delivery cursors.
type Recent struct {
	Version    int       `json:"version"`
	Kind       string    `json:"kind"`
	ServerTime time.Time `json:"server_time"`
	Notices    []Notice  `json:"notices"`
}

func (h *Hub) Recent(limit int) (Recent, error) {
	if limit < 1 || limit > 100 {
		return Recent{}, errors.New("recent limit must be 1..100")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	indices := make([]int, len(h.state.Notices))
	for i := range indices {
		indices[i] = i
	}
	when := func(n Notice) time.Time {
		if n.PublishedAt.IsZero() {
			return n.ObservedAt
		}
		return n.PublishedAt
	}
	sort.Slice(indices, func(i, j int) bool {
		a, b := h.state.Notices[indices[i]].Notice, h.state.Notices[indices[j]].Notice
		at, bt := when(a), when(b)
		if at.Equal(bt) {
			return a.Seq > b.Seq
		}
		return at.After(bt)
	})
	r := Recent{Version: 1, Kind: "recent_notices", ServerTime: h.now().UTC(), Notices: []Notice{}}
	payloadBytes := 1024
	for _, index := range indices {
		if len(r.Notices) >= limit {
			break
		}
		n := h.state.Notices[index].Notice
		encoded, _ := json.Marshal(n)
		if payloadBytes+len(encoded)+1 > 1<<20 && len(r.Notices) > 0 {
			break
		}
		payloadBytes += len(encoded) + 1
		n.CVEs = append([]string{}, n.CVEs...)
		r.Notices = append(r.Notices, n)
	}
	return r, nil
}

type SourceHealth struct {
	Name             string    `json:"name"`
	State            string    `json:"state"`
	LastAttempt      time.Time `json:"last_attempt"`
	LastSuccess      time.Time `json:"last_success"`
	NextPoll         time.Time `json:"next_poll"`
	Failures         int       `json:"failures"`
	PublishedNotices uint64    `json:"published_notices"`
	ErrorCode        string    `json:"error_code"`
}
type Status struct {
	Version         int            `json:"version"`
	Service         string         `json:"service"`
	KeyID           string         `json:"key_id"`
	ServerTime      time.Time      `json:"server_time"`
	LatestSequence  uint64         `json:"latest_sequence"`
	OldestSequence  uint64         `json:"oldest_sequence"`
	RetainedNotices int            `json:"retained_notices"`
	RetentionDays   int            `json:"retention_days"`
	Degraded        bool           `json:"degraded"`
	Sources         []SourceHealth `json:"sources"`
}

func (h *Hub) Status() Status {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := Status{Version: 1, Service: "firefighter-hub", KeyID: KeyID(h.key.Public().(ed25519.PublicKey)), ServerTime: h.now().UTC(), LatestSequence: h.state.Sequence, RetainedNotices: len(h.state.Notices), RetentionDays: h.config.RetentionDays, Sources: []SourceHealth{}}
	if len(h.state.Notices) > 0 {
		s.OldestSequence = h.state.Notices[0].Notice.Seq
	} else if h.state.Sequence > 0 {
		s.OldestSequence = h.state.Sequence + 1
	}
	for _, configured := range h.config.Sources {
		state := h.state.Sources[configured.Name]
		health := "healthy"
		if state.LastSuccess.IsZero() {
			health = "pending"
		}
		if state.ErrorCode != "" {
			health = "degraded"
		}
		if health != "healthy" {
			s.Degraded = true
		}
		s.Sources = append(s.Sources, SourceHealth{Name: configured.Name, State: health, LastAttempt: state.LastAttempt, LastSuccess: state.LastSuccess, NextPoll: state.NextPoll, Failures: state.Failures, PublishedNotices: state.Published, ErrorCode: state.ErrorCode})
	}
	return s
}

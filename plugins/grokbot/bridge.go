// Package grokbot implements the Firefighter reporting plugin for Grok Bot's
// documented routine webhooks. It is a standalone bridge, not an in-process SDK.
package grokbot

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

type Config struct {
	Secret       string
	WebhookURL   string
	Token        string
	StatePath    string
	Timeout      time.Duration
	MaxBodyBytes int64
	MaxAge       time.Duration
	// IncludeTypes is an optional allowlist. Other events are acknowledged without
	// waking Grok Bot, while remaining in Firefighter's own durable audit trail.
	IncludeTypes []string
	Client       *http.Client
}

type Bridge struct {
	cfg       Config
	client    *http.Client
	mu        sync.Mutex
	delivered map[string]int64
	dirty     bool
	now       func() time.Time
}

func New(cfg Config) (*Bridge, error) {
	if len(cfg.Secret) < 32 {
		return nil, errors.New("signing secret must contain at least 32 characters")
	}
	if cfg.Token == "" {
		return nil, errors.New("Grok Bot routine bearer token is required")
	}
	u, err := url.Parse(cfg.WebhookURL)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid Grok Bot webhook URL")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
		return nil, errors.New("Grok Bot webhook requires HTTPS except localhost")
	}
	if !filepath.IsAbs(cfg.StatePath) {
		return nil, errors.New("plugin state path must be absolute")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.Timeout < time.Millisecond || cfg.Timeout > time.Minute {
		return nil, errors.New("plugin timeout must be positive and at most one minute")
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxBodyBytes < 1024 || cfg.MaxBodyBytes > 8<<20 {
		return nil, errors.New("plugin max body bytes must be 1024..8388608")
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 5 * time.Minute
	}
	if cfg.MaxAge < time.Second || cfg.MaxAge > 15*time.Minute {
		return nil, errors.New("signature max age must be 1 second..15 minutes")
	}
	client := &http.Client{}
	if cfg.Client != nil {
		*client = *cfg.Client
	}
	client.Timeout = cfg.Timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	b := &Bridge{cfg: cfg, client: client, delivered: map[string]int64{}, now: time.Now}
	if err := os.MkdirAll(filepath.Dir(cfg.StatePath), 0700); err != nil {
		return nil, errors.New("cannot create plugin state directory")
	}
	f, err := os.Open(cfg.StatePath)
	if err == nil {
		defer f.Close()
		body, err := io.ReadAll(io.LimitReader(f, 4<<20+1))
		if err != nil || len(body) > 4<<20 || json.Unmarshal(body, &b.delivered) != nil || b.delivered == nil || len(b.delivered) > 10000 {
			return nil, errors.New("invalid plugin deduplication state")
		}
	} else if !os.IsNotExist(err) {
		return nil, errors.New("cannot read plugin deduplication state")
	}
	return b, nil
}

// ServeHTTP acknowledges only authenticated and successfully forwarded reports.
// A network ambiguity may deliver twice; event.id is forwarded for downstream
// deduplication and Idempotency-Key is provided when supported by the receiver.
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/events" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, b.cfg.MaxBodyBytes))
	if err != nil {
		http.Error(w, "invalid or oversized body", http.StatusRequestEntityTooLarge)
		return
	}
	if !b.authenticated(r, body) {
		http.Error(w, "invalid signature or timestamp", http.StatusUnauthorized)
		return
	}
	var event protocol.Event
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&event) != nil || dec.Decode(new(any)) != io.EOF || !validEvent(event) {
		http.Error(w, "invalid event", http.StatusBadRequest)
		return
	}
	if len(b.cfg.IncludeTypes) > 0 {
		included := false
		for _, typ := range b.cfg.IncludeTypes {
			if event.Type == typ {
				included = true
				break
			}
		}
		if !included {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	keyBytes := sha256.Sum256([]byte(event.Host + "\x00" + event.ID))
	key := hex.EncodeToString(keyBytes[:])
	// Serialize dedupe and delivery to avoid two concurrent requests starting the
	// same routine. Keep the bridge dedicated to a single reporting stream.
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.delivered[key]; exists {
		if b.dirty {
			if err := b.persist(); err != nil {
				http.Error(w, "plugin state persistence failed", http.StatusInternalServerError)
				return
			}
			b.dirty = false
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := b.forward(r.Context(), event); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	b.delivered[key] = b.now().Unix()
	b.dirty = true
	b.prune(key)
	if err := b.persist(); err != nil {
		// The event remains deduplicated in this process. A later retry retries
		// persistence before acknowledging instead of invoking Grok Bot again.
		http.Error(w, "downstream accepted but plugin state persistence failed", http.StatusInternalServerError)
		return
	}
	b.dirty = false
	w.WriteHeader(http.StatusNoContent)
}

func (b *Bridge) authenticated(r *http.Request, body []byte) bool {
	ts := r.Header.Get("X-Firefighter-Timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	now := b.now().Unix()
	window := int64(b.cfg.MaxAge / time.Second)
	if sec < now-window || sec > now+window {
		return false
	}
	sig := r.Header.Get("X-Firefighter-Signature")
	if !strings.HasPrefix(sig, "sha256=") {
		return false
	}
	actual, err := hex.DecodeString(strings.TrimPrefix(sig, "sha256="))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(b.cfg.Secret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hmac.Equal(actual, mac.Sum(nil))
}

func validEvent(e protocol.Event) bool {
	return e.ID != "" && len(e.ID) <= 256 && e.Host != "" && len(e.Host) <= 256 && e.Type != "" && len(e.Type) <= 128 && e.Summary != "" && len(e.Summary) <= 32768 && !e.Time.IsZero()
}

func (b *Bridge) forward(ctx context.Context, event protocol.Event) error {
	payload := struct {
		Source  string         `json:"source"`
		Message string         `json:"message"`
		Event   protocol.Event `json:"event"`
	}{"firefighter", Render(event), event}
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("cannot encode downstream report")
	}
	ctx, cancel := context.WithTimeout(ctx, b.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot construct downstream report")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.cfg.Token)
	req.Header.Set("Idempotency-Key", event.ID)
	resp, err := b.client.Do(req)
	if err != nil {
		return errors.New("Grok Bot delivery failed (network or timeout)")
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	// Grok Bot documents exactly 200 as accepted; 202/204 are not proof a routine started.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Grok Bot did not accept report (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func Render(e protocol.Event) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Firefighter · %s · %s\nHost: %s\nTime: %s\n", e.Type, e.ID, e.Host, e.Time.UTC().Format(time.RFC3339))
	if e.IncidentID != "" {
		fmt.Fprintf(&out, "Incident: %s\n", e.IncidentID)
	}
	fmt.Fprintf(&out, "\n%s\n", e.Summary)
	return out.String()
}

func (b *Bridge) prune(keep string) {
	cutoff := b.now().Add(-7 * 24 * time.Hour).Unix()
	for key, at := range b.delivered {
		if at < cutoff && key != keep {
			delete(b.delivered, key)
		}
	}
	for len(b.delivered) > 10000 {
		oldestKey := ""
		oldest := int64(1<<63 - 1)
		for key, at := range b.delivered {
			if key != keep && at <= oldest {
				oldest = at
				oldestKey = key
			}
		}
		delete(b.delivered, oldestKey)
	}
}

func (b *Bridge) persist() error {
	body, err := json.Marshal(b.delivered)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(b.cfg.StatePath), ".grokbot-state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, b.cfg.StatePath); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(b.cfg.StatePath))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

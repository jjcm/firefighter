package intel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jjcm/firefighter/internal/config"
)

const broadcastResponseLimit = 2 << 20

type BroadcastConfig struct {
	Name      string
	URL       string
	PublicKey string // Standard base64 of the pinned 32-byte Ed25519 public key.
	CAFile    string // Optional PEM trust bundle; normal hostname/IP checks remain enabled.
	Client    *http.Client
	Now       func() time.Time
	MaxPages  int
	PageSize  int
}

type Broadcast struct {
	name      string
	u         *url.URL
	publicKey ed25519.PublicKey
	keyID     string
	client    *http.Client
	now       func() time.Time
	maxPages  int
	pageSize  int
}

type broadcastEnvelope struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type broadcastBatch struct {
	Version       int               `json:"version"`
	Kind          string            `json:"kind"`
	After         uint64            `json:"after"`
	Oldest        uint64            `json:"oldest"`
	Latest        uint64            `json:"latest"`
	NextCursor    uint64            `json:"next_cursor"`
	HasMore       bool              `json:"has_more"`
	ResetRequired bool              `json:"reset_required"`
	ResetTo       uint64            `json:"reset_to"`
	ServerTime    time.Time         `json:"server_time"`
	Notices       []broadcastNotice `json:"notices"`
}

type broadcastNotice struct {
	Sequence    uint64    `json:"seq"`
	Source      string    `json:"source"`
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	URL         string    `json:"url"`
	CVEs        []string  `json:"cves"`
	PublishedAt time.Time `json:"published_at"`
	ObservedAt  time.Time `json:"observed_at"`
	Untrusted   bool      `json:"untrusted"`
}

type broadcastCursor struct {
	Version    int       `json:"version"`
	KeyID      string    `json:"key_id"`
	Sequence   uint64    `json:"sequence"`
	ServerTime time.Time `json:"server_time"`
}

// NewBroadcast pins the publisher's Ed25519 identity independently of TLS.
// Broadcasts contain factual notices only. Their text is still untrusted input
// for the local planner and never becomes a command or operator instruction.
func NewBroadcast(cfg BroadcastConfig) (*Broadcast, error) {
	if cfg.Name == "" {
		cfg.Name = "broadcast"
	}
	if err := config.ValidateSourceName(cfg.Name); err != nil {
		return nil, err
	}
	u, err := endpoint(cfg.URL, "")
	if err != nil {
		return nil, err
	}
	if u.RawQuery != "" || (u.Path != "" && u.Path != "/" && u.Path != "/api/v1/notices") {
		return nil, errors.New("broadcast URL must be the hub origin or /api/v1/notices endpoint without query parameters")
	}
	u.Path = "/api/v1/notices"
	u.RawPath = ""
	key, err := base64.StdEncoding.Strict().DecodeString(cfg.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("broadcast public_key must be standard base64 of a 32-byte Ed25519 public key")
	}
	if cfg.MaxPages == 0 {
		cfg.MaxPages = 10
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 100
	}
	if cfg.MaxPages < 1 || cfg.MaxPages > 100 || cfg.PageSize < 1 || cfg.PageSize > 500 || cfg.MaxPages*cfg.PageSize > 10000 {
		return nil, errors.New("broadcast pagination exceeds bounded batch limits")
	}
	client := clientFor(cfg.Client)
	if cfg.CAFile != "" {
		if u.Scheme != "https" || !filepath.IsAbs(cfg.CAFile) {
			return nil, errors.New("broadcast ca_file requires HTTPS and an absolute PEM file path")
		}
		file, err := os.Open(cfg.CAFile)
		if err != nil {
			return nil, errors.New("cannot read broadcast CA file")
		}
		pem, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		file.Close()
		if readErr != nil || len(pem) > 1<<20 {
			return nil, errors.New("broadcast CA file is unreadable or exceeds 1 MiB")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("broadcast CA file contains no PEM certificates")
		}
		var transport *http.Transport
		if client.Transport == nil {
			transport = http.DefaultTransport.(*http.Transport).Clone()
		} else if supplied, ok := client.Transport.(*http.Transport); ok {
			transport = supplied.Clone()
		} else {
			return nil, errors.New("broadcast custom CA requires a standard HTTP transport")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		client.Transport = transport
	}
	hash := sha256.Sum256(key)
	return &Broadcast{name: cfg.Name, u: u, publicKey: key, keyID: hex.EncodeToString(hash[:])[:16], client: client, now: nowFunc(cfg.Now), maxPages: cfg.MaxPages, pageSize: cfg.PageSize}, nil
}

func (s *Broadcast) Name() string { return s.name }

// Poll verifies a bounded contiguous batch before returning any notices. The
// engine must durably enqueue every Item together with Cursor. A signed history
// gap becomes an explicit coverage-gap incident and a reset checkpoint; the next
// poll resumes available history. It is never silently interpreted as no risk.
func (s *Broadcast) Poll(ctx context.Context, cursor string) (Result, error) {
	now := s.now().UTC()
	state := broadcastCursor{Version: 1, KeyID: s.keyID}
	if cursor != "" {
		if len(cursor) > 1024 || strictBroadcastJSON([]byte(cursor), &state) != nil || requireBroadcastFields([]byte(cursor), "version", "key_id", "sequence", "server_time") != nil || state.Version != 1 || state.KeyID != s.keyID || state.ServerTime.IsZero() {
			return unchanged(cursor, errors.New("invalid signed broadcast cursor or publisher mismatch"))
		}
		if state.ServerTime.After(now.Add(2 * time.Minute)) {
			return unchanged(cursor, errors.New("broadcast cursor time is ahead of the local clock"))
		}
	}
	result := Result{Cursor: cursor}
	var target uint64
	for page := 0; page < s.maxPages; page++ {
		u := *s.u
		q := u.Query()
		q.Set("after", strconv.FormatUint(state.Sequence, 10))
		q.Set("limit", strconv.Itoa(s.pageSize))
		u.RawQuery = q.Encode()
		body, err := s.get(ctx, &u)
		if err != nil {
			return unchanged(cursor, err)
		}
		batch, err := s.verify(body, state, s.now().UTC())
		if err != nil {
			return unchanged(cursor, err)
		}
		if batch.ResetRequired {
			if page != 0 {
				return unchanged(cursor, errors.New("broadcast retention changed during pagination; retrying the entire batch"))
			}
			detail := fmt.Sprintf("Signed publisher reported unavailable notice history. Previous client sequence: %d; available oldest sequence: %d; publisher latest sequence: %d; recovery checkpoint: %d. Notices in the missing interval were not assessed. This is a coverage gap, not evidence that this host is safe or compromised.", state.Sequence, batch.Oldest, batch.Latest, batch.ResetTo)
			result.Items = []Item{{ID: fmt.Sprintf("broadcast-coverage-gap-%s-%d-%d-%d", s.keyID, state.Sequence, batch.ResetTo, batch.Latest), Source: s.name, URL: s.u.String(), Title: "Signed intelligence history has a coverage gap", Body: detail, PublishedAt: batch.ServerTime, ModifiedAt: batch.ServerTime, Trust: "untrusted"}}
			state.Sequence = batch.ResetTo
			state.ServerTime = batch.ServerTime
			result.Cursor = encodeBroadcastCursor(state)
			return result, nil
		}
		if page == 0 {
			target = batch.Latest
		} else if batch.Latest < target {
			return unchanged(cursor, errors.New("broadcast publisher sequence regressed during pagination"))
		}
		for _, notice := range batch.Notices {
			// Keep the signed notice's original source visible without granting
			// authority to its text. No command-like fields exist in this schema.
			fact, _ := json.Marshal(notice)
			result.Items = append(result.Items, Item{ID: fmt.Sprintf("%s:%d", s.keyID, notice.Sequence), Source: s.name, URL: notice.URL, Title: notice.Title, Body: string(fact), CVEs: append([]string(nil), notice.CVEs...), PublishedAt: notice.PublishedAt, ModifiedAt: notice.ObservedAt, Trust: "untrusted"})
		}
		state.Sequence = batch.NextCursor
		state.ServerTime = batch.ServerTime
		result.Cursor = encodeBroadcastCursor(state)
		if !batch.HasMore || state.Sequence >= target {
			return result, nil
		}
	}
	// A bounded contiguous prefix is safe to checkpoint once all of its notices
	// are durable; remaining backlog is fetched from this exact sequence later.
	return result, nil
}

func (s *Broadcast) get(ctx context.Context, u *url.URL) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("cannot construct broadcast request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "firefighter/signed-notices-v1")
	resp, err := s.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("broadcast request failed (network or TLS verification)")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("broadcast returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, broadcastResponseLimit+1))
	if err != nil || len(body) > broadcastResponseLimit {
		return nil, errors.New("broadcast response unreadable or exceeds 2 MiB")
	}
	return body, nil
}

func (s *Broadcast) verify(body []byte, cursor broadcastCursor, now time.Time) (broadcastBatch, error) {
	var batch broadcastBatch
	var envelope broadcastEnvelope
	if err := strictBroadcastJSON(body, &envelope); err != nil || envelope.KeyID != s.keyID {
		return batch, errors.New("invalid broadcast envelope or unpinned publisher")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil {
		return batch, errors.New("invalid broadcast payload encoding")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(s.publicKey, payload, signature) {
		return batch, errors.New("broadcast signature verification failed")
	}
	if err := strictBroadcastJSON(payload, &batch); err != nil || requireBroadcastFields(payload, "version", "kind", "after", "oldest", "latest", "next_cursor", "has_more", "reset_required", "reset_to", "server_time", "notices") != nil {
		return batch, errors.New("signed broadcast violates the notice-only schema")
	}
	if batch.Version != 1 || batch.Kind != "notices" || batch.After != cursor.Sequence || batch.Notices == nil || len(batch.Notices) > s.pageSize {
		return batch, errors.New("signed broadcast version, cursor, or notice count is invalid")
	}
	_, offset := batch.ServerTime.Zone()
	if batch.ServerTime.IsZero() || offset != 0 || batch.ServerTime.Before(now.Add(-10*time.Minute)) || batch.ServerTime.After(now.Add(2*time.Minute)) || batch.ServerTime.Before(cursor.ServerTime) {
		return batch, errors.New("broadcast is stale, replayed, or ahead of the local clock")
	}
	if (batch.Oldest == 0 && batch.Latest != 0) || (batch.Oldest > batch.Latest && (batch.Latest == math.MaxUint64 || batch.Oldest != batch.Latest+1)) {
		return batch, errors.New("broadcast retained sequence range is invalid")
	}
	gap := cursor.Sequence > batch.Latest || (batch.Oldest > 0 && cursor.Sequence < batch.Oldest-1)
	if batch.ResetRequired {
		reset := uint64(0)
		if batch.Oldest > 0 {
			reset = batch.Oldest - 1
		}
		if !gap || batch.ResetTo != reset || batch.NextCursor != cursor.Sequence || batch.HasMore || len(batch.Notices) != 0 {
			return batch, errors.New("broadcast coverage-gap checkpoint is invalid")
		}
		return batch, nil
	}
	if gap || batch.ResetTo != 0 {
		return batch, errors.New("broadcast omitted an explicit coverage-gap notice")
	}
	expected := cursor.Sequence
	var raw struct {
		Notices []json.RawMessage `json:"notices"`
	}
	_ = json.Unmarshal(payload, &raw)
	for i, notice := range batch.Notices {
		if expected == math.MaxUint64 || notice.Sequence != expected+1 || notice.Sequence > batch.Latest {
			return batch, errors.New("broadcast contains a replayed, skipped, or out-of-order notice")
		}
		if requireBroadcastFields(raw.Notices[i], "seq", "source", "id", "title", "summary", "url", "cves", "published_at", "observed_at", "untrusted") != nil || validateBroadcastNotice(notice, batch.ServerTime) != nil {
			return batch, errors.New("broadcast notice violates the factual notice schema")
		}
		expected = notice.Sequence
	}
	if batch.NextCursor != expected || batch.HasMore != (expected < batch.Latest) || (batch.HasMore && len(batch.Notices) == 0) {
		return batch, errors.New("broadcast pagination cursor is inconsistent")
	}
	return batch, nil
}

func validateBroadcastNotice(n broadcastNotice, serverTime time.Time) error {
	if !n.Untrusted || n.ObservedAt.IsZero() || n.ObservedAt.After(serverTime.Add(2*time.Minute)) || n.CVEs == nil || len(n.CVEs) > 64 {
		return errors.New("invalid notice provenance, timestamp, or CVE list")
	}
	for _, field := range []struct {
		value    string
		max      int
		required bool
	}{{n.Source, 128, true}, {n.ID, 256, true}, {n.Title, 512, true}, {n.Summary, 4096, false}, {n.URL, 2048, false}} {
		if !utf8.ValidString(field.value) || len(field.value) > field.max || strings.ContainsRune(field.value, 0) || (field.required && strings.TrimSpace(field.value) == "") {
			return errors.New("notice text exceeds bounds or is invalid")
		}
	}
	if n.URL != "" {
		u, err := url.Parse(n.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return errors.New("notice URL is invalid")
		}
	}
	for _, cve := range n.CVEs {
		found := ExtractCVEs(cve)
		if len(cve) > 64 || len(found) != 1 || found[0] != cve {
			return errors.New("notice CVE identifier is invalid")
		}
	}
	return nil
}

func encodeBroadcastCursor(cursor broadcastCursor) string {
	b, _ := json.Marshal(cursor)
	return string(b)
}

func requireBroadcastFields(body []byte, fields ...string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil || object == nil {
		return errors.New("expected object")
	}
	for _, field := range fields {
		value, ok := object[field]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("missing required notice field")
		}
	}
	return nil
}

func strictBroadcastJSON(body []byte, target interface{}) error {
	if !utf8.Valid(body) {
		return errors.New("broadcast JSON contains invalid UTF-8")
	}
	// Reject duplicate keys before decoding: a signed payload must have only one
	// interpretation, including for fields nested inside each notice.
	d := json.NewDecoder(bytes.NewReader(body))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("broadcast JSON nesting exceeds limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return err
					}
					name, ok := key.(string)
					if !ok || seen[name] {
						return errors.New("duplicate broadcast field")
					}
					seen[name] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
			default:
				return errors.New("invalid broadcast JSON delimiter")
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing broadcast JSON")
	}
	d = json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	return d.Decode(target)
}

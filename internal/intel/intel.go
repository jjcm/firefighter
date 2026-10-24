// Package intel ingests external advisory data. Content returned by every source
// is untrusted data, never an instruction to the agent or its tools.
package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Item struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	URL         string    `json:"url"`
	Title       string    `json:"title"`
	Body        string    `json:"body"`
	CVEs        []string  `json:"cves"`
	PublishedAt time.Time `json:"published_at"`
	ModifiedAt  time.Time `json:"modified_at"`
	Trust       string    `json:"trust"`
}

// Result.Cursor is opaque. Persist Items durably before (or atomically with)
// Cursor. On any error Poll returns the input cursor, never a partial checkpoint.
type Result struct {
	Items  []Item `json:"items"`
	Cursor string `json:"cursor"`
}

type Source interface {
	Name() string
	Poll(context.Context, string) (Result, error)
}

const maxBodyBytes = 32 << 20
const maxCursorBytes = 2 << 20

var cvePattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

func ExtractCVEs(s string) []string {
	seen := map[string]bool{}
	for _, cve := range cvePattern.FindAllString(s, -1) {
		seen[strings.ToUpper(cve)] = true
	}
	out := make([]string, 0, len(seen))
	for cve := range seen {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func clientFor(in *http.Client) *http.Client {
	c := http.Client{Timeout: 45 * time.Second}
	if in != nil {
		c = *in
		if c.Timeout <= 0 || c.Timeout > 45*time.Second {
			c.Timeout = 45 * time.Second
		}
	}
	// Reject redirects even on a caller-supplied client. In particular, never
	// allow a configured endpoint to forward API credentials to another host.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func endpoint(raw, fallback string) (*url.URL, error) {
	if raw == "" {
		raw = fallback
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("source URL must be an absolute HTTP(S) URL without userinfo or fragment")
	}
	// Plain HTTP is permitted only for local fixtures and local feed bridges.
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return nil, errors.New("remote source URLs require HTTPS")
	}
	return u, nil
}

func get(ctx context.Context, c *http.Client, u *url.URL, headers http.Header) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("cannot construct source request")
	}
	req.Header = headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("User-Agent", "github.com/jjcm/firefighter/1.0 (security advisory monitor)")
	resp, err := c.Do(req)
	if err != nil {
		// Do not echo URLs, which can contain secret feed query parameters.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("source HTTP request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("source returned HTTP %d (retry-after %q)", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read source response: %w", err)
	}
	if len(b) > maxBodyBytes {
		return nil, fmt.Errorf("source response exceeds %d bytes", maxBodyBytes)
	}
	return b, nil
}

func nowFunc(now func() time.Time) func() time.Time {
	if now != nil {
		return now
	}
	return time.Now
}

func date(s string) time.Time {
	for _, format := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822, "2006-01-02"} {
		if t, err := time.Parse(format, strings.TrimSpace(s)); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func unchanged(cursor string, err error) (Result, error) {
	return Result{Cursor: cursor}, err
}

// Snapshot cursors detect edits to existing advisories as well as new IDs.
func snapshot(cursor string) (map[string]string, error) {
	old := map[string]string{}
	if cursor == "" {
		return old, nil
	}
	if len(cursor) > maxCursorBytes {
		return nil, errors.New("source cursor is too large")
	}
	if err := json.Unmarshal([]byte(cursor), &old); err != nil || old == nil {
		return nil, errors.New("invalid source snapshot cursor")
	}
	return old, nil
}

func snapshotResult(items []Item, old map[string]string) (Result, error) {
	next := make(map[string]string, len(items))
	result := Result{}
	for _, item := range items {
		b, err := json.Marshal(item)
		if err != nil {
			return Result{}, err
		}
		hash := digest(b)
		next[item.ID] = hash
		if old[item.ID] != hash {
			result.Items = append(result.Items, item)
		}
	}
	b, err := json.Marshal(next)
	if err != nil {
		return Result{}, err
	}
	if len(b) > maxCursorBytes {
		return Result{}, errors.New("source snapshot exceeds cursor limit")
	}
	result.Cursor = string(b)
	return result, nil
}

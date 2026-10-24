// Package report delivers durable events to the Grokbot plugin or another signed webhook.
package report

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
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

type Sender interface {
	Send(context.Context, protocol.Event) error
}
type Webhook struct {
	URL, Secret, BearerToken string
	Client                   *http.Client
}

func New(urlString, secret, bearer string) (*Webhook, error) {
	u, err := url.Parse(urlString)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid reporting URL")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
		return nil, errors.New("reporting URL requires HTTPS except on loopback")
	}
	if len(secret) < 32 {
		return nil, errors.New("report signing secret must contain at least 32 characters")
	}
	return &Webhook{URL: urlString, Secret: secret, BearerToken: bearer, Client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (w *Webhook) Send(ctx context.Context, event protocol.Event) error {
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(w.Secret))
	mac.Write([]byte(ts + "."))
	mac.Write(b)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(b))
	if err != nil {
		return errors.New("create reporting request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Firefighter-Timestamp", ts)
	req.Header.Set("X-Firefighter-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("Idempotency-Key", event.ID)
	if w.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+w.BearerToken)
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return errors.New("report delivery failed (network or timeout)")
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusTooManyRequests {
		return retryError(resp.Header, data, time.Now())
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("report delivery returned HTTP %d", resp.StatusCode)
	}
	return nil
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`),
	regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`),
	regexp.MustCompile(`(?i)(?:authorization\s*[:=]\s*(?:bearer|basic)\s+)[^\s"']+`),
	regexp.MustCompile(`(?i)(?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[=:]\s*[^\s,;]+`),
}

// Redactor is defense in depth, not a guarantee that arbitrary root output is secret-free.
func Redactor(secrets ...string) func(string) string {
	return func(s string) string {
		for _, secret := range secrets {
			if len(secret) >= 4 {
				s = strings.ReplaceAll(s, secret, "[REDACTED]")
			}
		}
		for _, re := range secretPatterns {
			s = re.ReplaceAllString(s, "[REDACTED]")
		}
		return s
	}
}

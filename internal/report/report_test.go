package report

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

const testSigningSecret = "fixture-signing-secret-at-least-32-bytes"

func TestWebhookSignsExactBodyAndIncludesStableID(t *testing.T) {
	event := protocol.Event{ID: "event-123", Time: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC), Host: "fixture-host", Type: "action_finished", IncidentID: "incident-123", Summary: "Targeted patch verified", Details: map[string]interface{}{"exit_code": 0}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Idempotency-Key") != event.ID || r.Header.Get("Authorization") != "Bearer fixture-report-bearer" {
			t.Errorf("incorrect request contract: %s %v", r.Method, r.Header)
		}
		ts := r.Header.Get("X-Firefighter-Timestamp")
		seconds, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || time.Since(time.Unix(seconds, 0)) > 5*time.Second {
			t.Errorf("bad signing timestamp: %q", ts)
		}
		mac := hmac.New(sha256.New, []byte(testSigningSecret))
		mac.Write([]byte(ts + "."))
		mac.Write(body)
		if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); !hmac.Equal([]byte(r.Header.Get("X-Firefighter-Signature")), []byte(want)) {
			t.Error("signature does not cover timestamp and exact request bytes")
		}
		var got protocol.Event
		if err := json.Unmarshal(body, &got); err != nil || got.ID != event.ID || got.IncidentID != event.IncidentID || got.Summary != event.Summary {
			t.Errorf("event body changed: %+v %v", got, err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	webhook, err := New(srv.URL, testSigningSecret, "fixture-report-bearer")
	if err != nil {
		t.Fatal(err)
	}
	if err := webhook.Send(context.Background(), event); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookDoesNotFollowRedirect(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	webhook, err := New(source.URL, testSigningSecret, "fixture-bearer")
	if err != nil {
		t.Fatal(err)
	}
	err = webhook.Send(context.Background(), protocol.Event{ID: "redirect-fixture"})
	if err == nil || !strings.Contains(err.Error(), "307") || targetCalls.Load() != 0 {
		t.Fatalf("redirect was followed or not reported: calls=%d err=%v", targetCalls.Load(), err)
	}
}

func TestWebhookErrorsDoNotExposeRemoteBodyOrURLSecrets(t *testing.T) {
	const secret = "fixture-must-not-appear"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, secret+strings.Repeat("x", 8192))
	}))
	defer srv.Close()
	webhook, err := New(srv.URL+"?token="+secret, testSigningSecret, secret)
	if err != nil {
		t.Fatal(err)
	}
	err = webhook.Send(context.Background(), protocol.Event{ID: "error-fixture"})
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), secret) {
		t.Fatalf("remote response leaked or error missing: %v", err)
	}
	webhook.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("network URL contained " + secret) })}
	err = webhook.Send(context.Background(), protocol.Event{ID: "network-error"})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("network transport error leaked: %v", err)
	}
}

func TestWebhookRejectsUnsafeEndpointConfiguration(t *testing.T) {
	for _, endpoint := range []string{"", "http://remote.example/hook", "https://user:password@example.com/hook", "https://example.com/hook#fragment", "file:///tmp/report"} {
		if _, err := New(endpoint, testSigningSecret, ""); err == nil {
			t.Fatalf("accepted invalid endpoint %q", endpoint)
		}
	}
	if _, err := New("https://example.com/hook", "short", ""); err == nil {
		t.Fatal("short signing secret accepted")
	}
	for _, endpoint := range []string{"https://example.com/hook", "http://127.0.0.1:3210/hook", "http://[::1]:3210/hook"} {
		if _, err := New(endpoint, testSigningSecret, ""); err != nil {
			t.Fatalf("valid endpoint rejected %q: %v", endpoint, err)
		}
	}
}

func TestRedactorRemovesConfiguredAndRecognizableSecrets(t *testing.T) {
	redact := Redactor("fixture-configured-credential")
	for _, raw := range []string{
		"token=fixture-configured-credential",
		"sk-abcdefghijklmnopqrstuvwxyz012345",
		"ghp_abcdefghijklmnopqrstuvwxyz012345",
		"Authorization: Bearer fixture-token",
		"password=fixture-value",
		"api_key=fixture-value",
		"-----BEGIN PRIVATE KEY-----\nfixture-key-body\n-----END PRIVATE KEY-----",
	} {
		got := redact(raw)
		if got == raw || !strings.Contains(got, "[REDACTED]") {
			t.Fatalf("secret not redacted: %q", got)
		}
	}
	if got := redact("Package openssl patched successfully"); got != "Package openssl patched successfully" {
		t.Fatalf("ordinary report changed: %q", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

package grokbot

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/report"
)

const fixtureSecret = "fixture-signing-secret-32-characters-long"

func testEvent() protocol.Event {
	return protocol.Event{ID: "event-1", Time: time.Now().UTC(), Host: "ubuntu-fixture", Type: "incident.completed", IncidentID: "CVE-fixture", Summary: "Patched and service checks passed; no complete compromise guarantee."}
}

func fixtureConfig(t *testing.T, url string) Config {
	t.Helper()
	return Config{Secret: fixtureSecret, WebhookURL: url, Token: "fixture-routine-secret", StatePath: filepath.Join(t.TempDir(), "delivered.json")}
}

func signed(event protocol.Event, at time.Time) *http.Request {
	body, _ := json.Marshal(event)
	ts := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(fixtureSecret))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	r := httptest.NewRequest(http.MethodPost, "http://plugin/events", bytes.NewReader(body))
	r.Header.Set("X-Firefighter-Timestamp", ts)
	r.Header.Set("X-Firefighter-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	return r
}

func TestReporterToGrokBotAndDurableDedup(t *testing.T) {
	var calls atomic.Int32
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-routine-secret" || r.Header.Get("Idempotency-Key") != "event-1" {
			t.Error("downstream auth/idempotency missing")
		}
		var body struct {
			Source, Message string
			Event           protocol.Event
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Source != "firefighter" || body.Event.ID != "event-1" || !strings.Contains(body.Message, "ubuntu-fixture") {
			t.Error("downstream report contract invalid")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()
	cfg := fixtureConfig(t, downstream.URL)
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	plugin := httptest.NewServer(b)
	sender, err := report.New(plugin.URL+"/events", fixtureSecret, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := sender.Send(context.Background(), testEvent()); err != nil {
			t.Fatal(err)
		}
	}
	plugin.Close()
	restored, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	restored.ServeHTTP(rec, signed(testEvent(), time.Now()))
	if rec.Code != http.StatusNoContent || calls.Load() != 1 {
		t.Fatalf("dedup failed: status=%d calls=%d", rec.Code, calls.Load())
	}
}

func TestAuthenticatesBeforeForwarding(t *testing.T) {
	var calls atomic.Int32
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer downstream.Close()
	b, err := New(fixtureConfig(t, downstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		at      time.Time
		corrupt bool
	}{
		{"expired", time.Now().Add(-10 * time.Minute), false},
		{"future", time.Now().Add(10 * time.Minute), false},
		{"wrong signature", time.Now(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := signed(testEvent(), tc.at)
			if tc.corrupt {
				r.Header.Set("X-Firefighter-Signature", "sha256="+strings.Repeat("0", 64))
			}
			w := httptest.NewRecorder()
			b.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("bad auth accepted: %d", w.Code)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("unauthenticated data forwarded")
	}
}

func TestFailedDeliveryRemainsRetryable(t *testing.T) {
	var calls atomic.Int32
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "fixture-sensitive-error")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer downstream.Close()
	b, err := New(fixtureConfig(t, downstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{http.StatusBadGateway, http.StatusNoContent} {
		w := httptest.NewRecorder()
		b.ServeHTTP(w, signed(testEvent(), time.Now()))
		if w.Code != want || strings.Contains(w.Body.String(), "fixture-sensitive-error") {
			t.Fatalf("unexpected delivery result %d %s", w.Code, w.Body.String())
		}
	}
	if calls.Load() != 2 {
		t.Fatal("failed event was deduplicated")
	}
}

func TestPersistenceFailureRetriesWithoutDuplicate(t *testing.T) {
	var calls atomic.Int32
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer downstream.Close()
	cfg := fixtureConfig(t, downstream.URL)
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfg.StatePath, 0700); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, signed(testEvent(), time.Now()))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected persistence failure, got %d", w.Code)
	}
	if err := os.Remove(cfg.StatePath); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	b.ServeHTTP(w, signed(testEvent(), time.Now()))
	if w.Code != http.StatusNoContent || calls.Load() != 1 {
		t.Fatalf("persistence retry redelivered %d %d", w.Code, calls.Load())
	}
}

func TestConcurrentDuplicates(t *testing.T) {
	var calls atomic.Int32
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer downstream.Close()
	b, err := New(fixtureConfig(t, downstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			b.ServeHTTP(w, signed(testEvent(), time.Now()))
			if w.Code != http.StatusNoContent {
				t.Errorf("status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("duplicate concurrent delivery %d", calls.Load())
	}
}

func TestFilterAndUnexpectedSuccessCode(t *testing.T) {
	var calls atomic.Int32
	downstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusAccepted) }))
	defer downstream.Close()
	cfg := fixtureConfig(t, downstream.URL)
	cfg.IncludeTypes = []string{"incident.failed"}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, signed(testEvent(), time.Now()))
	if w.Code != http.StatusNoContent || calls.Load() != 0 {
		t.Fatal("filter did not suppress event")
	}
	event := testEvent()
	event.Type = "incident.failed"
	w = httptest.NewRecorder()
	b.ServeHTTP(w, signed(event, time.Now()))
	if w.Code != http.StatusBadGateway || calls.Load() != 1 {
		t.Fatal("undocumented 202 treated as delivery")
	}
}

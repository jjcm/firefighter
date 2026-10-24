package broadcast

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jjcm/firefighter/internal/intel"
)

type fixtureSource func(context.Context, string) (intel.Result, error)

func (f fixtureSource) Name() string { return "fixture" }
func (f fixtureSource) Poll(ctx context.Context, cursor string) (intel.Result, error) {
	return f(ctx, cursor)
}

func fixtureHub(t *testing.T) (*Hub, Config, ed25519.PublicKey) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.StateDir = t.TempDir()
	cfg.WebsiteDir = ""
	cfg.Sources = []SourceConfig{{Name: "fixture", Type: "rss", URL: "https://example.invalid/advisories", IntervalSeconds: 60}}
	public, err := InitKey(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	return hub, cfg, public
}
func pollFixture(t *testing.T, h *Hub, items []intel.Item, cursor string) {
	t.Helper()
	err := h.PollOnce(context.Background(), ScheduledSource{Name: "fixture", Every: time.Nanosecond, Source: fixtureSource(func(context.Context, string) (intel.Result, error) {
		return intel.Result{Items: items, Cursor: cursor}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
}
func noticeItems(n int) []intel.Item {
	var items []intel.Item
	for i := 1; i <= n; i++ {
		items = append(items, intel.Item{ID: fmt.Sprintf("item-%d", i), Title: fmt.Sprintf("CVE-2026-%05d", i), Body: "Untrusted advisory evidence", URL: "https://vendor.example/advisory", PublishedAt: time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC), Trust: "official"})
	}
	return items
}
func getEnvelope(t *testing.T, handler http.Handler, url string) (Envelope, Batch) {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, url, nil))
	if rec.Code != 200 {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	var envelope Envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	var batch Batch
	if err := json.Unmarshal(envelope.Payload, &batch); err != nil {
		t.Fatal(err)
	}
	return envelope, batch
}

func TestSignedPaginationIsDataOnlyAndReplayIsStable(t *testing.T) {
	h, _, public := fixtureHub(t)
	pollFixture(t, h, noticeItems(3), "source3")
	handler := h.Handler()
	envelope, batch := getEnvelope(t, handler, "/api/v1/notices?after=0&limit=2")
	if envelope.KeyID != KeyID(public) || !ed25519.Verify(public, envelope.Payload, envelope.Signature) {
		t.Fatal("batch signature is invalid")
	}
	if batch.After != 0 || batch.NextCursor != 2 || !batch.HasMore || batch.Latest != 3 || batch.Oldest != 1 || len(batch.Notices) != 2 {
		t.Fatalf("invalid first page: %+v", batch)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(envelope.Payload, &object); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"version": true, "kind": true, "after": true, "oldest": true, "latest": true, "next_cursor": true, "has_more": true, "reset_required": true, "reset_to": true, "server_time": true, "notices": true}
	for key := range object {
		if !allowed[key] {
			t.Fatalf("unexpected wire field %q", key)
		}
	}
	for _, n := range batch.Notices {
		if !n.Untrusted || n.CVEs == nil {
			t.Fatal("notice lacks explicit untrusted marker or CVE array")
		}
	}
	_, again := getEnvelope(t, handler, "/api/v1/notices?after=0&limit=2")
	if again.Notices[0].Seq != 1 || again.NextCursor != 2 {
		t.Fatal("reading a page consumed global delivery state")
	}
	_, last := getEnvelope(t, handler, "/api/v1/notices?after=2&limit=2")
	if len(last.Notices) != 1 || last.Notices[0].Seq != 3 || last.HasMore || last.NextCursor != 3 {
		t.Fatalf("invalid second page: %+v", last)
	}
	tampered := append([]byte(nil), envelope.Payload...)
	tampered[0] ^= 1
	if ed25519.Verify(public, tampered, envelope.Signature) {
		t.Fatal("tampered batch verified")
	}
}

func TestUpstreamCursorDedupAndSequenceSurviveRestart(t *testing.T) {
	h, cfg, _ := fixtureHub(t)
	pollFixture(t, h, noticeItems(2), "checkpoint2")
	pollFixture(t, h, noticeItems(2), "checkpoint2")
	if h.state.Sequence != 2 {
		t.Fatal("overlapping poll duplicated notices")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	err = reopened.PollOnce(context.Background(), ScheduledSource{Name: "fixture", Every: time.Nanosecond, Source: fixtureSource(func(_ context.Context, cursor string) (intel.Result, error) {
		if cursor != "checkpoint2" {
			t.Errorf("restart lost cursor: %q", cursor)
		}
		return intel.Result{Items: noticeItems(3), Cursor: "checkpoint3"}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if reopened.state.Sequence != 3 || reopened.state.Notices[2].Notice.Seq != 3 {
		t.Fatal("restart reset or duplicated sequence")
	}
}

func TestUpstreamAndCheckpointFailuresDoNotAdvanceCursor(t *testing.T) {
	h, cfg, _ := fixtureHub(t)
	pollFixture(t, h, noticeItems(1), "old")
	err := h.PollOnce(context.Background(), ScheduledSource{Name: "fixture", Every: time.Nanosecond, Source: fixtureSource(func(context.Context, string) (intel.Result, error) {
		return intel.Result{Items: noticeItems(2), Cursor: "wrong"}, errors.New("upstream includes secret-token")
	})})
	if err != nil {
		t.Fatal(err)
	}
	if h.state.Sequence != 1 || h.state.Sources["fixture"].Cursor != "old" {
		t.Fatal("failed upstream page advanced durable position")
	}
	statePath := filepath.Join(cfg.StateDir, "hubstate.json")
	backup := statePath + ".backup"
	if err := os.Rename(statePath, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0700); err != nil {
		t.Fatal(err)
	}
	source := ScheduledSource{Name: "fixture", Every: time.Nanosecond, Source: fixtureSource(func(_ context.Context, cursor string) (intel.Result, error) {
		if cursor != "old" {
			t.Errorf("save failure lost prior cursor: %q", cursor)
		}
		return intel.Result{Items: noticeItems(2), Cursor: "new"}, nil
	})}
	err = h.PollOnce(context.Background(), source)
	if err == nil {
		t.Fatal("expected atomic rename failure")
	}
	if h.state.Sequence != 1 || h.state.Sources["fixture"].Cursor != "old" {
		t.Fatal("failed checkpoint advanced live position")
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, statePath); err != nil {
		t.Fatal(err)
	}
	if err := h.PollOnce(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	if h.state.Sequence != 2 || h.state.Sources["fixture"].Cursor != "new" {
		t.Fatal("retry failed to recover exactly once")
	}
}

func TestConfiguredSourceBypassesPersistedMissingCredentialBackoff(t *testing.T) {
	for _, outcome := range []string{"success", "upstream_failure", "still_missing"} {
		t.Run(outcome, func(t *testing.T) {
			h, cfg, _ := fixtureHub(t)
			now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
			h.now = func() time.Time { return now }
			source := ScheduledSource{Name: "fixture", Every: time.Minute, Fingerprint: "unchanged-config", Source: fixtureSource(func(context.Context, string) (intel.Result, error) {
				return intel.Result{Items: noticeItems(1), Cursor: "123"}, nil
			})}
			if err := h.PollOnce(context.Background(), source); err != nil {
				t.Fatal(err)
			}
			source.Source = missingSource{}
			for i := 0; i < 3; i++ {
				now = h.state.Sources[source.Name].NextPoll
				if err := h.PollOnce(context.Background(), source); err != nil {
					t.Fatal(err)
				}
			}
			previous := h.state.Sources[source.Name]
			if previous.ErrorCode != "not_configured" || previous.Failures != 3 || previous.Cursor != "123" {
				t.Fatalf("invalid missing-credential setup: %+v", previous)
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			now = now.Add(10 * time.Second)
			reopened.now = func() time.Time { return now }
			calls := 0
			if outcome != "still_missing" {
				source.Source = fixtureSource(func(_ context.Context, cursor string) (intel.Result, error) {
					calls++
					if cursor != "123" {
						t.Errorf("activation lost persisted cursor: %q", cursor)
					}
					if outcome == "upstream_failure" {
						return intel.Result{Items: noticeItems(2), Cursor: "uncommitted"}, errors.New("upstream unavailable")
					}
					return intel.Result{Items: noticeItems(2), Cursor: "456"}, nil
				})
			}
			if err := reopened.PollOnce(context.Background(), source); err != nil {
				t.Fatal(err)
			}
			persisted, err := readState(cfg.StateDir)
			if err != nil {
				t.Fatal(err)
			}
			got := persisted.Sources[source.Name]
			if got != reopened.state.Sources[source.Name] {
				t.Fatal("activation state was not durably committed")
			}
			switch outcome {
			case "still_missing":
				if got != previous || persisted.Sequence != 1 {
					t.Fatalf("missing credentials bypassed retry backoff: %+v", got)
				}
			case "success":
				if calls != 1 || got.Cursor != "456" || got.Failures != 0 || got.ErrorCode != "" || !got.LastSuccess.Equal(now) || persisted.Sequence != 2 {
					t.Fatalf("activation did not ingest promptly: calls=%d state=%+v sequence=%d", calls, got, persisted.Sequence)
				}
			case "upstream_failure":
				if calls != 1 || got.Cursor != "123" || got.Failures != 1 || got.ErrorCode != "upstream_unavailable" || got.LastSuccess != previous.LastSuccess || persisted.Sequence != 1 {
					t.Fatalf("genuine failure inherited missing-credential failures or committed data: calls=%d state=%+v", calls, got)
				}
			}
			if outcome != "still_missing" && !got.NextPoll.Equal(now.Add(source.Every)) {
				t.Fatalf("activation inherited old retry delay: %s", got.NextPoll)
			}
			if err := reopened.PollOnce(context.Background(), source); err != nil {
				t.Fatal(err)
			}
			if outcome != "still_missing" && calls != 1 {
				t.Fatal("activation bypassed normal retry schedule after its first attempt")
			}
		})
	}
}

func TestRetentionGapsAndAheadCursorsAreExplicit(t *testing.T) {
	h, _, public := fixtureHub(t)
	h.config.MaxNotices = 2
	now := time.Now().UTC()
	h.now = func() time.Time { return now }
	pollFixture(t, h, noticeItems(3), "three")
	envelope, gap := getEnvelope(t, h.Handler(), "/api/v1/notices?after=0")
	if !ed25519.Verify(public, envelope.Payload, envelope.Signature) || !gap.ResetRequired || gap.ResetTo != 1 || gap.NextCursor != 0 || len(gap.Notices) != 0 || gap.Notices == nil {
		t.Fatalf("retention gap was not signed and explicit: %+v", gap)
	}
	_, ahead := getEnvelope(t, h.Handler(), "/api/v1/notices?after=99")
	if !ahead.ResetRequired || ahead.ResetTo != 1 {
		t.Fatal("ahead cursor did not require explicit reset")
	}
	_, resume := getEnvelope(t, h.Handler(), "/api/v1/notices?after=1")
	if resume.ResetRequired || len(resume.Notices) != 2 || resume.Notices[0].Seq != 2 {
		t.Fatal("signed reset point does not permit replay")
	}
	now = now.Add(8 * 24 * time.Hour)
	pollFixture(t, h, nil, "three")
	empty, err := h.Batch(3, 100)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Oldest != 4 || empty.Latest != 3 || empty.ResetRequired || empty.HasMore || empty.Notices == nil {
		t.Fatalf("expired-history bounds are ambiguous: %+v", empty)
	}
}

func TestPollIsSharedAcrossReadersAndSameSourceConcurrency(t *testing.T) {
	h, _, _ := fixtureHub(t)
	calls := 0
	source := ScheduledSource{Name: "fixture", Every: time.Hour, Source: fixtureSource(func(context.Context, string) (intel.Result, error) {
		calls++
		return intel.Result{Items: noticeItems(1), Cursor: "one"}, nil
	})}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.PollOnce(context.Background(), source); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	handler := h.Handler()
	for i := 0; i < 30; i++ {
		getEnvelope(t, handler, "/api/v1/notices?after=0")
	}
	if calls != 1 {
		t.Fatalf("%d upstream requests for one scheduled poll and30 client reads", calls)
	}
}

func TestStrictPublicSurfaceAndSanitizedHealth(t *testing.T) {
	h, _, _ := fixtureHub(t)
	h.config.Sources[0].TokenEnv = "TOP_SECRET_ENV"
	h.config.Sources[0].URL = "https://example.invalid/?token=private"
	pollFixture(t, h, []intel.Item{{ID: "one", Title: strings.Repeat("é", 1000), Body: strings.Repeat("é", 4000) + `{"actions":["do evil"]}`, URL: "javascript:alert(1)", Trust: "execute"}}, "private-cursor")
	err := h.PollOnce(context.Background(), ScheduledSource{Name: "fixture", Every: time.Nanosecond, Source: fixtureSource(func(context.Context, string) (intel.Result, error) {
		return intel.Result{}, errors.New("private upstream token")
	})})
	if err != nil {
		t.Fatal(err)
	}
	handler := h.Handler()
	_, batch := getEnvelope(t, handler, "/api/v1/notices")
	n := batch.Notices[0]
	if len(n.Title) > 512 || len(n.Summary) > 4096 || !utf8.ValidString(n.Summary) || n.URL != "" || !n.Untrusted {
		t.Fatal("notice was not bounded as untrusted data")
	}
	b, _ := json.Marshal(n)
	var fields map[string]json.RawMessage
	json.Unmarshal(b, &fields)
	for _, forbidden := range []string{"actions", "argv", "commands", "trust", "instructions", "code"} {
		if _, exists := fields[forbidden]; exists {
			t.Fatalf("control field %s on notice wire", forbidden)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/status", nil))
	for _, secret := range []string{"TOP_SECRET_ENV", "private", "cursor", "token=", "example.invalid"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("public status leaked %q", secret)
		}
	}
	for _, target := range []string{"/api/v1/notices?limit=501", "/api/v1/notices?after=-1", "/api/v1/notices?actions=run", "/api/v1/notices?after=0&after=1"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != 400 {
			t.Errorf("%s returned %d", target, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/notices", strings.NewReader(`{"command":"run"}`)))
	if rec.Code != 405 {
		t.Fatal("hub accepts mutation requests")
	}
}

func TestStaticFilesCannotExposeStateOrSymlinkEscapes(t *testing.T) {
	h, cfg, _ := fixtureHub(t)
	web := t.TempDir()
	h.config.WebsiteDir = web
	if err := os.WriteFile(filepath.Join(web, "index.html"), []byte("public website"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(web, ".env"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cfg.StateDir, "signing.key"), filepath.Join(web, "leak.txt")); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	defer server.Close()
	resp, err := http.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "public website" {
		t.Fatalf("website not served: %d %s", resp.StatusCode, b)
	}
	for _, p := range []string{"/.env", "/leak.txt", "/signing.key", "/hubstate.json", "/api/v1/execute"} {
		resp, err := http.Get(server.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("private path %s returned%d", p, resp.StatusCode)
		}
	}
}

func TestFAQAliasesKeepStaticBoundaries(t *testing.T) {
	h, cfg, _ := fixtureHub(t)
	web := t.TempDir()
	h.config.WebsiteDir = web
	faq := filepath.Join(web, "faq.html")
	if err := os.WriteFile(faq, []byte("experimental root responder FAQ"), 0600); err != nil {
		t.Fatal(err)
	}
	// Even a shell script accidentally placed in the website tree is not public.
	if err := os.WriteFile(filepath.Join(web, "install.sh"), []byte("private script"), 0600); err != nil {
		t.Fatal(err)
	}
	handler := h.Handler()
	for _, target := range []string{"/faq", "/faq/", "/faq.html"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
			if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
				t.Errorf("%s %s returned %d %s", method, target, rec.Code, rec.Body.String())
			}
			if method == http.MethodGet && rec.Body.String() != "experimental root responder FAQ" {
				t.Errorf("FAQ alias %s returned wrong contents", target)
			}
			if method == http.MethodHead && rec.Body.Len() != 0 {
				t.Errorf("HEAD %s returned a body", target)
			}
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, target, nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s accepted: %d", target, rec.Code)
		}
	}
	for _, target := range []string{"/faq/unknown", "/install.sh", "/install.sh/extra", "/api/v1/install.sh", "/unknown"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("unexpected public path %s: %d", target, rec.Code)
		}
	}
	if err := os.Remove(faq); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cfg.StateDir, "signing.key"), faq); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/faq", "/faq/", "/faq.html"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("FAQ symlink escape %s: %d", target, rec.Code)
		}
	}
}

func TestKeyInitializationDoesNotReplacePin(t *testing.T) {
	_, cfg, public := fixtureHub(t)
	if _, err := InitKey(cfg.StateDir); err == nil {
		t.Fatal("existing signing key replaced")
	}
	got, err := PublicKey(cfg.StateDir)
	if err != nil || !got.Equal(public) {
		t.Fatal("public key changed")
	}
	fi, err := os.Stat(filepath.Join(cfg.StateDir, "signing.key"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatal("private key permissions are not0600")
	}
}

func TestRealBroadcastClientConsumesHubPagesAndSignedGap(t *testing.T) {
	h, _, public := fixtureHub(t)
	pollFixture(t, h, noticeItems(3), "three")
	server := httptest.NewServer(h.Handler())
	defer server.Close()
	client, err := intel.NewBroadcast(intel.BroadcastConfig{URL: server.URL, PublicKey: base64.StdEncoding.EncodeToString(public), PageSize: 1, MaxPages: 10})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Poll(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 3 || result.Cursor == "" {
		t.Fatalf("hub/client contract failed: %+v", result)
	}
	empty, err := client.Poll(context.Background(), result.Cursor)
	if err != nil || len(empty.Items) != 0 {
		t.Fatalf("already consumed notices replayed: %+v %v", empty, err)
	}
	h.config.MaxNotices = 1
	pollFixture(t, h, noticeItems(4), "four")
	fresh, err := intel.NewBroadcast(intel.BroadcastConfig{URL: server.URL, PublicKey: base64.StdEncoding.EncodeToString(public)})
	if err != nil {
		t.Fatal(err)
	}
	gap, err := fresh.Poll(context.Background(), "")
	if err != nil || len(gap.Items) != 1 {
		t.Fatalf("signed coverage gap not surfaced: %+v %v", gap, err)
	}
	resumed, err := fresh.Poll(context.Background(), gap.Cursor)
	if err != nil || len(resumed.Items) != 1 {
		t.Fatalf("gap checkpoint failed to resume retained history: %+v %v", resumed, err)
	}
}

func TestBatchByteBudgetFitsClientEnvelopeLimit(t *testing.T) {
	h, _, _ := fixtureHub(t)
	items := noticeItems(100)
	for i := range items {
		items[i].Body = strings.Repeat("<", 4096)
	}
	pollFixture(t, h, items, "many")
	envelope, batch := getEnvelope(t, h.Handler(), "/api/v1/notices?after=0&limit=500")
	b, _ := json.Marshal(envelope)
	if len(b) >= 2<<20 || len(batch.Notices) == 0 || !batch.HasMore {
		t.Fatalf("bounded envelope failed: bytes=%d notices=%d more=%v", len(b), len(batch.Notices), batch.HasMore)
	}
}

func TestCheckpointByteBudgetRetainsMonotonicTailAndCursor(t *testing.T) {
	s := diskState{Version: 1, Sequence: 20, Sources: map[string]sourceState{"fixture": {Cursor: "complete-upstream-checkpoint"}}}
	for i := 1; i <= 20; i++ {
		s.Notices = append(s.Notices, storedNotice{Notice: Notice{Seq: uint64(i), Summary: strings.Repeat("<", 200), Untrusted: true}, Hash: "fingerprint"})
	}
	b, err := boundedState(&s, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if len(b)+1 > 5000 || len(s.Notices) == 0 || len(s.Notices) >= 20 || s.Sequence != 20 || s.Notices[len(s.Notices)-1].Notice.Seq != 20 || s.Sources["fixture"].Cursor != "complete-upstream-checkpoint" {
		t.Fatal("byte retention lost its monotonic counter or cursor")
	}
	for i := 1; i < len(s.Notices); i++ {
		if s.Notices[i].Notice.Seq != s.Notices[i-1].Notice.Seq+1 {
			t.Fatal("byte retention created an internal sequence gap")
		}
	}
}

func TestRecentBoardSortsPublicationWithoutChangingDeliverySequence(t *testing.T) {
	h, _, _ := fixtureHub(t)
	now := time.Now().UTC()
	h.now = func() time.Time { return now }
	items := noticeItems(4)
	items[0].PublishedAt = now.Add(-time.Hour)
	items[1].PublishedAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	items[2].PublishedAt = time.Time{}
	items[3].PublishedAt = items[0].PublishedAt
	pollFixture(t, h, items, "complete")
	before, _ := json.Marshal(h.state)
	rec := httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/recent?limit=3", nil))
	if rec.Code != 200 {
		t.Fatalf("recent returned%d: %s", rec.Code, rec.Body.String())
	}
	var recent Recent
	if err := json.Unmarshal(rec.Body.Bytes(), &recent); err != nil {
		t.Fatal(err)
	}
	if recent.Version != 1 || recent.Kind != "recent_notices" || len(recent.Notices) != 3 || recent.Notices[0].Seq != 3 || recent.Notices[1].Seq != 4 || recent.Notices[2].Seq != 1 {
		t.Fatalf("wrong recent publication order: %+v", recent)
	}
	var wire map[string]json.RawMessage
	json.Unmarshal(rec.Body.Bytes(), &wire)
	if len(wire) != 4 || wire["notices"] == nil || wire["kind"] == nil || wire["server_time"] == nil || wire["version"] == nil {
		t.Fatal("recent endpoint contains unexpected control/schema fields")
	}
	after, _ := json.Marshal(h.state)
	if string(before) != string(after) {
		t.Fatal("viewing recent notices mutated hub state")
	}
	batch, err := h.Batch(0, 4)
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range batch.Notices {
		if n.Seq != uint64(i+1) || !n.Untrusted {
			t.Fatal("recent view reordered signed delivery or trusted source text")
		}
	}
	for _, target := range []string{"/api/v1/recent?limit=101", "/api/v1/recent?limit=0", "/api/v1/recent?after=1", "/api/v1/recent?actions=run"} {
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != 400 {
			t.Errorf("%s returned%d", target, rec.Code)
		}
	}
	rec = httptest.NewRecorder()
	h.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/recent", nil))
	if rec.Code != 405 {
		t.Fatal("recent endpoint accepts mutation methods")
	}
}

func TestRecentBoardExcludesRemovedSourcesWithoutChangingSignedHistory(t *testing.T) {
	h, cfg, public := fixtureHub(t)
	now := time.Now().UTC()
	h.now = func() time.Time { return now }
	h.config.Sources = append(h.config.Sources, SourceConfig{Name: "removed", Type: "rss", URL: "https://example.invalid/removed", IntervalSeconds: 60})
	activeItems := noticeItems(2)
	activeItems[0].PublishedAt = now.Add(-2 * time.Hour)
	activeItems[1].PublishedAt = now.Add(-time.Hour)
	pollFixture(t, h, activeItems, "active-checkpoint")
	removedItems := noticeItems(2)
	for i := range removedItems {
		removedItems[i].PublishedAt = now
	}
	if err := h.PollOnce(context.Background(), ScheduledSource{Name: "removed", Every: time.Minute, Source: fixtureSource(func(context.Context, string) (intel.Result, error) {
		return intel.Result{Items: removedItems, Cursor: "removed-checkpoint"}, nil
	})}); err != nil {
		t.Fatal(err)
	}
	initial, err := h.Recent(1)
	if err != nil || len(initial.Notices) != 1 || initial.Notices[0].Source != "removed" {
		t.Fatalf("newer configured source missing from initial board: %+v err=%v", initial, err)
	}
	statePath := filepath.Join(cfg.StateDir, "hubstate.json")
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	// Restart with only the fixture source configured, retaining the same state.
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return now }
	recent, err := reopened.Recent(1)
	if err != nil || len(recent.Notices) != 1 || recent.Notices[0].Source != "fixture" || recent.Notices[0].Seq != 2 {
		t.Fatalf("removed source displaced active notices: %+v err=%v", recent, err)
	}
	envelope, batch := getEnvelope(t, reopened.Handler(), "/api/v1/notices?after=0&limit=4")
	if !ed25519.Verify(public, envelope.Payload, envelope.Signature) || batch.Latest != 4 || batch.NextCursor != 4 || batch.HasMore || len(batch.Notices) != 4 {
		t.Fatalf("signed historical delivery changed after source removal: %+v", batch)
	}
	for i, notice := range batch.Notices {
		if notice.Seq != uint64(i+1) || (i >= 2 && notice.Source != "removed") {
			t.Fatalf("stored notice lost or reordered: %+v", notice)
		}
	}
	if reopened.state.Sources["removed"].Cursor != "removed-checkpoint" || reopened.state.Sources["fixture"].Cursor != "active-checkpoint" {
		t.Fatal("board filtering changed upstream checkpoints")
	}
	after, err := os.ReadFile(statePath)
	if err != nil || string(before) != string(after) {
		t.Fatalf("board filtering rewrote stored history: %v", err)
	}
}

func TestNVDHubPageSizeIsConfiguredAndBounded(t *testing.T) {
	for _, configured := range []int{0, 37} {
		t.Run(fmt.Sprint(configured), func(t *testing.T) {
			want := configured
			if want == 0 {
				want = 500
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("resultsPerPage") != fmt.Sprint(want) {
					t.Errorf("NVD page size=%s want%d", r.URL.Query().Get("resultsPerPage"), want)
				}
				fmt.Fprint(w, `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`)
			}))
			defer server.Close()
			cfg := DefaultConfig()
			cfg.Sources = []SourceConfig{{Name: "nvd", Type: "nvd", URL: server.URL, IntervalSeconds: 300, PageSize: configured}}
			sources, err := BuildSources(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = sources[0].Source.Poll(context.Background(), ""); err != nil {
				t.Fatal(err)
			}
		})
	}
	cfg := DefaultConfig()
	cfg.Sources[0].PageSize = 2001
	if err := cfg.Validate(); err == nil {
		t.Fatal("oversized NVD pages accepted")
	}
}

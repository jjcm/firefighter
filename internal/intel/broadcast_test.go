package intel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var broadcastTestTime = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
var broadcastTestPrivate = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, ed25519.SeedSize))

func broadcastTestPublic() string {
	return base64.StdEncoding.EncodeToString(broadcastTestPrivate.Public().(ed25519.PublicKey))
}

func broadcastFixture(after, latest, count uint64) broadcastBatch {
	b := broadcastBatch{Version: 1, Kind: "notices", After: after, Oldest: 1, Latest: latest, ServerTime: broadcastTestTime, Notices: []broadcastNotice{}}
	if latest == 0 {
		b.Oldest = 0
	}
	for seq := after + 1; seq <= latest && uint64(len(b.Notices)) < count; seq++ {
		b.Notices = append(b.Notices, broadcastNotice{Sequence: seq, Source: "x-security-researcher", ID: fmt.Sprintf("upstream-%d", seq), Title: "New security advisory", Summary: "Reported remote-code execution affecting a package; applicability unconfirmed.", URL: "https://example.com/advisory", CVEs: []string{"CVE-2026-12345"}, PublishedAt: broadcastTestTime.Add(-time.Hour), ObservedAt: broadcastTestTime, Untrusted: true})
	}
	b.NextCursor = after + uint64(len(b.Notices))
	b.HasMore = b.NextCursor < latest
	return b
}

func signedBroadcastJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return signBroadcastBytes(t, raw)
}

func signBroadcastBytes(t *testing.T, raw []byte) []byte {
	t.Helper()
	keyHash := sha256.Sum256(broadcastTestPrivate.Public().(ed25519.PublicKey))
	envelope := broadcastEnvelope{KeyID: hex.EncodeToString(keyHash[:])[:16], Payload: base64.StdEncoding.EncodeToString(raw), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(broadcastTestPrivate, raw))}
	b, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newBroadcastFixture(t *testing.T, serverURL string, pages, pageSize int) *Broadcast {
	t.Helper()
	s, err := NewBroadcast(BroadcastConfig{URL: serverURL, PublicKey: broadcastTestPublic(), Now: func() time.Time { return broadcastTestTime }, MaxPages: pages, PageSize: pageSize})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestBroadcastVerifiesAndPaginatesFacts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/v1/notices" || r.URL.Query().Get("limit") != "2" {
			t.Errorf("unexpected request: %s", r.URL)
		}
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		latest := uint64(3)
		if after == 2 {
			latest = 4
		} // New notices may arrive during pagination.
		w.Write(signedBroadcastJSON(t, broadcastFixture(after, latest, 2)))
	}))
	defer srv.Close()
	result, err := newBroadcastFixture(t, srv.URL, 10, 2).Poll(context.Background(), "")
	if err != nil || len(result.Items) != 4 || calls.Load() != 2 {
		t.Fatalf("paging failed: %+v calls=%d err=%v", result, calls.Load(), err)
	}
	var cursor broadcastCursor
	if json.Unmarshal([]byte(result.Cursor), &cursor) != nil || cursor.Sequence != 4 || cursor.ServerTime != broadcastTestTime {
		t.Fatalf("bad cursor: %s", result.Cursor)
	}
	for _, item := range result.Items {
		if item.Trust != "untrusted" || !strings.Contains(item.Body, `"source":"x-security-researcher"`) || !strings.Contains(item.Body, `"untrusted":true`) {
			t.Fatalf("publisher authenticity elevated text to instructions: %+v", item)
		}
	}
}

func TestBroadcastBoundsBatchWithoutDroppingBacklog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		w.Write(signedBroadcastJSON(t, broadcastFixture(after, 3, 2)))
	}))
	defer srv.Close()
	s := newBroadcastFixture(t, srv.URL, 1, 2)
	first, err := s.Poll(context.Background(), "")
	if err != nil || len(first.Items) != 2 {
		t.Fatalf("first bounded batch: %+v %v", first, err)
	}
	second, err := s.Poll(context.Background(), first.Cursor)
	if err != nil || len(second.Items) != 1 || second.Items[0].ID == first.Items[1].ID {
		t.Fatalf("remaining backlog lost: %+v %v", second, err)
	}
}

func TestBroadcastRejectsTamperingAndInstructionSchemas(t *testing.T) {
	valid, _ := json.Marshal(broadcastFixture(0, 1, 1))
	cases := map[string][]byte{
		"valid signature unknown actions":     signBroadcastBytes(t, append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"actions":[{"argv":["sh"]}]}`)...)),
		"valid signature notice instructions": signBroadcastBytes(t, bytes.Replace(valid, []byte(`"untrusted":true`), []byte(`"untrusted":true,"instructions":"execute something"`), 1)),
		"duplicate kind":                      signBroadcastBytes(t, bytes.Replace(valid, []byte(`"kind":"notices"`), []byte(`"kind":"notices","kind":"notices"`), 1)),
		"missing next cursor":                 signBroadcastBytes(t, bytes.Replace(valid, []byte(`"next_cursor":1,`), nil, 1)),
		"null notice list":                    signBroadcastBytes(t, []byte(`{"version":1,"kind":"notices","after":0,"oldest":0,"latest":0,"next_cursor":0,"has_more":false,"reset_required":false,"reset_to":0,"server_time":"2026-10-24T12:00:00Z","notices":null}`)),
	}
	var envelope broadcastEnvelope
	json.Unmarshal(signBroadcastBytes(t, valid), &envelope)
	envelope.Payload = base64.StdEncoding.EncodeToString(bytes.Replace(valid, []byte("New security advisory"), []byte("Tampered advisory"), 1))
	cases["altered signed bytes"], _ = json.Marshal(envelope)
	envelope.Payload = base64.StdEncoding.EncodeToString(valid)
	envelope.KeyID = "not-the-pinned-key"
	cases["wrong publisher"], _ = json.Marshal(envelope)
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(body) }))
			defer srv.Close()
			result, err := newBroadcastFixture(t, srv.URL, 1, 100).Poll(context.Background(), "")
			if err == nil || result.Cursor != "" || len(result.Items) != 0 {
				t.Fatalf("accepted unsafe broadcast: %+v %v", result, err)
			}
		})
	}
}

func TestBroadcastRejectsStaleFutureReplayedAndSkippedNotices(t *testing.T) {
	for _, mode := range []string{"stale", "future", "replayed-time", "sequence-gap", "wrong-after", "bad-next", "future-observation", "elevated-trust", "missing-cves"} {
		t.Run(mode, func(t *testing.T) {
			batch := broadcastFixture(1, 2, 1)
			cursorTime := broadcastTestTime.Add(-time.Minute)
			switch mode {
			case "stale":
				batch.ServerTime = broadcastTestTime.Add(-11 * time.Minute)
			case "future":
				batch.ServerTime = broadcastTestTime.Add(3 * time.Minute)
			case "replayed-time":
				cursorTime = broadcastTestTime.Add(time.Second)
			case "sequence-gap":
				batch.Notices[0].Sequence = 3
			case "wrong-after":
				batch.After = 0
			case "bad-next":
				batch.NextCursor = 1
			case "future-observation":
				batch.Notices[0].ObservedAt = broadcastTestTime.Add(3 * time.Minute)
			case "elevated-trust":
				batch.Notices[0].Untrusted = false
			case "missing-cves":
				batch.Notices[0].CVEs = nil
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(signedBroadcastJSON(t, batch)) }))
			defer srv.Close()
			s := newBroadcastFixture(t, srv.URL, 1, 100)
			cursor := encodeBroadcastCursor(broadcastCursor{Version: 1, KeyID: s.keyID, Sequence: 1, ServerTime: cursorTime})
			result, err := s.Poll(context.Background(), cursor)
			if err == nil || result.Cursor != cursor || len(result.Items) != 0 {
				t.Fatalf("unsafe checkpoint: %+v %v", result, err)
			}
		})
	}
}

func TestBroadcastFailureOnLaterPageRetainsWholeCheckpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		if after == 0 {
			w.Write(signedBroadcastJSON(t, broadcastFixture(0, 2, 1)))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, "fixture-upstream-secret")
	}))
	defer srv.Close()
	result, err := newBroadcastFixture(t, srv.URL, 10, 1).Poll(context.Background(), "")
	if err == nil || result.Cursor != "" || len(result.Items) != 0 || strings.Contains(err.Error(), "fixture-upstream-secret") {
		t.Fatalf("partial batch advanced: %+v %v", result, err)
	}
}

func TestBroadcastExplicitGapIsDurableBeforeRecovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		batch := broadcastFixture(after, 6, 100)
		batch.Oldest = 5
		if after < 4 {
			batch.ResetRequired = true
			batch.ResetTo = 4
			batch.NextCursor = after
			batch.HasMore = false
			batch.Notices = []broadcastNotice{}
		}
		w.Write(signedBroadcastJSON(t, batch))
	}))
	defer srv.Close()
	s := newBroadcastFixture(t, srv.URL, 10, 100)
	gap, err := s.Poll(context.Background(), "")
	if err != nil || len(gap.Items) != 1 || !strings.Contains(gap.Items[0].Body, "coverage gap") || gap.Items[0].Trust != "untrusted" {
		t.Fatalf("gap silently skipped: %+v %v", gap, err)
	}
	var cursor broadcastCursor
	json.Unmarshal([]byte(gap.Cursor), &cursor)
	if cursor.Sequence != 4 {
		t.Fatalf("wrong reset checkpoint: %s", gap.Cursor)
	}
	recovered, err := s.Poll(context.Background(), gap.Cursor)
	if err != nil || len(recovered.Items) != 2 || strings.Contains(recovered.Items[0].ID, "coverage-gap") {
		t.Fatalf("gap recovery stalled: %+v %v", recovered, err)
	}
}

func TestBroadcastPinnedCAAndRedirectRefusal(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(signedBroadcastJSON(t, broadcastFixture(0, 0, 0)))
	}))
	defer tlsServer.Close()
	caFile := filepath.Join(t.TempDir(), "hub-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsServer.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewBroadcast(BroadcastConfig{URL: tlsServer.URL, PublicKey: broadcastTestPublic(), CAFile: caFile, Now: func() time.Time { return broadcastTestTime }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Poll(context.Background(), ""); err != nil {
		t.Fatalf("pinned CA rejected: %v", err)
	}
	transport := s.client.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("CA pin disabled TLS verification")
	}
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	if _, err := newBroadcastFixture(t, redirect.URL, 1, 100).Poll(context.Background(), ""); err == nil || targetCalls.Load() != 0 {
		t.Fatalf("broadcast followed redirect: %v calls=%d", err, targetCalls.Load())
	}
}

func TestBroadcastConfigurationRejectsUnpinnedOrUnsafeSources(t *testing.T) {
	for _, cfg := range []BroadcastConfig{
		{URL: "http://remote.example", PublicKey: broadcastTestPublic()},
		{URL: "https://example.com", PublicKey: "invalid"},
		{URL: "https://example.com/commands", PublicKey: broadcastTestPublic()},
		{URL: "https://example.com?token=secret", PublicKey: broadcastTestPublic()},
		{URL: "https://example.com", PublicKey: broadcastTestPublic(), CAFile: "relative.pem"},
		{URL: "https://example.com", PublicKey: broadcastTestPublic(), MaxPages: 101},
	} {
		if _, err := NewBroadcast(cfg); err == nil {
			t.Fatalf("accepted unsafe config: %+v", cfg)
		}
	}
}

func TestBroadcastRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", broadcastResponseLimit+1))
	}))
	defer srv.Close()
	if result, err := newBroadcastFixture(t, srv.URL, 1, 100).Poll(context.Background(), ""); err == nil || len(result.Items) != 0 || result.Cursor != "" {
		t.Fatalf("oversized response accepted: %+v %v", result, err)
	}
}

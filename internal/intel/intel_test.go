package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 24, 10, 0, 0, 0, time.UTC)

func TestXPaginationCommitAndEarlyDisclosure(t *testing.T) {
	calls := 0
	nowCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing bearer token")
		}
		if r.URL.Query().Get("since_id") != "100" {
			t.Error("since_id changed during pagination")
		}
		if r.URL.Query().Has("start_time") || r.URL.Query().Has("end_time") {
			http.Error(w, "Invalid use of ID bounds in conjunction with time bounds", http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("until_id") != "2113933390771126272" {
			t.Error("incorrect or unstable exclusive Snowflake boundary")
		}
		if r.URL.Query().Get("next_token") == "" {
			fmt.Fprint(w, `{"data":[{"id":"300","text":"zero-day in widget, no CVE assigned","created_at":"2026-10-24T09:00:00Z"}],"meta":{"result_count":1,"next_token":"page2"}}`)
		} else {
			fmt.Fprint(w, `{"data":[{"id":"200","text":"CVE-2026-12345 advisory","created_at":"2026-10-24T08:00:00Z","entities":{"urls":[{"expanded_url":"https://vendor.example/advisory"}]}}],"meta":{"result_count":1}}`)
		}
	}))
	defer server.Close()
	s, err := NewX(XConfig{URL: server.URL + "?start_time=stale&end_time=stale", BearerToken: "secret", Now: func() time.Time {
		nowCalls++
		return testNow.Add(time.Duration(nowCalls-1) * time.Minute)
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Poll(context.Background(), "100")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || nowCalls != 1 || len(result.Items) != 2 || result.Cursor != "300" {
		t.Fatalf("unexpected result: %+v calls=%d", result, calls)
	}
	if len(result.Items[0].CVEs) != 0 || result.Items[0].Trust != "unverified" {
		t.Fatal("early disclosure missing or implicitly trusted")
	}
	if !strings.Contains(result.Items[1].Body, "https://vendor.example/advisory") {
		t.Fatal("expanded evidence URL absent")
	}
}

func TestXInitialPaginationUsesOnlyFixedTimeBounds(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if q.Has("since_id") || q.Has("until_id") || q.Has("pagination_token") {
			http.Error(w, "mixed ID and time bounds", http.StatusBadRequest)
			return
		}
		if q.Get("start_time") != "2026-10-24T08:59:30Z" || q.Get("end_time") != "2026-10-24T09:59:30Z" {
			t.Errorf("initial time bounds changed: %v", q)
		}
		if calls == 1 {
			if q.Has("next_token") {
				t.Error("first page used a stale pagination token")
			}
			fmt.Fprint(w, `{"data":[{"id":"300","text":"advisory","created_at":"2026-10-24T09:00:00Z"}],"meta":{"result_count":1,"next_token":"page2"}}`)
		} else {
			if q.Get("next_token") != "page2" {
				t.Error("missing next pagination token")
			}
			fmt.Fprint(w, `{"meta":{"result_count":0}}`)
		}
	}))
	defer server.Close()
	s, err := NewX(XConfig{URL: server.URL + "?since_id=stale&until_id=stale&next_token=stale&pagination_token=stale", BearerToken: "secret", Lookback: time.Hour, Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Poll(context.Background(), "")
	if err != nil || calls != 2 || len(result.Items) != 1 || result.Cursor != "300" {
		t.Fatalf("initial pagination failed: %+v calls=%d err=%v", result, calls, err)
	}
}

func TestXInvalidIDBoundsRetainCursorWithoutRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid ID bounds reached the upstream API")
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	defer server.Close()
	for _, tc := range []struct {
		name, cursor string
		now          time.Time
	}{
		{"equal bounds", "2113933390771126272", testNow},
		{"future cursor", "2113933390771126273", testNow},
		{"invalid cursor", "not-an-id", testNow},
		{"zero cursor", "0", testNow},
		{"before epoch", "100", time.UnixMilli(xEpochMillis)},
		{"timestamp overflow", "100", time.UnixMilli(xEpochMillis + 1<<41).Add(time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewX(XConfig{URL: server.URL, BearerToken: "secret", Now: func() time.Time { return tc.now }})
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.Poll(context.Background(), tc.cursor)
			if err == nil || result.Cursor != tc.cursor || len(result.Items) != 0 {
				t.Fatalf("invalid bounds changed the checkpoint: %+v err=%v", result, err)
			}
		})
	}
}

func TestXFailureAndTruncationRetainCursor(t *testing.T) {
	for _, scenario := range []string{"http failure", "page cap", "partial errors", "repeated token"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("next_token") != "" && scenario == "http failure" {
					http.Error(w, "rate limited", 429)
					return
				}
				if scenario == "partial errors" {
					fmt.Fprint(w, `{"data":[],"meta":{"result_count":0},"errors":[{"detail":"failure"}]}`)
					return
				}
				fmt.Fprint(w, `{"data":[{"id":"300","text":"advisory","created_at":"2026-10-24T09:00:00Z"}],"meta":{"result_count":1,"next_token":"page2"}}`)
			}))
			defer server.Close()
			maxPages := 3
			if scenario == "page cap" {
				maxPages = 1
			}
			s, err := NewX(XConfig{URL: server.URL, BearerToken: "secret", MaxPages: maxPages, Now: func() time.Time { return testNow }})
			if err != nil {
				t.Fatal(err)
			}
			result, err := s.Poll(context.Background(), "100")
			if err == nil || result.Cursor != "100" || len(result.Items) != 0 {
				t.Fatalf("partial poll must not commit: %+v err=%v", result, err)
			}
		})
	}
}

func TestCredentialRedirectRejected(t *testing.T) {
	leaked := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer server.Close()
	s, err := NewX(XConfig{URL: server.URL, BearerToken: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Poll(context.Background(), ""); err == nil {
		t.Fatal("expected redirect error")
	}
	if leaked {
		t.Fatal("redirect followed with credential-bearing request")
	}
}

func TestNVDPaginationAndWindowCursor(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		q := r.URL.Query()
		if q.Get("lastModStartDate") != "2026-10-24T08:55:00.000Z" || q.Get("lastModEndDate") != "2026-10-24T10:00:00.000Z" {
			t.Errorf("unexpected bounds: %v", q)
		}
		if r.Header.Get("apiKey") != "key" {
			t.Error("NVD key missing")
		}
		index := 0
		if q.Get("startIndex") == "1" {
			index = 1
		}
		fmt.Fprintf(w, `{"startIndex":%d,"resultsPerPage":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2026-%d","published":"2026-10-24T08:00:00.000","lastModified":"2026-10-24T09:30:00.000","descriptions":[{"lang":"en","value":"widget issue"}],"configurations":[{"nodes":[]}]}}]}`, index, 10000+index)
	}))
	defer server.Close()
	s, err := NewNVD(NVDConfig{URL: server.URL, APIKey: "key", Now: func() time.Time { return testNow }, PageSize: 1, RequestInterval: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Poll(context.Background(), "2026-10-24T09:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(result.Items) != 2 || result.Cursor != "2026-10-24T10:00:00Z" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !strings.Contains(result.Items[0].Body, "configurations") {
		t.Fatal("NVD applicability data was discarded")
	}
}

func TestNVDSecondPageFailureDoesNotSkip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("startIndex") == "1" {
			http.Error(w, "outage", 503)
			return
		}
		fmt.Fprint(w, `{"startIndex":0,"resultsPerPage":1,"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-2026-10000","lastModified":"2026-10-24T09:30:00.000"}}]}`)
	}))
	defer server.Close()
	s, err := NewNVD(NVDConfig{URL: server.URL, Now: func() time.Time { return testNow }, RequestInterval: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	cursor := "2026-10-24T09:00:00Z"
	result, err := s.Poll(context.Background(), cursor)
	if err == nil || result.Cursor != cursor || len(result.Items) != 0 {
		t.Fatalf("cursor advanced despite incomplete window: %+v %v", result, err)
	}
}

func TestKEVChangesAndLookback(t *testing.T) {
	body := "original"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"catalogVersion":"2026.10.24","count":2,"vulnerabilities":[{"cveID":"CVE-2026-10000","vulnerabilityName":"widget","dateAdded":"2026-10-23","shortDescription":%q},{"cveID":"CVE-2020-10000","vulnerabilityName":"old issue","dateAdded":"2020-01-01"}]}`, body)
	}))
	defer server.Close()
	s, err := NewKEV(KEVConfig{URL: server.URL, Now: func() time.Time { return testNow }, Lookback: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.Poll(context.Background(), "")
	if err != nil || len(first.Items) != 1 {
		t.Fatalf("unexpected first result: %+v %v", first, err)
	}
	second, err := s.Poll(context.Background(), first.Cursor)
	if err != nil || len(second.Items) != 0 {
		t.Fatalf("unchanged items re-emitted: %+v %v", second, err)
	}
	body = "updated mitigation"
	third, err := s.Poll(context.Background(), second.Cursor)
	if err != nil || len(third.Items) != 1 || !strings.Contains(third.Items[0].Body, body) {
		t.Fatalf("edit missed: %+v %v", third, err)
	}
	all, _ := NewKEV(KEVConfig{URL: server.URL})
	result, err := all.Poll(context.Background(), "")
	if err != nil || len(result.Items) != 2 {
		t.Fatal("default KEV ingestion must include all history")
	}
}

func TestFeedRSSAndAtom(t *testing.T) {
	for _, body := range []string{
		`<rss version="2.0"><channel><item><guid>one</guid><title>CVE-2026-12345</title><link>/advisory</link><description>Patch now</description><pubDate>Fri, 23 Oct 2026 10:00:00 +0000</pubDate></item></channel></rss>`,
		`<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>one</id><title>CVE-2026-12345</title><link href="/advisory"/><content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">Patch now</div></content><updated>2026-10-23T10:00:00Z</updated></entry></feed>`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		s, err := NewFeed(FeedConfig{Name: "vendor", URL: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		first, err := s.Poll(context.Background(), "")
		if err != nil || len(first.Items) != 1 {
			t.Fatalf("parse failed: %+v %v", first, err)
		}
		item := first.Items[0]
		if item.URL != server.URL+"/advisory" || len(item.CVEs) != 1 || item.PublishedAt.IsZero() || !strings.Contains(item.Body, "Patch now") {
			t.Fatalf("missing feed metadata: %+v", item)
		}
		second, err := s.Poll(context.Background(), first.Cursor)
		if err != nil || len(second.Items) != 0 {
			t.Fatalf("feed was not deduplicated: %+v %v", second, err)
		}
		server.Close()
	}
}

func TestMalformedFeedPreservesCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `<html>outage</html>`) }))
	defer server.Close()
	s, _ := NewFeed(FeedConfig{Name: "vendor", URL: server.URL})
	old, _ := json.Marshal(map[string]string{"a": "b"})
	result, err := s.Poll(context.Background(), string(old))
	if err == nil || result.Cursor != string(old) {
		t.Fatal("bad feed advanced the cursor")
	}
}

func TestExtractCVEs(t *testing.T) {
	got := ExtractCVEs("CVE-2026-12345 cve-2026-12345 CVE-2026-9999 notCVE-2026-1234 CVE-26-1234")
	if len(got) != 2 || got[0] != "CVE-2026-12345" || got[1] != "CVE-2026-9999" {
		t.Fatalf("unexpected CVEs: %v", got)
	}
}

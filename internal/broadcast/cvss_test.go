package broadcast

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/intel"
)

func cvssRecord(id, metrics string) string {
	return fmt.Sprintf(`{"id":%q,"metrics":%s}`, id, metrics)
}

func cvssMetric(version, source, kind, score string) string {
	return fmt.Sprintf(`{"source":%q,"type":%q,"cvssData":{"version":%q,"baseScore":%s}}`, source, kind, version, score)
}

func TestNVDCVSSSelection(t *testing.T) {
	const id = "CVE-2026-12345"
	for _, tc := range []struct {
		name, metrics, source, version string
		score                          float64
	}{
		{"v4 before primary v3", `{"cvssMetricV40":[` + cvssMetric("4.0", "v4.example", "Secondary", "5.3") + `],"cvssMetricV31":[` + cvssMetric("3.1", "v3.example", "Primary", "9.8") + `]}`, "v4.example", "4.0", 5.3},
		{"primary before higher secondary", `{"cvssMetricV31":[` + cvssMetric("3.1", "a.example", "Secondary", "10") + `,` + cvssMetric("3.1", "z.example", "Primary", "7.2") + `]}`, "z.example", "3.1", 7.2},
		{"source breaks primary tie", `{"cvssMetricV31":[` + cvssMetric("3.1", "z.example", "Primary", "10") + `,` + cvssMetric("3.1", "a.example", "Primary", "7.2") + `]}`, "a.example", "3.1", 7.2},
		{"same authority retains order", `{"cvssMetricV31":[` + cvssMetric("3.1", "a.example", "Primary", "7.2") + `,` + cvssMetric("3.1", "a.example", "Primary", "10") + `]}`, "a.example", "3.1", 7.2},
		{"v3 fallback", `{"cvssMetricV40":[],"cvssMetricV31":[],"cvssMetricV30":[` + cvssMetric("3.0", "a.example", "Primary", "4") + `],"cvssMetricV2":[` + cvssMetric("2.0", "a.example", "Primary", "10") + `]}`, "a.example", "3.0", 4},
		{"zero is a score", `{"cvssMetricV2":[` + cvssMetric("2.0", "a.example", "Primary", "0") + `]}`, "a.example", "2.0", 0},
		{"invalid entry skipped", `{"cvssMetricV31":[` + cvssMetric("3.1", "a.example", "Primary", "11") + `,` + cvssMetric("3.1", "b.example", "Secondary", "5.4") + `]}`, "b.example", "3.1", 5.4},
		{"invalid version family skipped", `{"cvssMetricV40":[` + cvssMetric("3.1", "a.example", "Primary", "10") + `],"cvssMetricV31":[` + cvssMetric("3.1", "b.example", "Primary", "7.5") + `]}`, "b.example", "3.1", 7.5},
		{"bad higher array skipped", `{"cvssMetricV40":{},"cvssMetricV31":[` + cvssMetric("3.1", "b.example", "Primary", "7.5") + `]}`, "b.example", "3.1", 7.5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := nvdCVSS(id, cvssRecord(id, tc.metrics))
			if got == nil || got.Score != tc.score || got.Version != tc.version || got.Source != tc.source {
				t.Fatalf("wrong selected assessment: %+v", got)
			}
		})
	}
}

func TestNVDCVSSDoesNotInventScores(t *testing.T) {
	const id = "CVE-2026-12345"
	valid := cvssRecord(id, `{"cvssMetricV31":[`+cvssMetric("3.1", "nvd@nist.gov", "Primary", "9.8")+`]}`)
	bodies := []string{
		`{"id":"CVE-2026-12345","description":"CVSS 9.8 critical"}`,
		`{"id":"CVE-2026-12345","metrics":{}}`,
		valid[:len(valid)-1],
		strings.Replace(valid, id, "CVE-2026-54321", 1),
		valid + `{}`,
		`null`,
	}
	for _, score := range []string{"-0.1", "10.1", "1e999", "null", `"9.8"`, "NaN", "true"} {
		bodies = append(bodies, cvssRecord(id, `{"cvssMetricV31":[`+cvssMetric("3.1", "nvd@nist.gov", "Primary", score)+`]}`))
	}
	for _, change := range [][2]string{
		{`"baseScore":9.8`, `"exploitabilityScore":9.8`},
		{`"version":"3.1"`, `"version":"5.0"`},
		{`"type":"Primary"`, `"type":"Unspecified"`},
		{`"source":"nvd@nist.gov"`, `"source":""`},
		{`"source":"nvd@nist.gov"`, `"source":" nvd@nist.gov"`},
		{`"source":"nvd@nist.gov"`, `"source":"nvd\u0000@nist.gov"`},
		{`"source":"nvd@nist.gov"`, `"source":"` + strings.Repeat("x", 257) + `"`},
	} {
		bodies = append(bodies, strings.Replace(valid, change[0], change[1], 1))
	}
	for i, body := range bodies {
		if got := nvdCVSS(id, body); got != nil {
			t.Errorf("case %d accepted unsupported score: %+v", i, got)
		}
	}
	if nvdCVSS("not-a-cve", valid) != nil {
		t.Fatal("accepted a non-CVE record")
	}
	for _, score := range []float64{math.Inf(1), math.Inf(-1), math.NaN()} {
		if validCVSS(&CVSS{Score: score, Version: "3.1", Source: "nvd@nist.gov"}) {
			t.Fatal("accepted nonfinite score")
		}
	}
}

func TestCVSSPersistsFullBodyWithoutChangingSignedProtocol(t *testing.T) {
	h, cfg, public := fixtureHub(t)
	cfg.Sources[0].Type = "nvd"
	h.config = cfg
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	id := "CVE-2026-12345"
	body := fmt.Sprintf(`{"id":%q,"description":%q,"metrics":{"cvssMetricV31":[%s]}}`, id, strings.Repeat("long description ", 400), cvssMetric("3.1", "nvd@nist.gov", "Primary", "9.8"))
	item := intel.Item{ID: id, Title: id, Body: body, PublishedAt: now, Trust: "official"}
	pollFixture(t, h, []intel.Item{item}, "upstream-checkpoint")
	if json.Valid([]byte(h.state.Notices[0].Notice.Summary)) {
		t.Fatal("test requires truncated stored summary")
	}
	recent, err := h.Recent(100)
	if err != nil || len(recent.Notices) != 1 || recent.Notices[0].CVSS == nil || recent.Notices[0].CVSS.Score != 9.8 {
		t.Fatalf("lost full-body score: %+v, %v", recent, err)
	}
	recent.Notices[0].CVSS.Score = 1
	if h.state.Notices[0].CVSS.Score != 9.8 {
		t.Fatal("board response aliases durable score")
	}
	envelope, batch := getEnvelope(t, h.Handler(), "/api/v1/notices")
	if !ed25519.Verify(public, envelope.Payload, envelope.Signature) {
		t.Fatal("signature invalid")
	}
	expectedNotice := publicNotice(item, "fixture", now)
	expectedNotice.Seq = 1
	expectedBatch := Batch{Version: 1, Kind: "notices", Oldest: 1, Latest: 1, NextCursor: 1, ServerTime: now, Notices: []Notice{expectedNotice}}
	expectedBytes, err := json.Marshal(expectedBatch)
	if err != nil || !bytes.Equal(envelope.Payload, expectedBytes) {
		t.Fatalf("display metadata changed signed wire payload: %v", err)
	}
	if batch.NextCursor != 1 || h.state.Sources["fixture"].Published != 1 {
		t.Fatal("wrong initial cursor/publication count")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return now }
	if score := reopened.state.Notices[0].CVSS; score == nil || score.Score != 9.8 {
		t.Fatalf("score lost at restart: %+v", score)
	}
	// An older checkpoint had no CVSS and cannot be seeded from this truncated
	// summary. Its next identical overlap should add metadata, not a new notice.
	reopened.state.Notices[0].CVSS = nil
	now = now.Add(time.Second)
	pollFixture(t, reopened, []intel.Item{item}, "upstream-checkpoint-2")
	if reopened.state.Sequence != 1 || reopened.state.Sources["fixture"].Published != 1 || reopened.state.Notices[0].CVSS == nil {
		t.Fatal("overlap failed to populate metadata without republishing")
	}
	if reopened.state.Sources["fixture"].Cursor != "upstream-checkpoint-2" {
		t.Fatal("overlap lost upstream cursor")
	}
	now = now.Add(-time.Second)
	after, _ := getEnvelope(t, reopened.Handler(), "/api/v1/notices")
	if !bytes.Equal(after.Payload, envelope.Payload) || !bytes.Equal(after.Signature, envelope.Signature) {
		t.Fatal("metadata-only overlap changed signed history")
	}
}

func TestLegacyCVSSSeedsOnlyCompleteNVDRecords(t *testing.T) {
	h, cfg, _ := fixtureHub(t)
	ids := []string{"CVE-2026-11111", "CVE-2026-22222", "CVE-2026-33333"}
	var items []intel.Item
	for i, id := range ids {
		body := cvssRecord(id, `{"cvssMetricV31":[`+cvssMetric("3.1", "nvd@nist.gov", "Primary", "7.5")+`]}`)
		if i == 1 {
			body = body[:len(body)-1]
		}
		items = append(items, intel.Item{ID: id, Title: id, Body: body})
	}
	// Feed initially has RSS semantics; no CVSS should be inferred even from
	// exact JSON pasted into another source's content.
	pollFixture(t, h, items, "old-cursor")
	for _, entry := range h.state.Notices {
		if entry.CVSS != nil {
			t.Fatal("non-NVD source supplied a score")
		}
	}
	h.state.Notices[2].Notice.Source = "other"
	if err := writeState(cfg.StateDir, &h.state); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Sources[0].Type = "nvd"
	cfg.Sources = append(cfg.Sources, SourceConfig{Name: "other", Type: "rss", URL: "https://example.invalid/feed", IntervalSeconds: 60})
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.state.Notices[0].CVSS == nil || reopened.state.Notices[1].CVSS != nil || reopened.state.Notices[2].CVSS != nil {
		t.Fatalf("wrong legacy metadata migration: %+v", reopened.state.Notices)
	}
	if reopened.state.Sequence != 3 || reopened.state.Sources["fixture"].Cursor != "old-cursor" {
		t.Fatal("legacy metadata migration changed delivery position")
	}
	recent, err := reopened.Recent(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, notice := range recent.Notices {
		raw, err := json.Marshal(notice)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		if _, exists := fields["cvss"]; exists != (notice.ID == ids[0]) {
			t.Fatalf("absent score was not omitted: %s", raw)
		}
	}
}

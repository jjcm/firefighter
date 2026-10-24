package broadcast

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/intel"
)

func nvdFixture(id, status string, modified time.Time) intel.Item {
	body := fmt.Sprintf(`{"id":%q,"vulnStatus":%q,"lastModified":%q}`, id, status, modified.Format(time.RFC3339Nano))
	return intel.Item{ID: id, Title: id + ": Advisory", Body: body, CVEs: []string{id}, PublishedAt: modified, ModifiedAt: modified}
}

func pollNamedFixture(t *testing.T, h *Hub, name string, items ...intel.Item) {
	t.Helper()
	err := h.PollOnce(context.Background(), ScheduledSource{Name: name, Every: time.Nanosecond, Source: fixtureSource(func(context.Context, string) (intel.Result, error) {
		return intel.Result{Items: items, Cursor: fmt.Sprint(h.state.Sequence)}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecentBoardUsesOfficialRetractionsWithoutChangingSignedHistory(t *testing.T) {
	h, cfg, public := fixtureHub(t)
	now := time.Now().UTC()
	h.now = func() time.Time { return now }
	h.config.Sources = append(h.config.Sources, SourceConfig{Name: "nvd-official", Type: "nvd", IntervalSeconds: 60})
	cfg.Sources = h.config.Sources
	const rejected, active = "CVE-2026-11111", "CVE-2026-22222"
	pollNamedFixture(t, h, "nvd-official", nvdFixture(rejected, "Analyzed", now.Add(-time.Hour)), nvdFixture(active, "Received", now))
	pollNamedFixture(t, h, "fixture", intel.Item{ID: "vendor", Title: "Combined advisory", CVEs: []string{rejected, active}})
	now = now.Add(time.Second)
	pollNamedFixture(t, h, "nvd-official", nvdFixture(rejected, "Rejected", now))
	now = now.Add(time.Second)
	// An overlapping old version must not reverse the newer official rejection.
	pollNamedFixture(t, h, "nvd-official", nvdFixture(rejected, "Modified", now.Add(-time.Minute)))
	// A non-NVD feed cannot revoke a CVE by embedding an NVD-shaped JSON object.
	pollNamedFixture(t, h, "fixture", nvdFixture(active, "Rejected", now))
	recent, err := h.Recent(100)
	if err != nil || len(recent.Notices) != 2 {
		t.Fatalf("unexpected board after rejection: %+v, %v", recent, err)
	}
	for _, notice := range recent.Notices {
		for _, cve := range notice.CVEs {
			if cve == rejected {
				t.Fatalf("rejected CVE remains visible: %+v", notice)
			}
		}
	}
	_, before := getEnvelope(t, h.Handler(), "/api/v1/notices?after=0&limit=100")
	if len(before.Notices) != 6 || before.Notices[3].ID != rejected || !strings.Contains(before.Notices[3].Summary, `"Rejected"`) {
		t.Fatalf("client history lost retraction evidence: %+v", before)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = h.now
	envelope, after := getEnvelope(t, reopened.Handler(), "/api/v1/notices?after=0&limit=100")
	b, _ := json.Marshal(before)
	a, _ := json.Marshal(after)
	if string(b) != string(a) || !ed25519.Verify(public, envelope.Payload, envelope.Signature) {
		t.Fatal("lifecycle metadata changed signed delivery after restart")
	}
	recent, err = reopened.Recent(100)
	if err != nil || len(recent.Notices) != 2 {
		t.Fatalf("rejection lost after restart: %+v, %v", recent, err)
	}
}

func TestRetractionSurvivesRetentionAndNewerOfficialReinstatement(t *testing.T) {
	h, _, _ := fixtureHub(t)
	h.config.Sources = append(h.config.Sources, SourceConfig{Name: "nvd", Type: "nvd", IntervalSeconds: 60})
	h.config.MaxNotices = 1
	now := time.Now().UTC()
	h.now = func() time.Time { return now }
	const id = "CVE-2026-33333"
	pollNamedFixture(t, h, "nvd", nvdFixture(id, "Rejected", now))
	now = now.Add(8 * 24 * time.Hour)
	pollNamedFixture(t, h, "fixture", intel.Item{ID: "late-vendor", Title: id + ": A late reference", CVEs: []string{id}})
	recent, err := h.Recent(100)
	if err != nil || len(recent.Notices) != 0 || !h.state.CVEStatuses[id].Withdrawn || len(h.state.Notices) != 1 {
		t.Fatalf("retention forgot the rejection: %+v, %v", recent, err)
	}
	now = now.Add(time.Second)
	pollNamedFixture(t, h, "nvd", nvdFixture(id, "Analyzed", now))
	recent, err = h.Recent(100)
	if err != nil || len(recent.Notices) != 1 || h.state.CVEStatuses[id].Withdrawn {
		t.Fatalf("new official reinstatement failed: %+v, %v", recent, err)
	}
}

func TestHistoricRetractionEntryStaysHiddenAfterReinstatement(t *testing.T) {
	h, _, _ := fixtureHub(t)
	h.config.Sources[0].Type = "nvd"
	now := time.Now().UTC()
	h.now = func() time.Time { return now }
	const id = "CVE-2026-33334"
	rejected := nvdFixture(id, "Rejected", now)
	// Lifecycle extraction uses the full upstream record before public truncation.
	rejected.Body = `{"padding":"` + strings.Repeat("a", 5000) + `",` + strings.TrimPrefix(rejected.Body, "{")
	pollNamedFixture(t, h, "fixture", rejected)
	now = now.Add(time.Second)
	pollNamedFixture(t, h, "fixture", nvdFixture(id, "Analyzed", now))
	recent, err := h.Recent(100)
	if err != nil || len(recent.Notices) != 1 || recent.Notices[0].Seq != 2 {
		t.Fatalf("historic retraction resurfaced: %+v, %v", recent, err)
	}
	if len(h.state.Notices[0].Notice.Summary) != 4096 || !h.state.Notices[0].Withdrawn {
		t.Fatal("full-record lifecycle was lost during public summary truncation")
	}
}

func TestLegacyCheckpointSeedsRejectionsWithoutRewritingHistory(t *testing.T) {
	h, cfg, _ := fixtureHub(t)
	h.config.Sources[0].Type = "nvd"
	cfg.Sources = h.config.Sources
	now := time.Now().UTC()
	const rejected, replacement = "CVE-2026-44444", "CVE-2026-55555"
	item := nvdFixture(rejected, "Rejected", now)
	item.Title = rejected + ": Rejected reason: duplicate of " + replacement
	item.Body = strings.Repeat("x", 5000) // Simulate pre-metadata truncated JSON.
	item.ModifiedAt = time.Time{}
	pollNamedFixture(t, h, "fixture", item, nvdFixture(replacement, "Analyzed", now))
	// Write an old-format checkpoint with neither the registry nor entry flag.
	h.state.CVEStatuses = nil
	for i := range h.state.Notices {
		h.state.Notices[i].Withdrawn = false
	}
	if err := writeState(cfg.StateDir, &h.state); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.StateDir, "hubstate.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recent, err := reopened.Recent(100)
	if err != nil || len(recent.Notices) != 1 || recent.Notices[0].ID != replacement {
		t.Fatalf("legacy rejection was not recognized or duplicate target was rejected: %+v, %v", recent, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("opening an old checkpoint rewrote stored history")
	}
}

func TestNVDLifecycleRequiresStatusOrExplicitRejectionPrefix(t *testing.T) {
	now := time.Now().UTC()
	const id = "CVE-2026-66666"
	for _, tc := range []struct {
		name, status, title string
		known, withdrawn    bool
	}{
		{"ordinary rejection language", "Analyzed", "Rejected requests bypass authentication", true, false},
		{"rejection mentioned later", "", "This vulnerability affects systems with rejected requests", false, false},
		{"unknown status", "Unrecognized", "Regular advisory", false, false},
		{"legacy reason", "", "Rejected reason: assigned by mistake", true, true},
		{"legacy marker", "", "** REJECT ** DO NOT USE THIS CANDIDATE", true, true},
		{"withdrawn", "Withdrawn", "Advisory", true, true},
		{"revoked", "Revoked", "Advisory", true, true},
		{"deferred is active", "Deferred", "Advisory", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := nvdFixture(id, tc.status, now)
			status, ok := nvdLifecycle(id, id+": "+tc.title, item.Body, now)
			if ok != tc.known || status.Withdrawn != tc.withdrawn {
				t.Fatalf("status=%+v, known=%v", status, ok)
			}
		})
	}
}

func TestLifecycleRegistryRespectsCheckpointRetentionBudget(t *testing.T) {
	now := time.Now().UTC()
	state := diskState{Version: 1, Sources: map[string]sourceState{}, CVEStatuses: map[string]cveLifecycle{
		"CVE-2026-99999": {Withdrawn: true, ModifiedAt: now},
	}}
	for i := 1; i <= 20; i++ {
		id := fmt.Sprintf("CVE-2026-%05d", i)
		state.CVEStatuses[id] = cveLifecycle{ModifiedAt: now}
		state.Sequence++
		state.Notices = append(state.Notices, storedNotice{Notice: Notice{Seq: state.Sequence, CVEs: []string{id}, Summary: strings.Repeat("a", 300), Untrusted: true}, Hash: "fingerprint"})
	}
	b, err := boundedState(&state, 5000)
	if err != nil || len(b)+1 > 5000 || !state.CVEStatuses["CVE-2026-99999"].Withdrawn {
		t.Fatalf("checkpoint budget discarded retraction metadata: bytes=%d, err=%v", len(b), err)
	}
	if len(state.CVEStatuses) != len(state.Notices)+1 {
		t.Fatal("checkpoint retained active lifecycle metadata without a retained notice")
	}
}

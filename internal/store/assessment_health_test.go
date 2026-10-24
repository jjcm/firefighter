package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

func TestHealthReplayUsesCheckpointOrderNotTimestamps(t *testing.T) {
	for _, skew := range []time.Duration{0, -time.Hour} {
		t.Run(fmt.Sprintf("clock-skew-%s", skew), func(t *testing.T) {
			dir := t.TempDir()
			s, state, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			base := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
			first := protocol.Event{ID: "initial-error", Type: "assessment_health_error", Time: base, Details: map[string]any{"failure_count": 3}}
			if err := s.Append("report_queued", "", first); err != nil {
				t.Fatal(err)
			}
			state.AssessmentHealth = AssessmentHealth{ConsecutiveFailures: 8, EpisodeFailures: 8, LastReportedFailures: 3, LastReportedAt: base, LastFailureAt: base, UpdatedAt: base}
			if err := s.Save(state); err != nil {
				t.Fatal(err)
			}
			checkpoint := *state.AuditCheckpoint
			if checkpoint == "" {
				t.Fatal("state omitted its nonempty audit boundary")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			statePath := filepath.Join(dir, "state.json")
			old := time.Unix(1, 0)
			if err := os.Chtimes(statePath, old, old); err != nil {
				t.Fatal(err)
			}
			s, state, err = Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if state.AssessmentHealth.ConsecutiveFailures != 8 || state.AssessmentHealth.EpisodeFailures != 8 {
				t.Fatal("historical error overwrote newer saved progress")
			}
			// This append follows the checkpoint even when its timestamp is
			// identical to, or earlier than, the checkpointed event and state.
			second := protocol.Event{ID: "new-error", Type: "assessment_health_error", Time: base.Add(skew), Details: map[string]any{"failure_count": 13}}
			if err := s.Append("report_queued", "", second); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			future := base.AddDate(100, 0, 0)
			if err := os.Chtimes(statePath, future, future); err != nil {
				t.Fatal(err)
			}
			s, state, err = Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			if state.AssessmentHealth.EpisodeFailures != 13 || state.AssessmentHealth.LastReportedFailures != 13 || !state.AssessmentHealth.ReportQueued || len(state.Outbox) != 2 {
				t.Fatal("clock/file timestamp hid an error appended after the checkpoint")
			}
			state.AssessmentHealth.ConsecutiveSuccesses = 2
			if err := s.Save(state); err != nil {
				t.Fatal(err)
			}
			recovery := protocol.Event{ID: "recovered", Type: "assessment_health_recovered", Time: base.Add(2 * skew), Details: map[string]any{"failure_count": 13}}
			if err := s.Append("report_queued", "", recovery); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(statePath, future, future); err != nil {
				t.Fatal(err)
			}
			s, state, err = Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if state.AssessmentHealth.EpisodeFailures != 0 || state.AssessmentHealth.ReportQueued || !state.AssessmentHealth.LastReportedAt.Equal(recovery.Time) || len(state.Outbox) != 3 {
				t.Fatal("clock/file timestamp hid recovery appended after the checkpoint")
			}
		})
	}
}

func TestEmptyAuditCheckpointReplaysFirstHealthAlert(t *testing.T) {
	dir := t.TempDir()
	s, state, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state.AssessmentHealth.ConsecutiveFailures = 2
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	if state.AuditCheckpoint == nil || *state.AuditCheckpoint != "" {
		t.Fatal("empty journal checkpoint cannot be distinguished from legacy state")
	}
	if err := s.Append("report_queued", "", protocol.Event{ID: "first-error", Type: "assessment_health_error", Time: time.Unix(1, 0), Details: map[string]any{"failure_count": 3}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, state, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if state.AssessmentHealth.LastReportedFailures != 3 || !state.AssessmentHealth.ReportQueued {
		t.Fatal("first appended alert was lost across checkpoint crash window")
	}
}

func TestStateRejectsAuditCheckpointMissingFromJournal(t *testing.T) {
	dir := t.TempDir()
	s, state, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append("fixture", "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "audit.jsonl"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if opened, _, err := Open(dir); err == nil {
		opened.Close()
		t.Fatal("state accepted a checkpoint whose journal records were missing")
	} else if !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("wrong validation error: %v", err)
	}
}

func TestHealthLocalRecoveryAfterCheckpointClosesEpisode(t *testing.T) {
	dir := t.TempDir()
	s, state, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	if err := s.Append("report_queued", "", protocol.Event{ID: "error", Type: "assessment_health_error", Time: base, Details: map[string]any{"failure_count": 3}}); err != nil {
		t.Fatal(err)
	}
	state.AssessmentHealth = AssessmentHealth{EpisodeFailures: 3, ConsecutiveSuccesses: 2, LastReportedFailures: 3, LastReportedAt: base, LastFailureAt: base, ReportQueued: true, UpdatedAt: base}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	// Reporting was disabled or filtered after the error. Recovery still
	// closes the episode, even if only its local audit append survived.
	recoveredAt := base.Add(-time.Hour)
	if err := s.Append("event", "", protocol.Event{ID: "local-recovery", Type: "assessment_health_recovered", Time: recoveredAt, Details: map[string]any{"failure_count": 3}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, state, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if state.AssessmentHealth.EpisodeFailures != 0 || state.AssessmentHealth.LastReportedFailures != 0 || state.AssessmentHealth.ReportQueued || !state.AssessmentHealth.LastReportedAt.Equal(recoveredAt) {
		t.Fatal("local recovery crash retained old reminder state instead of new-episode cooldown")
	}
	if len(state.Outbox) != 1 || state.Outbox[0].Event.Type != "assessment_health_error" {
		t.Fatal("local recovery was incorrectly queued externally during replay")
	}
}

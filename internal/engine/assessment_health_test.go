package engine

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/report"
	"github.com/jjcm/firefighter/internal/store"
)

func healthFixture(t *testing.T) (*Engine, *store.Incident, string) {
	t.Helper()
	e, dir, _ := fixtureEngine(t)
	in := addIncident(e, "deferred")
	in.ApplicabilityStatus = "unknown"
	in.UpdatedAt = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	// Exercise the production direct filter, which must admit aggregate health
	// events even though all the underlying advisory investigations are quiet.
	sender, err := report.NewSender(report.Options{Type: "grokbot", URL: "https://example.invalid/routine", BearerToken: strings.Repeat("a", 32)})
	if err != nil {
		t.Fatal(err)
	}
	e.Reporter = sender
	return e, in, dir
}

func observeHealth(t *testing.T, e *Engine, in *store.Incident, status string, cause error) {
	t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.observeAssessmentHealthLocked(in, status, cause); err != nil {
		t.Fatal(err)
	}
	if err := e.Store.Save(e.State); err != nil {
		t.Fatal(err)
	}
}

func TestAssessmentHealthAggregatesAndBoundsRepeatedFailures(t *testing.T) {
	e, in, dir := healthFixture(t)
	cause := errors.New("private-provider-error-and-advisory-content")
	for i := 0; i < 2; i++ {
		observeHealth(t, e, in, "deferred", cause)
	}
	if len(e.State.Outbox) != 0 {
		t.Fatal("isolated applicability failures generated monitoring noise")
	}
	observeHealth(t, e, in, "deferred", cause)
	if len(e.State.Outbox) != 1 {
		t.Fatalf("threshold should report one aggregate failure, got %d", len(e.State.Outbox))
	}
	first := e.State.Outbox[0].Event
	if first.Type != "assessment_health_error" || first.IncidentID != "" || first.Details["failure_count"] != 3 || first.Details["health_scope"] != "advisory_applicability" {
		t.Fatalf("wrong aggregate event: %+v", first)
	}
	for _, key := range []string{"advisory_id", "advisory_title", "cves", "error", "evidence", "applicability_status"} {
		if _, exists := first.Details[key]; exists {
			t.Fatalf("aggregate health event leaked per-notice details: %s", key)
		}
	}
	in.UpdatedAt = in.UpdatedAt.Add(time.Minute)
	for i := 0; i < 10; i++ {
		observeHealth(t, e, in, "deferred", cause)
	}
	if len(e.State.Outbox) != 1 {
		t.Fatal("rapid failures bypassed reminder cooldown")
	}
	in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthReminderInterval)
	observeHealth(t, e, in, "deferred", cause)
	if len(e.State.Outbox) != 2 || e.State.Outbox[1].Event.Details["failure_count"] != 14 {
		t.Fatal("bounded reminder did not include the aggregate failure count")
	}
	in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthReminderInterval)
	observeHealth(t, e, in, "deferred", cause)
	if len(e.State.Outbox) != 2 {
		t.Fatal("elapsed time alone bypassed additional-failure threshold")
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(audit), cause.Error()) || strings.Contains(string(audit), in.Item.ID) {
		t.Fatal("aggregate report exported raw cause or advisory identity")
	}
}

func TestAssessmentHealthRecoveryAndNonFailures(t *testing.T) {
	for _, resolved := range []string{"affected", "not_affected"} {
		t.Run(resolved, func(t *testing.T) {
			e, in, _ := healthFixture(t)
			observeHealth(t, e, in, "deferred", errors.New("planner failed"))
			observeHealth(t, e, in, "deferred", errors.New("planner failed"))
			ignored := *in
			ignored.Item.Source = "local-host"
			observeHealth(t, e, &ignored, "deferred", errors.New("host audit failed"))
			observeHealth(t, e, in, "deferred", &assessmentInterrupted{reason: "daemon_stopping", cause: context.Canceled})
			observeHealth(t, e, in, "observed", nil)
			if e.State.AssessmentHealth.ConsecutiveFailures != 2 || len(e.State.Outbox) != 0 {
				t.Fatal("host audit, requested stop, or observation mode counted as applicability failure")
			}
			in.ApplicabilityStatus = resolved
			observeHealth(t, e, in, "completed", nil)
			if e.State.AssessmentHealth != (store.AssessmentHealth{}) || len(e.State.Outbox) != 0 {
				t.Fatal("unreported failure streak did not reset quietly")
			}
			in.ApplicabilityStatus = "unknown"
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "deferred", errors.New("planner failed"))
			}
			in.ApplicabilityStatus = resolved
			observeHealth(t, e, in, "completed", nil)
			if e.State.AssessmentHealth != (store.AssessmentHealth{}) || len(e.State.Outbox) != 2 {
				t.Fatal("reported health outage did not reset with a single recovery")
			}
			recovery := e.State.Outbox[1].Event
			if recovery.Type != "assessment_health_recovered" || recovery.IncidentID != "" || recovery.Details["failure_count"] != 3 {
				t.Fatalf("bad recovery event: %+v", recovery)
			}
			observeHealth(t, e, in, "completed", nil)
			if len(e.State.Outbox) != 2 {
				t.Fatal("healthy assessments repeatedly emitted recovery")
			}
		})
	}
}

func TestAssessmentHealthSurvivesRestart(t *testing.T) {
	e, in, dir := healthFixture(t)
	for i := 0; i < 2; i++ {
		observeHealth(t, e, in, "deferred", errors.New("planner failed"))
	}
	if err := e.Store.Close(); err != nil {
		t.Fatal(err)
	}
	disk, state, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	e.Store, e.State = disk, state
	in = state.Incidents[in.ID]
	observeHealth(t, e, in, "deferred", errors.New("planner failed again"))
	if len(e.State.Outbox) != 1 || e.State.AssessmentHealth.ConsecutiveFailures != 3 || e.State.AssessmentHealth.LastReportedFailures != 3 {
		t.Fatal("restart discarded the threshold progress")
	}
	if err := e.Store.Close(); err != nil {
		t.Fatal(err)
	}
	disk, state, err = store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	e.Store, e.State = disk, state
	in = state.Incidents[in.ID]
	observeHealth(t, e, in, "deferred", errors.New("planner still failed"))
	if len(e.State.Outbox) != 1 || e.State.AssessmentHealth.ConsecutiveFailures != 4 {
		t.Fatal("restart re-alerted before reminder threshold")
	}
	in.ApplicabilityStatus = "not_affected"
	observeHealth(t, e, in, "completed", nil)
	if len(e.State.Outbox) != 2 || e.State.Outbox[1].Event.Type != "assessment_health_recovered" {
		t.Fatal("restart lost the recovery obligation")
	}
	encoded, err := json.Marshal(e.State.Outbox)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "planner still failed") {
		t.Fatal("restart exposed raw cause in queued events")
	}
}

func TestAssessmentHealthThroughAdvisoryProcessing(t *testing.T) {
	e, in, dir := healthFixture(t)
	calls := 0
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		calls++
		if calls <= 3 {
			return protocol.Decision{}, errors.New("fixture provider unavailable")
		}
		return protocol.Decision{Summary: "Observed local evidence excludes the affected product", Assessment: "not_affected", Done: true, Applicability: notAffectedFixtureApplicability()}, nil
	})
	for attempt := 1; attempt <= 4; attempt++ {
		in.NextAttempt = time.Time{}
		if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
			t.Fatalf("attempt %d did not finish: worked=%v err=%v", attempt, worked, err)
		}
		want := 0
		if attempt >= 3 {
			want = attempt - 2
		}
		if len(e.State.Outbox) != want {
			t.Fatalf("attempt %d queued %d reports, want %d aggregate reports", attempt, len(e.State.Outbox), want)
		}
		if in.ReportedActivity {
			t.Fatal("global health report marked the unrelated advisory as reported")
		}
	}
	if e.State.Outbox[0].Event.Type != "assessment_health_error" || e.State.Outbox[1].Event.Type != "assessment_health_recovered" {
		t.Fatalf("processing failed to emit aggregate outage/recovery: %+v", e.State.Outbox)
	}
	if in.Status != "completed" || in.ApplicabilityStatus != "not_affected" || e.State.AssessmentHealth != (store.AssessmentHealth{}) {
		t.Fatal("resolved advisory did not finish and reset operational health")
	}
	if calls := e.Runner.(*fakeRunner).called(); len(calls) != 0 {
		t.Fatalf("unknown or irrelevant advisory executed commands: %+v", calls)
	}
	if readState(t, dir).AssessmentHealth != (store.AssessmentHealth{}) {
		t.Fatal("finish did not checkpoint the recovery")
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	completed := 0
	for _, line := range strings.Split(strings.TrimSpace(string(audit)), "\n") {
		var record store.Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.Type != "event" && record.Type != "report_queued" {
			continue
		}
		var event protocol.Event
		if err := json.Unmarshal(record.Data, &event); err != nil {
			t.Fatal(err)
		}
		if event.Type == "assessment_finished" {
			completed++
			if record.Type != "event" {
				t.Fatal("individual unconfirmed/irrelevant assessment reached external reporting")
			}
		}
	}
	if completed != 4 {
		t.Fatalf("local audit lost quiet assessments: got %d", completed)
	}
}

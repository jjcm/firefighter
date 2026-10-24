package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	in.UpdatedAt = time.Now().UTC()
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

func healthEpisodeCleared(health store.AssessmentHealth) bool {
	return health.ConsecutiveFailures == 0 && health.EpisodeFailures == 0 && health.ConsecutiveSuccesses == 0 && health.LastReportedFailures == 0 && !health.ReportQueued && health.LastFailureAt.IsZero()
}

func reopenHealth(t *testing.T, e *Engine, in *store.Incident, dir string) *store.Incident {
	t.Helper()
	if err := e.Store.Close(); err != nil {
		t.Fatal(err)
	}
	disk, state, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disk.Close() })
	e.Store, e.State = disk, state
	return state.Incidents[in.ID]
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
			in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
			for i := 0; i < assessmentHealthRecoverySuccesses; i++ {
				observeHealth(t, e, in, "completed", nil)
			}
			if !healthEpisodeCleared(e.State.AssessmentHealth) || len(e.State.Outbox) != 0 {
				t.Fatal("unreported failure streak did not reset quietly")
			}
			in.ApplicabilityStatus = "unknown"
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "deferred", errors.New("planner failed"))
			}
			in.ApplicabilityStatus = resolved
			in.UpdatedAt = in.UpdatedAt.Add(time.Minute)
			for i := 0; i < assessmentHealthRecoverySuccesses; i++ {
				observeHealth(t, e, in, "completed", nil)
			}
			if len(e.State.Outbox) != 1 {
				t.Fatal("three rapid successes ended an unstable episode")
			}
			in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
			observeHealth(t, e, in, "completed", nil)
			if !healthEpisodeCleared(e.State.AssessmentHealth) || len(e.State.Outbox) != 2 {
				t.Fatal("reported health outage did not reset with a single recovery")
			}
			recovery := e.State.Outbox[1].Event
			if recovery.Type != "assessment_health_recovered" || recovery.IncidentID != "" || recovery.Details["failure_count"] != 3 || recovery.Details["resolved_count"] != 4 || recovery.Details["failure_count_scope"] != "health_episode" {
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
	in = reopenHealth(t, e, in, dir)
	observeHealth(t, e, in, "deferred", errors.New("planner failed again"))
	if len(e.State.Outbox) != 1 || e.State.AssessmentHealth.ConsecutiveFailures != 3 || e.State.AssessmentHealth.LastReportedFailures != 3 {
		t.Fatal("restart discarded the threshold progress")
	}
	in = reopenHealth(t, e, in, dir)
	observeHealth(t, e, in, "deferred", errors.New("planner still failed"))
	if len(e.State.Outbox) != 1 || e.State.AssessmentHealth.ConsecutiveFailures != 4 {
		t.Fatal("restart re-alerted before reminder threshold")
	}
	in.ApplicabilityStatus = "not_affected"
	in.UpdatedAt = in.UpdatedAt.Add(time.Minute)
	observeHealth(t, e, in, "completed", nil)
	observeHealth(t, e, in, "completed", nil)
	lastFailure := e.State.AssessmentHealth.LastFailureAt
	in = reopenHealth(t, e, in, dir)
	if e.State.AssessmentHealth.ConsecutiveSuccesses != 2 || !e.State.AssessmentHealth.LastFailureAt.Equal(lastFailure) {
		t.Fatal("restart lost partial recovery progress or last failure time")
	}
	in.UpdatedAt = lastFailure.Add(assessmentHealthRecoveryInterval)
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
	in = reopenHealth(t, e, in, dir)
	if !healthEpisodeCleared(e.State.AssessmentHealth) || e.State.AssessmentHealth.LastReportedAt.IsZero() {
		t.Fatal("restart lost the cross-episode notification cooldown")
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
		if calls == 5 {
			return protocol.Decision{Summary: "Attempt complete, but applicability remains unknown", Assessment: "unknown", Done: true, Applicability: &protocol.Applicability{Status: "unknown"}}, nil
		}
		return protocol.Decision{Summary: "Observed local evidence excludes the affected product", Assessment: "not_affected", Done: true, Applicability: notAffectedFixtureApplicability()}, nil
	})
	for attempt := 1; attempt <= 8; attempt++ {
		if attempt > 4 {
			in = scheduledIncident(e, fmt.Sprintf("resolved-%d", attempt), "pending", time.Now().UTC())
		}
		if attempt == 6 {
			e.State.AssessmentHealth.LastFailureAt = time.Now().UTC().Add(-assessmentHealthRecoveryInterval - time.Second)
		}
		in.NextAttempt = time.Time{}
		if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
			t.Fatalf("attempt %d did not finish: worked=%v err=%v", attempt, worked, err)
		}
		want := 0
		if attempt >= 3 {
			want = 1
		}
		if attempt == 8 {
			want = 2
		}
		if len(e.State.Outbox) != want {
			t.Fatalf("attempt %d queued %d reports, want %d aggregate reports", attempt, len(e.State.Outbox), want)
		}
		if in.ReportedActivity {
			t.Fatal("global health report marked the unrelated advisory as reported")
		}
		if attempt == 5 && (in.Status != "completed" || in.ApplicabilityStatus != "unknown" || e.State.AssessmentHealth.ConsecutiveSuccesses != 0 || e.State.AssessmentHealth.EpisodeFailures != 4) {
			t.Fatal("completed unknown assessment did not break recovery and count as unresolved")
		}
		if attempt == 7 && e.State.AssessmentHealth.ConsecutiveSuccesses != 2 {
			t.Fatal("completed unknown was incorrectly included in the successful recovery sequence")
		}
	}
	if e.State.Outbox[0].Event.Type != "assessment_health_error" || e.State.Outbox[1].Event.Type != "assessment_health_recovered" {
		t.Fatalf("processing failed to emit aggregate outage/recovery: %+v", e.State.Outbox)
	}
	if e.State.Outbox[1].Event.Details["failure_count"] != 4 {
		t.Fatal("recovery omitted the completed unknown outcome from episode failures")
	}
	if in.Status != "completed" || in.ApplicabilityStatus != "not_affected" || !healthEpisodeCleared(e.State.AssessmentHealth) {
		t.Fatal("resolved advisory did not finish and reset operational health")
	}
	if calls := e.Runner.(*fakeRunner).called(); len(calls) != 0 {
		t.Fatalf("unknown or irrelevant advisory executed commands: %+v", calls)
	}
	if !healthEpisodeCleared(readState(t, dir).AssessmentHealth) {
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
	if completed != 8 {
		t.Fatalf("local audit lost quiet assessments: got %d", completed)
	}
}

func TestAssessmentHealthRecoveryRequiresStreakAndQuietWindow(t *testing.T) {
	e, in, _ := healthFixture(t)
	for i := 0; i < 3; i++ {
		observeHealth(t, e, in, "deferred", errors.New("unresolved"))
	}
	in.ApplicabilityStatus = "affected"
	in.UpdatedAt = in.UpdatedAt.Add(time.Minute)
	observeHealth(t, e, in, "completed", nil)
	ignored := *in
	ignored.Item.Source = "local-host"
	observeHealth(t, e, &ignored, "completed", nil)
	ignored = *in
	ignored.ApplicabilityStatus = "unknown"
	observeHealth(t, e, in, "observed", nil)
	observeHealth(t, e, &ignored, "deferred", &assessmentInterrupted{reason: "daemon_stopping", cause: context.Canceled})
	if e.State.AssessmentHealth.ConsecutiveSuccesses != 1 || len(e.State.Outbox) != 1 {
		t.Fatal("non-resolution events advanced recovery")
	}
	in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
	observeHealth(t, e, in, "completed", nil)
	if e.State.AssessmentHealth.ConsecutiveSuccesses != 2 || len(e.State.Outbox) != 1 {
		t.Fatal("elapsed quiet time bypassed the three-success requirement")
	}
	in.ApplicabilityStatus = "unknown"
	observeHealth(t, e, in, "deferred", errors.New("unresolved again"))
	if e.State.AssessmentHealth.ConsecutiveSuccesses != 0 || e.State.AssessmentHealth.EpisodeFailures != 4 {
		t.Fatal("failure did not reset the recovery streak or retain episode failures")
	}
	in.ApplicabilityStatus = "not_affected"
	for i := 0; i < 3; i++ {
		observeHealth(t, e, in, "completed", nil)
	}
	if len(e.State.Outbox) != 1 {
		t.Fatal("old quiet window survived a new failure")
	}
	in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
	observeHealth(t, e, in, "completed", nil)
	if len(e.State.Outbox) != 2 || e.State.Outbox[1].Event.Details["failure_count"] != 4 {
		t.Fatal("stable recovery lost aggregate episode failures")
	}
}

func TestAssessmentHealthCompletedUnknownCountsAsUnresolved(t *testing.T) {
	e, in, _ := healthFixture(t)
	for i := 0; i < 3; i++ {
		observeHealth(t, e, in, "completed", nil)
	}
	if len(e.State.Outbox) != 1 || e.State.AssessmentHealth.EpisodeFailures != 3 {
		t.Fatal("completed unknown assessments did not raise aggregate operational failure")
	}
	in.ApplicabilityStatus = "not_affected"
	in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
	observeHealth(t, e, in, "completed", nil)
	observeHealth(t, e, in, "completed", nil)
	in.ApplicabilityStatus = "unknown"
	in.UpdatedAt = in.UpdatedAt.Add(time.Second)
	observeHealth(t, e, in, "completed", nil)
	if e.State.AssessmentHealth.ConsecutiveSuccesses != 0 || e.State.AssessmentHealth.EpisodeFailures != 4 || !e.State.AssessmentHealth.LastFailureAt.Equal(in.UpdatedAt) {
		t.Fatal("completed unknown did not reset the recovery streak and quiet window")
	}
	in.ApplicabilityStatus = "affected"
	for i := 0; i < 3; i++ {
		observeHealth(t, e, in, "completed", nil)
	}
	if len(e.State.Outbox) != 1 {
		t.Fatal("recovery reused quiet time from before completed unknown outcome")
	}
}

func TestAssessmentHealthFirstAlertRequiresConsecutiveFailures(t *testing.T) {
	e, in, _ := healthFixture(t)
	for i := 0; i < 2; i++ {
		observeHealth(t, e, in, "deferred", errors.New("unresolved"))
	}
	in.ApplicabilityStatus = "not_affected"
	observeHealth(t, e, in, "completed", nil)
	in.ApplicabilityStatus = "unknown"
	for i := 0; i < 2; i++ {
		observeHealth(t, e, in, "deferred", errors.New("unresolved"))
	}
	if len(e.State.Outbox) != 0 {
		t.Fatal("intermittent failures bypassed first-alert consecutive threshold")
	}
	observeHealth(t, e, in, "deferred", errors.New("unresolved"))
	if len(e.State.Outbox) != 1 || e.State.Outbox[0].Event.Details["failure_count"] != 5 || e.State.AssessmentHealth.ConsecutiveFailures != 3 {
		t.Fatal("first alert confused episode total and consecutive failures")
	}
}

func TestAssessmentHealthCooldownSurvivesRecoveryAndRestart(t *testing.T) {
	for _, resolveQuietEpisode := range []bool{false, true} {
		t.Run(fmt.Sprintf("quiet-recovery-%v", resolveQuietEpisode), func(t *testing.T) {
			e, in, dir := healthFixture(t)
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "deferred", errors.New("unresolved"))
			}
			in.ApplicabilityStatus = "not_affected"
			in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "completed", nil)
			}
			recoveredAt := e.State.AssessmentHealth.LastReportedAt
			if !recoveredAt.Equal(in.UpdatedAt) || len(e.State.Outbox) != 2 {
				t.Fatal("recovery failed to retain its notification timestamp")
			}
			in.ApplicabilityStatus = "unknown"
			in.UpdatedAt = recoveredAt.Add(time.Minute)
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "deferred", errors.New("new episode"))
			}
			if len(e.State.Outbox) != 2 || e.State.AssessmentHealth.LastReportedFailures != 0 {
				t.Fatal("new episode bypassed recovery cooldown")
			}
			in = reopenHealth(t, e, in, dir)
			if !e.State.AssessmentHealth.LastReportedAt.Equal(recoveredAt) {
				t.Fatal("restart lost cooldown")
			}
			if resolveQuietEpisode {
				in.ApplicabilityStatus = "not_affected"
				in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
				for i := 0; i < 3; i++ {
					observeHealth(t, e, in, "completed", nil)
				}
				if len(e.State.Outbox) != 2 || !healthEpisodeCleared(e.State.AssessmentHealth) {
					t.Fatal("never-reported episode emitted a recovery")
				}
			} else {
				in.UpdatedAt = recoveredAt.Add(assessmentHealthRecoveryInterval)
				observeHealth(t, e, in, "deferred", errors.New("still unresolved"))
				if len(e.State.Outbox) != 3 || e.State.Outbox[2].Event.Details["failure_count"] != 4 {
					t.Fatal("new episode waited for reminder threshold after cooldown elapsed")
				}
			}
		})
	}
}

func TestAssessmentHealthMigratesLegacyStateConservatively(t *testing.T) {
	e, in, dir := healthFixture(t)
	for i := 0; i < 3; i++ {
		observeHealth(t, e, in, "deferred", errors.New("unresolved"))
	}
	// Model an old deployment's checkpoint after five more unreported failures.
	e.State.AssessmentHealth = store.AssessmentHealth{ConsecutiveFailures: 8, LastReportedFailures: 3, LastReportedAt: in.UpdatedAt}
	if err := e.Store.Save(e.State); err != nil {
		t.Fatal(err)
	}
	in = reopenHealth(t, e, in, dir)
	if e.State.AssessmentHealth.ConsecutiveFailures != 8 {
		t.Fatal("historical report replay overwrote the legacy checkpoint")
	}
	in.UpdatedAt = in.UpdatedAt.Add(time.Hour)
	in.ApplicabilityStatus = "not_affected"
	for i := 0; i < 3; i++ {
		observeHealth(t, e, in, "completed", nil)
	}
	if len(e.State.Outbox) != 1 || e.State.AssessmentHealth.EpisodeFailures != 8 || !e.State.AssessmentHealth.LastFailureAt.Equal(in.UpdatedAt) {
		t.Fatal("legacy state skipped conservative recovery window or lost failures")
	}
	in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
	observeHealth(t, e, in, "completed", nil)
	if len(e.State.Outbox) != 2 || e.State.Outbox[1].Event.Details["failure_count"] != 8 {
		t.Fatal("legacy episode did not recover after stable evidence")
	}
}

func TestAssessmentHealthRecoversNotificationCrashWindows(t *testing.T) {
	e, in, dir := healthFixture(t)
	for i := 0; i < 2; i++ {
		observeHealth(t, e, in, "deferred", errors.New("unresolved"))
	}
	e.mu.Lock()
	err := e.observeAssessmentHealthLocked(in, "deferred", errors.New("unresolved"))
	e.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// The alert append survives, but its state checkpoint does not.
	in = reopenHealth(t, e, in, dir)
	if len(e.State.Outbox) != 1 || e.State.AssessmentHealth.LastReportedFailures != 3 || e.State.AssessmentHealth.EpisodeFailures != 3 {
		t.Fatal("crash lost durable alert marker")
	}
	in.UpdatedAt = e.State.AssessmentHealth.LastFailureAt.Add(time.Minute)
	observeHealth(t, e, in, "deferred", errors.New("unresolved"))
	if len(e.State.Outbox) != 1 {
		t.Fatal("crash caused duplicate health alert")
	}
	in.ApplicabilityStatus = "not_affected"
	in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
	observeHealth(t, e, in, "completed", nil)
	observeHealth(t, e, in, "completed", nil)
	e.mu.Lock()
	err = e.observeAssessmentHealthLocked(in, "completed", nil)
	e.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// The recovery append survives, but its episode reset does not.
	in = reopenHealth(t, e, in, dir)
	if len(e.State.Outbox) != 2 || !healthEpisodeCleared(e.State.AssessmentHealth) || e.State.AssessmentHealth.LastReportedAt.IsZero() {
		t.Fatal("crash lost durable recovery/cooldown marker")
	}
	observeHealth(t, e, in, "completed", nil)
	if len(e.State.Outbox) != 2 {
		t.Fatal("crash caused duplicate recovery")
	}
	in.ApplicabilityStatus = "unknown"
	in.UpdatedAt = e.State.AssessmentHealth.LastReportedAt.Add(time.Minute)
	for i := 0; i < 3; i++ {
		observeHealth(t, e, in, "deferred", errors.New("unresolved"))
	}
	if len(e.State.Outbox) != 2 {
		t.Fatal("recovery crash discarded cross-episode cooldown")
	}
}

func TestAssessmentHealthDoesNotRecoverAnUnreportedError(t *testing.T) {
	for _, filtered := range []bool{false, true} {
		t.Run(fmt.Sprintf("filtered-%v", filtered), func(t *testing.T) {
			e, in, dir := healthFixture(t)
			reporter := e.Reporter
			e.Reporter = nil
			if filtered {
				e.Reporter = notificationSender{filter: func(protocol.Event) bool { return false }}
			}
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "deferred", errors.New("unresolved"))
			}
			if len(e.State.Outbox) != 0 || e.State.AssessmentHealth.ReportQueued || e.State.AssessmentHealth.LastReportedFailures != 3 {
				t.Fatal("local-only health event was treated as externally queued")
			}
			// Local auditing still has a reminder cooldown, even with no channel.
			observeHealth(t, e, in, "deferred", errors.New("unresolved"))
			if e.State.AssessmentHealth.LastReportedFailures != 3 {
				t.Fatal("no channel bypassed local health cooldown")
			}
			in = reopenHealth(t, e, in, dir)
			if e.State.AssessmentHealth.ReportQueued {
				t.Fatal("restart invented an external report obligation")
			}
			e.Reporter = reporter
			in.ApplicabilityStatus = "not_affected"
			in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "completed", nil)
			}
			if len(e.State.Outbox) != 0 || !healthEpisodeCleared(e.State.AssessmentHealth) {
				t.Fatal("newly enabled channel received recovery without an original health alert")
			}
		})
	}
}

func TestAssessmentHealthLegacyReportObligationMatchesActiveEpisode(t *testing.T) {
	for _, localRecovery := range []bool{false, true} {
		t.Run(fmt.Sprintf("local-recovery-%v", localRecovery), func(t *testing.T) {
			e, in, dir := healthFixture(t)
			reporter := e.Reporter
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "deferred", errors.New("unresolved"))
			}
			// A later reminder is local-only, but the first externally queued
			// error in this same episode still requires an eventual closure.
			e.Reporter = nil
			in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthReminderInterval)
			for i := 0; i < 10; i++ {
				observeHealth(t, e, in, "deferred", errors.New("unresolved"))
			}
			e.State.AssessmentHealth.ReportQueued = false // Legacy checkpoint has no marker.
			if err := e.Store.Save(e.State); err != nil {
				t.Fatal(err)
			}
			in = reopenHealth(t, e, in, dir)
			if !e.State.AssessmentHealth.ReportQueued {
				t.Fatal("legacy migration lost earlier queued alert in the active episode")
			}
			if !localRecovery {
				e.Reporter = reporter
			}
			in.ApplicabilityStatus = "not_affected"
			in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "completed", nil)
			}
			before := len(e.State.Outbox)
			// A new episode is wholly local. Neither a queued nor a local
			// recovery boundary may let the old episode's alert contaminate it.
			e.Reporter = nil
			in.ApplicabilityStatus = "unknown"
			in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "deferred", errors.New("new local episode"))
			}
			in = reopenHealth(t, e, in, dir)
			if e.State.AssessmentHealth.ReportQueued {
				t.Fatal("previous episode's report became the new local episode's obligation")
			}
			e.Reporter = reporter
			in.ApplicabilityStatus = "not_affected"
			in.UpdatedAt = in.UpdatedAt.Add(assessmentHealthRecoveryInterval)
			for i := 0; i < 3; i++ {
				observeHealth(t, e, in, "completed", nil)
			}
			if len(e.State.Outbox) != before {
				t.Fatal("closed prior episode caused an unrelated recovery notification")
			}
		})
	}
}

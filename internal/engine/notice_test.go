package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

func nonNoticeDecision() protocol.Decision {
	return protocol.Decision{Summary: "Conference promotion is not a vulnerability notice", Assessment: "not_a_notice", Done: true, Applicability: &protocol.Applicability{Status: "unknown"}, Evidence: []string{"The supplied text promotes a conference and contains no vulnerability or exploitation claim."}}
}

func TestNonNoticesRetireQuietlyWithoutChangingHealthAcrossRestart(t *testing.T) {
	e, in, dir := healthFixture(t)
	for i := 0; i < 3; i++ {
		observeHealth(t, e, in, "deferred", errors.New("real unresolved advisory"))
	}
	// Preserve an in-progress recovery as well as the open failure episode.
	e.State.AssessmentHealth.ConsecutiveSuccesses = 2
	baseline := e.State.AssessmentHealth
	priorReports := len(e.State.Outbox)
	in.NextAttempt = time.Now().Add(time.Hour)
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) { return nonNoticeDecision(), nil })
	for i := 0; i < 4; i++ {
		item := scheduledIncident(e, fmt.Sprintf("chatter-%d", i), "pending", time.Now().UTC())
		item.Item.Source = "x"
		item.Item.Body = "Join our conference."
		if _, err := e.ProcessOne(context.Background()); err != nil {
			t.Fatal(err)
		}
		if item.Status != "completed" || !item.NextAttempt.IsZero() || item.ApplicabilityStatus != "unknown" || item.LastError != "" {
			t.Fatalf("non-notice remained retryable or claimed host safety: %+v", item)
		}
	}
	if e.State.AssessmentHealth != baseline || len(e.State.Outbox) != priorReports {
		t.Fatal("non-notices changed failure/recovery state or queued reports")
	}
	if worked, err := e.ProcessOne(context.Background()); err != nil || worked {
		t.Fatalf("terminal non-notice retried: worked=%v err=%v", worked, err)
	}
	in = reopenHealth(t, e, in, dir)
	if e.State.AssessmentHealth != baseline || len(e.State.Outbox) != priorReports {
		t.Fatal("restart/replay changed non-notice health neutrality")
	}
	for i := 0; i < 4; i++ {
		item := e.State.Incidents[fmt.Sprintf("chatter-%d", i)]
		if item.Status != "completed" || !item.NextAttempt.IsZero() || item.History[0].Decision.Assessment != "not_a_notice" {
			t.Fatal("non-notice disposition was not durable")
		}
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil || !strings.Contains(string(audit), `"assessment":"not_a_notice"`) {
		t.Fatalf("non-notice lacks local audit: %v", err)
	}
	// An older disposition must never hide a later provider failure.
	in.History = []protocol.Turn{{Decision: nonNoticeDecision()}}
	observeHealth(t, e, in, "deferred", errors.New("provider failure"))
	if e.State.AssessmentHealth.EpisodeFailures != baseline.EpisodeFailures+1 {
		t.Fatal("prior non-notice hid a later failure")
	}
}

func TestCVELessSocialClaimsRemainUnknownHealthFailures(t *testing.T) {
	e, first, _ := healthFixture(t)
	first.NextAttempt = time.Now().Add(time.Hour)
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		return protocol.Decision{Summary: "Possible zero-day claim lacks sufficient detail", Assessment: "unknown", Done: true, Applicability: &protocol.Applicability{Status: "unknown"}}, nil
	})
	for i := 0; i < 3; i++ {
		in := scheduledIncident(e, fmt.Sprintf("zero-day-%d", i), "pending", time.Now().UTC())
		in.Item.Source = "x"
		in.Item.Body = "An actively exploited zero-day is alleged; the reference is inaccessible."
		if _, err := e.ProcessOne(context.Background()); err != nil {
			t.Fatal(err)
		}
		if in.NextAttempt.IsZero() || in.ApplicabilityStatus != "unknown" {
			t.Fatal("missing CVE/social source incorrectly retired a substantive claim")
		}
	}
	if e.State.AssessmentHealth.EpisodeFailures != 3 || len(e.State.Outbox) != 1 || e.State.Outbox[0].Event.Type != "assessment_health_error" {
		t.Fatal("unknown zero-day claims no longer raise aggregate health alerts")
	}
}

func TestNonNoticeHealthExemptionRequiresSuccessfulCurrentCompletion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
		cause  error
	}{
		{"error", "completed", errors.New("assessment failed")},
		{"deferred", "deferred", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, in, _ := healthFixture(t)
			d := nonNoticeDecision()
			e.mu.Lock()
			err := e.observeAssessmentHealthLocked(in, tc.status, tc.cause, &d)
			e.mu.Unlock()
			if err != nil || e.State.AssessmentHealth.EpisodeFailures != 1 {
				t.Fatalf("non-notice label hid unfinished or failed assessment: health=%+v err=%v", e.State.AssessmentHealth, err)
			}
		})
	}
}

func TestNonNoticeCannotHideActionsOrReplaceHostReview(t *testing.T) {
	for _, hostReview := range []bool{false, true} {
		t.Run(fmt.Sprint(hostReview), func(t *testing.T) {
			e, _, runner := fixtureEngine(t)
			in := addIncident(e, "pending")
			if hostReview {
				in.Item.Source = "local-host"
			}
			e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
				d := nonNoticeDecision()
				if !hostReview {
					d.Actions = []protocol.Action{{ID: "hidden-change", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true}}
				}
				return d, nil
			})
			if _, err := e.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			if in.Status != "deferred" || in.NextAttempt.IsZero() || len(runner.called()) != 0 {
				t.Fatalf("invalid non-notice accepted: %+v", in)
			}
		})
	}
}

func TestNonNoticeStillClosesPriorReportableActivity(t *testing.T) {
	for _, priorMutation := range []bool{false, true} {
		t.Run(fmt.Sprint(priorMutation), func(t *testing.T) {
			e, _, _ := fixtureEngine(t)
			in := addIncident(e, "pending")
			if priorMutation {
				in.History = []protocol.Turn{{Decision: protocol.Decision{Actions: []protocol.Action{{ID: "prior-change", Mutates: true}}}, Results: []protocol.ActionResult{{ActionID: "prior-change"}}}}
			} else {
				in.ReportedActivity = true
			}
			e.Reporter = &notificationLegacySender{}
			e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) { return nonNoticeDecision(), nil })
			if _, err := e.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			var outcomes []string
			for _, delivery := range e.State.Outbox {
				if delivery.Event.Type == "assessment_finished" {
					outcomes = append(outcomes, delivery.Event.Details["assessment"].(string))
				}
			}
			if !reflect.DeepEqual(outcomes, []string{"not_a_notice"}) {
				t.Fatalf("prior activity closure was hidden: %v", outcomes)
			}
		})
	}
}

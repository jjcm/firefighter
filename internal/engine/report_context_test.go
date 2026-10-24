package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/report"
)

func TestFailedObservationCheckOnAffectedHostReplansAndReportsClosure(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	in.Item.CVEs = []string{"CVE-2026-12345"}
	e.RunID, e.Version = "run-fixture", "build-fixture"
	// Use the real channel filter, without making any network requests.
	sender, err := report.NewSender(report.Options{Type: "grokbot", URL: "https://example.test/routine", BearerToken: strings.Repeat("a", 32)})
	if err != nil {
		t.Fatal(err)
	}
	e.Reporter = sender
	runner.exitCode["presence-verify"] = 1
	round := 0
	e.Planner = plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
		round++
		if round == 1 {
			return protocol.Decision{Summary: "Inspect affected product", Assessment: "unknown", Applicability: affectedFixtureApplicability(), Actions: []protocol.Action{
				{ID: "presence", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/false"}, Reason: "Inspect deployment directories"},
				{ID: "must-replan", Kind: "command", Argv: []string{"/bin/true"}, Reason: "Dependent check"},
			}}, nil
		}
		if len(request.History) != 1 || len(request.History[0].Results) != 2 || request.History[0].Results[1].ExitCode != 1 {
			t.Fatalf("failed check not supplied for interpretation: %+v", request.History)
		}
		return protocol.Decision{Summary: "Product absent in independently established coverage; missing directory explained", Assessment: "not_affected", Applicability: notAffectedFixtureApplicability(), Done: true}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := runner.called(); len(got) != 2 || got[1] != "presence-verify" {
		t.Fatalf("failed check did not stop dependent batch: %v", got)
	}
	var failure, closure bool
	for _, delivery := range e.State.Outbox {
		v := delivery.Event
		if v.Details["advisory_id"] != in.Item.ID || v.Details["attempt"] != 1 || v.Details["run_id"] != e.RunID || v.Details["version"] != e.Version || v.Details["assessment_scope"] != "advisory" {
			t.Fatalf("missing incident correlation: %+v", v)
		}
		cves, ok := v.Details["cves"].([]string)
		if !ok || len(cves) != 1 || cves[0] != in.Item.CVEs[0] {
			t.Fatalf("missing CVE identity: %+v", v)
		}
		if v.Type == "action_finished" {
			failure = true
			if v.Details["parent_mutates"] != false || v.Details["check_outcome"] != "failed" || v.Details["verified"] != false || v.Details["verification_scope"] != "action_check" {
				t.Fatalf("check misrepresented as remediation: %+v", v)
			}
			if _, ok := v.Details["duration_ms"].(int64); !ok {
				t.Fatal("check lacks duration")
			}
		}
		if v.Type == "assessment_finished" {
			closure = true
			if v.Details["assessment"] != "not_affected" || v.Details["had_reported_activity"] != true || v.Details["remediation_verified"] != false || v.Details["changed_this_attempt"] != false {
				t.Fatalf("wrong closure semantics: %+v", v)
			}
		}
	}
	if !failure || !closure || !in.ReportedActivity {
		t.Fatalf("reported failure lacks closure: failure=%v closure=%v retained=%v", failure, closure, in.ReportedActivity)
	}
}

func TestRetryReportsChangesFromThisAttemptSeparately(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	in := addIncident(e, "pending")
	e.Reporter = &notificationLegacySender{}
	round := 0
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		round++
		if round == 1 {
			return protocol.Decision{Summary: "Contain exposure", Assessment: "exposed", Applicability: affectedFixtureApplicability(), Actions: []protocol.Action{{ID: "contain", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Reason: "Contain exposure", Mutates: true}}}, nil
		}
		return protocol.Decision{Summary: "Residual exposure remains", Assessment: "exposed", Applicability: affectedFixtureApplicability(), Done: true}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	in.NextAttempt = time.Now().Add(-time.Second)
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	finished := 0
	for _, delivery := range e.State.Outbox {
		v := delivery.Event
		if v.Type != "assessment_finished" {
			continue
		}
		finished++
		if v.Details["attempt"] != finished || v.Details["changed"] != true || v.Details["changed_scope"] != "retained_incident_history" || v.Details["changed_this_attempt"] != (finished == 1) {
			t.Fatalf("retry confuses earlier changes with current attempt: %+v", v)
		}
		if v.Details["remediation_verified"] != false {
			t.Fatal("residual exposure claimed remediated")
		}
	}
	if finished != 2 {
		t.Fatalf("got %d completions", finished)
	}
}

func TestPlannerDeferralGetsRecoveryClosureWithoutActions(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	in := addIncident(e, "pending")
	// The recovery closes an incident already visible in the monitoring channel.
	in.ReportedActivity = true

	sender, err := report.NewSender(report.Options{Type: "grokbot", URL: "https://example.test/routine", BearerToken: strings.Repeat("b", 32)})
	if err != nil {
		t.Fatal(err)
	}
	e.Reporter = sender
	first := true
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		if first {
			first = false
			return protocol.Decision{}, errors.New("provider unavailable")
		}
		return protocol.Decision{Summary: "Previous evidence rules out this advisory", Assessment: "not_affected", Applicability: notAffectedFixtureApplicability(), Done: true}, nil
	})
	for i := 0; i < 2; i++ {
		in.NextAttempt = time.Now().Add(-time.Second)
		if _, err := e.ProcessOne(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(e.State.Outbox) != 2 || e.State.Outbox[0].Event.Details["status"] != "deferred" || e.State.Outbox[1].Event.Details["status"] != "completed" {
		t.Fatalf("reported planner error has no recovery completion: %+v", e.State.Outbox)
	}
}

func TestRollbackAfterObservationCountsAsChangeAttempt(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	e.Reporter = &notificationLegacySender{}
	runner.exitCode["probe-verify"] = 1
	round := 0
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		round++
		if round == 1 {
			return protocol.Decision{Summary: "Check affected deployment", Assessment: "unknown", Applicability: affectedFixtureApplicability(), Actions: []protocol.Action{{ID: "probe", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/false"}, Rollback: []string{"/bin/true"}, Reason: "Check deployment"}}}, nil
		}
		return protocol.Decision{Summary: "Replan after recovery", Assessment: "unknown", Done: true}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	v := e.State.Outbox[len(e.State.Outbox)-1].Event
	if v.Type != "assessment_finished" || v.Details["changed"] != true || v.Details["changed_this_attempt"] != true {
		t.Fatalf("rollback on incident %s was omitted from changes: %+v", in.ID, v)
	}
}

func TestCurrentAttemptChangeSurvivesHistoryCompaction(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	in := addIncident(e, "pending")
	e.Reporter = &notificationLegacySender{}
	e.Config.MaxRounds = 20
	round := 0
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		round++
		if round == 19 {
			return protocol.Decision{Summary: "Assessment complete with residual exposure", Assessment: "exposed", Applicability: affectedFixtureApplicability(), Done: true}, nil
		}
		action := protocol.Action{ID: "inspect", Kind: "command", Argv: []string{"/bin/true"}, Reason: "Inspect state"}
		if round == 1 {
			action.ID, action.Mutates, action.Verify = "patch", true, []string{"/bin/true"}
		}
		return protocol.Decision{Summary: "Work through evidence", Assessment: "exposed", Applicability: affectedFixtureApplicability(), Actions: []protocol.Action{action}}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	v := e.State.Outbox[len(e.State.Outbox)-1].Event
	if len(in.History) != 16 || !in.AttemptChanged || v.Details["changed_this_attempt"] != true {
		t.Fatalf("compaction hid an executed change: history=%d event=%+v", len(in.History), v)
	}
}

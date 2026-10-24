package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jjcm/firefighter/internal/protocol"
)

func noticeClaim(status string) *protocol.Applicability {
	return &protocol.Applicability{Status: status, Product: "fixture plugin", Condition: "locally observed fixture version satisfies the advisory condition", Evidence: []string{"local application manifest and runtime inspection"}}
}

func TestAbsentWordPressNoticeExecutesNothingAndStaysQuiet(t *testing.T) {
	e, dir, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	in.Item.Title, in.Item.CVEs = "WordPress plugin vulnerability", []string{"CVE-2026-12345"}
	// Even senders without a filter must never receive irrelevant notices.
	e.Reporter = &notificationLegacySender{}
	e.Planner = plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
		if !request.ApplicabilityRequired {
			t.Fatal("incoming advisory was treated as a general host review")
		}
		d := protocol.Decision{Summary: "No WordPress deployment in current inventory and recent scoped deployment checks", Assessment: "not_affected", Actions: []protocol.Action{{ID: "unrelated-ssh-hardening", Kind: "command", Argv: []string{"/bin/false"}, Verify: []string{"/bin/false"}, Mutates: true, Reason: "Unrelated hardening"}}, MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("unexecuted-change", "A proposed change supposedly succeeded")}}
		d.Applicability = &protocol.Applicability{Status: "not_affected", Product: "WordPress", Condition: "No WordPress deployment in checked deployment paths/runtimes", Evidence: []string{"current inventory plus recent complete scoped WordPress deployment checks"}}
		return d, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.called()) != 0 || len(e.State.Outbox) != 0 || in.Status != "completed" || in.ApplicabilityStatus != "not_affected" || !in.NextAttempt.IsZero() {
		t.Fatalf("irrelevant notice was acted on, reported, or left retrying: calls=%v outbox=%+v incident=%+v", runner.called(), e.State.Outbox, in)
	}
	if len(e.State.Memory.Notes) != 0 {
		t.Fatal("notes from suppressed work were promoted into memory")
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil || !strings.Contains(string(audit), "assessment_finished") || !strings.Contains(string(audit), "applicability_gate") || strings.Contains(string(audit), "action_intent") {
		t.Fatalf("quiet decision lacks local evidence or wrote executable intent: %v", err)
	}
}

func TestUnprovenMutationReplansBeforeAnyExecution(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	e.Reporter = &notificationLegacySender{}
	round := 0
	e.Planner = plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
		round++
		if round == 3 {
			return protocol.Decision{Summary: "Verified local fix", Assessment: "remediated", Done: true, Applicability: noticeClaim("affected")}, nil
		}
		d := protocol.Decision{Summary: "Patch applicable product", Assessment: "exposed", Actions: []protocol.Action{{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "Patch observed vulnerable deployment"}}}
		if round == 2 {
			if len(runner.called()) != 0 || len(request.RecoveryNotes) == 0 || len(request.History) != 1 || len(request.History[0].Decision.Actions) != 0 {
				t.Fatal("unproven work executed or was replayable before evidence")
			}
			d.Applicability = noticeClaim("affected")
		}
		return d, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if round != 3 || in.Status != "completed" || len(runner.called()) != 2 {
		t.Fatalf("confirmed fix did not proceed autonomously: round=%d calls=%v status=%s", round, runner.called(), in.Status)
	}
	for _, delivery := range e.State.Outbox {
		if delivery.Event.Details["applicability_status"] != "affected" {
			t.Fatalf("triage escaped to monitoring: %+v", delivery.Event)
		}
	}
}

func TestUnsupportedOrContradictoryAbsenceCannotRetireNotice(t *testing.T) {
	for _, test := range []struct {
		name       string
		assessment string
		claim      *protocol.Applicability
	}{
		{"legacy_absence", "not_affected", nil},
		{"unresolved_absence", "not_affected", &protocol.Applicability{Status: "unknown"}},
		{"affected_but_absent", "not_affected", noticeClaim("affected")},
		{"absent_but_exposed", "exposed", noticeClaim("not_affected")},
	} {
		t.Run(test.name, func(t *testing.T) {
			e, _, runner := fixtureEngine(t)
			in := addIncident(e, "pending")
			e.Config.MaxRounds = 1
			e.Reporter = &notificationLegacySender{}
			e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
				return protocol.Decision{Summary: "Unsupported conclusion", Assessment: test.assessment, Applicability: test.claim, Done: true, MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("unsupported-absence", "Product supposedly absent")}}, nil
			})
			if _, err := e.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(runner.called()) != 0 || in.Status != "deferred" || in.NextAttempt.IsZero() || in.ApplicabilityStatus != "unknown" || len(e.State.Outbox) != 0 || len(e.State.Memory.Notes) != 0 {
				t.Fatalf("unsupported absence was treated as resolved: %+v", in)
			}
		})
	}
}

func TestUncertainProbeCannotExecuteVerificationOrRollbackOrNotify(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	e.Reporter = &notificationLegacySender{}
	runner.exitCode["inspect-deployment"] = 1
	round := 0
	e.Planner = plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
		round++
		if round == 1 {
			return protocol.Decision{Summary: "Check one deployment gap", Assessment: "unknown", Applicability: &protocol.Applicability{Status: "unknown"}, Actions: []protocol.Action{{ID: "inspect-deployment", Kind: "command", Argv: []string{"/bin/false"}, Verify: []string{"/bin/false"}, Rollback: []string{"/bin/false"}, Reason: "Observe deployment path"}}}, nil
		}
		if len(request.History) != 1 || len(request.History[0].Results) != 1 || request.History[0].Results[0].ExitCode != 1 {
			t.Fatal("probe error was hidden from the next decision")
		}
		return protocol.Decision{Summary: "Missing optional path explained; independent scoped evidence rules product out", Assessment: "not_affected", Done: true, Applicability: noticeClaim("not_affected")}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls := runner.called(); len(calls) != 1 || calls[0] != "inspect-deployment" {
		t.Fatalf("unconfirmed probe executed a follow-up command: %v", calls)
	}
	if in.Status != "completed" || len(e.State.Outbox) != 0 || in.ReportedActivity {
		t.Fatalf("unaffected notice produced monitoring noise: %+v", e.State.Outbox)
	}
}

func TestPriorAffectedStatusDoesNotAuthorizeNewAttempt(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	in.ApplicabilityStatus = "affected"
	e.Config.MaxRounds = 1
	e.Reporter = &notificationLegacySender{}
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		return protocol.Decision{Summary: "Patch without current evidence", Assessment: "exposed", Actions: []protocol.Action{{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "Patch"}}}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.called()) != 0 || in.Status != "deferred" || len(e.State.Outbox) != 0 || in.ApplicabilityStatus != "unknown" {
		t.Fatalf("stale approval or an exposure label bypassed local evidence: %+v", in)
	}
}

func TestEmptyAffectedClaimCannotAuthorizeMutation(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	e.Reporter = &notificationLegacySender{}
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		return protocol.Decision{Summary: "Bare claim", Assessment: "exposed", Applicability: &protocol.Applicability{Status: "affected"}, Actions: []protocol.Action{{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "Patch"}}}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.called()) != 0 || in.Status != "deferred" || len(e.State.Outbox) != 0 {
		t.Fatal("an affected label without evidence authorized work")
	}
}

func TestUnprovenMixedBatchDoesNotExecuteDependentObservations(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	addIncident(e, "pending")
	e.Config.MaxRounds = 1
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		return protocol.Decision{Summary: "Inspect then make an unconfirmed change", Assessment: "unknown", Actions: []protocol.Action{
			{ID: "inspect", Kind: "command", Argv: []string{"/bin/true"}, Reason: "Inspect"},
			{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Reason: "Unproven patch", Mutates: true},
			{ID: "dependent", Kind: "command", Argv: []string{"/bin/true"}, Reason: "Depends on previous change"},
		}}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.called()) != 0 {
		t.Fatalf("executed fragments of a rejected batch: %v", runner.called())
	}
}

func TestPeriodicHostReviewRetainsAutonomousRemediation(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	in.Item.Source = "local-host"
	e.Reporter = &notificationLegacySender{}
	round := 0
	e.Planner = plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
		if request.ApplicabilityRequired {
			t.Fatal("general host review required notice-specific applicability")
		}
		round++
		if round == 1 {
			return protocol.Decision{Summary: "Repair observed host issue", Assessment: "exposed", Actions: []protocol.Action{{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "Repair host issue"}}}, nil
		}
		return protocol.Decision{Summary: "Fix observed and verified", Assessment: "remediated", Done: true}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.called()) != 2 || in.Status != "completed" || len(e.State.Outbox) == 0 {
		t.Fatal("periodic host review lost its autonomous response/reporting")
	}
}

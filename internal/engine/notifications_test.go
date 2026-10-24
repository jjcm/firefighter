package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/store"
)

type notificationSender struct {
	send   func(context.Context, protocol.Event) error
	filter func(protocol.Event) bool
}

func (s notificationSender) Send(ctx context.Context, e protocol.Event) error { return s.send(ctx, e) }
func (s notificationSender) ShouldSend(e protocol.Event) bool                 { return s.filter == nil || s.filter(e) }

type notificationRunner struct {
	before func(protocol.Action)
	exit   map[string]int
}

func (r notificationRunner) Validate(a protocol.Action) error { return nil }
func (r notificationRunner) Run(_ context.Context, a protocol.Action) protocol.ActionResult {
	if r.before != nil {
		r.before(a)
	}
	return protocol.ActionResult{ActionID: a.ID, ExitCode: r.exit[a.ID]}
}

func TestNotificationsPersistIntentAndVerificationOutcomes(t *testing.T) {
	for _, failVerify := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "rolled-back"}[failVerify], func(t *testing.T) {
			e, dir, _ := fixtureEngine(t)
			in := addIncident(e, "pending")
			in.Item.Source = "local-host"
			e.Reporter = notificationSender{send: func(context.Context, protocol.Event) error { return nil }}
			calls := 0
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				calls++
				if calls == 1 {
					return protocol.Decision{Summary: "Apply update", Assessment: "exposed", Actions: []protocol.Action{{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Reason: "Patch affected service", Mutates: true, Verify: []string{"/bin/true"}, Rollback: []string{"/bin/true"}}}}, nil
				}
				if failVerify {
					return protocol.Decision{Summary: "Verification failed; reverted", Assessment: "exposed", Done: false, FollowUp: "Investigate failed service check"}, nil
				}
				return protocol.Decision{Summary: "Fix verified", Assessment: "remediated", Done: true}, nil
			})
			exit := map[string]int{}
			if failVerify {
				exit["patch-verify"] = 1
			}
			e.Runner = notificationRunner{exit: exit, before: func(a protocol.Action) {
				persisted := readState(t, dir)
				found := false
				for _, d := range persisted.Outbox {
					if d.Event.Type == "action_started" && d.Event.Details["action_id"] == a.ID {
						found = true
					}
				}
				if !found {
					t.Error("command started without its notification checkpoint")
				}
			}}
			if _, err := e.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			var start, finish, verification, rollback bool
			for _, d := range e.State.Outbox {
				v := d.Event
				if v.Type == "assessment_started" {
					start = v.Details["source"] == "local-host"
				}
				if v.Type == "action_started" || v.Type == "action_finished" {
					switch v.Details["phase"] {
					case "action":
						if v.Details["mutates_source"] != "planner_declaration" || v.Details["parent_action_id"] != nil || v.Details["mutates"] != true {
							t.Errorf("ordinary action misrepresented: %+v", v)
						}
					case "verification":
						if v.Details["mutates_source"] != "expected_read_only_verification" || v.Details["parent_action_id"] != "patch" || v.Details["mutates"] != false {
							t.Errorf("verification lacks intended behavior or parent: %+v", v)
						}
						if v.Summary != "Check the outcome of action patch" || strings.Contains(v.Summary, "Patch affected service") {
							t.Errorf("verification describes the original mutation: %s", v.Summary)
						}
					case "rollback":
						if v.Details["mutates_source"] != "rollback_contract" || v.Details["parent_action_id"] != "patch" || v.Details["parent_mutates"] != true || v.Details["mutates"] != true {
							t.Errorf("rollback lacks intended behavior or parent: %+v", v)
						}
						if v.Summary != "Run recovery for action patch" || strings.Contains(v.Summary, "Patch affected service") {
							t.Errorf("rollback repeats the forward change as its recovery description: %s", v.Summary)
						}
					}
					if v.Type == "action_started" {
						if _, ok := v.Details["exit_code"]; ok {
							t.Error("start event acquired the later outcome through shared details")
						}
					}
				}
				if v.Type == "action_finished" && v.Details["phase"] == "verification" {
					verification = true
					if v.Details["verified"] == failVerify {
						t.Error("incorrect verification outcome")
					}
				}
				if v.Type == "action_finished" && v.Details["phase"] == "rollback" {
					rollback = true
				}
				if v.Type == "assessment_finished" {
					finish = true
					if v.Details["changed"] != true || v.Details["source"] != "local-host" || v.Details["verified"] == failVerify {
						t.Errorf("incorrect final report: %+v", v)
					}
				}
				for _, key := range []string{"argv", "output", "environment", "command"} {
					if _, ok := v.Details[key]; ok {
						t.Errorf("raw execution data leaked to report: %s", key)
					}
				}
			}
			if !start || !finish || !verification || rollback != failVerify {
				t.Fatalf("missing notifications: start=%v finish=%v verify=%v rollback=%v", start, finish, verification, rollback)
			}
		})
	}
}

func TestNotificationFilteringKeepsLocalAuditWithoutQueueingNoise(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	e.Reporter = notificationSender{filter: func(e protocol.Event) bool { return e.Type != "assessment_started" }, send: func(context.Context, protocol.Event) error { return nil }}
	if err := e.emit("assessment_started", "quiet", "Unrelated disclosure", nil); err != nil {
		t.Fatal(err)
	}
	if len(e.State.Outbox) != 0 {
		t.Fatal("filtered event entered delivery queue")
	}
	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "Unrelated disclosure") || strings.Contains(string(data), "report_queued") {
		t.Fatal("filtered event did not remain local")
	}
}

type notificationRateLimit struct{}

func (notificationRateLimit) Error() string             { return "rate limited" }
func (notificationRateLimit) RetryAfter() time.Duration { return 5 * time.Minute }

func TestNotificationFailurePausesDestinationAcrossRestartWithoutBlockingWork(t *testing.T) {
	for _, failure := range []error{errors.New("network unavailable"), notificationRateLimit{}} {
		t.Run(failure.Error(), func(t *testing.T) {
			e, dir, _ := fixtureEngine(t)
			sent := 0
			e.Reporter = notificationSender{send: func(context.Context, protocol.Event) error { sent++; return failure }}
			for i := 0; i < 3; i++ {
				if err := e.emit("started", "", "Test", nil); err != nil {
					t.Fatal(err)
				}
			}
			if err := e.FlushReports(context.Background()); err != nil {
				t.Fatal(err)
			}
			if sent != 1 || len(e.State.Outbox) != 3 || !e.State.ReportRetryAt.After(time.Now()) {
				t.Fatal("failure did not pause channel and preserve outbox")
			}
			if _, ok := failure.(notificationRateLimit); ok && time.Until(e.State.ReportRetryAt) < 4*time.Minute {
				t.Fatal("provider Retry-After was ignored")
			}
			addIncident(e, "pending")
			if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
				t.Fatalf("delivery blocked investigation: %v", err)
			}
			if err := e.FlushReports(context.Background()); err != nil || sent != 1 {
				t.Fatal("new events bypassed channel cooldown")
			}
			if err := e.Store.Close(); err != nil {
				t.Fatal(err)
			}
			disk, state, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer disk.Close()
			e.Store, e.State = disk, state
			if err := e.FlushReports(context.Background()); err != nil || sent != 1 {
				t.Fatal("restart lost destination cooldown")
			}
			e.State.ReportRetryAt = time.Time{}
			for i := range e.State.Outbox {
				e.State.Outbox[i].NextAttempt = time.Time{}
			}
			e.Reporter = notificationSender{send: func(context.Context, protocol.Event) error { return nil }}
			if err := e.FlushReports(context.Background()); err != nil || len(e.State.Outbox) != 0 {
				t.Fatalf("recovered channel did not drain: %v", err)
			}
		})
	}
}

func TestNotificationsWakeWhileInvestigationIsStillRunning(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	e.Config.TickSeconds = 60
	sent := make(chan protocol.Event, 20)
	e.Reporter = notificationSender{send: func(_ context.Context, event protocol.Event) error { sent <- event; return nil }}
	e.Planner = plannerFunc(func(ctx context.Context, _ protocol.Request) (protocol.Decision, error) {
		<-ctx.Done()
		return protocol.Decision{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-sent:
			if event.Type == "assessment_started" && event.Details["source"] == "local-host" {
				return
			}
		case <-timer.C:
			t.Fatal("audit notification waited for investigation or polling tick")
		}
	}
}

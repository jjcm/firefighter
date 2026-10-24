package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/config"
	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/intel"
	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/store"
)

type plannerFunc func(context.Context, protocol.Request) (protocol.Decision, error)

func (f plannerFunc) Decide(ctx context.Context, request protocol.Request) (protocol.Decision, error) {
	return f(ctx, request)
}

type sourceFunc func(context.Context, string) (intel.Result, error)

func (f sourceFunc) Name() string { return "fixture" }
func (f sourceFunc) Poll(ctx context.Context, cursor string) (intel.Result, error) {
	return f(ctx, cursor)
}

type fakeRunner struct {
	mu       sync.Mutex
	calls    []string
	exitCode map[string]int
}

func (r *fakeRunner) Validate(action protocol.Action) error { return host.Validate(action) }
func (r *fakeRunner) Run(_ context.Context, action protocol.Action) protocol.ActionResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, action.ID)
	return protocol.ActionResult{ActionID: action.ID, ExitCode: r.exitCode[action.ID], StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}
}
func (r *fakeRunner) called() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func fixtureEngine(t *testing.T) (*Engine, string, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	s, state, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	cfg := config.Default()
	cfg.StateDir = dir
	cfg.MaxRounds = 3
	runner := &fakeRunner{exitCode: make(map[string]int)}
	e := &Engine{
		Config: cfg, Store: s, State: state, Runner: runner,
		Collect: func(context.Context) (host.Snapshot, error) { return host.Snapshot{}, nil },
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Planner: plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
			return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Fixture assessment complete"}, nil
		}),
	}
	e.defaults()
	return e, dir, runner
}

func addIncident(e *Engine, status string) *store.Incident {
	item := intel.Item{ID: "fixture-advisory", Source: "fixture", Title: "Fixture advisory", Body: "Test evidence", PublishedAt: time.Now().UTC()}
	key := store.Key(item)
	in := &store.Incident{ID: key, Item: item, Status: status}
	e.State.Incidents[key] = in
	return in
}

func readState(t *testing.T, dir string) store.State {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var state store.State
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func scheduledIncident(e *Engine, id, status string, when time.Time, assessments ...string) *store.Incident {
	in := &store.Incident{ID: id, Item: intel.Item{ID: id, Source: "fixture", Title: id, PublishedAt: when}, Status: status, UpdatedAt: when}
	for _, assessment := range assessments {
		in.History = append(in.History, protocol.Turn{Decision: protocol.Decision{Assessment: assessment, Summary: "Prior fixture assessment"}})
	}
	e.State.Incidents[id] = in
	return in
}

func TestKnownExposureDeferredIncidentResumesBeforeFreshDisclosure(t *testing.T) {
	for _, assessment := range []string{"exposed", "suspected_compromise", "confirmed_compromise"} {
		t.Run(assessment, func(t *testing.T) {
			e, dir, _ := fixtureEngine(t)
			now := time.Now().UTC()
			urgent := scheduledIncident(e, "unfinished-response", "deferred", now.Add(-24*time.Hour), "unknown", assessment)
			urgent.NextAttempt = now.Add(-time.Minute)
			fresh := scheduledIncident(e, "unrelated-new-notice", "pending", now)
			var selected string
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				selected = req.IncidentID
				return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Fixture complete"}, nil
			})
			if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
				t.Fatalf("resume failed: worked=%v err=%v", worked, err)
			}
			if selected != urgent.ID || urgent.Attempts != 1 || fresh.Attempts != 0 {
				t.Fatalf("known exposure buried behind new intake: selected=%q urgent=%d fresh=%d", selected, urgent.Attempts, fresh.Attempts)
			}
			persisted := readState(t, dir)
			if persisted.Incidents[urgent.ID].Attempts != 1 || persisted.Incidents[fresh.ID].Status != "pending" {
				t.Fatal("resume choice was not reflected in durable incident state")
			}
		})
	}
}

func TestUrgentDeferredIncidentStillWaitsForNextAttempt(t *testing.T) {
	for _, processed := range []uint64{0, 4} {
		t.Run(fmt.Sprintf("selection-%d", processed+1), func(t *testing.T) {
			e, _, _ := fixtureEngine(t)
			e.processed = processed
			now := time.Now().UTC()
			urgent := scheduledIncident(e, "not-yet-due", "deferred", now.Add(-24*time.Hour), "confirmed_compromise")
			urgent.NextAttempt = now.Add(time.Hour)
			fresh := scheduledIncident(e, "due-disclosure", "pending", now)
			var selected string
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				selected = req.IncidentID
				return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Fixture complete"}, nil
			})
			if worked, err := e.ProcessOne(context.Background()); err != nil || !worked || selected != fresh.ID {
				t.Fatalf("future retry bypassed due-time gate: selected=%q worked=%v err=%v", selected, worked, err)
			}
			if worked, err := e.ProcessOne(context.Background()); err != nil || worked || urgent.Attempts != 0 || urgent.Status != "deferred" {
				t.Fatalf("future incident was revived early: worked=%v urgent=%+v err=%v", worked, urgent, err)
			}
		})
	}
}

func TestUrgentDeferredResumePreservesOldestFairnessAndTerminalExclusion(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	e.processed = 4
	now := time.Now().UTC()
	terminal := scheduledIncident(e, "already-remediated", "completed", now.Add(-72*time.Hour), "confirmed_compromise", "remediated")
	oldest := scheduledIncident(e, "oldest-generic-advisory", "pending", now.Add(-48*time.Hour))
	urgent := scheduledIncident(e, "unfinished-exposure", "deferred", now.Add(-24*time.Hour), "exposed")
	scheduledIncident(e, "fresh-generic-advisory", "pending", now)
	var selected []string
	e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		selected = append(selected, req.IncidentID)
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Fixture complete"}, nil
	})
	for i := 0; i < 3; i++ {
		if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
			t.Fatalf("selection %d: worked=%v err=%v", i+1, worked, err)
		}
	}
	if !reflect.DeepEqual(selected, []string{oldest.ID, urgent.ID, "fresh-generic-advisory"}) {
		t.Fatalf("fairness or urgent ordering changed: %v", selected)
	}
	if worked, err := e.ProcessOne(context.Background()); err != nil || worked || terminal.Attempts != 0 || terminal.Status != "completed" || !terminal.NextAttempt.IsZero() {
		t.Fatalf("terminal incident was revived: worked=%v terminal=%+v err=%v", worked, terminal, err)
	}
}

func TestDeferredPriorityUsesLatestAssessment(t *testing.T) {
	for _, latest := range []string{"unknown", "not_affected", "remediated", ""} {
		t.Run("latest-"+latest, func(t *testing.T) {
			e, _, _ := fixtureEngine(t)
			now := time.Now().UTC()
			scheduledIncident(e, "routine-retry", "deferred", now.Add(-time.Hour), "confirmed_compromise", latest)
			fresh := scheduledIncident(e, "new-disclosure", "pending", now)
			var selected string
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				selected = req.IncidentID
				return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Fixture complete"}, nil
			})
			if worked, err := e.ProcessOne(context.Background()); err != nil || !worked || selected != fresh.ID {
				t.Fatalf("historical exposure overrode latest assessment: selected=%q worked=%v err=%v", selected, worked, err)
			}
		})
	}
}

func TestPollQueueLimitRetainsCursorAtomically(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	e.Config.MaxPendingIncidents = 1
	addIncident(e, "pending")
	e.State.Sources["news"] = store.SourceState{Cursor: "old-cursor"}
	e.Sources = []ScheduledSource{{Name: "news", Every: time.Minute, Source: sourceFunc(func(_ context.Context, cursor string) (intel.Result, error) {
		if cursor != "old-cursor" {
			t.Errorf("unexpected polling cursor: %q", cursor)
		}
		return intel.Result{Cursor: "new-cursor", Items: []intel.Item{{ID: "new", Title: "New disclosure"}}}, nil
	})}}
	if err := e.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved := readState(t, dir)
	if saved.Sources["news"].Cursor != "old-cursor" || len(saved.Incidents) != 1 {
		t.Fatalf("overflow advanced cursor or partly queued items: %+v", saved)
	}
	if !strings.Contains(saved.Sources["news"].LastError, "queue limit") {
		t.Fatal("queue overflow was not recorded as degraded intake")
	}
}

func TestPollPersistsIncidentsAndCursorTogether(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	e.Sources = []ScheduledSource{{Name: "news", Every: time.Minute, Source: sourceFunc(func(context.Context, string) (intel.Result, error) {
		return intel.Result{Cursor: "new-cursor", Items: []intel.Item{{ID: "new", Title: "New disclosure"}}}, nil
	})}}
	if err := e.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	saved := readState(t, dir)
	if saved.Sources["news"].Cursor != "new-cursor" || len(saved.Incidents) != 1 {
		t.Fatalf("cursor was not committed with the work it represents: %+v", saved)
	}
	for _, in := range saved.Incidents {
		if in.Status != "pending" || in.Item.Source != "news" {
			t.Fatalf("invalid persisted incident: %+v", in)
		}
	}
}

func TestFeedIngestionContinuesWhilePlannerIsBlocked(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	addIncident(e, "pending")
	entered, release := make(chan struct{}), make(chan struct{})
	e.Planner = plannerFunc(func(ctx context.Context, _ protocol.Request) (protocol.Decision, error) {
		close(entered)
		select {
		case <-release:
			return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Done"}, nil
		case <-ctx.Done():
			return protocol.Decision{}, ctx.Err()
		}
	})
	e.Sources = []ScheduledSource{{Name: "news", Every: time.Minute, Source: sourceFunc(func(context.Context, string) (intel.Result, error) {
		return intel.Result{Cursor: "fresh", Items: []intel.Item{{ID: "urgent", Title: "Urgent disclosure"}}}, nil
	})}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	processed := make(chan error, 1)
	go func() { _, err := e.ProcessOne(ctx); processed <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("planner was not invoked")
	}
	polled := make(chan error, 1)
	go func() { polled <- e.Poll(ctx) }()
	select {
	case err := <-polled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("feed polling blocked on the planner")
	}
	saved := readState(t, dir)
	if saved.Sources["news"].Cursor != "fresh" || len(saved.Incidents) != 2 {
		t.Fatal("incoming intelligence was not persisted while planner waited")
	}
	close(release)
	if err := <-processed; err != nil {
		t.Fatal(err)
	}
}

func TestCrashRecoveryReassessesWithoutReplayingCommands(t *testing.T) {
	dir := t.TempDir()
	s, state, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	item := intel.Item{ID: "interrupted", Source: "fixture", Title: "Interrupted assessment"}
	key := store.Key(item)
	state.Incidents[key] = &store.Incident{ID: key, Item: item, Status: "running", History: []protocol.Turn{{Decision: protocol.Decision{Actions: []protocol.Action{{ID: "dangerous-to-repeat", Kind: "command", Argv: []string{"/bin/true"}}}}}}}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, state, err = store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if state.Incidents[key].Status != "pending" || len(state.Incidents[key].RecoveryNotes) == 0 {
		t.Fatal("interrupted incident was not marked for reassessment")
	}
	runner := &fakeRunner{exitCode: map[string]int{}}
	plannerCalled := false
	e := &Engine{Config: config.Default(), Store: s, State: state, Runner: runner, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Collect: func(context.Context) (host.Snapshot, error) { return host.Snapshot{}, nil }, Planner: plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
		plannerCalled = true
		if len(request.RecoveryNotes) == 0 || !strings.Contains(request.RecoveryNotes[0], "may have executed") {
			t.Error("planner lacks uncertainty about interrupted commands")
		}
		return protocol.Decision{Done: true, Assessment: "unknown", Summary: "Reassessed current state"}, nil
	})}
	if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
		t.Fatalf("recovery work failed: worked=%v err=%v", worked, err)
	}
	if !plannerCalled || len(runner.called()) != 0 {
		t.Fatalf("saved commands were replayed: %v", runner.called())
	}
}

func TestObserveModeExecutesNoPlannedCommands(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	e.Config.Observe = true
	in := addIncident(e, "pending")
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		return protocol.Decision{Assessment: "exposed", Summary: "Would repair the fixture", Actions: []protocol.Action{{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "Repair"}}}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if in.Status != "observed" || len(runner.called()) != 0 {
		t.Fatalf("observation executed planned work: status=%s calls=%v", in.Status, runner.called())
	}
	if len(in.History) != 1 || len(in.History[0].Decision.Actions) != 1 {
		t.Fatal("observation did not persist the proposed work")
	}
}

func TestVerificationFailureRollsBackAndSkipsRemainingBatch(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	runner.exitCode["patch-verify"] = 1
	rounds := 0
	e.Planner = plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
		rounds++
		if rounds == 1 {
			return protocol.Decision{Assessment: "exposed", Summary: "Repair fixture", Actions: []protocol.Action{
				{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/false"}, Rollback: []string{"/bin/true"}, Mutates: true, Reason: "Repair"},
				{ID: "must-not-run", Kind: "command", Argv: []string{"/bin/true"}, Reason: "Dependent operation"},
			}}, nil
		}
		if len(request.History) != 1 || len(request.History[0].Results) != 3 {
			t.Error("planner did not receive action, failed verification, and rollback evidence")
		}
		return protocol.Decision{Done: true, Assessment: "unknown", Summary: "Repair rolled back"}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"patch", "patch-verify", "patch-rollback"}
	if !reflect.DeepEqual(runner.called(), want) || in.Status != "completed" {
		t.Fatalf("unexpected recovery behavior: calls=%v status=%s", runner.called(), in.Status)
	}
}

func TestLaterFailureInvalidatesEarlierVerification(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	runner.exitCode["second-patch"] = 1
	rounds := 0
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		rounds++
		if rounds == 1 {
			return protocol.Decision{Assessment: "exposed", Summary: "Repair two components", Actions: []protocol.Action{
				{ID: "first-patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "First repair"},
				{ID: "second-patch", Kind: "command", Argv: []string{"/bin/false"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "Second repair"},
			}}, nil
		}
		return protocol.Decision{Done: true, Assessment: "remediated", Summary: "Incorrect claim after failed second repair"}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if in.Status != "deferred" || !strings.Contains(in.LastError, "verification") {
		t.Fatalf("stale verification accepted an unverified remediation: status=%s error=%s", in.Status, in.LastError)
	}
}

func TestDeferredWorkCountsAgainstPendingLimit(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	e.Config.MaxPendingIncidents = 1
	addIncident(e, "deferred")
	e.State.Sources["news"] = store.SourceState{Cursor: "old"}
	e.Sources = []ScheduledSource{{Name: "news", Every: time.Minute, Source: sourceFunc(func(context.Context, string) (intel.Result, error) {
		return intel.Result{Cursor: "new", Items: []intel.Item{{ID: "new", Title: "New disclosure"}}}, nil
	})}}
	if err := e.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(e.State.Incidents) != 1 || e.State.Sources["news"].Cursor != "old" {
		t.Fatal("deferred backlog bypassed queue capacity")
	}
}

func TestDeferredHostReviewIsNotDuplicated(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	in := addIncident(e, "deferred")
	in.Item.Source = "local-host"
	if err := e.enqueueHostReview(); err != nil {
		t.Fatal(err)
	}
	if len(e.State.Incidents) != 1 {
		t.Fatal("another posture review was queued while an earlier one remains unresolved")
	}
}

func TestInvalidVerificationPreventsOriginalMutation(t *testing.T) {
	e, _, runner := fixtureEngine(t)
	in := addIncident(e, "pending")
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		return protocol.Decision{Assessment: "exposed", Summary: "Invalid proposed repair", Actions: []protocol.Action{{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"./untrusted-relative-check"}, Mutates: true, Reason: "Repair"}}}, nil
	})
	if _, err := e.ProcessOne(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.called()) != 0 || in.Status != "deferred" {
		t.Fatalf("mutation ran before verification command validation: status=%s calls=%v", in.Status, runner.called())
	}
}

func TestAuditOutboxRecoversQueueAndAcknowledgementCrashWindows(t *testing.T) {
	dir := t.TempDir()
	s, state, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	event := protocol.Event{ID: "durable-event", Time: time.Now().UTC(), Type: "assessment_finished", Summary: "Repair completed"}
	// Crash after queuing in the journal, before adding it to the state snapshot.
	if err := s.Append("report_queued", "", event); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, state, err = store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Outbox) != 1 || state.Outbox[0].Event.ID != event.ID {
		t.Fatal("journaled event was lost before snapshot persistence")
	}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	// Crash after delivery acknowledgement, before deleting the snapshot entry.
	if err := s.Append("report_delivered", "", map[string]string{"id": event.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, state, err = store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(state.Outbox) != 0 {
		t.Fatal("durably acknowledged event was queued again")
	}
}

func TestTornAuditTailRecoversWithoutDiscardingEarlierEvents(t *testing.T) {
	dir := t.TempDir()
	s, state, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	event := protocol.Event{ID: "complete-event", Time: time.Now().UTC(), Type: "assessment_started", Summary: "Started"}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	if err := s.Append("report_queued", "", event); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"time":"2026-10-24T00:00:00Z","type":"interrupted`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	s, state, err = store.Open(dir)
	if err != nil {
		t.Fatalf("incomplete final journal append prevented recovery: %v", err)
	}
	if len(state.Outbox) != 1 || state.Outbox[0].Event.ID != event.ID {
		t.Fatal("tail recovery discarded a complete journaled event")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Verify the recovery record itself leaves a valid append-only hash chain.
	s, _, err = store.Open(dir)
	if err != nil {
		t.Fatalf("recovered journal cannot be reopened: %v", err)
	}
	defer s.Close()
}

func TestCompleteAuditCorruptionIsNotSilentlyRepaired(t *testing.T) {
	dir := t.TempDir()
	s, _, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append("event", "", map[string]string{"evidence": "preserve"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	s, _, err = store.Open(dir)
	if err == nil {
		s.Close()
		t.Fatal("complete invalid journal record was silently discarded")
	}
}

func TestEveryFifthAssessmentServicesOldestDueWorkUnderFreshTraffic(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	now := time.Now().UTC()
	oldIDs := make([]string, 0, 2)
	for i, status := range []string{"pending", "deferred"} {
		item := intel.Item{ID: fmt.Sprintf("old-%d", i), Source: "official", Title: "Earlier unresolved advisory", PublishedAt: now.Add(-365 * 24 * time.Hour)}
		key := store.Key(item)
		e.State.Incidents[key] = &store.Incident{ID: key, Item: item, Status: status, UpdatedAt: now.Add(-24*time.Hour + time.Duration(i)*time.Hour)}
		oldIDs = append(oldIDs, key)
	}
	var selected []string
	e.Planner = plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
		selected = append(selected, request.IncidentID)
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Fixture checked"}, nil
	})
	for i := 0; i < 10; i++ {
		// There is always another newly published pending post competing with
		// the older advisory and deferred retry, just as with a busy social feed.
		item := intel.Item{ID: fmt.Sprintf("fresh-%d", i), Source: "social", Title: "New disclosure", PublishedAt: now.Add(time.Duration(i) * time.Second)}
		key := store.Key(item)
		e.State.Incidents[key] = &store.Incident{ID: key, Item: item, Status: "pending", UpdatedAt: now}
		worked, err := e.ProcessOne(context.Background())
		if err != nil || !worked {
			t.Fatalf("assessment %d: worked=%v err=%v", i+1, worked, err)
		}
		want := key
		if i%5 == 4 {
			want = oldIDs[i/5]
		}
		if got := selected[len(selected)-1]; got != want {
			t.Fatalf("assessment %d selected %s, want %s; older work starved or fresh priority lost", i+1, got, want)
		}
	}
}

func TestTerminalAdvisoriesStayCompletedWhileHostReviewsContinue(t *testing.T) {
	for _, assessment := range []string{"not_affected", "remediated"} {
		t.Run(assessment, func(t *testing.T) {
			e, dir, _ := fixtureEngine(t)
			in := addIncident(e, "pending")
			advisoryRounds, hostReviews := 0, 0
			e.Planner = plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
				item, ok := request.Intel.(intel.Item)
				if !ok {
					t.Fatal("planner request lost its intake evidence")
				}
				if item.Source == "local-host" {
					hostReviews++
					return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Periodic posture reviewed"}, nil
				}
				advisoryRounds++
				if assessment == "remediated" && advisoryRounds == 1 {
					return protocol.Decision{Assessment: "exposed", Summary: "Repair fixture", Actions: []protocol.Action{{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "Repair and verify"}}}, nil
				}
				return protocol.Decision{Done: true, Assessment: assessment, Summary: "Terminal advisory assessment"}, nil
			})
			if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
				t.Fatalf("initial assessment failed: worked=%v err=%v", worked, err)
			}
			if in.Status != "completed" || !in.NextAttempt.IsZero() {
				t.Fatalf("terminal assessment was scheduled again: status=%s next=%v", in.Status, in.NextAttempt)
			}
			completedRounds := advisoryRounds
			for i := 0; i < 3; i++ {
				if worked, err := e.ProcessOne(context.Background()); err != nil || worked {
					t.Fatalf("terminal advisory was reassessed: worked=%v err=%v", worked, err)
				}
			}
			persisted := readState(t, dir).Incidents[in.ID]
			if persisted == nil || persisted.Status != "completed" || !persisted.NextAttempt.IsZero() {
				t.Fatal("terminal scheduling was not persisted")
			}
			for i := 0; i < 2; i++ {
				// Advance the posture schedule without waiting in real time.
				e.State.LastHostReview = time.Now().Add(-config.Seconds(e.Config.InventorySeconds) - time.Second)
				if err := e.enqueueHostReview(); err != nil {
					t.Fatal(err)
				}
				if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
					t.Fatalf("posture assessment %d did not run: worked=%v err=%v", i+1, worked, err)
				}
			}
			if hostReviews != 2 || advisoryRounds != completedRounds {
				t.Fatalf("terminal completion interfered with periodic posture: host=%d advisory rounds=%d want=%d", hostReviews, advisoryRounds, completedRounds)
			}
		})
	}
}

func TestPlannerRetryReceivesPreviousFailureAndExecutionLimits(t *testing.T) {
	for _, timeout := range []struct{ configured, expected int }{{73, 73}, {3600, 1800}} {
		t.Run(fmt.Sprintf("configured_%d", timeout.configured), func(t *testing.T) {
			e, _, _ := fixtureEngine(t)
			e.Config.CommandTimeoutSeconds = timeout.configured
			e.Config.IncidentTimeoutSeconds = 432
			e.Config.Instructions = "Fixture operator policy"
			in := addIncident(e, "pending")
			calls := 0
			e.Planner = plannerFunc(func(_ context.Context, request protocol.Request) (protocol.Decision, error) {
				calls++
				if calls == 1 {
					return protocol.Decision{}, errors.New("provider temporarily unavailable")
				}
				notes := strings.Join(request.RecoveryNotes, "\n")
				if !strings.Contains(notes, "Previous assessment failed: provider temporarily unavailable") {
					t.Errorf("retry did not explain the preceding failure: %q", notes)
				}
				for _, required := range []string{"Fixture operator policy", fmt.Sprintf("timeout_seconds must be 0..%d", timeout.expected), "total incident time budget is 432 seconds"} {
					if !strings.Contains(request.Instructions, required) {
						t.Errorf("planner instructions omit %q: %q", required, request.Instructions)
					}
				}
				return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Retry succeeded"}, nil
			})
			if _, err := e.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			if in.Status != "deferred" || in.LastError == "" {
				t.Fatal("provider failure was not retained for the next assessment")
			}
			in.NextAttempt = time.Time{}
			if _, err := e.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			if calls != 2 || in.Status != "completed" || in.LastError != "" {
				t.Fatalf("retry did not complete cleanly: calls=%d status=%s error=%q", calls, in.Status, in.LastError)
			}
		})
	}
}

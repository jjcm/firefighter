package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

func TestLifecycleReportsCorrelateVersionAndDistinctRuns(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	e.Version = "release-123"
	var events []protocol.Event
	e.Reporter = notificationSender{send: func(_ context.Context, event protocol.Event) error {
		events = append(events, event)
		return nil
	}}
	if err := e.startLifecycle(); err != nil {
		t.Fatal(err)
	}
	firstRun := e.RunID
	if len(firstRun) != 32 {
		t.Fatalf("missing random run identity: %q", firstRun)
	}
	if err := e.stopLifecycle(nil); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Type != "started" || events[1].Type != "stopped" {
		t.Fatalf("missing lifecycle reports: %+v", events)
	}
	for _, event := range events {
		if event.Details["run_id"] != firstRun || event.Details["version"] != "release-123" {
			t.Fatalf("lifecycle event lost correlation: %+v", event)
		}
	}
	if events[1].Details["stop_reason"] != "requested_stop" {
		t.Fatalf("normal shutdown guessed a cause: %+v", events[1])
	}
	if pending := len(readState(t, dir).Outbox); pending != 0 {
		t.Fatalf("delivered shutdown reports still pending: %d", pending)
	}
	if err := e.startLifecycle(); err != nil {
		t.Fatal(err)
	}
	if e.RunID == firstRun {
		t.Fatal("a later daemon invocation reused the prior run identity")
	}
}

func TestLifecycleEngineErrorIsRedactedAndKeptOnDeliveryFailure(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	e.Redact = func(s string) string { return strings.ReplaceAll(s, "private-value", "[REDACTED]") }
	sent := 0
	e.Reporter = notificationSender{send: func(context.Context, protocol.Event) error {
		sent++
		return errors.New("destination offline")
	}}
	if err := e.startLifecycle(); err != nil {
		t.Fatal(err)
	}
	if err := e.stopLifecycle(errors.New("checkpoint failed: private-value")); err != nil {
		t.Fatal(err)
	}
	state := readState(t, dir)
	if sent != 1 || len(state.Outbox) != 2 || !state.ReportRetryAt.After(time.Now()) {
		t.Fatalf("shutdown lost failed reports or ignored destination backoff: sends=%d state=%+v", sent, state.Outbox)
	}
	stopped := state.Outbox[1].Event
	if stopped.Type != "stopped" || stopped.Details["stop_reason"] != "engine_error" || stopped.Details["error"] != "checkpoint failed: [REDACTED]" {
		t.Fatalf("engine failure misreported: %+v", stopped)
	}
}

func TestShutdownReportFlushRespectsExistingBackoff(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	e.Reporter = notificationSender{send: func(context.Context, protocol.Event) error {
		t.Fatal("shutdown bypassed a destination retry deadline")
		return nil
	}}
	e.State.ReportRetryAt = time.Now().Add(time.Minute)
	if err := e.stopLifecycle(nil); err != nil {
		t.Fatal(err)
	}
	if state := readState(t, dir); len(state.Outbox) != 1 || state.Outbox[0].Event.Type != "stopped" {
		t.Fatalf("shutdown report was not retained for a later run: %+v", state.Outbox)
	}
}

func TestShutdownReportFlushIsBoundedAndLeavesUnacknowledgedEvent(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	e.Reporter = notificationSender{send: func(ctx context.Context, _ protocol.Event) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	if err := e.emit("stopped", "", "Stopped", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := e.flushShutdownReports(ctx); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("shutdown report flush did not honor its deadline")
	}
	if len(readState(t, dir).Outbox) != 1 {
		t.Fatal("timed out report was incorrectly acknowledged")
	}
}

func TestShutdownReportFlushDrainsMoreThanOneBatch(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	sent := 0
	e.Reporter = notificationSender{send: func(context.Context, protocol.Event) error { sent++; return nil }}
	for i := 0; i < 33; i++ {
		if err := e.emit("report_test", "", "Queued", nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.stopLifecycle(nil); err != nil {
		t.Fatal(err)
	}
	if sent != 34 || len(e.State.Outbox) != 0 {
		t.Fatalf("stopped event was stranded behind the first batch: sent=%d pending=%d", sent, len(e.State.Outbox))
	}
}

func TestAssessmentInterruptionDistinguishesDaemonAndIncidentDeadline(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	incident, expire := context.WithDeadline(parent, time.Now().Add(-time.Second))
	defer expire()
	summary, cause := assessmentInterruption(parent, incident)
	if interruptionReason(cause) != "incident_timeout" || !errors.Is(cause, context.DeadlineExceeded) || !strings.Contains(summary, "time limit") {
		t.Fatalf("incident deadline misclassified: %s / %v", summary, cause)
	}
	stop()
	summary, cause = assessmentInterruption(parent, incident)
	if interruptionReason(cause) != "daemon_stopping" || !errors.Is(cause, context.Canceled) || !strings.Contains(summary, "future run") {
		t.Fatalf("daemon stop misclassified: %s / %v", summary, cause)
	}
	if _, cause = assessmentInterruption(context.Background(), context.Background()); cause != nil {
		t.Fatal("live contexts were classified as interrupted")
	}
	if interruptionReason(context.DeadlineExceeded) != "" {
		t.Fatal("provider request timeout was classified as an incident timeout")
	}
}

func TestRunJoinsReporterBeforeShutdownAndClassifiesCanceledPlanner(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	e.Version = "release-cancel-test"
	e.State.LastHostReview = time.Now()
	in := addIncident(e, "pending")
	// Stopping an already-reported incident must still close its visible activity.
	in.ReportedActivity = true

	plannerStarted, senderStarted := make(chan struct{}), make(chan struct{})
	e.Planner = plannerFunc(func(ctx context.Context, _ protocol.Request) (protocol.Decision, error) {
		close(plannerStarted)
		<-ctx.Done()
		return protocol.Decision{}, errors.New("cannot read planner response")
	})
	var mu sync.Mutex
	var events []protocol.Event
	sending, calls := false, 0
	e.Reporter = notificationSender{send: func(ctx context.Context, event protocol.Event) error {
		mu.Lock()
		if sending {
			t.Error("shutdown flush raced the background reporter")
		}
		sending = true
		calls++
		first := calls == 1
		mu.Unlock()
		defer func() { mu.Lock(); sending = false; mu.Unlock() }()
		if first {
			close(senderStarted)
			<-ctx.Done()
			return ctx.Err()
		}
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx) }()
	for _, started := range []chan struct{}{plannerStarted, senderStarted} {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("daemon did not start planner and reporter")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon did not stop")
	}
	state := readState(t, dir)
	if state.Incidents[in.ID].Status != "deferred" || len(state.Outbox) != 0 {
		t.Fatalf("canceled assessment or final reports not checkpointed: %+v", state.Incidents[in.ID])
	}
	mu.Lock()
	defer mu.Unlock()
	foundAssessment, foundStop := false, false
	for _, event := range events {
		if event.Details["run_id"] != e.RunID || event.Details["version"] != e.Version {
			t.Errorf("event has no lifecycle identity: %+v", event)
		}
		if event.Type == "assessment_finished" {
			foundAssessment = event.Details["interruption_reason"] == "daemon_stopping" && !strings.Contains(event.Summary, "Planner unavailable")
		}
		if event.Type == "stopped" {
			foundStop = event.Details["stop_reason"] == "requested_stop"
		}
	}
	if !foundAssessment || !foundStop {
		t.Fatalf("canceled assessment and stop were not reported accurately: %+v", events)
	}
}

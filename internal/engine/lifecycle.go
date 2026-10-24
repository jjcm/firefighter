package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

const shutdownReportTimeout = 5 * time.Second

// startLifecycle runs before any workers start, so every event in this daemon
// invocation can carry the same identity without changing it underneath them.
func (e *Engine) startLifecycle() error {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	e.RunID = hex.EncodeToString(id[:])
	if e.Version == "" {
		e.Version = "unknown"
	}
	return e.emit("started", "", "Autonomous host defense started", map[string]interface{}{
		"observe": e.Config.Observe, "run_id": e.RunID, "version": e.Version,
	})
}

// stopLifecycle must run after workers, including the regular report sender,
// have stopped. A requested stop does not tell us whether an operator, an
// upgrade, or a service manager requested it; do not guess from cancellation.
func (e *Engine) stopLifecycle(runErr error) error {
	reason := "requested_stop"
	details := map[string]interface{}{"run_id": e.RunID, "version": e.Version}
	if runErr != nil {
		reason = "engine_error"
		details["error"] = runErr.Error()
	}
	details["stop_reason"] = reason
	if err := e.emit("stopped", "", "Autonomous host defense stopped", details); err != nil {
		return err
	}
	// The run context is already canceled. Use a separate, bounded opportunity
	// to deliver the durable shutdown event, respecting destination backoff.
	ctx, cancel := context.WithTimeout(context.Background(), shutdownReportTimeout)
	defer cancel()
	err := e.flushShutdownReports(ctx)
	e.mu.Lock()
	pending := len(e.State.Outbox)
	e.mu.Unlock()
	if pending > 0 {
		e.Log.Warn("shutdown left undelivered reports in the durable outbox", "pending", pending)
	}
	return err
}

func (e *Engine) flushShutdownReports(ctx context.Context) error {
	for ctx.Err() == nil {
		e.mu.Lock()
		before := len(e.State.Outbox)
		e.mu.Unlock()
		if before == 0 {
			return nil
		}
		if err := e.FlushReports(ctx); err != nil {
			return err
		}
		e.mu.Lock()
		after := len(e.State.Outbox)
		e.mu.Unlock()
		// No progress means the destination is unavailable, backing off, or has
		// no due entries. Do not spin or override rate limits while stopping.
		if after >= before {
			return nil
		}
	}
	return nil
}

type assessmentInterrupted struct {
	reason string
	cause  error
}

func (e *assessmentInterrupted) Error() string {
	if e.reason == "daemon_stopping" {
		return "assessment interrupted because the daemon is stopping"
	}
	return "assessment incident time limit reached"
}
func (e *assessmentInterrupted) Unwrap() error { return e.cause }

// assessmentInterruption distinguishes a canceled daemon from its per-incident
// deadline. A provider's own request timeout is still a planner failure while
// both contexts remain live.
func assessmentInterruption(parent, incident context.Context) (string, error) {
	if err := parent.Err(); err != nil {
		return "Daemon stopping; unfinished assessment saved for a future run", &assessmentInterrupted{reason: "daemon_stopping", cause: err}
	}
	if err := incident.Err(); err != nil {
		return "Assessment time limit reached; assessment will retry", &assessmentInterrupted{reason: "incident_timeout", cause: err}
	}
	return "", nil
}

func interruptionReason(err error) string {
	var interrupted *assessmentInterrupted
	if errors.As(err, &interrupted) {
		return interrupted.reason
	}
	return ""
}

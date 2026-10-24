// Package engine runs independent feed polling, serialized host work, and a durable outbox.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/jjcm/firefighter/internal/config"
	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/intel"
	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/report"
	"github.com/jjcm/firefighter/internal/store"
)

type Planner interface {
	Decide(context.Context, protocol.Request) (protocol.Decision, error)
}
type Runner interface {
	Validate(protocol.Action) error
	Run(context.Context, protocol.Action) protocol.ActionResult
}
type ScheduledSource struct {
	Name   string
	Every  time.Duration
	Source intel.Source
}
type Engine struct {
	Config    config.Config
	Store     *store.Store
	State     *store.State
	Planner   Planner
	Runner    Runner
	Sources   []ScheduledSource
	Reporter  report.Sender
	Collect   func(context.Context) (host.Snapshot, error)
	Redact    func(string) string
	Log       *slog.Logger
	Hostname  string
	mu        sync.Mutex
	workMu    sync.Mutex
	reportMu  sync.Mutex
	wake      chan struct{}
	processed uint64
}

func (e *Engine) defaults() {
	if e.Collect == nil {
		e.Collect = host.Collect
	}
	if e.Redact == nil {
		e.Redact = func(s string) string { return s }
	}
	if e.Log == nil {
		e.Log = slog.Default()
	}
	if e.wake == nil {
		e.wake = make(chan struct{}, 1)
	}
}
func (e *Engine) signal() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}
func (e *Engine) Run(ctx context.Context) error {
	e.defaults()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := e.emit("started", "", "Autonomous host defense started", map[string]interface{}{"observe": e.Config.Observe}); err != nil {
		return err
	}
	errCh := make(chan error, len(e.Sources)+1)
	var wg sync.WaitGroup
	for _, src := range e.Sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(config.Seconds(e.Config.TickSeconds))
			defer ticker.Stop()
			for {
				if err := e.pollOne(ctx, src); err != nil {
					select {
					case errCh <- err:
					case <-ctx.Done():
					}
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			if err := e.FlushReports(ctx); err != nil {
				select {
				case errCh <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { cancel(); wg.Wait() }()
	ticker := time.NewTicker(config.Seconds(e.Config.TickSeconds))
	defer ticker.Stop()
	for {
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return nil
		default:
		}
		if err := e.enqueueHostReview(); err != nil {
			return err
		}
		worked, err := e.ProcessOne(ctx)
		if err != nil {
			return err
		}
		if worked {
			continue
		}
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-e.wake:
		}
	}
}

// Once polls all sources, then processes a bounded number of queued incidents.
func (e *Engine) Once(ctx context.Context) error {
	e.defaults()
	if err := e.Poll(ctx); err != nil {
		return err
	}
	if err := e.enqueueHostReview(); err != nil {
		return err
	}
	for i := 0; i < e.Config.MaxIncidentsPerTick; i++ {
		worked, err := e.ProcessOne(ctx)
		if err != nil {
			return err
		}
		if !worked {
			break
		}
	}
	return e.FlushReports(ctx)
}
func (e *Engine) Poll(ctx context.Context) error {
	e.defaults()
	errs := make(chan error, len(e.Sources))
	var wg sync.WaitGroup
	for _, src := range e.Sources {
		wg.Add(1)
		go func(src ScheduledSource) {
			defer wg.Done()
			if err := e.pollOne(ctx, src); err != nil {
				errs <- err
			}
		}(src)
	}
	wg.Wait()
	close(errs)
	var all []error
	for err := range errs {
		all = append(all, err)
	}
	return errors.Join(all...)
}
func (e *Engine) pollOne(ctx context.Context, src ScheduledSource) error {
	e.mu.Lock()
	ss := e.State.Sources[src.Name]
	e.mu.Unlock()
	if time.Now().Before(ss.NextPoll) {
		return nil
	}
	result, fetchErr := src.Source.Poll(ctx, ss.Cursor)
	if ctx.Err() != nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now().UTC()
	ss.NextPoll = now.Add(src.Every)
	if fetchErr == nil {
		pending := 0
		for _, in := range e.State.Incidents {
			if in.Status == "pending" || in.Status == "running" || in.Status == "deferred" {
				pending++
			}
		}
		incoming := map[string]intel.Item{}
		for _, item := range result.Items {
			item.Source = src.Name
			key := store.Key(item)
			if _, exists := e.State.Incidents[key]; !exists {
				incoming[key] = item
			}
		}
		if pending+len(incoming) > e.Config.MaxPendingIncidents {
			fetchErr = errors.New("pending incident queue limit reached; cursor retained for retry")
		} else {
			for key, item := range incoming {
				e.State.Incidents[key] = &store.Incident{ID: key, Item: item, Status: "pending", UpdatedAt: now}
			}
			ss.Cursor = result.Cursor
			ss.LastSuccess = now
			previousError := ss.LastError
			ss.LastError = ""
			ss.Failures = 0
			if previousError != "" {
				if err := e.emitLocked("source_recovered", "", src.Name+" intake recovered", nil); err != nil {
					return err
				}
			}
			if len(incoming) > 0 {
				e.Log.Info("intelligence queued", "source", src.Name, "items", len(incoming))
				e.signal()
			}
		}
	}
	if fetchErr != nil {
		message := e.Redact(fetchErr.Error())
		ss.Failures++
		ss.NextPoll = now.Add(backoff(ss.Failures, src.Every, 30*time.Minute))
		if message != ss.LastError || ss.Failures == 1 || ss.Failures%10 == 0 {
			if err := e.emitLocked("source_error", "", src.Name+": "+message, map[string]interface{}{"failures": ss.Failures}); err != nil {
				return err
			}
		}
		ss.LastError = message
	}
	e.State.Sources[src.Name] = ss
	return e.Store.Save(e.State)
}
func (e *Engine) enqueueHostReview() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now().UTC()
	if !e.State.LastHostReview.IsZero() && now.Sub(e.State.LastHostReview) < config.Seconds(e.Config.InventorySeconds) {
		return nil
	}
	// Detailed evidence remains in the audit. Retire old terminal state so every
	// checkpoint does not rewrite the lifetime history of a continuously run host.
	for key, in := range e.State.Incidents {
		if (in.Status == "completed" || in.Status == "observed") && (in.NextAttempt.IsZero() || in.Item.Source == "local-host") && now.Sub(in.UpdatedAt) > time.Duration(e.Config.RecordRetentionDays)*24*time.Hour {
			delete(e.State.Incidents, key)
		}
	}
	// Keep at most one unfinished posture review, even through provider outages.
	for _, in := range e.State.Incidents {
		if in.Item.Source == "local-host" && (in.Status == "pending" || in.Status == "running" || in.Status == "deferred") {
			return nil
		}
	}
	item := intel.Item{ID: "host-review-" + now.Format(time.RFC3339Nano), Source: "local-host", Title: "Periodic host exposure and compromise assessment", Body: "Assess this Ubuntu host and locally deployed applications. Run available vulnerability and compromise checks, investigate suspicious persistence or authentication evidence, check pending security updates and restarts, and repair verified exposure. No incoming advisory is required to find existing problems. Missing scans mean unknown coverage, not clean status.", Trust: "local", PublishedAt: now}
	key := store.Key(item)
	e.State.Incidents[key] = &store.Incident{ID: key, Item: item, Status: "pending", UpdatedAt: now}
	e.State.LastHostReview = now
	return e.Store.Save(e.State)
}
func (e *Engine) ProcessOne(ctx context.Context) (bool, error) {
	e.defaults()
	e.workMu.Lock()
	defer e.workMu.Unlock()
	e.mu.Lock()
	now := time.Now().UTC()
	var eligible []*store.Incident
	for _, in := range e.State.Incidents {
		if in.Status == "completed" && in.NextAttempt.IsZero() {
			continue
		}
		if (in.Status == "pending" || in.Status == "deferred" || in.Status == "completed" || in.Status == "observed") && !now.Before(in.NextAttempt) {
			if in.Item.Source == "local-host" && (in.Status == "completed" || in.Status == "observed") {
				continue
			}
			eligible = append(eligible, in)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		// Every fifth selection services the oldest due item, preventing a busy
		// social feed from indefinitely starving an earlier advisory or retry.
		if e.processed%5 == 4 {
			if eligible[i].UpdatedAt.Equal(eligible[j].UpdatedAt) {
				return eligible[i].ID < eligible[j].ID
			}
			return eligible[i].UpdatedAt.Before(eligible[j].UpdatedAt)
		}
		// Fresh disclosures precede scheduled reassessments; newest discoveries win.
		pi, pj := eligible[i].Status == "pending", eligible[j].Status == "pending"
		if pi != pj {
			return pi
		}
		if eligible[i].Item.PublishedAt.Equal(eligible[j].Item.PublishedAt) {
			return eligible[i].ID < eligible[j].ID
		}
		return eligible[i].Item.PublishedAt.After(eligible[j].Item.PublishedAt)
	})
	if len(eligible) == 0 {
		e.mu.Unlock()
		return false, nil
	}
	in := eligible[0]
	e.processed++
	in.Status = "running"
	in.Attempts++
	in.UpdatedAt = now
	if err := e.Store.Save(e.State); err != nil {
		e.mu.Unlock()
		return true, err
	}
	e.mu.Unlock()
	err := e.investigate(ctx, in)
	if err != nil {
		return true, err
	}
	return true, nil
}
func (e *Engine) investigate(parent context.Context, in *store.Incident) error {
	ctx, cancel := context.WithTimeout(parent, config.Seconds(e.Config.IncidentTimeoutSeconds))
	defer cancel()
	if err := e.emit("assessment_started", in.ID, in.Item.Title, nil); err != nil {
		return err
	}
	snapshot, collectErr := e.Collect(ctx)
	notes := append([]string(nil), in.RecoveryNotes...)
	if in.LastError != "" {
		notes = append(notes, "Previous assessment failed: "+e.Redact(in.LastError))
	}
	if collectErr != nil {
		notes = append(notes, "Inventory incomplete: "+e.Redact(collectErr.Error()))
	}
	verified := false
	for round := 0; round < e.Config.MaxRounds; round++ {
		if ctx.Err() != nil {
			return e.finish(in, "deferred", "Assessment time limit reached or daemon stopping; further work scheduled", ctx.Err(), nil)
		}
		e.mu.Lock()
		history := modelHistory(in.History)
		e.mu.Unlock()
		instructions := e.Config.Instructions + fmt.Sprintf("\nExecution limits: command timeout_seconds must be 0..%d; the total incident time budget is %d seconds. You must assess execution results in another turn before declaring remediation complete.", min(e.Config.CommandTimeoutSeconds, 1800), e.Config.IncidentTimeoutSeconds)
		req := protocol.Request{IncidentID: in.ID, Host: snapshot, Intel: in.Item, History: history, Instructions: instructions, RotationHooks: e.Config.RotationHooks, RecoveryNotes: notes, RoundsRemaining: e.Config.MaxRounds - round}
		decision, err := e.Planner.Decide(ctx, req)
		if err != nil {
			return e.finish(in, "deferred", "Planner unavailable; assessment will retry", err, nil)
		}
		if len(decision.Actions) > e.Config.MaxActionsPerRound {
			return e.finish(in, "deferred", "Planner exceeded action budget", errors.New("too many planned actions"), nil)
		}
		for _, action := range decision.Actions {
			if err = e.Runner.Validate(action); err != nil {
				return e.finish(in, "deferred", "Planner returned an invalid action", err, nil)
			}
			for name, argv := range map[string][]string{"verify": action.Verify, "rollback": action.Rollback} {
				if len(argv) > 0 {
					derived := action
					derived.ID += "-" + name
					derived.Argv = argv
					if err = e.Runner.Validate(derived); err != nil {
						return e.finish(in, "deferred", "Planner returned invalid "+name+" command", err, nil)
					}
				}
			}
		}
		// Persist the decision before any commands. Scrub model text before storing or reporting.
		safeDecision := e.cleanDecision(decision)
		e.mu.Lock()
		in.History = append(in.History, protocol.Turn{Decision: safeDecision})
		if len(in.History) > 16 {
			in.History = in.History[len(in.History)-16:]
		}
		turn := len(in.History) - 1
		err = e.Store.Append("decision", in.ID, safeDecision)
		if err == nil {
			err = e.Store.Save(e.State)
		}
		e.mu.Unlock()
		if err != nil {
			return err
		}
		if len(decision.Actions) == 0 {
			if decision.Done {
				if decision.Assessment == "remediated" && !verified {
					return e.finish(in, "deferred", "Remediation claim lacks successful verification in this assessment", errors.New("verification required"), nil)
				}
				return e.finish(in, "completed", decision.Summary, nil, &safeDecision)
			}
			return e.finish(in, "deferred", decision.Summary, errors.New("planner requested follow-up without an action"), &safeDecision)
		}
		if e.Config.Observe {
			return e.finish(in, "observed", "Observation mode: "+decision.Summary, nil, &safeDecision)
		}
		for _, action := range decision.Actions {
			if action.Mutates {
				verified = false
			}
			result, err := e.execute(ctx, in, turn, action)
			if err != nil {
				return err
			}
			failed := result.ExitCode != 0 || result.Error != "" || result.TimedOut
			if !failed && len(action.Verify) > 0 {
				check := protocol.Action{ID: action.ID + "-verify", Kind: "command", Argv: action.Verify, Dir: action.Dir, TimeoutSeconds: action.TimeoutSeconds, Reason: "Verify: " + action.Reason}
				vr, xerr := e.execute(ctx, in, turn, check)
				if xerr != nil {
					return xerr
				}
				failed = vr.ExitCode != 0 || vr.Error != "" || vr.TimedOut
				if !failed {
					verified = true
				}
			}
			if failed && len(action.Rollback) > 0 && ctx.Err() == nil {
				rollback := protocol.Action{ID: action.ID + "-rollback", Kind: "command", Argv: action.Rollback, Dir: action.Dir, TimeoutSeconds: action.TimeoutSeconds, Reason: "Recover after failed action or verification: " + action.Reason, Mutates: true}
				if _, err = e.execute(ctx, in, turn, rollback); err != nil {
					return err
				}
				verified = false
			}
			// A failed action invalidates any later commands in this batch. Replan using evidence.
			if failed {
				verified = false
				break
			}
		}
	}
	return e.finish(in, "deferred", "Assessment round budget reached; further work scheduled", errors.New("round budget exhausted"), nil)
}
func (e *Engine) execute(ctx context.Context, in *store.Incident, turn int, action protocol.Action) (protocol.ActionResult, error) {
	if err := e.Runner.Validate(action); err != nil {
		return protocol.ActionResult{}, err
	}
	e.mu.Lock()
	err := e.Store.Append("action_intent", in.ID, e.cleanDecision(protocol.Decision{Actions: []protocol.Action{action}}).Actions[0])
	e.mu.Unlock()
	if err != nil {
		return protocol.ActionResult{}, err
	}
	result := e.Runner.Run(ctx, action)
	result.Output = e.Redact(result.Output)
	result.Error = e.Redact(result.Error)
	e.mu.Lock()
	defer e.mu.Unlock()
	if err = e.Store.Append("action_result", in.ID, result); err != nil {
		return result, err
	}
	in.History[turn].Results = append(in.History[turn].Results, result)
	if err = e.emitLocked("action_finished", in.ID, action.Reason, map[string]interface{}{"action_id": action.ID, "exit_code": result.ExitCode, "timed_out": result.TimedOut, "error": result.Error}); err != nil {
		return result, err
	}
	return result, e.Store.Save(e.State)
}
func (e *Engine) finish(in *store.Incident, status, summary string, cause error, decision *protocol.Decision) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	in.Status = status
	in.UpdatedAt = time.Now().UTC()
	in.NextAttempt = in.UpdatedAt.Add(config.Seconds(e.Config.RecheckSeconds))
	in.LastError = ""
	terminal := status == "completed" && decision != nil && (decision.Assessment == "not_affected" || decision.Assessment == "remediated")
	if terminal {
		in.NextAttempt = time.Time{}
		in.History = []protocol.Turn{{Decision: *decision}}
		in.Item.Body = ""
	}
	if cause != nil {
		in.LastError = e.Redact(cause.Error())
		in.NextAttempt = in.UpdatedAt.Add(backoff(in.Attempts, 30*time.Second, 15*time.Minute))
	}
	details := map[string]interface{}{"status": status, "error": in.LastError}
	if !in.NextAttempt.IsZero() {
		details["next_assessment"] = in.NextAttempt
	}
	if decision != nil {
		details["assessment"] = decision.Assessment
		details["evidence"] = decision.Evidence
		details["follow_up"] = decision.FollowUp
	}
	if err := e.emitLocked("assessment_finished", in.ID, summary, details); err != nil {
		return err
	}
	return e.Store.Save(e.State)
}
func (e *Engine) emit(typ, id, summary string, details map[string]interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.emitLocked(typ, id, summary, details); err != nil {
		return err
	}
	return e.Store.Save(e.State)
}
func (e *Engine) emitLocked(typ, id, summary string, details map[string]interface{}) error {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	event := protocol.Event{ID: hex.EncodeToString(b[:]), Time: time.Now().UTC(), Host: e.Hostname, Type: typ, IncidentID: id, Summary: e.Redact(summary), Details: details}
	auditType := "event"
	if e.Reporter != nil {
		auditType = "report_queued"
	}
	if err := e.Store.Append(auditType, id, event); err != nil {
		return err
	}
	if e.Reporter != nil {
		e.State.Outbox = append(e.State.Outbox, store.Delivery{Event: event})
	}
	e.Log.Info(event.Summary, "event", typ, "incident", id)
	return nil
}
func (e *Engine) FlushReports(ctx context.Context) error {
	e.reportMu.Lock()
	defer e.reportMu.Unlock()
	if e.Reporter == nil {
		return nil
	}
	e.mu.Lock()
	var due []store.Delivery
	now := time.Now()
	for _, d := range e.State.Outbox {
		if !now.Before(d.NextAttempt) {
			due = append(due, d)
			if len(due) >= 32 {
				break
			}
		}
	}
	e.mu.Unlock()
	for _, d := range due {
		err := e.Reporter.Send(ctx, d.Event)
		if ctx.Err() != nil {
			return nil
		}
		e.mu.Lock()
		for i := range e.State.Outbox {
			if e.State.Outbox[i].Event.ID != d.Event.ID {
				continue
			}
			if err == nil {
				if ackErr := e.Store.Append("report_delivered", d.Event.IncidentID, map[string]string{"id": d.Event.ID}); ackErr != nil {
					e.mu.Unlock()
					return ackErr
				}
				e.State.Outbox = append(e.State.Outbox[:i], e.State.Outbox[i+1:]...)
			} else {
				e.State.Outbox[i].Attempts++
				e.State.Outbox[i].NextAttempt = time.Now().Add(backoff(e.State.Outbox[i].Attempts, 10*time.Second, 30*time.Minute))
				e.Log.Warn("report delivery delayed", "error", e.Redact(err.Error()))
			}
			break
		}
		saveErr := e.Store.Save(e.State)
		e.mu.Unlock()
		if saveErr != nil {
			return saveErr
		}
	}
	return nil
}
func backoff(attempt int, base, cap time.Duration) time.Duration {
	for i := 1; i < attempt && base < cap; i++ {
		if base > cap/2 {
			return cap
		}
		base *= 2
	}
	if base > cap {
		return cap
	}
	return base
}
func modelHistory(history []protocol.Turn) []protocol.Turn {
	if len(history) > 4 {
		history = history[len(history)-4:]
	}
	b, _ := json.Marshal(history)
	var copy []protocol.Turn
	json.Unmarshal(b, &copy)
	for i := range copy {
		for j := range copy[i].Results {
			r := &copy[i].Results[j]
			if len(r.Output) > 8192 {
				r.Output = r.Output[:8192] + "\n[earlier output truncated for model context; full evidence remains in local audit]"
				r.Truncated = true
			}
		}
	}
	return copy
}
func (e *Engine) cleanDecision(d protocol.Decision) protocol.Decision {
	d.Summary = e.Redact(d.Summary)
	d.FollowUp = e.Redact(d.FollowUp)
	d.Evidence = append([]string(nil), d.Evidence...)
	for i := range d.Evidence {
		d.Evidence[i] = e.Redact(d.Evidence[i])
	}
	d.Actions = append([]protocol.Action(nil), d.Actions...)
	for i := range d.Actions {
		a := &d.Actions[i]
		a.Reason = e.Redact(a.Reason)
		a.Argv = cleanStrings(a.Argv, e.Redact)
		a.Verify = cleanStrings(a.Verify, e.Redact)
		a.Rollback = cleanStrings(a.Rollback, e.Redact)
	}
	return d
}
func cleanStrings(v []string, f func(string) string) []string {
	out := make([]string, len(v))
	for i := range v {
		out[i] = f(v[i])
	}
	return out
}

// MissingSource keeps unavailable required feeds visible and retryable.
type MissingSource struct{ SourceName, Problem string }

func (m MissingSource) Name() string { return m.SourceName }
func (m MissingSource) Poll(context.Context, string) (intel.Result, error) {
	return intel.Result{}, fmt.Errorf("%s", m.Problem)
}

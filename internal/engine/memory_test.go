package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/config"
	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/memory"
	"github.com/jjcm/firefighter/internal/planner"
	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/store"
)

func memorySnapshot(version string) host.Snapshot {
	return host.Snapshot{CollectedAt: time.Now().UTC(), Hostname: "fixture-host", Platform: "linux", Packages: []host.Package{{Name: "fixture-package", Version: version, Manager: "dpkg"}}}
}

func memoryUpdate(key, text string) protocol.MemoryUpdate {
	return protocol.MemoryUpdate{Operation: "upsert", Key: key, Text: text, Evidence: []string{"fixture-package inventory"}, Tags: []string{"CVE-2026-12345"}, TTLHours: 24}
}

func memoryRequest(t *testing.T, req protocol.Request) (host.Snapshot, memoryContext) {
	t.Helper()
	snapshot, ok := req.Host.(host.Snapshot)
	if !ok {
		t.Fatalf("request host type %T, want host.Snapshot", req.Host)
	}
	context, ok := req.Memory.(memoryContext)
	if !ok {
		t.Fatalf("request memory type %T, want memoryContext", req.Memory)
	}
	return snapshot, context
}

func processMemoryIncident(t *testing.T, e *Engine) {
	t.Helper()
	if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
		t.Fatalf("process incident: worked=%v err=%v", worked, err)
	}
}

func TestMemorySharesInventoryAndNotesAcrossIncidents(t *testing.T) {
	for _, done := range []bool{true, false} {
		t.Run(fmt.Sprintf("first-decision-done-%v", done), func(t *testing.T) {
			e, dir, _ := fixtureEngine(t)
			first := addIncident(e, "pending")
			first.Item.CVEs = []string{"CVE-2026-12345"}
			collections, rounds := 0, 0
			e.Collect = func(context.Context) (host.Snapshot, error) { collections++; return memorySnapshot("1.2.3"), nil }
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				rounds++
				snapshot, mem := memoryRequest(t, req)
				if snapshot.Packages[0].Version != "1.2.3" || mem.Inventory.Stale || mem.Inventory.TTLSeconds != 300 {
					t.Fatalf("inventory provenance missing: snapshot=%+v metadata=%+v", snapshot, mem.Inventory)
				}
				if rounds == 1 {
					if mem.Inventory.Cached || len(mem.Notes) != 0 {
						t.Fatalf("first request unexpectedly reused memory: %+v", mem)
					}
					assessment := "not_affected"
					if !done {
						assessment = "unknown"
					}
					return protocol.Decision{Done: done, Assessment: assessment, Summary: "Observed fixture package", MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("fixture-package", "Observed package 1.2.3; recheck before remediation")}}, nil
				}
				if !mem.Inventory.Cached || len(mem.Notes) != 1 || mem.Notes[0].Key != "fixture-package" || mem.Notes[0].IncidentID != first.ID {
					t.Fatalf("second incident lost shared evidence/provenance: %+v", mem)
				}
				if len(mem.PreviousIncidents) != 1 || mem.PreviousIncidents[0].IncidentID != first.ID {
					t.Fatalf("second incident lacks prior conclusion: %+v", mem.PreviousIncidents)
				}
				return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Rechecked fixture", MemoryUpdates: []protocol.MemoryUpdate{{Operation: "delete", Key: "fixture-package"}}}, nil
			})
			processMemoryIncident(t, e)
			saved := readState(t, dir)
			if saved.Memory.Notes["fixture-package"].Text == "" || saved.Memory.Inventory == nil {
				t.Fatal("actionless decision did not persist note and inventory")
			}
			second := scheduledIncident(e, "second-disclosure", "pending", time.Now().UTC())
			second.Item.CVEs = []string{"CVE-2026-12345"}
			processMemoryIncident(t, e)
			if collections != 1 || rounds != 2 {
				t.Fatalf("cache was not shared: collections=%d rounds=%d", collections, rounds)
			}
			if _, exists := readState(t, dir).Memory.Notes["fixture-package"]; exists {
				t.Fatal("actionless note deletion was not persisted")
			}
		})
	}
}

func TestMemoryRestartRetainsNotesButRefreshesInventory(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	addIncident(e, "pending")
	e.Collect = func(context.Context) (host.Snapshot, error) { return memorySnapshot("before-restart"), nil }
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Save observation", MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("durable-note", "Previously observed fixture package")}}, nil
	})
	processMemoryIncident(t, e)
	if err := e.Store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, state, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if state.Memory.Inventory == nil || state.Memory.Inventory.InvalidatedAt.IsZero() || len(state.Memory.Notes) != 1 {
		t.Fatalf("restart lost notes or trusted old inventory: %+v", state.Memory)
	}
	restarted := &Engine{Config: e.Config, Store: reopened, State: state, Runner: &fakeRunner{exitCode: map[string]int{}}, Log: e.Log}
	collections := 0
	restarted.Collect = func(context.Context) (host.Snapshot, error) {
		collections++
		return memorySnapshot("after-restart"), nil
	}
	restarted.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		snapshot, mem := memoryRequest(t, req)
		if snapshot.Packages[0].Version != "after-restart" || mem.Inventory.Cached || mem.Inventory.Stale || len(mem.Notes) != 1 || mem.Notes[0].Key != "durable-note" {
			t.Fatalf("restart context incorrect: snapshot=%+v memory=%+v", snapshot, mem)
		}
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Reviewed after restart"}, nil
	})
	scheduledIncident(restarted, "after-restart", "pending", time.Now().UTC())
	processMemoryIncident(t, restarted)
	if collections != 1 {
		t.Fatalf("restart collected %d times, want 1", collections)
	}
}

type memoryCheckingRunner struct {
	before  func(protocol.Action)
	exits   map[string]int
	calls   []string
	results map[string]protocol.ActionResult
}

func (r *memoryCheckingRunner) Validate(action protocol.Action) error { return host.Validate(action) }
func (r *memoryCheckingRunner) Run(_ context.Context, action protocol.Action) protocol.ActionResult {
	r.before(action)
	r.calls = append(r.calls, action.ID)
	if result, ok := r.results[action.ID]; ok {
		result.ActionID = action.ID
		return result
	}
	return protocol.ActionResult{ActionID: action.ID, ExitCode: r.exits[action.ID], StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}
}

func TestMemoryInvalidatesDurablyBeforeEveryExecutedCommand(t *testing.T) {
	for _, tc := range []struct {
		name              string
		mutates, recovery bool
		calls             []string
	}{
		{"mutation", true, false, []string{"inspect-or-patch"}},
		{"declared-read-only", false, false, []string{"inspect-or-patch"}},
		{"verification-and-rollback", true, true, []string{"inspect-or-patch", "inspect-or-patch-verify", "inspect-or-patch-rollback"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, dir, _ := fixtureEngine(t)
			addIncident(e, "pending")
			version, collections, rounds := "before", 0, 0
			e.Collect = func(context.Context) (host.Snapshot, error) { collections++; return memorySnapshot(version), nil }
			runner := &memoryCheckingRunner{exits: map[string]int{}, before: func(action protocol.Action) {
				cached := readState(t, dir).Memory.Inventory
				if cached == nil || cached.InvalidatedAt.IsZero() || cached.InvalidatedReason == "" || cached.Fresh(time.Now()) {
					t.Fatalf("%s began before durable invalidation: %+v", action.ID, cached)
				}
				// Even a command labeled read-only can change the machine.
				version = "after"
			}}
			if tc.recovery {
				runner.exits["inspect-or-patch-verify"] = 1
			}
			e.Runner = runner
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				rounds++
				snapshot, mem := memoryRequest(t, req)
				if rounds == 1 {
					action := protocol.Action{ID: "inspect-or-patch", Kind: "command", Argv: []string{"/bin/true"}, Reason: "Inspect or repair fixture", Mutates: tc.mutates}
					if tc.recovery {
						action.Verify = []string{"/bin/false"}
						action.Rollback = []string{"/bin/true"}
					}
					return protocol.Decision{Assessment: "unknown", Summary: "Investigate fixture", Actions: []protocol.Action{action}}, nil
				}
				if snapshot.Packages[0].Version != "after" || mem.Inventory.Cached || mem.Inventory.Stale || collections != 2 {
					t.Fatalf("next model round reused pre-command inventory: snapshot=%+v metadata=%+v collections=%d", snapshot, mem.Inventory, collections)
				}
				return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Current version inspected"}, nil
			})
			processMemoryIncident(t, e)
			if !reflect.DeepEqual(runner.calls, tc.calls) || rounds != 2 {
				t.Fatalf("unexpected execution: calls=%v rounds=%d", runner.calls, rounds)
			}
		})
	}
}

func TestMemoryCacheAndNotesExpireBeforeNextIncident(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	now := time.Now().UTC()
	e.State.Memory.Inventory = &memory.Inventory{Snapshot: memorySnapshot("expired")}
	e.State.Memory.Inventory.Snapshot.CollectedAt = now.Add(-memory.CacheTTL - time.Second)
	e.State.Memory.Notes = map[string]memory.Note{
		"expired": {Key: "expired", Text: "Obsolete package version", UpdatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		"current": {Key: "current", Text: "Still relevant observation", UpdatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
	}
	collections := 0
	e.Collect = func(context.Context) (host.Snapshot, error) { collections++; return memorySnapshot("fresh"), nil }
	e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		snapshot, mem := memoryRequest(t, req)
		if snapshot.Packages[0].Version != "fresh" || mem.Inventory.Cached || mem.Inventory.Stale || len(mem.Notes) != 1 || mem.Notes[0].Key != "current" {
			t.Fatalf("expired memory reached planner: snapshot=%+v memory=%+v", snapshot, mem)
		}
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Expiry checked"}, nil
	})
	addIncident(e, "pending")
	processMemoryIncident(t, e)
	if collections != 1 {
		t.Fatalf("expired cache collected %d times", collections)
	}
	if _, exists := readState(t, dir).Memory.Notes["expired"]; exists {
		t.Fatal("expired note remained durable")
	}
}

func TestMemoryFailedRefreshIsExplicitAndRetried(t *testing.T) {
	for _, haveCache := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing-cache-%v", haveCache), func(t *testing.T) {
			e, dir, _ := fixtureEngine(t)
			if haveCache {
				e.State.Memory.Inventory = &memory.Inventory{Snapshot: memorySnapshot("stale-version"), InvalidatedAt: time.Now().UTC(), InvalidatedReason: "prior command"}
			}
			collections, rounds := 0, 0
			e.Collect = func(context.Context) (host.Snapshot, error) {
				collections++
				if collections == 1 {
					return host.Snapshot{}, errors.New("fixture inventory unavailable")
				}
				return memorySnapshot("recovered-version"), nil
			}
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				rounds++
				snapshot, mem := memoryRequest(t, req)
				if rounds == 1 {
					if !mem.Inventory.Stale || !strings.Contains(mem.Inventory.RefreshError, "fixture inventory unavailable") || len(snapshot.Problems) == 0 {
						t.Fatalf("collection failure disguised as fresh inventory: snapshot=%+v metadata=%+v", snapshot, mem.Inventory)
					}
				} else if mem.Inventory.Stale || mem.Inventory.Cached || mem.Inventory.RefreshError != "" || snapshot.Packages[0].Version != "recovered-version" {
					t.Fatalf("failed collection poisoned later cache: snapshot=%+v metadata=%+v", snapshot, mem.Inventory)
				}
				return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Fixture assessment only"}, nil
			})
			addIncident(e, "pending")
			processMemoryIncident(t, e)
			if cached := readState(t, dir).Memory.Inventory; cached != nil && cached.Fresh(time.Now()) {
				t.Fatalf("failed refresh was committed as fresh: %+v", cached)
			}
			scheduledIncident(e, "retry-collection", "pending", time.Now().UTC())
			processMemoryIncident(t, e)
			if collections != 2 || rounds != 2 {
				t.Fatalf("failed inventory not retried: collections=%d rounds=%d", collections, rounds)
			}
		})
	}
}

func TestMemoryPeriodicHostReviewsForceNewInventory(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	e.State.Memory.Inventory = &memory.Inventory{Snapshot: memorySnapshot("cached-before-review")}
	collections := 0
	e.Collect = func(context.Context) (host.Snapshot, error) {
		collections++
		return memorySnapshot(fmt.Sprintf("review-%d", collections)), nil
	}
	e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		snapshot, mem := memoryRequest(t, req)
		if mem.Inventory.Cached || mem.Inventory.Stale || snapshot.Packages[0].Version != fmt.Sprintf("review-%d", collections) {
			t.Fatalf("posture review trusted preceding cache: snapshot=%+v metadata=%+v", snapshot, mem.Inventory)
		}
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Posture review complete"}, nil
	})
	for i := 0; i < 2; i++ {
		e.State.LastHostReview = time.Now().Add(-config.Seconds(e.Config.InventorySeconds) - time.Second)
		if err := e.enqueueHostReview(); err != nil {
			t.Fatal(err)
		}
		processMemoryIncident(t, e)
	}
	if collections != 2 {
		t.Fatalf("two reviews collected %d times", collections)
	}
}

func TestMemoryRejectsInvalidAndUnverifiedUpdates(t *testing.T) {
	for _, tc := range []struct {
		name               string
		action, invalidTTL bool
		assessment         string
	}{
		{"unverified-remediation", false, false, "remediated"},
		{"invalid-ttl", false, true, "not_affected"},
		{"invalid-ttl-with-action", true, true, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, dir, runner := fixtureEngine(t)
			in := addIncident(e, "pending")
			e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
				update := memoryUpdate("premature-conclusion", "All fixed")
				if tc.invalidTTL {
					update.TTLHours = 0
				}
				d := protocol.Decision{Done: true, Assessment: tc.assessment, Summary: "Premature conclusion", MemoryUpdates: []protocol.MemoryUpdate{update}}
				if tc.action {
					d.Done = false
					d.Actions = []protocol.Action{{ID: "not-yet-executed", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Reason: "Potential change", Mutates: true}}
				}
				return d, nil
			})
			processMemoryIncident(t, e)
			if len(readState(t, dir).Memory.Notes) != 0 || in.Status != "deferred" || len(runner.called()) != 0 {
				t.Fatalf("invalid conclusion persisted or acted on: notes=%v status=%s calls=%v", e.State.Memory.Notes, in.Status, runner.called())
			}
		})
	}
}

func TestMemoryMixedDecisionRunsActionsAndReconsidersNotesAfterResults(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	in := addIncident(e, "pending")
	const premature = "premature-note-content-must-not-be-retained"
	e.State.Memory.Apply([]protocol.MemoryUpdate{memoryUpdate("existing", "Previously observed fact")}, "earlier", time.Now().UTC())
	checkDiscarded := func() {
		t.Helper()
		saved := readState(t, dir)
		if len(saved.Memory.Notes) != 1 || saved.Memory.Notes["existing"].Text != "Previously observed fact" {
			t.Fatalf("mixed update was applied: %+v", saved.Memory.Notes)
		}
		if len(saved.Incidents[in.ID].RecoveryNotes) != 1 || saved.Incidents[in.ID].RecoveryNotes[0] != discardedMemoryUpdateNote {
			t.Fatal("omission recovery note was not durably checkpointed")
		}
		for _, filename := range []string{"state.json", "audit.jsonl"} {
			b, err := os.ReadFile(filepath.Join(dir, filename))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), premature) {
				t.Fatalf("discarded memory content retained in %s", filename)
			}
		}
	}
	runner := &memoryCheckingRunner{before: func(protocol.Action) { checkDiscarded() }}
	e.Runner = runner
	rounds := 0
	e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		rounds++
		var d protocol.Decision
		if rounds == 1 {
			d = protocol.Decision{Summary: "Update fixture package", Assessment: "exposed", Evidence: []string{}, Actions: []protocol.Action{{ID: "fix", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "Apply fixture fix"}}, MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("premature", premature), {Operation: "delete", Key: "existing", Evidence: []string{}, Tags: []string{}}}}
		} else {
			checkDiscarded()
			if len(req.RecoveryNotes) != 1 || req.RecoveryNotes[0] != discardedMemoryUpdateNote {
				t.Fatalf("next planner turn lacks omission feedback: %v", req.RecoveryNotes)
			}
			if len(req.History) != 1 || len(req.History[0].Decision.MemoryUpdates) != 0 || len(req.History[0].Results) != 2 || req.History[0].Results[1].ActionID != "fix-verify" {
				t.Fatalf("next planner turn lost actual results or retained premature notes: %+v", req.History)
			}
			encoded, err := json.Marshal(req)
			if err != nil || strings.Contains(string(encoded), premature) {
				t.Fatalf("discarded note entered the next model request: %v", err)
			}
			d = protocol.Decision{Summary: "Observed successful fixture fix and verification", Assessment: "remediated", Done: true, Evidence: []string{}, Actions: []protocol.Action{}, MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("observed", "Fixture fix passed its verification")}}
		}
		// Exercise the actual parser boundary that previously rejected this reply.
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return planner.ParseDecision(b, e.Config.MaxActionsPerRound)
	})
	processMemoryIncident(t, e)
	if rounds != 2 || in.Status != "completed" || in.LastError != "" || !reflect.DeepEqual(runner.calls, []string{"fix", "fix-verify"}) {
		t.Fatalf("mixed decision stalled valid work: rounds=%d status=%s error=%q calls=%v", rounds, in.Status, in.LastError, runner.calls)
	}
	saved := readState(t, dir)
	if len(saved.Memory.Notes) != 2 || saved.Memory.Notes["observed"].Text != "Fixture fix passed its verification" {
		t.Fatalf("actionless observed note was not saved: %+v", saved.Memory.Notes)
	}
	audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	omissions := 0
	for _, line := range strings.Split(strings.TrimSpace(string(audit)), "\n") {
		var record store.Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record.Type == "memory_updates_discarded" {
			omissions++
			var data map[string]interface{}
			if err := json.Unmarshal(record.Data, &data); err != nil {
				t.Fatal(err)
			}
			if len(data) != 2 || data["count"] != float64(2) || data["reason"] != "pending_actions" {
				t.Fatalf("omission audit must contain only count and reason: %v", data)
			}
		}
	}
	if omissions != 1 || strings.Contains(string(audit), premature) {
		t.Fatalf("unexpected omission audit: count=%d", omissions)
	}
}

func TestMemoryMixedDecisionObserveModeDiscardsNotesWithoutExecution(t *testing.T) {
	e, dir, runner := fixtureEngine(t)
	e.Config.Observe = true
	in := addIncident(e, "pending")
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		return protocol.Decision{Summary: "Propose fixture fix", Assessment: "exposed", Actions: []protocol.Action{{ID: "fix", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Mutates: true, Reason: "Fix fixture"}}, MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("premature", "Planned fix succeeded")}}, nil
	})
	processMemoryIncident(t, e)
	saved := readState(t, dir)
	if in.Status != "observed" || len(runner.called()) != 0 || len(saved.Memory.Notes) != 0 || len(saved.Incidents[in.ID].History[0].Decision.MemoryUpdates) != 0 {
		t.Fatalf("observe mode executed work or saved premature notes: status=%s calls=%v memory=%+v", in.Status, runner.called(), saved.Memory)
	}
}

func TestMemoryMixedNotesStayDiscardedAcrossFailureAndRestart(t *testing.T) {
	for _, exitCode := range []int{0, 1} {
		t.Run(fmt.Sprintf("inspection-exit-%d", exitCode), func(t *testing.T) {
			e, dir, runner := fixtureEngine(t)
			e.Config.MaxRounds = 2
			in := addIncident(e, "pending")
			runner.exitCode["inspect"] = exitCode
			rounds := 0
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				rounds++
				if rounds > 1 && (len(req.History[0].Results) != 1 || req.History[0].Results[0].ExitCode != exitCode || len(req.RecoveryNotes) != 1) {
					t.Fatalf("replan lost execution result or omission feedback: %+v", req)
				}
				return protocol.Decision{Summary: "Inspect fixture", Assessment: "unknown", Actions: []protocol.Action{{ID: "inspect", Kind: "command", Argv: []string{"/bin/true"}, Reason: "Check fixture"}}, MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("premature", "Unobserved result must not survive")}}, nil
			})
			processMemoryIncident(t, e)
			saved := readState(t, dir)
			if in.Status != "deferred" || in.LastError != "round budget exhausted" || len(runner.called()) != 2 || len(saved.Memory.Notes) != 0 || len(saved.Incidents[in.ID].RecoveryNotes) != 1 {
				t.Fatalf("round exhaustion retained notes or lost progress: status=%s error=%q calls=%v notes=%v recovery=%v", in.Status, in.LastError, runner.called(), saved.Memory.Notes, saved.Incidents[in.ID].RecoveryNotes)
			}
			if err := e.Store.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, state, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reopened.Close() })
			e.Store, e.State = reopened, state
			state.Incidents[in.ID].NextAttempt = time.Time{}
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				if len(req.History) != 2 || req.History[1].Results[0].ExitCode != exitCode || req.RecoveryNotes[0] != discardedMemoryUpdateNote {
					t.Fatalf("restart lost actual results or persisted omission feedback: %+v", req)
				}
				encoded, err := json.Marshal(req)
				if err != nil || strings.Contains(string(encoded), "Unobserved result must not survive") {
					t.Fatalf("discarded note reached restarted planner: %v", err)
				}
				observed := fmt.Sprintf("Inspection returned exit code %d; assessment remains unresolved", exitCode)
				return protocol.Decision{Summary: "Record actual inspection outcome", Assessment: "unknown", FollowUp: "Further investigation needed", MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("observed", observed)}}, nil
			})
			processMemoryIncident(t, e)
			if notes := readState(t, dir).Memory.Notes; len(notes) != 1 || notes["observed"].Text == "" || len(runner.called()) != 2 {
				t.Fatalf("restart replayed work or did not save actionless observation: notes=%v calls=%v", notes, runner.called())
			}
		})
	}
}

func TestMemoryRedactsInventoryAndNotesBeforePersistenceAndRetrieval(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	secret := "fixture-sensitive-token"
	e.Redact = func(value string) string { return strings.ReplaceAll(value, secret, "[redacted]") }
	e.Collect = func(context.Context) (host.Snapshot, error) {
		snapshot := memorySnapshot("version-" + secret)
		snapshot.Hostname, snapshot.Services, snapshot.Containers = secret, secret, secret
		snapshot.OSRelease = map[string]string{"PRETTY_NAME": secret}
		snapshot.Probes = []host.ProbeStatus{{Name: "fixture", Error: secret}}
		snapshot.Problems = []host.Problem{{Probe: "fixture", Kind: "incomplete", Detail: secret}}
		return snapshot, nil
	}
	rounds := 0
	e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		rounds++
		_, mem := memoryRequest(t, req)
		encoded, err := json.Marshal(struct{ Host, Memory interface{} }{req.Host, req.Memory})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Fatal("model received unredacted shared memory or inventory")
		}
		if rounds == 2 && (len(mem.Notes) != 2 || !mem.Inventory.Cached) {
			t.Fatalf("retrieval did not reuse saved observations: %+v", mem)
		}
		if rounds == 1 {
			update := memoryUpdate("secret-bearing-note", "Observed "+secret)
			update.Evidence, update.Tags = []string{"Evidence " + secret}, []string{secret}
			return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "First assessment", MemoryUpdates: []protocol.MemoryUpdate{update}}, nil
		}
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Second assessment"}, nil
	})
	addIncident(e, "pending")
	processMemoryIncident(t, e)
	for _, filename := range []string{"state.json", "audit.jsonl"} {
		data, err := os.ReadFile(filepath.Join(dir, filename))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), secret) {
			t.Fatalf("%s retained unredacted inventory/note data", filename)
		}
	}
	// A newly configured redactor must also scrub older cached observations at retrieval.
	now := time.Now().UTC()
	e.State.Memory.Notes["older-note"] = memory.Note{Key: "older-note", Text: secret, Evidence: []string{secret}, Tags: []string{secret}, UpdatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	e.State.Memory.Inventory.Snapshot.Kernel = secret
	scheduledIncident(e, "redacted-retrieval", "pending", now)
	processMemoryIncident(t, e)
}

func TestMemoryPreviousIncidentsAreRelevantBoundedAndExcludeUnassessedWork(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	now := time.Now().UTC()
	current := addIncident(e, "pending")
	current.Item.CVEs = []string{"CVE-2026-12345"}
	current.History = []protocol.Turn{{Decision: protocol.Decision{Assessment: "unknown", Summary: "Current assessment must not duplicate itself"}}}
	matching := scheduledIncident(e, "older-matching-cve", "completed", now.Add(-24*time.Hour), "exposed")
	matching.Item.CVEs = []string{"CVE-2026-12345"}
	matching.Item.Title = strings.Repeat("t", 500)
	matching.History[0].Decision.Summary = strings.Repeat("s", 1500)
	matching.History[0].Decision.FollowUp = strings.Repeat("f", 1500)
	matching.LastError = strings.Repeat("e", 800)
	matching.History[0].Decision.Evidence = make([]string, 10)
	for i := range matching.History[0].Decision.Evidence {
		matching.History[0].Decision.Evidence[i] = strings.Repeat("v", 700)
	}
	for i := 0; i < 20; i++ {
		matching.Item.CVEs = append(matching.Item.CVEs, strings.Repeat("C", 100))
	}
	for i := 0; i < 12; i++ {
		scheduledIncident(e, fmt.Sprintf("recent-other-%02d", i), "completed", now.Add(-time.Duration(i+1)*time.Minute), "not_affected")
	}
	pending := scheduledIncident(e, "pending-with-old-history", "pending", now.Add(time.Minute), "unknown")
	pending.NextAttempt = now.Add(time.Hour)
	scheduledIncident(e, "no-assessment-history", "completed", now)
	e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		_, mem := memoryRequest(t, req)
		if len(mem.PreviousIncidents) != 8 || mem.PreviousIncidents[0].IncidentID != matching.ID || mem.PreviousIncidents[1].IncidentID != "recent-other-00" {
			t.Fatalf("prior assessment relevance/recency order incorrect: %+v", mem.PreviousIncidents)
		}
		for _, previous := range mem.PreviousIncidents {
			if previous.IncidentID == current.ID || previous.IncidentID == pending.ID || previous.IncidentID == "no-assessment-history" {
				t.Fatalf("ineligible prior assessment included: %+v", previous)
			}
			if len(previous.Title) > 200 || len(previous.Summary) > 600 || len(previous.FollowUp) > 600 || len(previous.LastError) > 300 || len(previous.Evidence) > 4 || len(previous.CVEs) > 16 {
				t.Fatalf("prior assessment exceeded context bounds: %+v", previous)
			}
			for _, evidence := range previous.Evidence {
				if len(evidence) > 300 {
					t.Fatal("prior evidence exceeded 300 bytes")
				}
			}
			for _, cve := range previous.CVEs {
				if len(cve) > 64 {
					t.Fatal("prior CVE exceeded 64 bytes")
				}
			}
		}
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Context bounded"}, nil
	})
	processMemoryIncident(t, e)
}

func TestMemoryRejectedRemediationRetainsFailureWithoutPromotingClaim(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	first := addIncident(e, "pending")
	first.Item.CVEs = []string{"CVE-2026-12345"}
	actionID := strings.Repeat("failed-patch-", 20)
	rawOutput := "raw-command-evidence-not-for-cross-incident-memory"
	finished := time.Now().UTC()
	e.Runner = &memoryCheckingRunner{before: func(protocol.Action) {}, results: map[string]protocol.ActionResult{
		actionID: {ExitCode: 23, Error: strings.Repeat("failure ", 100), Output: rawOutput, TimedOut: true, Skipped: true, FinishedAt: finished},
	}}
	rounds := 0
	e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		rounds++
		if rounds == 1 {
			return protocol.Decision{Assessment: "exposed", Summary: "Attempt a fix", Actions: []protocol.Action{{ID: actionID, Kind: "command", Argv: []string{"/bin/false"}, Mutates: true, Reason: "Fixture fix"}}}, nil
		}
		if rounds == 2 {
			return protocol.Decision{Done: true, Assessment: "remediated", Summary: "Incorrect claim after failed fix", MemoryUpdates: []protocol.MemoryUpdate{memoryUpdate("false-fix", "The fixture was fixed")}}, nil
		}
		_, mem := memoryRequest(t, req)
		if len(mem.PreviousIncidents) != 1 {
			t.Fatalf("missing rejected prior assessment: %+v", mem)
		}
		previous := mem.PreviousIncidents[0]
		if previous.IncidentID != first.ID || previous.Assessment != "unknown" || previous.FinalAssessment || previous.Status != "deferred" || !strings.Contains(previous.LastError, "verification required") {
			t.Fatalf("rejected remediation became trusted history: %+v", previous)
		}
		if len(previous.LastActionResults) != 1 {
			t.Fatalf("failed result omitted: %+v", previous)
		}
		failure := previous.LastActionResults[0]
		if len(failure.ActionID) > 128 || len(failure.Error) > 300 || failure.Error == "" || failure.ExitCode != 23 || !failure.TimedOut || !failure.Skipped || !failure.FinishedAt.Equal(finished) {
			t.Fatalf("failed action metadata lost or unbounded: %+v", failure)
		}
		encoded, err := json.Marshal(mem)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), rawOutput) || strings.Contains(string(encoded), `"output"`) {
			t.Fatal("raw command output leaked into cross-incident memory")
		}
		if len(mem.Notes) != 0 {
			t.Fatalf("rejected fix created a durable note: %+v", mem.Notes)
		}
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Follow-up evidence assessed"}, nil
	})
	processMemoryIncident(t, e)
	saved := readState(t, dir).Incidents[first.ID]
	if saved.Status != "deferred" || saved.History[len(saved.History)-1].Decision.Assessment != "remediated" {
		t.Fatalf("fixture did not retain the rejected claim being tested: %+v", saved)
	}
	second := scheduledIncident(e, "related-cve-after-rejection", "pending", time.Now().UTC())
	second.Item.CVEs = []string{"CVE-2026-12345"}
	processMemoryIncident(t, e)
	if rounds != 3 {
		t.Fatalf("expected three planner turns, got %d", rounds)
	}
}

func TestMemoryPreviousActionResultsKeepOnlyLatestBoundedMetadata(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	now := time.Now().UTC()
	prior := scheduledIncident(e, "prior-many-results", "completed", now.Add(-time.Hour), "unknown", "unknown")
	for i := 0; i < 7; i++ {
		prior.History[0].Results = append(prior.History[0].Results, protocol.ActionResult{ActionID: fmt.Sprintf("action-%d", i), ExitCode: i, Output: "raw evidence stays in audit", Error: strings.Repeat("err ", 100), FinishedAt: now.Add(-time.Duration(7-i) * time.Minute)})
	}
	addIncident(e, "pending")
	e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		_, mem := memoryRequest(t, req)
		if len(mem.PreviousIncidents) != 1 || len(mem.PreviousIncidents[0].LastActionResults) != 4 {
			t.Fatalf("result bound was not enforced: %+v", mem)
		}
		for i, result := range mem.PreviousIncidents[0].LastActionResults {
			if result.ActionID != fmt.Sprintf("action-%d", i+3) || result.ExitCode != i+3 || len(result.Error) > 300 {
				t.Fatalf("wrong action metadata retained: %+v", result)
			}
		}
		encoded, err := json.Marshal(mem)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "raw evidence stays in audit") {
			t.Fatal("result summary retained raw output")
		}
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Reviewed bounded action metadata"}, nil
	})
	processMemoryIncident(t, e)
}

func TestMemoryRedactionExpansionKeepsValidNotesAndDropsOnlyInvalidKey(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	secret := "secretmarker"
	e.Redact = func(value string) string {
		return strings.ReplaceAll(value, secret, strings.Repeat("[redacted]", 1000))
	}
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		expanding := memoryUpdate("expanded-note", secret)
		expanding.Evidence, expanding.Tags = []string{secret}, []string{secret}
		invalidKey := memoryUpdate(secret+"-key", "This key will no longer be a valid identifier")
		unrelated := memoryUpdate("ordinary-note", "Unrelated observed fact")
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Record redacted evidence", MemoryUpdates: []protocol.MemoryUpdate{expanding, invalidKey, unrelated}}, nil
	})
	addIncident(e, "pending")
	processMemoryIncident(t, e)
	notes := readState(t, dir).Memory.Notes
	expanded, ok := notes["expanded-note"]
	if len(notes) != 2 || !ok || notes["ordinary-note"].Text != "Unrelated observed fact" {
		t.Fatalf("one invalid redacted key discarded unrelated valid notes: %+v", notes)
	}
	if len(expanded.Text) > 2000 || !strings.Contains(expanded.Text, "[redacted]") || len(expanded.Evidence) != 1 || len(expanded.Evidence[0]) > 500 || len(expanded.Tags) != 1 || len(expanded.Tags[0]) > 64 {
		t.Fatalf("redaction expansion exceeded note bounds: %+v", expanded)
	}
	for _, filename := range []string{"state.json", "audit.jsonl"} {
		data, err := os.ReadFile(filepath.Join(dir, filename))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), secret) {
			t.Fatalf("%s retained the redacted key or content", filename)
		}
	}
}

func TestMemoryPlannerCannotMutateFreshOrCachedInventoryThroughRequest(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	collected := memorySnapshot("original-version")
	collected.OSRelease = map[string]string{"VERSION_ID": "original-release"}
	collected.Scanners = []host.ToolStatus{{Name: "fixture-scanner", Path: "/usr/bin/fixture-scanner"}}
	collected.Probes = []host.ProbeStatus{{Name: "fixture-probe", Error: "original-error"}}
	collected.Problems = []host.Problem{{Probe: "fixture-probe", Detail: "original-detail"}}
	original, err := json.Marshal(collected)
	if err != nil {
		t.Fatal(err)
	}
	collections, rounds := 0, 0
	e.Collect = func(context.Context) (host.Snapshot, error) { collections++; return collected, nil }
	e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
		rounds++
		snapshot, mem := memoryRequest(t, req)
		if mem.Inventory.Cached != (rounds == 2) {
			t.Fatalf("unexpected cache path on turn %d: %+v", rounds, mem.Inventory)
		}
		snapshot.OSRelease["VERSION_ID"] = "tampered-request"
		snapshot.Packages[0].Version = "tampered-request"
		snapshot.Scanners[0].Path = "tampered-request"
		snapshot.Probes[0].Error = "tampered-request"
		snapshot.Problems[0].Detail = "tampered-request"
		for name, shared := range map[string]host.Snapshot{"cache": e.State.Memory.Inventory.Snapshot, "collector buffer": collected} {
			encoded, err := json.Marshal(shared)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != string(original) {
				t.Fatalf("planner mutated %s through request fields", name)
			}
		}
		return protocol.Decision{Done: true, Assessment: "not_affected", Summary: "Request isolated"}, nil
	})
	addIncident(e, "pending")
	processMemoryIncident(t, e)
	scheduledIncident(e, "cache-isolation-follow-up", "pending", time.Now().UTC())
	processMemoryIncident(t, e)
	encoded, err := json.Marshal(readState(t, dir).Memory.Inventory.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(original) || collections != 1 || rounds != 2 {
		t.Fatalf("inventory isolation/cache reuse failed: collections=%d rounds=%d cache=%s", collections, rounds, encoded)
	}
}

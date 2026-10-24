package engine

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/protocol"
)

type verificationRecoveryRunner struct {
	runner *host.Runner
	calls  []protocol.Action
}

func (r *verificationRecoveryRunner) Validate(a protocol.Action) error { return r.runner.Validate(a) }
func (r *verificationRecoveryRunner) Run(ctx context.Context, a protocol.Action) protocol.ActionResult {
	r.calls = append(r.calls, a)
	return r.runner.Run(ctx, a)
}

func TestPartialMutationRequiresFormalVerificationRecovery(t *testing.T) {
	for _, tc := range []struct {
		name    string
		formal  bool
		healthy bool
	}{
		{"verification-only recovery", true, true},
		{"ordinary successful assertion is not formal verification", false, true},
		{"failed formal assertion remains unresolved", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _, _ := fixtureEngine(t)
			in := addIncident(e, "pending")
			dir := t.TempDir()
			patched, health := filepath.Join(dir, "patched-version"), filepath.Join(dir, "service-health")
			healthValue := "healthy"
			if !tc.healthy {
				healthValue = "failed"
			}
			if err := os.WriteFile(health, []byte(healthValue), 0600); err != nil {
				t.Fatal(err)
			}
			runner := &verificationRecoveryRunner{runner: host.NewRunner(host.Config{})}
			e.Runner = runner
			round := 0
			e.Planner = plannerFunc(func(_ context.Context, req protocol.Request) (protocol.Decision, error) {
				round++
				switch round {
				case 1:
					// Simulate a command that installs the fixed content but fails
					// later. The engine must not run its automatic verification.
					return protocol.Decision{Summary: "Apply fixture fix", Assessment: "exposed", Applicability: affectedFixtureApplicability(), Actions: []protocol.Action{{
						ID: "partial-patch", Kind: "command", Mutates: true, Reason: "Apply fixture fix",
						Argv:   []string{"/bin/sh", "-c", `printf '%s' patched > "$1"; exit 17`, "fixture", patched},
						Verify: []string{"/bin/false"},
					}}}, nil
				case 2:
					if len(req.History) != 1 || len(req.History[0].Results) != 1 || req.History[0].Results[0].ExitCode != 17 {
						t.Fatal("planner did not receive the failed partial mutation")
					}
					if value, err := os.ReadFile(patched); err != nil || string(value) != "patched" {
						t.Fatalf("fixture did not leave the intended partial change: value=%q err=%v", value, err)
					}
					assertion := []string{"/bin/sh", "-c", `test "$(cat "$1")" = patched && test "$(cat "$2")" = healthy`, "fixture", patched, health}
					a := protocol.Action{ID: "verify-existing-fix", Kind: "command", Reason: "Verify the existing fixture change and service health", Argv: assertion}
					if tc.formal {
						a.Argv = []string{"/bin/sh", "-c", `test -f "$1"`, "fixture", patched}
						a.Verify = assertion
					}
					return protocol.Decision{Summary: "Check the existing partial change without another mutation", Assessment: "exposed", Applicability: affectedFixtureApplicability(), Actions: []protocol.Action{a}}, nil
				default:
					return protocol.Decision{Summary: "Fixture fix verified", Assessment: "remediated", Applicability: affectedFixtureApplicability(), Done: true}, nil
				}
			})
			if _, err := e.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			var ids []string
			mutations := 0
			for _, action := range runner.calls {
				ids = append(ids, action.ID)
				if action.Mutates {
					mutations++
				}
			}
			want := []string{"partial-patch", "verify-existing-fix"}
			if tc.formal {
				want = append(want, "verify-existing-fix-verify")
			}
			if !reflect.DeepEqual(ids, want) || mutations != 1 || round != 3 {
				t.Fatalf("unexpected commands or repeated mutation: calls=%v mutations=%d rounds=%d", ids, mutations, round)
			}
			if tc.formal && tc.healthy {
				if in.Status != "completed" || !in.NextAttempt.IsZero() || in.LastError != "" {
					t.Fatalf("successful verification-only recovery did not complete: %+v", in)
				}
			} else if in.Status != "deferred" || !strings.Contains(in.LastError, "verification required") {
				t.Fatalf("unverified or failed check closed remediation: %+v", in)
			}
		})
	}
}

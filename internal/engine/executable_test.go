package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jjcm/firefighter/internal/protocol"
)

func TestMalformedLaterCommandPreventsEntireBatchExecution(t *testing.T) {
	for _, field := range []string{"argv", "verify", "rollback"} {
		t.Run(field, func(t *testing.T) {
			e, dir, runner := fixtureEngine(t)
			in := addIncident(e, "pending")
			e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
				later := protocol.Action{ID: "later-change", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Reason: "Later repair", Mutates: true}
				malformed := []string{"/usr/sbin/ufw delete limit 22/tcp && /usr/sbin/ufw allow 22/tcp"}
				switch field {
				case "argv":
					later.Argv = malformed
				case "verify":
					later.Verify = malformed
				case "rollback":
					later.Rollback = malformed
				}
				return protocol.Decision{Summary: "Repair two components", Assessment: "exposed", Applicability: affectedFixtureApplicability(), Actions: []protocol.Action{
					{ID: "first-change", Kind: "command", Argv: []string{"/bin/true"}, Verify: []string{"/bin/true"}, Reason: "Earlier valid repair", Mutates: true},
					later,
				}}, nil
			})
			if _, err := e.ProcessOne(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(runner.called()) != 0 || in.Status != "deferred" || !strings.Contains(in.LastError, "single token") || in.NextAttempt.IsZero() {
				t.Fatalf("batch began before %s validation: calls=%v status=%s error=%q retry=%v", field, runner.called(), in.Status, in.LastError, in.NextAttempt)
			}
			audit, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(audit), `"action_intent"`) {
				t.Fatal("invalid batch reached action intent")
			}
		})
	}
}

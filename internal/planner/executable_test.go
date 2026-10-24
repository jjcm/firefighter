package planner

import (
	"strings"
	"testing"

	"github.com/jjcm/firefighter/internal/protocol"
)

func TestDecisionRejectsMalformedExecutableInEveryCommand(t *testing.T) {
	for _, field := range []string{"argv", "verify", "rollback"} {
		t.Run(field, func(t *testing.T) {
			action := protocol.Action{ID: "change", Kind: "command", Argv: []string{"/usr/sbin/ufw", "limit", "22/tcp"}, Verify: []string{"/bin/true"}, Reason: "Fixture change", Mutates: true}
			malformed := []string{"/usr/sbin/ufw delete limit 22/tcp && /usr/sbin/ufw allow 22/tcp"}
			switch field {
			case "argv":
				action.Argv = malformed
			case "verify":
				action.Verify = malformed
			case "rollback":
				action.Rollback = malformed
			}
			d := protocol.Decision{Summary: "Fixture decision", Assessment: "unknown", Actions: []protocol.Action{action}}
			if err := Validate(d, 8); err == nil || !strings.Contains(err.Error(), "single token") {
				t.Fatalf("accepted malformed %s executable: %v", field, err)
			}
		})
	}
}

func TestDecisionPreservesExplicitShellAndLiteralArguments(t *testing.T) {
	action := protocol.Action{
		ID: "change", Kind: "command", Reason: "Fixture change", Mutates: true,
		Argv:     []string{"/not-yet-installed/check", "argument with spaces && literal shell text\n"},
		Verify:   []string{"/bin/sh", "-c", `exec "$1"`, "firefighter", "/opt/local tools/check"},
		Rollback: []string{"/bin/sh", "-c", "command1 && command2"},
	}
	d := protocol.Decision{Summary: "Fixture decision", Assessment: "unknown", Actions: []protocol.Action{action}}
	if err := Validate(d, 8); err != nil {
		t.Fatalf("valid explicit argv rejected: %v", err)
	}
}

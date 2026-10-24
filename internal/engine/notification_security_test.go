package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/report"
	"github.com/jjcm/firefighter/internal/store"
)

// A legacy sender performs no filtering or redaction of its own. The durable
// report boundary must protect credentials before any sender receives events.
type notificationLegacySender struct{ events []protocol.Event }

func (s *notificationLegacySender) Send(_ context.Context, event protocol.Event) error {
	s.events = append(s.events, event)
	return nil
}

func TestNotificationActionIdentifiersAreRedactedBeforeQueueAuditAndLegacyDelivery(t *testing.T) {
	e, dir, _ := fixtureEngine(t)
	apiSecret, sourceSecret := "private-model-key-123456", "private-feed-token-987654"
	e.Redact = report.Redactor(apiSecret, sourceSecret)
	e.Hostname = "host-" + apiSecret
	in := scheduledIncident(e, "incident-"+sourceSecret, "pending", time.Now().UTC())
	in.Item.Source = "local-host"
	sender := &notificationLegacySender{}
	e.Reporter = sender
	rounds := 0
	e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
		rounds++
		if rounds == 1 {
			return protocol.Decision{
				Summary: "Apply update", Assessment: "exposed",
				Actions: []protocol.Action{{ID: "patch-" + apiSecret + "-" + sourceSecret, Kind: "command", Argv: []string{"/bin/true"}, Reason: "Patch using " + apiSecret, Mutates: true, Verify: []string{"/bin/true"}}},
			}, nil
		}
		return protocol.Decision{Summary: "Verified " + sourceSecret, Assessment: "remediated", Done: true}, nil
	})
	if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
		t.Fatalf("process incident: worked=%v err=%v", worked, err)
	}
	assertNoNotificationSecrets(t, e.State.Outbox, apiSecret, sourceSecret)
	assertNoNotificationSecrets(t, readState(t, dir).Outbox, apiSecret, sourceSecret)
	started, finished := false, false
	for _, delivery := range e.State.Outbox {
		if delivery.Event.Type == "action_started" {
			started = true
		}
		if delivery.Event.Type == "action_finished" {
			finished = true
		}
	}
	if !started || !finished {
		t.Fatal("test did not cover both action event boundaries")
	}
	file, err := os.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 65536), 16<<20)
	reports := 0
	for scanner.Scan() {
		var record store.Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		// Local execution journals are distinct from the externally deliverable
		// report contract and intentionally outside this regression's scope.
		if record.Type == "report_queued" || record.Type == "event" {
			reports++
			assertNoNotificationSecrets(t, record, apiSecret, sourceSecret)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if reports == 0 {
		t.Fatal("no queued reports found in audit")
	}
	if err := e.FlushReports(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sender.events) != reports {
		t.Fatalf("legacy sender received %d of %d reports", len(sender.events), reports)
	}
	assertNoNotificationSecrets(t, sender.events, apiSecret, sourceSecret)
}

func TestNotificationNestedDetailsAreRedactedAndIndependentlyCopied(t *testing.T) {
	e, _, _ := fixtureEngine(t)
	secret := "private-nested-credential"
	e.Redact = report.Redactor(secret)
	e.Reporter = &notificationLegacySender{}
	now := time.Now().UTC()
	evidence := []string{"observed " + secret}
	nested := map[string]interface{}{"credential-" + secret: "value-" + secret}
	list := []interface{}{nested, []string{secret}}
	details := map[string]interface{}{
		"evidence": evidence, "nested": list, "when": now,
		"count": int64(42), "ratio": 0.5, "enabled": true, "empty": nil,
		"unsupported": struct{ Token string }{secret},
	}
	if err := e.emit("custom-report", "incident", "Nested report", details); err != nil {
		t.Fatal(err)
	}
	if evidence[0] != "observed "+secret || nested["credential-"+secret] != "value-"+secret {
		t.Fatal("report sanitization modified producer-owned evidence")
	}
	queued := e.State.Outbox[0].Event.Details
	if queued["when"] != now || queued["count"] != int64(42) || queued["ratio"] != 0.5 || queued["enabled"] != true || queued["empty"] != nil || queued["unsupported"] != nil {
		t.Fatalf("report scalar types changed or unsupported content survived: %+v", queued)
	}
	assertNoNotificationSecrets(t, queued, secret)
	wantNested := []interface{}{map[string]interface{}{"credential-[REDACTED]": "value-[REDACTED]"}, []string{"[REDACTED]"}}
	if !reflect.DeepEqual(queued["nested"], wantNested) {
		t.Fatalf("nested values or map keys were not recursively sanitized: %+v", queued["nested"])
	}
	evidence[0] = "producer changed evidence"
	nested["credential-"+secret] = "producer changed map"
	list[1].([]string)[0] = "producer changed list"
	details["count"] = int64(99)
	if queued["evidence"].([]string)[0] != "observed [REDACTED]" || queued["count"] != int64(42) || !reflect.DeepEqual(queued["nested"], wantNested) {
		t.Fatal("queued reports alias producer-owned nested data")
	}
}

type notificationSkippedRunner struct {
	skipID string
	calls  []string
}

func (r *notificationSkippedRunner) Validate(protocol.Action) error { return nil }
func (r *notificationSkippedRunner) Run(_ context.Context, action protocol.Action) protocol.ActionResult {
	r.calls = append(r.calls, action.ID)
	return protocol.ActionResult{ActionID: action.ID, ExitCode: 0, Skipped: action.ID == r.skipID}
}

func TestNotificationSkippedCommandsCannotProduceVerifiedRemediation(t *testing.T) {
	for _, skippedID := range []string{"patch", "patch-verify"} {
		t.Run(skippedID, func(t *testing.T) {
			e, _, _ := fixtureEngine(t)
			in := addIncident(e, "pending")
			e.Reporter = &notificationLegacySender{}
			runner := &notificationSkippedRunner{skipID: skippedID}
			e.Runner = runner
			rounds := 0
			e.Planner = plannerFunc(func(context.Context, protocol.Request) (protocol.Decision, error) {
				rounds++
				if rounds == 1 {
					return protocol.Decision{Summary: "Apply patch", Assessment: "exposed", Actions: []protocol.Action{{ID: "patch", Kind: "command", Argv: []string{"/bin/true"}, Reason: "Patch service", Mutates: true, Verify: []string{"/bin/true"}}}}, nil
				}
				return protocol.Decision{Summary: "Claim remediation after skipped command", Assessment: "remediated", Done: true}, nil
			})
			if worked, err := e.ProcessOne(context.Background()); err != nil || !worked {
				t.Fatalf("process incident: worked=%v err=%v", worked, err)
			}
			if in.Status != "deferred" || !strings.Contains(in.LastError, "verification required") {
				t.Fatalf("skipped command led to completed remediation: %+v", in)
			}
			sawSkipped, sawFinal := false, false
			for _, delivery := range e.State.Outbox {
				event := delivery.Event
				if event.Details["verified"] == true || event.Details["assessment"] == "remediated" {
					t.Fatalf("skipped command produced a successful verification report: %+v", event)
				}
				if event.Type == "action_finished" && event.Details["action_id"] == skippedID {
					sawSkipped = event.Details["skipped"] == true
				}
				if event.Type == "assessment_finished" {
					sawFinal = event.Details["status"] == "deferred"
				}
			}
			if !sawSkipped || !sawFinal {
				t.Fatal("skipped outcome or deferred final report missing")
			}
			if skippedID == "patch" && len(runner.calls) != 1 {
				t.Fatal("verification ran after its prerequisite action was skipped")
			}
		})
	}
}

func assertNoNotificationSecrets(t *testing.T, value interface{}, secrets ...string) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(string(data), secret) {
			t.Fatal("notification retained a configured credential")
		}
	}
}

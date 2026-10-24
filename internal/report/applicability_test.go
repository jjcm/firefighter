package report

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jjcm/firefighter/internal/protocol"
)

func TestAdvisoryApplicabilityReportingBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		typ     string
		details map[string]any
		quiet   bool
		send    bool
	}{
		{"new advisory", "assessment_started", nil, true, false},
		{"probe failed", "action_finished", map[string]any{"phase": "action", "exit_code": 1, "error": "no package found"}, true, false},
		{"probe timed out", "action_finished", map[string]any{"phase": "action", "timed_out": true}, true, false},
		{"probe skipped", "action_finished", map[string]any{"phase": "action", "skipped": true}, true, false},
		{"probe verification failed", "action_finished", map[string]any{"phase": "verification", "parent_mutates": false, "verified": false, "exit_code": 1}, true, false},
		{"uncertain assessment deferred", "assessment_finished", map[string]any{"status": "deferred", "error": "inventory unavailable"}, true, false},
		{"unrelated advisory", "assessment_finished", map[string]any{"applicability_status": "not_affected", "assessment": "not_affected", "status": "completed"}, true, false},
		{"non-notice", "assessment_finished", map[string]any{"assessment": "not_a_notice", "status": "completed"}, true, false},
		{"non-notice prior mutation", "assessment_finished", map[string]any{"assessment": "not_a_notice", "status": "completed", "changed": true}, false, true},
		{"non-notice current mutation", "assessment_finished", map[string]any{"assessment": "not_a_notice", "status": "completed", "changed_this_attempt": true}, false, true},
		{"non-notice reported activity", "assessment_finished", map[string]any{"assessment": "not_a_notice", "status": "completed", "had_reported_activity": true}, false, true},
		{"unrelated advisory failed check", "action_finished", map[string]any{"applicability_status": "not_affected", "phase": "verification", "exit_code": 1}, true, false},
		{"unconfirmed exposure label", "assessment_finished", map[string]any{"assessment": "exposed"}, true, false},
		{"confirmed exposure", "assessment_finished", map[string]any{"applicability_status": "affected", "assessment": "exposed"}, false, true},
		{"affected check failed", "action_finished", map[string]any{"applicability_status": "affected", "phase": "verification", "exit_code": 1}, false, true},
		{"mutation intent", "action_started", map[string]any{"mutates": true}, false, true},
		{"mutation result", "action_finished", map[string]any{"mutates": true, "exit_code": 1}, false, true},
		{"mutation verification", "action_finished", map[string]any{"phase": "verification", "parent_mutates": true, "verified": false, "exit_code": 1}, false, true},
		{"prior mutation closure", "assessment_finished", map[string]any{"applicability_status": "not_affected", "assessment": "not_affected", "changed": true}, false, true},
		{"current mutation closure", "assessment_finished", map[string]any{"assessment": "not_affected", "changed_this_attempt": true}, false, true},
		{"reported activity closure", "assessment_finished", map[string]any{"applicability_status": "not_affected", "assessment": "not_affected", "had_reported_activity": true}, false, true},
		{"host audit", "assessment_finished", map[string]any{"source": "local-host", "assessment": "not_affected"}, false, true},
		{"host probe failure", "action_finished", map[string]any{"assessment_scope": "host", "exit_code": 1}, false, true},
		{"source outage", "source_error", map[string]any{"error": "feed unavailable"}, false, true},
		{"daemon startup", "started", nil, false, true},
		{"test notification", "report_test", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			details := map[string]any{"source": "nvd", "assessment_scope": "advisory", "applicability_status": "unknown"}
			for key, value := range tc.details {
				details[key] = value
			}
			event := protocol.Event{ID: "applicability-event", IncidentID: "applicability-incident", Type: tc.typ, Details: details}
			if got := QuietAdvisory(event); got != tc.quiet {
				t.Fatalf("QuietAdvisory = %v, want %v", got, tc.quiet)
			}
			for _, kind := range []string{"slack", "discord", "telegram", "grokbot"} {
				s := directFixture(t, kind)
				if got := s.ShouldSend(event); got != tc.send {
					t.Errorf("%s ShouldSend = %v, want %v", kind, got, tc.send)
				}
				if !tc.send {
					// Replayed outbox events must be just as quiet as live events.
					body, err := json.Marshal(event)
					if err != nil {
						t.Fatal(err)
					}
					var replay protocol.Event
					if err := json.Unmarshal(body, &replay); err != nil {
						t.Fatal(err)
					}
					s.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
						t.Fatalf("%s sent an unconfirmed/irrelevant advisory", kind)
						return nil, nil
					})
					if err := s.Send(context.Background(), replay); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func TestQuietAdvisoryPreservesLegacyEvents(t *testing.T) {
	for _, event := range []protocol.Event{
		{Type: "action_finished", Details: map[string]any{"exit_code": 1}},
		{Type: "assessment_finished", Details: map[string]any{"assessment": "exposed"}},
		{Type: "assessment_finished", Details: map[string]any{"assessment": "not_affected"}},
		{Type: "custom-report", Details: map[string]any{"applicability_status": "unknown"}},
	} {
		if QuietAdvisory(event) {
			t.Fatalf("legacy or unrelated event became quiet: %+v", event)
		}
	}
}

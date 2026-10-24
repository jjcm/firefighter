package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/jjcm/firefighter/internal/protocol"
)

func TestReportContextRetainsIdentityAndSeparatesCheckFromRemediation(t *testing.T) {
	event := safeEvent(protocol.Event{ID: "event", IncidentID: "incident", Type: "action_finished", Summary: "Inventory check", Details: map[string]any{
		"advisory_id": "notice-123", "advisory_title": "WordPress plugin vulnerability", "cves": []any{"CVE-2026-12345"},
		"run_id": "run-123", "version": "commit-123", "attempt": float64(2), "duration_ms": json.Number("125"),
		"action_id": "check-verify", "parent_action_id": "check", "parent_mutates": false,
		"phase": "verification", "check_outcome": "passed", "verification_scope": "action_check", "verified": true,
	}}, Redactor())
	message := formatEvent(event)
	for _, expected := range []string{"Advisory: notice-123", "CVEs: CVE-2026-12345", "Run: run-123", "Version: commit-123", "Attempt: 2", "Duration: 125 ms", "Parent declared changes: false", "Check: passed (command outcome; not proof of remediation or a clean host)"} {
		if !strings.Contains(message, expected) {
			t.Errorf("missing %q in %s", expected, message)
		}
	}
	if strings.Contains(message, "Remediation verified: true") || event.Details["verification_scope"] != "action_check" {
		t.Fatal("successful probe became a remediation claim or lost its scope")
	}
	assessment := safeEvent(protocol.Event{Type: "assessment_finished", Details: map[string]any{
		"assessment": "exposed", "status": "completed", "remediation_verified": false,
		"changed": true, "changed_this_attempt": false, "changed_scope": "retained_incident_history",
		"terminal_reason": "assessment_complete", "next_assessment": "2026-10-24T14:00:00Z",
	}}, Redactor())
	message = formatEvent(assessment)
	for _, expected := range []string{"Assessment: exposed", "Assessment status: completed", "Remediation verified: false", "Change commands run this attempt: false", "Change commands run in retained incident history: true", "Completion reason: assessment_complete", "Next assessment: 2026-10-24T14:00:00Z"} {
		if !strings.Contains(message, expected) {
			t.Errorf("missing %q in %s", expected, message)
		}
	}
}

func TestReportBoundedDetailsMakeOmissionsExplicit(t *testing.T) {
	const secret = "fixture-private-key-value"
	evidence := []any{strings.Repeat("a", 500), "second " + secret, "third", "fourth", "fifth", "sixth", "seventh", "eighth", 123}
	event := protocol.Event{Summary: strings.Repeat("s", 1100), Details: map[string]any{
		"follow_up": strings.Repeat("f", 1100), "evidence": evidence,
		"cves":           []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4", "CVE-2026-5", "CVE-2026-6", "CVE-2026-7", "CVE-2026-8", "CVE-2026-9"},
		"clipped_fields": []string{"attacker-controlled-claim"}, "evidence_omitted": -99,
		"advisory_title": "A\nFake: title\u202e " + secret,
		"argv":           []string{"must-stay-local"}, "output": "must-stay-local", "environment": "must-stay-local",
	}}
	safe := safeEvent(event, Redactor(secret))
	if len(safe.Details["evidence"].([]string)) != 6 || safe.Details["evidence_omitted"] != 2 || safe.Details["cves_omitted"] != 1 {
		t.Fatalf("incorrect bounded arrays/omission counts: %+v", safe.Details)
	}
	clipped := strings.Join(safe.Details["clipped_fields"].([]string), ",")
	for _, field := range []string{"summary", "follow_up", "evidence", "evidence[0]", "cves"} {
		if !strings.Contains(clipped, field) {
			t.Errorf("missing clipping signal for %s", field)
		}
	}
	body, _ := json.Marshal(safe)
	for _, forbidden := range []string{secret, "must-stay-local", "attacker-controlled-claim", "seventh", "eighth", "CVE-2026-9", "\\u202e", "\\n"} {
		if strings.Contains(string(body), forbidden) {
			t.Errorf("unsafe/omitted content retained: %q", forbidden)
		}
	}
	if !strings.Contains(formatEvent(safe), "Report fields shortened:") {
		t.Fatal("human report hides field truncation")
	}
	if event.Details["evidence_omitted"] != -99 || len(evidence) != 9 {
		t.Fatal("sanitizing altered the locally retained event")
	}
	if len(body) > 12000 {
		t.Fatalf("structured event unexpectedly large: %d", len(body))
	}
}

func TestReportExpandedFollowUpAndEvidenceSurviveUsefulLength(t *testing.T) {
	followUp := strings.Repeat("follow-up detail; ", 40)
	evidence := strings.Repeat("observed detail; ", 20)
	event := safeEvent(protocol.Event{Details: map[string]any{"follow_up": followUp, "evidence": []string{evidence, "two", "three", "four"}}}, Redactor())
	if event.Details["follow_up"] != strings.TrimSpace(followUp) || event.Details["evidence"].([]string)[0] != strings.TrimSpace(evidence) || len(event.Details["evidence"].([]string)) != 4 || event.Details["clipped_fields"] != nil {
		t.Fatal("useful follow-up or evidence still clipped at old short bounds")
	}
}

func TestChannelClippingIsExplicitUnicodeSafeAndPreservesOutcomePrefix(t *testing.T) {
	for _, limit := range []int{2000, 2900, 4096} {
		value := "Event: event-123\nCheck: failed\n" + strings.Repeat("🙂", 5000)
		message := channelText(value, limit)
		if len(utf16.Encode([]rune(message))) > limit || !utf8.ValidString(message) || !strings.HasSuffix(message, "[Message shortened; full event in local audit.]") || !strings.Contains(message, "Check: failed") {
			t.Fatalf("unsafe or silently clipped message at %d", limit)
		}
	}
	if channelText("complete", 100) != "complete" {
		t.Fatal("unclipped message was altered")
	}
}

func TestReportRejectsInvalidNumericMetadata(t *testing.T) {
	event := safeEvent(protocol.Event{Details: map[string]any{"attempt": -1, "duration_ms": 1.5, "output": "raw"}}, Redactor())
	if event.Details["attempt"] != nil || event.Details["duration_ms"] != nil || event.Details["output"] != nil {
		t.Fatal("invalid numeric or unknown metadata retained")
	}
}

func TestReportNextAssessmentSurvivesLiveAndPersistedEvents(t *testing.T) {
	when := time.Date(2026, 10, 24, 21, 0, 0, 123456789, time.FixedZone("fixture", 7*60*60))
	const expected = "2026-10-24T14:00:00.123456789Z"
	live := protocol.Event{Time: when, Details: map[string]any{"next_assessment": when}}
	body, err := json.Marshal(live)
	if err != nil {
		t.Fatal(err)
	}
	var persisted protocol.Event
	if err := json.Unmarshal(body, &persisted); err != nil {
		t.Fatal(err)
	}
	for _, event := range []protocol.Event{live, persisted, {Time: when, Details: map[string]any{"next_assessment": expected}}} {
		safe := safeEvent(event, Redactor())
		value, ok := safe.Details["next_assessment"].(string)
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if !ok || err != nil || !parsed.Equal(when) {
			t.Fatalf("next assessment lost or changed: %#v", safe.Details)
		}
		message := formatEvent(safe)
		if !strings.Contains(message, "Next assessment: "+value) || !strings.Contains(message, "Time: "+expected) {
			t.Fatalf("schedule or subsecond event time omitted: %s", message)
		}
	}
	if safeEvent(protocol.Event{Details: map[string]any{"next_assessment": time.Time{}}}, Redactor()).Details["next_assessment"] != nil {
		t.Fatal("zero schedule was rendered as an actual next assessment")
	}
}

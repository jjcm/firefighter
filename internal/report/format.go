package report

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jjcm/firefighter/internal/protocol"
)

// safeEvent keeps the structured Grok Bot envelope while excluding arbitrary
// command output, argv, logs, environments, and unknown model-supplied fields.
func safeEvent(event protocol.Event, redact func(string) string) protocol.Event {
	out := event
	out.Details = map[string]any{}
	var clipped []string
	bounded := func(key, value string, limit int) string {
		clean := cleanPlain(value, redact)
		short := limitText(clean, limit)
		if short != clean {
			clipped = append(clipped, key)
		}
		return short
	}
	out.ID, out.IncidentID = bounded("id", event.ID, 128), bounded("incident_id", event.IncidentID, 128)
	out.Host, out.Type = bounded("host", event.Host, 96), bounded("type", event.Type, 64)
	out.Summary = bounded("summary", event.Summary, 900)
	for _, field := range []struct {
		key   string
		limit int
	}{
		{"source", 96}, {"status", 32}, {"assessment", 32}, {"phase", 32}, {"action_id", 96}, {"parent_action_id", 96}, {"mutates_source", 40},
		{"advisory_id", 128}, {"advisory_title", 300}, {"run_id", 64}, {"version", 96}, {"stop_reason", 64}, {"terminal_reason", 96}, {"interruption_reason", 64},
		{"check_outcome", 32}, {"verification_scope", 40}, {"assessment_scope", 32}, {"applicability_status", 32}, {"changed_scope", 40}, {"next_assessment", 40}, {"health_scope", 40},
		{"reason", 400}, {"error", 300}, {"follow_up", 1000},
	} {
		if value, ok := event.Details[field.key].(string); ok && value != "" {
			out.Details[field.key] = bounded(field.key, value, field.limit)
		}
	}
	// Live events carry time.Time; persisted outbox events decode to strings.
	if value, ok := event.Details["next_assessment"].(time.Time); ok && !value.IsZero() {
		out.Details["next_assessment"] = bounded("next_assessment", value.UTC().Format(time.RFC3339Nano), 40)
	}
	for _, key := range []string{"changed", "changed_this_attempt", "mutates", "parent_mutates", "verified", "remediation_verified", "timed_out", "skipped", "had_reported_activity"} {
		if value, ok := event.Details[key].(bool); ok {
			out.Details[key] = value
		}
	}
	if value, ok := integer(event.Details["exit_code"]); ok {
		out.Details["exit_code"] = value
	}
	for _, key := range []string{"attempt", "duration_ms", "failure_count"} {
		if value, ok := integer(event.Details[key]); ok && value >= 0 {
			out.Details[key] = value
		}
	}
	for _, field := range []struct {
		key          string
		count, limit int
	}{{"evidence", 6, 400}, {"cves", 8, 32}} {
		values := stringValues(event.Details[field.key])
		if len(values) > field.count {
			out.Details[field.key+"_omitted"] = len(values) - field.count
			clipped = append(clipped, field.key)
			values = values[:field.count]
		}
		if len(values) > 0 {
			items := make([]string, len(values))
			for i, value := range values {
				items[i] = bounded(field.key+"["+strconv.Itoa(i)+"]", value, field.limit)
			}
			out.Details[field.key] = items
		}
	}
	if len(clipped) > 0 {
		out.Details["clipped_fields"] = clipped
	}
	return out
}

func stringValues(value any) []string {
	switch values := value.(type) {
	case []string:
		return values
	case []any:
		var result []string
		for _, value := range values {
			if text, ok := value.(string); ok {
				result = append(result, text)
			}
		}
		return result
	}
	return nil
}

func formatEvent(event protocol.Event) string {
	lines := []string{"Firefighter · " + strings.ReplaceAll(event.Type, "_", " "), "Host: " + event.Host}
	if !event.Time.IsZero() {
		lines = append(lines, "Time: "+event.Time.UTC().Format(time.RFC3339Nano))
	}
	// Keep identity and outcome ahead of longer model prose so a short channel
	// can still identify the incident when its display text must be clipped.
	lines = append(lines, "Event: "+event.ID)
	if event.IncidentID != "" {
		lines = append(lines, "Incident: "+event.IncidentID)
	}
	for _, field := range []struct{ key, label string }{{"run_id", "Run"}, {"version", "Version"}, {"advisory_id", "Advisory"}} {
		if value, ok := event.Details[field.key].(string); ok && value != "" {
			lines = append(lines, field.label+": "+value)
		}
	}
	if cves := stringValues(event.Details["cves"]); len(cves) > 0 {
		lines = append(lines, "CVEs: "+strings.Join(cves, ", "))
	}
	if attempt, ok := integer(event.Details["attempt"]); ok {
		lines = append(lines, "Attempt: "+strconv.FormatInt(attempt, 10))
	}
	phase, _ := event.Details["phase"].(string)
	if phase != "" {
		lines = append(lines, "Phase: "+phase)
	}
	if parent, ok := event.Details["parent_action_id"].(string); ok && parent != "" {
		lines = append(lines, "Parent action: "+parent)
	}
	if parentMutates, ok := event.Details["parent_mutates"].(bool); ok {
		lines = append(lines, "Parent declared changes: "+strconv.FormatBool(parentMutates))
	}
	if mutates, ok := event.Details["mutates"].(bool); ok {
		intent := "no changes declared"
		if mutates {
			intent = "changes declared"
		}
		switch event.Details["mutates_source"] {
		case "planner_declaration":
			intent += " by planner"
		case "expected_read_only_verification":
			intent = "verification expected to be read-only"
		case "rollback_contract":
			intent = "rollback expected to change state"
		}
		lines = append(lines, "Mutation intent: "+intent+" (declaration, not enforcement)")
	}
	exit, hasExit := integer(event.Details["exit_code"])
	if hasExit {
		lines = append(lines, "Exit: "+strconv.FormatInt(exit, 10))
	}
	verified, _ := event.Details["verified"].(bool)
	if phase == "verification" && event.Type == "action_finished" {
		outcome, _ := event.Details["check_outcome"].(string)
		if outcome == "" {
			outcome = "failed"
			if verified {
				outcome = "passed"
			}
		}
		lines = append(lines, "Check: "+outcome+" (command outcome; not proof of remediation or a clean host)")
	} else if event.Type == "assessment_finished" {
		remediated, known := event.Details["remediation_verified"].(bool)
		if known {
			lines = append(lines, "Remediation verified: "+strconv.FormatBool(remediated))
		} else if verified {
			lines = append(lines, "Assessment verification: passed")
		}
	}
	mutates, _ := event.Details["mutates"].(bool)
	timedOut, _ := event.Details["timed_out"].(bool)
	skipped, _ := event.Details["skipped"].(bool)
	problem, _ := event.Details["error"].(string)
	if event.Type == "action_finished" && phase == "action" && mutates && hasExit && exit == 0 && !timedOut && !skipped && problem == "" {
		lines = append(lines, "Change command finished; verification pending")
	}
	if duration, ok := integer(event.Details["duration_ms"]); ok {
		lines = append(lines, "Duration: "+strconv.FormatInt(duration, 10)+" ms")
	}
	if failures, ok := integer(event.Details["failure_count"]); ok {
		lines = append(lines, "Consecutive unresolved assessments: "+strconv.FormatInt(failures, 10))
	}
	for _, field := range []struct{ key, label string }{{"assessment", "Assessment"}, {"status", "Assessment status"}, {"assessment_scope", "Assessment scope"}, {"applicability_status", "Advisory applicability"}, {"source", "Source"}, {"action_id", "Action"}, {"stop_reason", "Stop reason"}, {"interruption_reason", "Interruption"}, {"terminal_reason", "Completion reason"}, {"next_assessment", "Next assessment"}} {
		if value, ok := event.Details[field.key].(string); ok && value != "" {
			lines = append(lines, field.label+": "+value)
		}
	}
	if changed, ok := event.Details["changed_this_attempt"].(bool); ok {
		lines = append(lines, "Change commands run this attempt: "+strconv.FormatBool(changed))
	}
	if changed, ok := event.Details["changed"].(bool); ok && event.Details["changed_scope"] == "retained_incident_history" {
		lines = append(lines, "Change commands run in retained incident history: "+strconv.FormatBool(changed))
	}
	for _, field := range []struct{ key, label string }{{"timed_out", "Command timed out"}, {"skipped", "Command was skipped"}} {
		if value, _ := event.Details[field.key].(bool); value {
			lines = append(lines, field.label)
		}
	}
	lines = append(lines, event.Summary)
	for _, field := range []struct{ key, label string }{{"advisory_title", "Advisory title"}, {"reason", "Reason"}, {"error", "Error"}, {"follow_up", "Follow-up"}} {
		if value, ok := event.Details[field.key].(string); ok && value != "" {
			lines = append(lines, field.label+": "+value)
		}
	}
	if evidence, ok := event.Details["evidence"].([]string); ok {
		for _, value := range evidence {
			lines = append(lines, "Evidence: "+value)
		}
	}
	if fields := stringValues(event.Details["clipped_fields"]); len(fields) > 0 {
		lines = append(lines, "Report fields shortened: "+strings.Join(fields, ", ")+". Full event is in the local audit.")
	}
	return strings.Join(lines, "\n")
}

func integer(value any) (int64, bool) {
	switch n := value.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if !math.IsNaN(n) && !math.IsInf(n, 0) && n == math.Trunc(n) && n > math.MinInt64 && n < math.MaxInt64 {
			return int64(n), true
		}
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func plain(value string, limit int, redact func(string) string) string {
	return limitText(cleanPlain(value, redact), limit)
}

func cleanPlain(value string, redact func(string) string) string {
	value = redact(value)
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, value)
	return strings.Join(strings.Fields(value), " ")
}

// Keep truncation explicit even when the channel cuts off a follow-up sentence.
// The structured Grok Bot event has its own bounds and clipped_fields metadata.
func channelText(value string, limit int) string {
	if limitText(value, limit) == value {
		return value
	}
	const suffix = "\n[Message shortened; full event in local audit.]"
	return limitText(value, limit-len(suffix)) + suffix
}

// UTF-16 units are conservative for the providers' character limits and avoid
// splitting a multibyte Unicode character or an astral-plane emoji.
func limitText(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	units := 0
	for _, r := range value {
		n := 1
		if r > 0xffff {
			n = 2
		}
		units += n
	}
	if units <= limit {
		return value
	}
	units = 0
	for offset, r := range value {
		n := 1
		if r > 0xffff {
			n = 2
		}
		if units+n > limit-1 {
			return value[:offset] + "…"
		}
		units += n
	}
	return "…"
}

func discordPlain(value string) string {
	var out strings.Builder
	for _, r := range value {
		if strings.ContainsRune(`\*_~`+"`"+`>|[]()#-+.!`, r) {
			out.WriteByte('\\')
		}
		// Mentions are disabled in the payload as well; break their syntax so
		// they remain visibly inert even if a client re-renders copied text.
		if r == '@' {
			out.WriteString("@\u200b")
			continue
		}
		if r == '<' {
			out.WriteString("‹")
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}

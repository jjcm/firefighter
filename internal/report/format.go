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
	out.ID, out.IncidentID = plain(event.ID, 128, redact), plain(event.IncidentID, 128, redact)
	out.Host, out.Type = plain(event.Host, 96, redact), plain(event.Type, 64, redact)
	out.Summary = plain(event.Summary, 450, redact)
	out.Details = map[string]any{}
	for _, field := range []struct {
		key   string
		limit int
	}{{"source", 96}, {"status", 32}, {"assessment", 32}, {"phase", 32}, {"action_id", 96}, {"parent_action_id", 96}, {"mutates_source", 40}, {"reason", 200}, {"error", 200}, {"follow_up", 240}} {
		if value, ok := event.Details[field.key].(string); ok && value != "" {
			out.Details[field.key] = plain(value, field.limit, redact)
		}
	}
	for _, key := range []string{"changed", "mutates", "verified", "timed_out", "skipped"} {
		if value, ok := event.Details[key].(bool); ok {
			out.Details[key] = value
		}
	}
	if value, ok := integer(event.Details["exit_code"]); ok {
		out.Details["exit_code"] = value
	}
	var evidence []string
	switch values := event.Details["evidence"].(type) {
	case []string:
		evidence = values
	case []any:
		for _, value := range values {
			if s, ok := value.(string); ok {
				evidence = append(evidence, s)
			}
			if len(evidence) >= 3 {
				break
			}
		}
	}
	if len(evidence) > 3 {
		evidence = evidence[:3]
	}
	if len(evidence) > 0 {
		bounded := make([]string, len(evidence))
		for i, value := range evidence {
			bounded[i] = plain(value, 200, redact)
		}
		out.Details["evidence"] = bounded
	}
	return out
}

func formatEvent(event protocol.Event) string {
	lines := []string{"Firefighter · " + strings.ReplaceAll(event.Type, "_", " "), "Host: " + event.Host}
	if !event.Time.IsZero() {
		lines = append(lines, "Time: "+event.Time.UTC().Format(time.RFC3339))
	}
	lines = append(lines, event.Summary)
	phase, _ := event.Details["phase"].(string)
	if phase != "" {
		lines = append(lines, "Phase: "+phase)
	}
	if parent, ok := event.Details["parent_action_id"].(string); ok && parent != "" {
		lines = append(lines, "Parent action: "+parent)
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
	if phase == "verification" && event.Type == "action_finished" && !verified {
		lines = append(lines, "Verification: failed")
	} else if verified {
		lines = append(lines, "Verification: passed")
	}
	mutates, _ := event.Details["mutates"].(bool)
	timedOut, _ := event.Details["timed_out"].(bool)
	skipped, _ := event.Details["skipped"].(bool)
	problem, _ := event.Details["error"].(string)
	if event.Type == "action_finished" && phase == "action" && mutates && hasExit && exit == 0 && !timedOut && !skipped && problem == "" {
		lines = append(lines, "Change command finished; verification pending")
	}
	lines = append(lines, "Event: "+event.ID)
	if event.IncidentID != "" {
		lines = append(lines, "Incident: "+event.IncidentID)
	}
	for _, field := range []struct{ key, label string }{{"assessment", "Assessment"}, {"status", "Status"}, {"source", "Source"}, {"reason", "Reason"}, {"action_id", "Action"}} {
		if value, ok := event.Details[field.key].(string); ok && value != "" {
			lines = append(lines, field.label+": "+value)
		}
	}
	for _, field := range []struct{ key, label string }{{"timed_out", "Command timed out"}, {"skipped", "Command was skipped"}} {
		if value, _ := event.Details[field.key].(bool); value {
			lines = append(lines, field.label)
		}
	}
	for _, field := range []struct{ key, label string }{{"error", "Error"}, {"follow_up", "Follow-up"}} {
		if value, ok := event.Details[field.key].(string); ok && value != "" {
			lines = append(lines, field.label+": "+value)
		}
	}
	if evidence, ok := event.Details["evidence"].([]string); ok {
		for _, value := range evidence {
			lines = append(lines, "Evidence: "+value)
		}
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
	value = redact(value)
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, value)
	return limitText(strings.Join(strings.Fields(value), " "), limit)
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

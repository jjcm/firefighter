package report

import "github.com/jjcm/firefighter/internal/protocol"

// QuietAdvisory keeps applicability investigations local until the host is
// confirmed affected. The engine uses this before queuing any external report;
// direct senders also use it when replaying persisted events. Events predating
// explicit applicability metadata retain their existing reporting behavior.
func QuietAdvisory(event protocol.Event) bool {
	switch event.Type {
	case "assessment_started", "assessment_finished", "action_started", "action_finished":
	default:
		return false
	}
	if event.Details["source"] == "local-host" || event.Details["assessment_scope"] == "host" {
		return false
	}
	applicability, known := event.Details["applicability_status"].(string)
	if !known || applicability == "affected" {
		return false
	}
	// A later applicability verdict must not hide a real change, its recovery,
	// or the closing report for activity that was already sent externally.
	for _, key := range []string{"changed", "changed_this_attempt", "had_reported_activity", "mutates", "parent_mutates"} {
		if value, _ := event.Details[key].(bool); value {
			return false
		}
	}
	return true
}

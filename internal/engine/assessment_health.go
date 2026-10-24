package engine

import (
	"fmt"
	"time"

	"github.com/jjcm/firefighter/internal/store"
)

const (
	assessmentHealthThreshold        = 3
	assessmentHealthReminderFailures = 10
	assessmentHealthReminderInterval = 30 * time.Minute
)

// observeAssessmentHealthLocked reports an aggregate inability to determine
// applicability without turning each unrelated disclosure into an alert. The
// caller holds e.mu and checkpoints State after this method succeeds.
func (e *Engine) observeAssessmentHealthLocked(in *store.Incident, status string, cause error) error {
	if !requiresApplicability(in) || interruptionReason(cause) == "daemon_stopping" {
		return nil
	}
	health := &e.State.AssessmentHealth
	if status == "completed" && (in.ApplicabilityStatus == "affected" || in.ApplicabilityStatus == "not_affected") {
		if health.LastReportedFailures > 0 {
			if err := e.emitLocked("assessment_health_recovered", "", "Firefighter can determine advisory applicability again; the consecutive failure streak has ended", map[string]interface{}{
				"health_scope": "advisory_applicability", "failure_count": health.ConsecutiveFailures,
			}); err != nil {
				return err
			}
		}
		*health = store.AssessmentHealth{}
		return nil
	}
	if status != "deferred" || (in.ApplicabilityStatus != "" && in.ApplicabilityStatus != "unknown") {
		return nil
	}
	health.ConsecutiveFailures++
	if health.ConsecutiveFailures < assessmentHealthThreshold {
		return nil
	}
	now := in.UpdatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if health.LastReportedFailures > 0 && (health.ConsecutiveFailures-health.LastReportedFailures < assessmentHealthReminderFailures || now.Sub(health.LastReportedAt) < assessmentHealthReminderInterval) {
		return nil
	}
	if err := e.emitLocked("assessment_health_error", "", fmt.Sprintf("Firefighter could not determine advisory applicability in %d consecutive assessments; review its local audit for the cause", health.ConsecutiveFailures), map[string]interface{}{
		"health_scope": "advisory_applicability", "failure_count": health.ConsecutiveFailures,
	}); err != nil {
		return err
	}
	health.LastReportedFailures = health.ConsecutiveFailures
	health.LastReportedAt = now
	return nil
}

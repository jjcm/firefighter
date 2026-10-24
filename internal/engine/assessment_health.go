package engine

import (
	"fmt"
	"time"

	"github.com/jjcm/firefighter/internal/store"
)

const (
	assessmentHealthThreshold         = 3
	assessmentHealthReminderFailures  = 10
	assessmentHealthReminderInterval  = 30 * time.Minute
	assessmentHealthRecoverySuccesses = 3
	assessmentHealthRecoveryInterval  = 5 * time.Minute
)

// observeAssessmentHealthLocked reports an aggregate inability to determine
// applicability without turning each unrelated disclosure into an alert. The
// caller holds e.mu and checkpoints State after this method succeeds.
func (e *Engine) observeAssessmentHealthLocked(in *store.Incident, status string, cause error) error {
	if !requiresApplicability(in) || interruptionReason(cause) == "daemon_stopping" {
		return nil
	}
	health := &e.State.AssessmentHealth
	now := in.UpdatedAt
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// Older checkpoints tracked only the failure streak. Treat an existing
	// streak as an open episode and start a conservative recovery window now;
	// the old last-report timestamp cannot establish when its final failure was.
	if health.EpisodeFailures == 0 && (health.ConsecutiveFailures > 0 || health.LastReportedFailures > 0) {
		health.EpisodeFailures = max(health.ConsecutiveFailures, health.LastReportedFailures)
		health.LastFailureAt = now
	}
	if status == "completed" && (in.ApplicabilityStatus == "affected" || in.ApplicabilityStatus == "not_affected") {
		if health.EpisodeFailures == 0 {
			return nil
		}
		health.ConsecutiveFailures = 0
		health.ConsecutiveSuccesses++
		health.UpdatedAt = time.Now().UTC()
		if health.ConsecutiveSuccesses < assessmentHealthRecoverySuccesses || now.Sub(health.LastFailureAt) < assessmentHealthRecoveryInterval {
			return nil
		}
		lastReportedAt := health.LastReportedAt
		if health.ReportQueued {
			if err := e.emitLocked("assessment_health_recovered", "", fmt.Sprintf("Firefighter's advisory assessments have stabilized: %d consecutive assessments resolved applicability, with no unresolved assessment for at least five minutes", health.ConsecutiveSuccesses), map[string]interface{}{
				"health_scope": "advisory_applicability", "failure_count": health.EpisodeFailures,
				"failure_count_scope": "health_episode", "resolved_count": health.ConsecutiveSuccesses,
			}); err != nil {
				return err
			}
			lastReportedAt = now
		}
		// Preserve the cooldown across episodes. A new burst immediately after
		// a recovery must not generate another error/recovery notification pair.
		*health = store.AssessmentHealth{LastReportedAt: lastReportedAt, UpdatedAt: time.Now().UTC()}
		return nil
	}
	// An actionless decision can finish "completed" while applicability is
	// still unknown. Completion of the attempt is not a successful resolution:
	// it must break recovery and count toward the same unresolved-health alert.
	if (status != "deferred" && status != "completed") || (in.ApplicabilityStatus != "" && in.ApplicabilityStatus != "unknown") {
		return nil
	}
	health.ConsecutiveFailures++
	health.EpisodeFailures++
	health.ConsecutiveSuccesses = 0
	health.LastFailureAt = now
	health.UpdatedAt = time.Now().UTC()
	if health.LastReportedFailures == 0 && health.ConsecutiveFailures < assessmentHealthThreshold {
		return nil
	}
	cooldown := assessmentHealthRecoveryInterval
	if health.LastReportedFailures > 0 {
		cooldown = assessmentHealthReminderInterval
	}
	if !health.LastReportedAt.IsZero() && now.Sub(health.LastReportedAt) < cooldown {
		return nil
	}
	if health.LastReportedFailures > 0 && health.EpisodeFailures-health.LastReportedFailures < assessmentHealthReminderFailures {
		return nil
	}
	queuedBefore := len(e.State.Outbox)
	if err := e.emitLocked("assessment_health_error", "", fmt.Sprintf("Firefighter has repeatedly been unable to determine advisory applicability (%d unresolved assessments during this period); review its local audit for the cause", health.EpisodeFailures), map[string]interface{}{
		"health_scope": "advisory_applicability", "failure_count": health.EpisodeFailures,
		"failure_count_scope": "health_episode",
	}); err != nil {
		return err
	}
	health.LastReportedFailures = health.EpisodeFailures
	health.LastReportedAt = now
	health.ReportQueued = health.ReportQueued || len(e.State.Outbox) > queuedBefore
	health.UpdatedAt = time.Now().UTC()
	return nil
}

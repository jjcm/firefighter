package engine

import (
	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/store"
)

const applicabilityRecoveryNote = "Before changing this host for a notice, return applicability.status=affected with the observed local product, vulnerable version/configuration condition, and concrete local evidence. The notice alone is not proof. Reuse sufficiently fresh scoped inventory and memory. If the product is absent or the condition does not apply, finish not_affected with no actions. Otherwise use only minimal read-only observations; do not install tools, harden unrelated services, or attach verification/rollback commands during applicability investigation."

func requiresApplicability(in *store.Incident) bool {
	return in.Item.Source != "local-host"
}

// This is an execution-contract gate, not independent validation of the model's
// factual interpretation or an OS sandbox for commands declared read-only.
func noticeApplicability(d protocol.Decision) string {
	if d.Applicability == nil || protocol.ValidateApplicability(d.Applicability) != nil || conflictingApplicability(d) {
		return "unknown"
	}
	return d.Applicability.Status
}

func conflictingApplicability(d protocol.Decision) bool {
	if d.Applicability == nil {
		return false
	}
	if d.Applicability.Status == "affected" && d.Assessment == "not_affected" {
		return true
	}
	if d.Applicability.Status == "not_affected" {
		switch d.Assessment {
		case "exposed", "suspected_compromise", "confirmed_compromise", "remediated":
			return true
		}
	}
	return false
}

// gateNoticeDecision removes unauthorized work before it can be checkpointed as
// executable intent. A rejected batch is replanned in the same bounded incident
// budget without asking the operator or trusting a prior attempt's verdict.
func gateNoticeDecision(d protocol.Decision) (protocol.Decision, bool, bool) {
	// The engine validates this explicit final disposition before the gate.
	// It classifies the source text, without asserting anything about host safety.
	if d.Assessment == "not_a_notice" && protocol.ValidateNoticeDisposition(d) == nil {
		return d, false, false
	}
	if conflictingApplicability(d) {
		// Resolve contradictory conclusions before either executing work or
		// permanently retiring the notice as irrelevant.
		d.Actions, d.MemoryUpdates = nil, nil
		d.Assessment, d.Done = "unknown", false
		d.FollowUp = applicabilityRecoveryNote
		return d, true, true
	}
	status := noticeApplicability(d)
	if status == "not_affected" {
		blocked := len(d.Actions) > 0
		if blocked {
			// These notes accompanied work that will not execute; they may claim
			// its results, so they cannot become observations for a future notice.
			d.MemoryUpdates = nil
		}
		d.Actions = nil
		d.Assessment, d.Done = "not_affected", true
		return d, false, blocked
	}
	if status == "affected" {
		return d, false, false
	}

	blocked := false
	var observations []protocol.Action
	for _, action := range d.Actions {
		if action.Mutates {
			// Actions are ordered and can depend on each other. Do not execute
			// fragments of a batch whose proposed changes lack applicability.
			d.Actions, d.MemoryUpdates = nil, nil
			d.Assessment, d.Done = "unknown", false
			d.FollowUp = applicabilityRecoveryNote
			return d, true, true
		}
	}
	for _, action := range d.Actions {
		// Observations are interpreted by the next planner turn. Neither a
		// synthetic verification nor a mutating rollback is needed to observe.
		if len(action.Verify) > 0 || len(action.Rollback) > 0 {
			blocked = true
		}
		action.Verify, action.Rollback = nil, nil
		observations = append(observations, action)
	}
	if d.Assessment != "unknown" {
		blocked = true
	}
	d.Assessment = "unknown"
	d.Actions = observations
	if blocked {
		d.MemoryUpdates = nil
		d.Done = false
		d.FollowUp = applicabilityRecoveryNote
	}
	return d, blocked && len(observations) == 0, blocked
}

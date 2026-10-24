package protocol

import (
	"errors"
	"strings"
)

// ValidateApplicability checks the bounded claim's shape, not whether its
// evidence is true. Nil remains readable for older/custom planners and stored
// decisions; callers must treat missing applicability as unknown, never proof.
func ValidateApplicability(a *Applicability) error {
	if a == nil {
		return nil
	}
	switch a.Status {
	case "unknown", "affected", "not_affected":
	default:
		return errors.New("planner applicability status must be unknown, affected, or not_affected")
	}
	if len(a.Product) > 500 || len(a.Condition) > 2000 || len(a.Evidence) > 16 {
		return errors.New("planner applicability exceeds product, condition, or evidence limits")
	}
	for _, evidence := range a.Evidence {
		if strings.TrimSpace(evidence) == "" || len(evidence) > 2000 {
			return errors.New("planner applicability evidence must contain 1..2000 bytes per entry")
		}
	}
	if a.Status != "unknown" && (strings.TrimSpace(a.Product) == "" || strings.TrimSpace(a.Condition) == "" || len(a.Evidence) == 0) {
		return errors.New("planner resolved applicability requires product, condition, and local evidence")
	}
	return nil
}

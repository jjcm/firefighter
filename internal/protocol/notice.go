package protocol

import (
	"errors"
	"strings"
)

// ValidateNoticeDisposition bounds an explicit classification of source text
// as not being a vulnerability notice. It does not establish that the model's
// interpretation is correct. Older outcomes retain their existing contract.
func ValidateNoticeDisposition(d Decision) error {
	if d.Assessment != "not_a_notice" {
		return nil
	}
	if !d.Done || len(d.Actions) != 0 || len(d.MemoryUpdates) != 0 {
		return errors.New("not_a_notice requires a final decision with no actions or memory updates")
	}
	if d.Applicability == nil || d.Applicability.Status != "unknown" {
		return errors.New("not_a_notice requires explicit unknown applicability, not a host safety claim")
	}
	if len(d.Evidence) == 0 || len(d.Evidence) > 16 {
		return errors.New("not_a_notice requires 1..16 evidence strings explaining the source classification")
	}
	for _, evidence := range d.Evidence {
		if strings.TrimSpace(evidence) == "" || len(evidence) > 2000 {
			return errors.New("not_a_notice evidence must contain 1..2000 bytes per entry")
		}
	}
	return nil
}

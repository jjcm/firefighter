package protocol

import (
	"errors"
	"regexp"
	"strings"
)

var memoryKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidateMemoryUpdates bounds persistent model notes before they are retained.
// Callers additionally require an actionless decision before applying updates.
func ValidateMemoryUpdates(updates []MemoryUpdate) error {
	if len(updates) > 8 {
		return errors.New("planner exceeded 8 memory updates")
	}
	keys := make(map[string]bool, len(updates))
	for _, update := range updates {
		if !memoryKeyPattern.MatchString(update.Key) || keys[update.Key] {
			return errors.New("planner memory keys must be unique lowercase identifiers of 1..64 characters")
		}
		keys[update.Key] = true
		switch update.Operation {
		case "delete":
			if update.Text != "" || len(update.Evidence) != 0 || len(update.Tags) != 0 || update.TTLHours != 0 {
				return errors.New("planner memory deletion requires empty text, evidence, tags, and zero ttl_hours")
			}
		case "upsert":
			if strings.TrimSpace(update.Text) == "" || len(update.Text) > 2000 {
				return errors.New("planner memory text must contain 1..2000 bytes")
			}
			if update.TTLHours < 1 || update.TTLHours > 720 {
				return errors.New("planner memory ttl_hours must be 1..720")
			}
			if len(update.Evidence) > 8 || len(update.Tags) > 8 {
				return errors.New("planner memory evidence and tags must each have at most 8 entries")
			}
			for _, evidence := range update.Evidence {
				if len(evidence) > 500 {
					return errors.New("planner memory evidence exceeds 500 bytes")
				}
			}
			for _, tag := range update.Tags {
				if len(tag) > 64 {
					return errors.New("planner memory tag exceeds 64 bytes")
				}
			}
		default:
			return errors.New("planner memory operation must be upsert or delete")
		}
	}
	return nil
}

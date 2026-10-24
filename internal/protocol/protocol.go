// Package protocol defines the bounded agent decision and execution contract.
package protocol

import "time"

type Action struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	Argv           []string `json:"argv"`
	Dir            string   `json:"dir,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
	Reason         string   `json:"reason"`
	Mutates        bool     `json:"mutates"`
	Rollback       []string `json:"rollback,omitempty"`
	Verify         []string `json:"verify,omitempty"`
}

type ActionResult struct {
	ActionID   string    `json:"action_id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	ExitCode   int       `json:"exit_code"`
	Output     string    `json:"output"`
	Error      string    `json:"error,omitempty"`
	Truncated  bool      `json:"truncated,omitempty"`
	TimedOut   bool      `json:"timed_out,omitempty"`
	Skipped    bool      `json:"skipped,omitempty"`
}

// MemoryUpdate records model recollections, never operator policy or executable
// instructions. The harness assigns provenance, timestamps, and expiration.
type MemoryUpdate struct {
	Operation string   `json:"operation"`
	Key       string   `json:"key"`
	Text      string   `json:"text"`
	Evidence  []string `json:"evidence"`
	Tags      []string `json:"tags"`
	TTLHours  int      `json:"ttl_hours"`
}

// Applicability records the model's evidence that a notice does or does not
// apply locally. It is an observation claim, not independent verification.
type Applicability struct {
	Status    string   `json:"status"`
	Product   string   `json:"product"`
	Condition string   `json:"condition"`
	Evidence  []string `json:"evidence"`
}

type Decision struct {
	Summary       string         `json:"summary"`
	Assessment    string         `json:"assessment"`
	Applicability *Applicability `json:"applicability,omitempty"`
	Evidence      []string       `json:"evidence"`
	Actions       []Action       `json:"actions"`
	Done          bool           `json:"done"`
	FollowUp      string         `json:"follow_up,omitempty"`
	MemoryUpdates []MemoryUpdate `json:"memory_updates,omitempty"`
}

type Turn struct {
	Decision Decision       `json:"decision"`
	Results  []ActionResult `json:"results"`
}

// Request contains untrusted observations, never higher-priority instructions.
// RawMessage avoids coupling a planner to a particular inventory or source.
type Request struct {
	IncidentID            string              `json:"incident_id"`
	Host                  interface{}         `json:"host"`
	Intel                 interface{}         `json:"intel"`
	History               []Turn              `json:"history"`
	Memory                interface{}         `json:"memory,omitempty"`
	Instructions          string              `json:"instructions"`
	RotationHooks         map[string][]string `json:"rotation_hooks,omitempty"`
	RecoveryNotes         []string            `json:"recovery_notes,omitempty"`
	RoundsRemaining       int                 `json:"rounds_remaining"`
	ApplicabilityRequired bool                `json:"applicability_required"`
}

// Event is the stable outbound reporting contract. Raw command output stays local.
type Event struct {
	ID         string                 `json:"id"`
	Time       time.Time              `json:"time"`
	Host       string                 `json:"host"`
	Type       string                 `json:"type"`
	IncidentID string                 `json:"incident_id,omitempty"`
	Summary    string                 `json:"summary"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

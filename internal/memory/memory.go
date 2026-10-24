// Package memory stores bounded, expiring host observations shared by incidents.
// Notes are untrusted model observations, never instructions or proof that a
// remembered version, exposure, or remediation is still current.
package memory

import (
	"sort"
	"strings"
	"time"

	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/protocol"
)

const (
	CacheTTL        = 5 * time.Minute
	MaxNotes        = 128
	MaxContextNotes = 16
)

type State struct {
	Inventory *Inventory      `json:"inventory,omitempty"`
	Notes     map[string]Note `json:"notes,omitempty"`
}

type Inventory struct {
	Snapshot          host.Snapshot `json:"snapshot"`
	InvalidatedAt     time.Time     `json:"invalidated_at,omitempty"`
	InvalidatedReason string        `json:"invalidated_reason,omitempty"`
}

type Note struct {
	Key        string    `json:"key"`
	Text       string    `json:"text"`
	Evidence   []string  `json:"evidence,omitempty"`
	Tags       []string  `json:"tags,omitempty"`
	IncidentID string    `json:"incident_id"`
	UpdatedAt  time.Time `json:"updated_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Fresh describes cache age only. A fresh inventory may still contain failed or
// incomplete probes and is not evidence that the host is uncompromised.
func (in *Inventory) Fresh(now time.Time) bool {
	return in != nil && in.InvalidatedAt.IsZero() &&
		!in.Snapshot.CollectedAt.IsZero() && !in.Snapshot.CollectedAt.After(now) &&
		now.Sub(in.Snapshot.CollectedAt) <= CacheTTL
}

// Invalidate retains the old snapshot as explicitly stale context. Call before
// starting a mutation, since a crash can hide whether the command completed.
func (s *State) Invalidate(reason string, now time.Time) {
	if s.Inventory != nil {
		s.Inventory.InvalidatedAt = now.UTC()
		s.Inventory.InvalidatedReason = reason
	}
}

// Prune also checks loaded state so expired, malformed, or oversized notes do not
// become model context after a restart. Ties consistently retain the first key.
func (s *State) Prune(now time.Time) {
	for key, note := range s.Notes {
		if key != note.Key || !validNote(note, now) {
			delete(s.Notes, key)
		}
	}
	if len(s.Notes) <= MaxNotes {
		return
	}
	notes := make([]Note, 0, len(s.Notes))
	for _, note := range s.Notes {
		notes = append(notes, note)
	}
	sort.Slice(notes, func(i, j int) bool { return newer(notes[i], notes[j]) })
	for _, note := range notes[MaxNotes:] {
		delete(s.Notes, note.Key)
	}
}

// Apply ignores invalid update batches defensively. The planner rejects
// malformed decisions before this point; redaction belongs to the caller.
func (s *State) Apply(updates []protocol.MemoryUpdate, incidentID string, now time.Time) {
	s.Prune(now)
	if protocol.ValidateMemoryUpdates(updates) != nil {
		return
	}
	for _, update := range updates {
		if update.Operation == "delete" {
			delete(s.Notes, update.Key)
			continue
		}
		if s.Notes == nil {
			s.Notes = make(map[string]Note)
		}
		s.Notes[update.Key] = Note{
			Key: update.Key, Text: update.Text,
			Evidence: append([]string(nil), update.Evidence...),
			Tags:     append([]string(nil), update.Tags...), IncidentID: incidentID,
			UpdatedAt: now.UTC(), ExpiresAt: now.UTC().Add(time.Duration(update.TTLHours) * time.Hour),
		}
	}
	s.Prune(now)
}

// RelevantNotes returns independent copies, prioritizing exact case-insensitive
// tag matches, then recent observations. It does not mutate shared state.
func (s *State) RelevantNotes(tags []string, now time.Time) []Note {
	wanted := make(map[string]bool, len(tags))
	for _, tag := range tags {
		wanted[strings.ToLower(strings.TrimSpace(tag))] = true
	}
	type candidate struct {
		note    Note
		matches int
	}
	var candidates []candidate
	for key, note := range s.Notes {
		if key != note.Key || !validNote(note, now) {
			continue
		}
		matches := 0
		seen := make(map[string]bool, len(note.Tags))
		for _, tag := range note.Tags {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag != "" && wanted[tag] && !seen[tag] {
				matches++
				seen[tag] = true
			}
		}
		candidates = append(candidates, candidate{note: note, matches: matches})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].matches != candidates[j].matches {
			return candidates[i].matches > candidates[j].matches
		}
		return newer(candidates[i].note, candidates[j].note)
	})
	var notes []Note
	for _, c := range candidates[:min(len(candidates), MaxContextNotes)] {
		note := c.note
		note.Evidence = append([]string(nil), note.Evidence...)
		note.Tags = append([]string(nil), note.Tags...)
		notes = append(notes, note)
	}
	return notes
}

func newer(a, b Note) bool {
	if !a.UpdatedAt.Equal(b.UpdatedAt) {
		return a.UpdatedAt.After(b.UpdatedAt)
	}
	return a.Key < b.Key
}

func validNote(note Note, now time.Time) bool {
	content := protocol.MemoryUpdate{
		Operation: "upsert", Key: note.Key, Text: note.Text,
		Evidence: note.Evidence, Tags: note.Tags, TTLHours: 1,
	}
	return protocol.ValidateMemoryUpdates([]protocol.MemoryUpdate{content}) == nil &&
		!note.UpdatedAt.IsZero() && !note.UpdatedAt.After(now) &&
		note.ExpiresAt.After(note.UpdatedAt) && note.ExpiresAt.After(now) &&
		note.ExpiresAt.Sub(note.UpdatedAt) <= 720*time.Hour
}

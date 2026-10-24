package engine

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/memory"
	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/store"
)

const discardedMemoryUpdateNote = "An earlier decision bundled memory updates with pending actions. Those updates were discarded and were not saved. Inspect the actual action results before proposing any replacement notes in a decision with no actions; never assume a planned action succeeded."

// These records are observations supplied in the planner's data message. They
// never enter operator instructions or provide authority to execute commands.
type memoryContext struct {
	Inventory         inventoryContext `json:"inventory"`
	Notes             []memory.Note    `json:"notes"`
	PreviousIncidents []incidentMemory `json:"previous_incidents"`
}

type inventoryContext struct {
	CollectedAt       time.Time `json:"collected_at"`
	Cached            bool      `json:"cached"`
	Stale             bool      `json:"stale"`
	Incomplete        bool      `json:"incomplete"`
	TTLSeconds        int       `json:"ttl_seconds"`
	RefreshError      string    `json:"refresh_error,omitempty"`
	InvalidatedReason string    `json:"invalidated_reason,omitempty"`
}

type incidentMemory struct {
	IncidentID        string         `json:"incident_id"`
	Title             string         `json:"title"`
	CVEs              []string       `json:"cves"`
	Status            string         `json:"status"`
	Assessment        string         `json:"assessment"`
	Summary           string         `json:"summary"`
	Evidence          []string       `json:"evidence"`
	FollowUp          string         `json:"follow_up,omitempty"`
	LastError         string         `json:"last_error,omitempty"`
	UpdatedAt         time.Time      `json:"updated_at"`
	FinalAssessment   bool           `json:"final_assessment"`
	LastActionResults []actionMemory `json:"last_action_results,omitempty"`
}

type actionMemory struct {
	ActionID   string    `json:"action_id"`
	ExitCode   int       `json:"exit_code"`
	Error      string    `json:"error,omitempty"`
	TimedOut   bool      `json:"timed_out"`
	Skipped    bool      `json:"skipped"`
	FinishedAt time.Time `json:"finished_at"`
}

func (e *Engine) inventory(ctx context.Context, force bool) (host.Snapshot, inventoryContext, error) {
	now := time.Now().UTC()
	e.mu.Lock()
	cache := e.State.Memory.Inventory
	if !force && cache.Fresh(now) {
		snapshot := e.cleanSnapshot(cache.Snapshot)
		info := inventoryContext{CollectedAt: snapshot.CollectedAt, Cached: true, Incomplete: len(snapshot.Problems) > 0, TTLSeconds: int(memory.CacheTTL.Seconds())}
		e.mu.Unlock()
		return snapshot, info, nil
	}
	e.mu.Unlock()

	snapshot, collectErr := e.Collect(ctx)
	if snapshot.CollectedAt.IsZero() {
		snapshot.CollectedAt = now
	}
	snapshot = e.cleanSnapshot(snapshot)
	cache = &memory.Inventory{Snapshot: snapshot}
	info := inventoryContext{CollectedAt: snapshot.CollectedAt, TTLSeconds: int(memory.CacheTTL.Seconds())}
	if collectErr != nil {
		info.RefreshError = e.Redact(collectErr.Error())
		snapshot.Problems = append(snapshot.Problems, host.Problem{Probe: "inventory", Kind: "collection_failed", Detail: info.RefreshError})
		cache.Snapshot = snapshot
		cache.InvalidatedAt = time.Now().UTC()
		cache.InvalidatedReason = "Inventory collection failed; current host state is incomplete"
		info.InvalidatedReason = cache.InvalidatedReason
	}
	info.Incomplete = len(snapshot.Problems) > 0
	info.Stale = !cache.Fresh(time.Now().UTC())
	e.mu.Lock()
	defer e.mu.Unlock()
	e.State.Memory.Inventory = cache
	e.State.Memory.Prune(time.Now().UTC())
	// Store only redacted inventory, and checkpoint before it drives a decision.
	return e.cleanSnapshot(snapshot), info, e.Store.Save(e.State)
}

func (e *Engine) cleanMemoryUpdates(updates []protocol.MemoryUpdate) []protocol.MemoryUpdate {
	var clean []protocol.MemoryUpdate
	for _, update := range updates {
		update.Key = e.Redact(update.Key)
		update.Text = bounded(e.Redact(update.Text), 2000)
		update.Evidence = boundedStrings(update.Evidence, 8, 500, e.Redact)
		update.Tags = boundedStrings(update.Tags, 8, 64, e.Redact)
		// A key containing a credential may no longer be a valid identifier
		// after redaction. Discard that update rather than retaining the secret
		// or preventing unrelated valid notes from being remembered.
		if protocol.ValidateMemoryUpdates([]protocol.MemoryUpdate{update}) == nil {
			clean = append(clean, update)
		}
	}
	return clean
}

// memoryContextLocked selects a bounded view, including incidents recorded by
// earlier versions. There is no embedding service or additional model call.
func (e *Engine) memoryContextLocked(current *store.Incident, info inventoryContext) memoryContext {
	now := time.Now().UTC()
	e.State.Memory.Prune(now)
	tags := incidentTags(current)
	result := memoryContext{Inventory: info, Notes: e.State.Memory.RelevantNotes(tags, now), PreviousIncidents: []incidentMemory{}}
	for i := range result.Notes {
		n := &result.Notes[i]
		n.Key, n.Text, n.IncidentID = e.Redact(n.Key), e.Redact(n.Text), e.Redact(n.IncidentID)
		n.Evidence, n.Tags = cleanStrings(n.Evidence, e.Redact), cleanStrings(n.Tags, e.Redact)
	}
	type candidate struct {
		incident *store.Incident
		score    int
	}
	var previous []candidate
	for _, in := range e.State.Incidents {
		if in == nil || in.ID == current.ID || in.Status == "pending" || len(in.History) == 0 {
			continue
		}
		score := overlap(tags, incidentTags(in))
		// Exact CVE matches outrank title keywords.
		score += 100 * overlap(current.Item.CVEs, in.Item.CVEs)
		previous = append(previous, candidate{in, score})
	}
	sort.Slice(previous, func(i, j int) bool {
		if previous[i].score != previous[j].score {
			return previous[i].score > previous[j].score
		}
		if !previous[i].incident.UpdatedAt.Equal(previous[j].incident.UpdatedAt) {
			return previous[i].incident.UpdatedAt.After(previous[j].incident.UpdatedAt)
		}
		return previous[i].incident.ID < previous[j].incident.ID
	})
	if len(previous) > 8 {
		previous = previous[:8]
	}
	for _, p := range previous {
		in := p.incident
		d := in.History[len(in.History)-1].Decision
		summary := incidentMemory{
			IncidentID: e.Redact(in.ID), Title: bounded(e.Redact(in.Item.Title), 200), CVEs: boundedStrings(in.Item.CVEs, 16, 64, e.Redact),
			Status: bounded(e.Redact(in.Status), 32), Assessment: bounded(e.Redact(d.Assessment), 32),
			Summary: bounded(e.Redact(d.Summary), 600), Evidence: boundedStrings(d.Evidence, 4, 300, e.Redact),
			FollowUp: bounded(e.Redact(d.FollowUp), 600), LastError: bounded(e.Redact(in.LastError), 300), UpdatedAt: in.UpdatedAt,
			FinalAssessment: in.Status == "completed" && in.LastError == "",
		}
		if summary.Assessment == "remediated" && !summary.FinalAssessment {
			// The most recent model claim may have been rejected by the engine.
			// Keep its error/status visible without promoting it to a past fix.
			summary.Assessment = "unknown"
		}
		for i := len(in.History) - 1; i >= 0; i-- {
			results := in.History[i].Results
			if len(results) == 0 {
				continue
			}
			if len(results) > 4 {
				results = results[len(results)-4:]
			}
			for _, r := range results {
				summary.LastActionResults = append(summary.LastActionResults, actionMemory{ActionID: bounded(e.Redact(r.ActionID), 128), ExitCode: r.ExitCode, Error: bounded(e.Redact(r.Error), 300), TimedOut: r.TimedOut, Skipped: r.Skipped, FinishedAt: r.FinishedAt})
			}
			break
		}
		result.PreviousIncidents = append(result.PreviousIncidents, summary)
	}
	return result
}

func incidentTags(in *store.Incident) []string {
	tags := append([]string(nil), in.Item.CVEs...)
	for _, word := range strings.FieldsFunc(strings.ToLower(in.Item.Title), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(word) < 4 || len(word) > 64 || strings.IndexFunc(word, unicode.IsLetter) < 0 {
			continue
		}
		switch word {
		case "security", "update", "updates", "advisory", "vulnerability", "vulnerabilities", "critical", "notice", "multiple":
			continue
		}
		tags = append(tags, word)
		if len(tags) >= 64 {
			break
		}
	}
	return tags
}

func overlap(a, b []string) int {
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[strings.ToLower(v)] = true
	}
	n := 0
	for _, v := range b {
		key := strings.ToLower(v)
		if set[key] {
			n++
			delete(set, key)
		}
	}
	return n
}

func bounded(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit-3]
	for !utf8.ValidString(s) && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return s + "..."
}

func boundedStrings(values []string, count, size int, redact func(string) string) []string {
	if len(values) > count {
		values = values[:count]
	}
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = bounded(redact(v), size)
	}
	return out
}

// Copy all reference fields before redaction so neither cached state nor a
// collector's buffer can be modified through a planner request.
func (e *Engine) cleanSnapshot(s host.Snapshot) host.Snapshot {
	s.Hostname, s.Platform, s.Architecture = e.Redact(s.Hostname), e.Redact(s.Platform), e.Redact(s.Architecture)
	s.Kernel, s.PackageManager = e.Redact(s.Kernel), e.Redact(s.PackageManager)
	s.PackageUpdates = e.Redact(s.PackageUpdates)
	s.Processes, s.ListeningSockets = e.Redact(s.Processes), e.Redact(s.ListeningSockets)
	s.Services, s.Containers = e.Redact(s.Services), e.Redact(s.Containers)
	release := make(map[string]string, len(s.OSRelease))
	for key, value := range s.OSRelease {
		release[e.Redact(key)] = e.Redact(value)
	}
	s.OSRelease = release
	s.Packages = append([]host.Package(nil), s.Packages...)
	for i := range s.Packages {
		p := &s.Packages[i]
		p.Name, p.Version, p.Architecture, p.Manager = e.Redact(p.Name), e.Redact(p.Version), e.Redact(p.Architecture), e.Redact(p.Manager)
	}
	s.Scanners = append([]host.ToolStatus(nil), s.Scanners...)
	for i := range s.Scanners {
		s.Scanners[i].Name = e.Redact(s.Scanners[i].Name)
		s.Scanners[i].Path = e.Redact(s.Scanners[i].Path)
	}
	s.Probes = append([]host.ProbeStatus(nil), s.Probes...)
	for i := range s.Probes {
		s.Probes[i].Name = e.Redact(s.Probes[i].Name)
		s.Probes[i].Error = e.Redact(s.Probes[i].Error)
	}
	s.Problems = append([]host.Problem(nil), s.Problems...)
	for i := range s.Problems {
		p := &s.Problems[i]
		p.Probe, p.Kind, p.Detail = e.Redact(p.Probe), e.Redact(p.Kind), e.Redact(p.Detail)
	}
	return s
}

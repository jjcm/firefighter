package memory

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/protocol"
)

func TestInventoryFreshnessAndInvalidation(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		inventory *Inventory
		want      bool
	}{
		{"missing", nil, false},
		{"undated", &Inventory{}, false},
		{"current", &Inventory{Snapshot: host.Snapshot{CollectedAt: now}}, true},
		{"ttl boundary", &Inventory{Snapshot: host.Snapshot{CollectedAt: now.Add(-CacheTTL)}}, true},
		{"expired", &Inventory{Snapshot: host.Snapshot{CollectedAt: now.Add(-CacheTTL - time.Nanosecond)}}, false},
		{"future", &Inventory{Snapshot: host.Snapshot{CollectedAt: now.Add(time.Nanosecond)}}, false},
		{"invalidated", &Inventory{Snapshot: host.Snapshot{CollectedAt: now}, InvalidatedAt: now}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.inventory.Fresh(now); got != tc.want {
				t.Fatalf("Fresh = %v, want %v", got, tc.want)
			}
		})
	}
	s := State{Inventory: &Inventory{Snapshot: host.Snapshot{CollectedAt: now, Kernel: "remembered-kernel"}}}
	s.Invalidate("command may have changed this host", now)
	if s.Inventory.Fresh(now) || s.Inventory.Snapshot.Kernel != "remembered-kernel" || s.Inventory.InvalidatedReason == "" || !s.Inventory.InvalidatedAt.Equal(now) {
		t.Fatalf("invalidation discarded evidence or left it fresh: %+v", s.Inventory)
	}
	var empty State
	empty.Invalidate("no inventory", now)
}

func TestNotesReplaceExpireDeleteAndDoNotAliasInput(t *testing.T) {
	now := time.Now().UTC()
	var s State
	update := protocol.MemoryUpdate{Operation: "upsert", Key: "nginx.location", Text: "nginx serves /srv/www", Evidence: []string{"observed nginx configuration"}, Tags: []string{"nginx"}, TTLHours: 24}
	s.Apply([]protocol.MemoryUpdate{update}, "incident-1", now)
	update.Evidence[0] = "changed by caller"
	update.Tags[0] = "changed by caller"
	note := s.Notes[update.Key]
	if note.IncidentID != "incident-1" || note.Evidence[0] != "observed nginx configuration" || note.Tags[0] != "nginx" || !note.ExpiresAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("note metadata or copied evidence lost: %+v", note)
	}
	update.Text = "nginx now serves /srv/new"
	update.TTLHours = 1
	s.Apply([]protocol.MemoryUpdate{update}, "incident-2", now.Add(time.Minute))
	if len(s.Notes) != 1 || s.Notes[update.Key].Text != update.Text || s.Notes[update.Key].IncidentID != "incident-2" {
		t.Fatalf("updated note did not replace stale observation: %+v", s.Notes)
	}
	s.Prune(now.Add(time.Hour + time.Minute))
	if len(s.Notes) != 0 {
		t.Fatal("note remained at its expiration time")
	}
	s.Apply([]protocol.MemoryUpdate{update}, "incident-3", now)
	s.Apply([]protocol.MemoryUpdate{{Operation: "delete", Key: update.Key}}, "incident-4", now)
	if len(s.Notes) != 0 {
		t.Fatal("delete retained the note")
	}
}

func TestInvalidUpdateBatchCannotPartiallyChangeNotes(t *testing.T) {
	now := time.Now().UTC()
	good := protocol.MemoryUpdate{Operation: "upsert", Key: "retained", Text: "original observation", TTLHours: 24}
	for _, tc := range []struct {
		name    string
		updates []protocol.MemoryUpdate
	}{
		{"unknown operation", []protocol.MemoryUpdate{{Operation: "execute", Key: "bad", Text: "command", TTLHours: 1}}},
		{"missing expiry", []protocol.MemoryUpdate{{Operation: "upsert", Key: "bad", Text: "observation"}}},
		{"oversized text", []protocol.MemoryUpdate{{Operation: "upsert", Key: "bad", Text: strings.Repeat("a", 2001), TTLHours: 1}}},
		{"duplicate keys", []protocol.MemoryUpdate{good, good}},
		{"delete with payload", []protocol.MemoryUpdate{{Operation: "delete", Key: "retained", Text: "ignored?"}}},
		{"too many", make([]protocol.MemoryUpdate, 9)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s State
			s.Apply([]protocol.MemoryUpdate{good}, "original", now)
			s.Apply(append([]protocol.MemoryUpdate{{Operation: "delete", Key: "retained"}}, tc.updates...), "invalid", now)
			if len(s.Notes) != 1 || s.Notes["retained"].IncidentID != "original" {
				t.Fatalf("invalid batch partially applied: %+v", s.Notes)
			}
		})
	}
}

func TestNotesBoundedWithDeterministicEviction(t *testing.T) {
	now := time.Now().UTC()
	var s State
	for i := 0; i < MaxNotes+2; i++ {
		update := protocol.MemoryUpdate{Operation: "upsert", Key: fmt.Sprintf("note.%03d", i), Text: "observed fact", TTLHours: 1}
		s.Apply([]protocol.MemoryUpdate{update}, "incident", now.Add(time.Duration(i)*time.Second))
	}
	if len(s.Notes) != MaxNotes || s.Notes["note.000"].Key != "" || s.Notes["note.001"].Key != "" || s.Notes["note.129"].Key == "" {
		t.Fatalf("oldest notes were not evicted: count=%d", len(s.Notes))
	}
	s.Notes = make(map[string]Note)
	for i := 0; i < MaxNotes+2; i++ {
		key := fmt.Sprintf("note.%03d", i)
		s.Notes[key] = Note{Key: key, Text: "same timestamp", UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	s.Prune(now)
	if len(s.Notes) != MaxNotes || s.Notes["note.000"].Key == "" || s.Notes["note.127"].Key == "" || s.Notes["note.128"].Key != "" {
		t.Fatal("equal-age eviction was not deterministic by key")
	}
}

func TestRelevantNotesPreferMatchingTagsAndReturnBoundedCopies(t *testing.T) {
	now := time.Now().UTC()
	var s State
	for i := 0; i < MaxContextNotes+4; i++ {
		s.Apply([]protocol.MemoryUpdate{{Operation: "upsert", Key: fmt.Sprintf("recent.%02d", i), Text: "unrelated fact", TTLHours: 1}}, "other", now.Add(time.Duration(i)*time.Second))
	}
	update := protocol.MemoryUpdate{Operation: "upsert", Key: "relevant", Text: "openssl is used by a private service", Evidence: []string{"read private service manifest"}, Tags: []string{"OpenSSL", "CVE-2026-12345", "openssl"}, TTLHours: 1}
	s.Apply([]protocol.MemoryUpdate{update}, "older", now.Add(20*time.Second))
	// Match relevance must win even when this note is older than other notes.
	note := s.Notes["relevant"]
	note.UpdatedAt = now.Add(-time.Minute)
	note.ExpiresAt = now.Add(30 * time.Minute)
	s.Notes["relevant"] = note
	got := s.RelevantNotes([]string{" openssl ", "cve-2026-12345"}, now.Add(time.Minute))
	if len(got) != MaxContextNotes || got[0].Key != "relevant" || got[1].Key != "recent.19" {
		t.Fatalf("relevance/recency or context bounds lost: %+v", got)
	}
	got[0].Text = "changed"
	got[0].Evidence[0] = "changed"
	got[0].Tags[0] = "changed"
	if stored := s.Notes["relevant"]; stored.Text == "changed" || stored.Evidence[0] == "changed" || stored.Tags[0] == "changed" {
		t.Fatal("planner-visible notes alias durable state")
	}
	if got := s.RelevantNotes([]string{"open"}, now.Add(time.Minute)); got[0].Key == "relevant" {
		t.Fatal("partial tag unexpectedly counted as exact match")
	}
	if got := s.RelevantNotes([]string{"openssl"}, now.Add(time.Hour)); len(got) != MaxContextNotes || got[0].Key == "relevant" {
		t.Fatal("expired matching note was included")
	}
}

func TestPruneAndRetrievalExcludeInvalidLoadedNotes(t *testing.T) {
	now := time.Now().UTC()
	valid := Note{Key: "valid", Text: "observed fact", UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
	s := State{Notes: map[string]Note{"valid": valid}}
	for _, key := range []string{"empty", "future", "expired", "unbounded", "oversized", "wrong-key", "undated"} {
		note := valid
		note.Key = key
		switch key {
		case "empty":
			note.Text = "  "
		case "future":
			note.UpdatedAt = now.Add(time.Minute)
		case "expired":
			note.ExpiresAt = now
		case "unbounded":
			note.ExpiresAt = now.Add(721 * time.Hour)
		case "oversized":
			note.Text = strings.Repeat("a", 2001)
		case "wrong-key":
			note.Key = "different-key"
		case "undated":
			note.UpdatedAt = time.Time{}
		}
		s.Notes[key] = note
	}
	if got := s.RelevantNotes(nil, now); len(got) != 1 || got[0].Key != "valid" {
		t.Fatalf("invalid loaded notes reached context before pruning: %+v", got)
	}
	s.Prune(now)
	if len(s.Notes) != 1 || s.Notes["valid"].Key != "valid" {
		t.Fatalf("invalid loaded notes remained in state: %+v", s.Notes)
	}
}

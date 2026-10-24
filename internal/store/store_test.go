package store

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/intel"
	"github.com/jjcm/firefighter/internal/memory"
	"github.com/jjcm/firefighter/internal/protocol"
)

func TestHostMemorySurvivesRestartButInventoryMustRefresh(t *testing.T) {
	dir := t.TempDir()
	s, state, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	state.Memory.Inventory = &memory.Inventory{Snapshot: host.Snapshot{CollectedAt: now, Hostname: "remembered-host", Packages: []host.Package{{Name: "nginx", Version: "1.2.3", Manager: "apt"}}}}
	state.Memory.Apply([]protocol.MemoryUpdate{{Operation: "upsert", Key: "nginx.location", Text: "nginx serves /srv/www", Evidence: []string{"read nginx configuration"}, Tags: []string{"nginx"}, TTLHours: 24}}, "incident-1", now)
	state.Memory.Notes["expired"] = memory.Note{Key: "expired", Text: "no longer valid", UpdatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, recovered, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	note := recovered.Memory.Notes["nginx.location"]
	if len(recovered.Memory.Notes) != 1 || note.IncidentID != "incident-1" || note.Text != "nginx serves /srv/www" || note.Tags[0] != "nginx" || !note.UpdatedAt.Equal(now) {
		t.Fatalf("persistent notes or expiry lost on restart: %+v", recovered.Memory.Notes)
	}
	inventory := recovered.Memory.Inventory
	if inventory == nil || inventory.Fresh(time.Now()) || inventory.InvalidatedAt.IsZero() || !strings.Contains(inventory.InvalidatedReason, "restarted") {
		t.Fatalf("restart treated cached inventory as current: %+v", inventory)
	}
	if inventory.Snapshot.Hostname != "remembered-host" || inventory.Snapshot.Packages[0].Version != "1.2.3" || !inventory.Snapshot.CollectedAt.Equal(now) {
		t.Fatalf("restart discarded prior host evidence: %+v", inventory)
	}
}

func TestStateWithoutHostMemoryStillLoads(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"version":1,"sources":{"hub":{"cursor":"42"}},"incidents":{},"outbox":[],"last_host_review":"0001-01-01T00:00:00Z"}`
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	s, state, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if state.Sources["hub"].Cursor != "42" || state.Memory.Inventory != nil || len(state.Memory.Notes) != 0 {
		t.Fatalf("old state did not retain cursors and empty memory: %+v", state)
	}
	state.Memory.Apply([]protocol.MemoryUpdate{{Operation: "upsert", Key: "first-note", Text: "first observation after upgrade", TTLHours: 1}}, "new-incident", time.Now())
	if len(state.Memory.Notes) != 1 {
		t.Fatal("upgraded state could not accept new notes")
	}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
}

func TestExclusiveLockAndStatePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, _, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if other, _, err := Open(dir); err == nil {
		other.Close()
		t.Fatal("second daemon acquired an active state directory")
	}
	for _, path := range []string{dir, filepath.Join(dir, "lock"), filepath.Join(dir, "audit.jsonl")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatalf("state is accessible to other users: %s %o", path, info.Mode().Perm())
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, _, err = Open(dir)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	s.Close()
}

func TestStatePersistenceRecoversRunningIncidentWithoutReplay(t *testing.T) {
	dir := t.TempDir()
	s, state, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 24, 1, 0, 0, 0, time.UTC)
	action := protocol.Action{ID: "patch-1", Kind: "command", Argv: []string{"/usr/bin/true"}, Mutates: true, Reason: "fixture only"}
	state.Sources["x"] = SourceState{Cursor: "12345", LastSuccess: now, NextPoll: now.Add(time.Minute)}
	state.Incidents["incident-1"] = &Incident{ID: "incident-1", Item: intel.Item{ID: "CVE-fixture", Source: "x"}, Status: "running", Attempts: 2, NextAttempt: now.Add(time.Hour), History: []protocol.Turn{{Decision: protocol.Decision{Summary: "pending fixture command", Actions: []protocol.Action{action}}}}}
	state.LastHostReview = now
	if err := s.Append("action_intent", "incident-1", action); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, recovered, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	incident := recovered.Incidents["incident-1"]
	if incident.Status != "pending" || !incident.NextAttempt.IsZero() || incident.Attempts != 2 || len(incident.History) != 1 || len(incident.History[0].Results) != 0 {
		t.Fatalf("interrupted command was not scheduled for reassessment: %+v", incident)
	}
	if !strings.Contains(strings.Join(incident.RecoveryNotes, " "), "do not blindly replay") {
		t.Fatalf("uncertain execution state was not disclosed: %+v", incident.RecoveryNotes)
	}
	if recovered.Sources["x"].Cursor != "12345" || !recovered.LastHostReview.Equal(now) {
		t.Fatalf("durable cursors lost: %+v", recovered)
	}
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("state file is not private: %v %v", info, err)
	}
}

func TestActionJournalPersistsOrderAndContinuesHashChain(t *testing.T) {
	dir := t.TempDir()
	s, _, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append("action_intent", "incident", protocol.Action{ID: "command-1", Kind: "command", Argv: []string{"/usr/bin/true"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append("action_result", "incident", protocol.ActionResult{ActionID: "command-1", ExitCode: 0}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, _, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append("event", "incident", protocol.Event{ID: "event-1", Type: "assessment_finished"}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	records := readRecords(t, dir)
	if len(records) != 3 || records[0].Type != "action_intent" || records[1].Type != "action_result" || records[2].Type != "event" {
		t.Fatalf("audit sequence lost: %+v", records)
	}
	if records[0].Previous != "" || records[1].Previous != records[0].Hash || records[2].Previous != records[1].Hash {
		t.Fatal("audit hash chain did not continue across reopen")
	}
	s, _, err = Open(dir)
	if err != nil {
		t.Fatalf("new audit suffix failed validation: %v", err)
	}
	s.Close()
}

func TestAuditRejectsEditedOrMissingMiddleRecord(t *testing.T) {
	for _, mode := range []string{"edited", "missing-middle"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			s, _, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, value := range []string{"first", "second", "third"} {
				if err := s.Append("fixture", "", value); err != nil {
					t.Fatal(err)
				}
			}
			s.Close()
			path := filepath.Join(dir, "audit.jsonl")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
			if mode == "edited" {
				lines[1] = strings.Replace(lines[1], "second", "tampered", 1)
			} else {
				lines = append(lines[:1], lines[2:]...)
			}
			if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if reopened, _, err := Open(dir); err == nil {
				reopened.Close()
				t.Fatal("tampered audit was accepted")
			}
		})
	}
}

func TestStoreRejectsSymlinkStatePaths(t *testing.T) {
	for _, name := range []string{"lock", "audit.jsonl", "state.json"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if opened, _, err := Open(dir); err == nil {
				opened.Close()
				t.Fatal("symlink accepted")
			}
			data, _ := os.ReadFile(target)
			if string(data) != "untouched" {
				t.Fatal("symlink target changed")
			}
		})
	}
}

func TestOutboxReplaysAuditAcrossStateCrashWindows(t *testing.T) {
	dir := t.TempDir()
	s, state, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	acknowledged := protocol.Event{ID: "already-delivered", Type: "action_finished", Summary: "delivered before state save"}
	retrying := protocol.Event{ID: "still-retrying", Type: "action_finished", Summary: "retry should retain schedule"}
	newEvent := protocol.Event{ID: "audit-only", Type: "assessment_finished", Summary: "queued before state save"}
	retryTime := time.Date(2026, 10, 24, 2, 0, 0, 0, time.UTC)
	for _, event := range []protocol.Event{acknowledged, retrying} {
		if err := s.Append("report_queued", "", event); err != nil {
			t.Fatal(err)
		}
	}
	state.Outbox = []Delivery{{Event: acknowledged}, {Event: retrying, Attempts: 3, NextAttempt: retryTime}}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	// Both durable journal operations happen after the last state checkpoint.
	if err := s.Append("report_delivered", "", map[string]string{"id": acknowledged.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.Append("report_queued", "", newEvent); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, recovered, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if len(recovered.Outbox) != 2 {
		t.Fatalf("expected two unacknowledged events: %+v", recovered.Outbox)
	}
	found := make(map[string]Delivery)
	for _, delivery := range recovered.Outbox {
		found[delivery.Event.ID] = delivery
	}
	if _, exists := found[acknowledged.ID]; exists {
		t.Fatal("acknowledged report was rescheduled from stale state")
	}
	if got := found[retrying.ID]; got.Attempts != 3 || !got.NextAttempt.Equal(retryTime) {
		t.Fatalf("retry schedule lost: %+v", got)
	}
	if got := found[newEvent.ID]; got.Event.Summary != newEvent.Summary || got.Attempts != 0 {
		t.Fatalf("audit-only report was lost: %+v", got)
	}
}

func TestIncompleteFinalAuditWriteIsPreservedAndRecovered(t *testing.T) {
	dir := t.TempDir()
	s, state, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state.Incidents["interrupted"] = &Incident{ID: "interrupted", Status: "running"}
	if err := s.Append("action_intent", "interrupted", protocol.Action{ID: "fixture-command", Kind: "command", Argv: []string{"/usr/bin/true"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	s.Close()
	fragment := `{"type":"action_result","data":{"output":"incomplete`
	file, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"), os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(fragment); err != nil {
		t.Fatal(err)
	}
	file.Close()
	s, recovered, err := Open(dir)
	if err != nil {
		t.Fatalf("torn append prevented recovery: %v", err)
	}
	if recovered.Incidents["interrupted"].Status != "pending" {
		t.Fatal("interrupted action was not scheduled for reassessment")
	}
	s.Close()
	files, err := filepath.Glob(filepath.Join(dir, "audit-interrupted-*.jsonpart"))
	if err != nil || len(files) != 1 {
		t.Fatalf("torn audit evidence missing: %v %v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil || string(data) != fragment {
		t.Fatalf("torn record bytes were not preserved: %q %v", data, err)
	}
	info, err := os.Stat(files[0])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("torn-record evidence permissions: %v %v", info, err)
	}
	records := readRecords(t, dir)
	if len(records) != 2 || records[0].Type != "action_intent" || records[1].Type != "audit_tail_recovered" {
		t.Fatalf("recovered audit sequence: %+v", records)
	}
	s, _, err = Open(dir)
	if err != nil {
		t.Fatalf("recovered chain failed next startup: %v", err)
	}
	s.Close()
}

func readRecords(t *testing.T, dir string) []Record {
	t.Helper()
	file, err := os.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	var records []Record
	for scanner.Scan() {
		var record Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

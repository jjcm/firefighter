package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/config"
	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/memory"
	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/store"
)

func TestMemoryAndStatusReadOnlyWithDaemonLock(t *testing.T) {
	c := config.Default()
	c.StateDir = t.TempDir()
	s, state, err := store.Open(c.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	state.Memory.Inventory = &memory.Inventory{Snapshot: host.Snapshot{Hostname: "fixture", CollectedAt: now}}
	state.Memory.Apply([]protocol.MemoryUpdate{{Operation: "upsert", Key: "api.repo", Text: "API source lives in /srv/api", TTLHours: 24}}, "previous-cve", now)
	state.Memory.Notes["expired"] = memory.Note{Key: "expired", Text: "Old fact", UpdatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(c.StateDir, "state.json")
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"memory", "status"} {
		t.Run(command, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "output")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			previous := os.Stdout
			os.Stdout = f
			defer func() { os.Stdout = previous }()
			if command == "memory" {
				err = showMemory(c)
			} else {
				err = status(c)
			}
			os.Stdout = previous
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			output, err := io.ReadAll(f)
			if err != nil {
				t.Fatal(err)
			}
			if command == "memory" {
				var got memory.State
				if err := json.Unmarshal(output, &got); err != nil {
					t.Fatal(err)
				}
				if len(got.Notes) != 1 || got.Notes["api.repo"].Text == "" || got.Inventory.Snapshot.Hostname != "fixture" {
					t.Fatalf("unexpected memory: %s", output)
				}
			} else {
				var got struct {
					Memory struct {
						Notes int  `json:"notes"`
						Fresh bool `json:"inventory_fresh"`
					} `json:"memory"`
				}
				if err := json.Unmarshal(output, &got); err != nil {
					t.Fatal(err)
				}
				if got.Memory.Notes != 1 || !got.Memory.Fresh {
					t.Fatalf("unexpected status: %s", output)
				}
			}
			after, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("inspection changed daemon state")
			}
		})
	}
}

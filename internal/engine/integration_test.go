package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/planner"
	"github.com/jjcm/firefighter/internal/protocol"
)

// Exercise the actual HTTP planner, strict parser, subprocess runner, verifier,
// state checkpoints and signed-outbox producer without touching the real host.
func TestAPIToRealPatchVerificationAndDurableCompletion(t *testing.T) {
	e, stateDir, _ := fixtureEngine(t)
	target := filepath.Join(t.TempDir(), "application.conf")
	if err := os.WriteFile(target, []byte("vulnerable"), 0600); err != nil {
		t.Fatal(err)
	}
	in := addIncident(e, "pending")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Errorf("wrong API request: %s", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		var request struct {
			Messages       []struct{ Role, Content string }
			ResponseFormat map[string]interface{} `json:"response_format"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if request.ResponseFormat["type"] != "json_schema" {
			t.Error("missing strict schema request")
		}
		turn := calls.Add(1)
		var d protocol.Decision
		if turn == 1 {
			d = protocol.Decision{Summary: "Replace the vulnerable fixture setting", Assessment: "exposed", Evidence: []string{"Fixture advisory and installed configuration"}, Actions: []protocol.Action{{ID: "patch-config", Kind: "command", Argv: []string{"/bin/sh", "-c", `printf '%s' patched > "$1"`, "fixture", target}, Reason: "Patch temporary application configuration", Mutates: true, TimeoutSeconds: 5, Verify: []string{"/bin/sh", "-c", `test "$(cat "$1")" = patched`, "fixture", target}}}}
		} else {
			if len(request.Messages) < 2 || !strings.Contains(request.Messages[1].Content, "patch-config-verify") {
				t.Error("planner did not receive verification evidence")
			}
			d = protocol.Decision{Summary: "Fixture patched and verified; no claim about overall compromise", Assessment: "remediated", Evidence: []string{"patch-config-verify exited 0"}, Actions: []protocol.Action{}, Done: true}
		}
		content, _ := json.Marshal(d)
		json.NewEncoder(w).Encode(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"finish_reason": "stop", "message": map[string]interface{}{"content": string(content)}}}})
	}))
	defer server.Close()
	api, err := planner.NewAPI(planner.APIConfig{BaseURL: server.URL + "/v1", Model: "fixture", APIKey: "fixture-token", Timeout: time.Second * 5})
	if err != nil {
		t.Fatal(err)
	}
	e.Planner = api
	e.Runner = host.NewRunner(host.Config{MaxTimeout: time.Second * 5, MaxOutputBytes: 4096})
	worked, err := e.ProcessOne(context.Background())
	if err != nil || !worked {
		t.Fatalf("process: worked=%v err=%v", worked, err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "patched" {
		t.Fatalf("target=%q err=%v", content, err)
	}
	if calls.Load() != 2 || in.Status != "completed" {
		t.Fatalf("calls=%d status=%s error=%s", calls.Load(), in.Status, in.LastError)
	}
	saved := readState(t, stateDir)
	if saved.Incidents[in.ID].Status != "completed" {
		t.Fatal("completion not durable")
	}
	audit, err := os.ReadFile(filepath.Join(stateDir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audit), `"type":"action_intent"`) || !strings.Contains(string(audit), `"action_id":"patch-config-verify"`) {
		t.Fatal("missing durable intent or verification evidence")
	}
}

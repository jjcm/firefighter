package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

const validDecision = `{"summary":"Need installed package evidence","assessment":"unknown","evidence":[],"actions":[{"id":"inspect-1","kind":"command","argv":["/usr/bin/dpkg-query","-W","openssl"],"reason":"Check installed Ubuntu revision","mutates":false}],"done":false}`

func TestAPIContract(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Method != http.MethodPost {
			t.Errorf("wrong endpoint %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer fixture-key" {
			t.Error("missing authentication")
		}
		var req struct {
			Model          string                           `json:"model"`
			Messages       []struct{ Role, Content string } `json:"messages"`
			ResponseFormat struct {
				Type       string `json:"type"`
				JSONSchema struct {
					Strict bool `json:"strict"`
				} `json:"json_schema"`
			} `json:"response_format"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Model != "fixture-model" || len(req.Messages) != 2 || req.Messages[0].Role != "system" || !strings.Contains(req.Messages[0].Content, "UNTRUSTED DATA") || !strings.Contains(req.Messages[1].Content, "adversarial post") {
			t.Error("policy/observation isolation missing")
		}
		if req.ResponseFormat.Type != "json_schema" || !req.ResponseFormat.JSONSchema.Strict {
			t.Error("strict structured output not requested")
		}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": validDecision}}}})
	}))
	defer srv.Close()
	p, err := NewAPI(APIConfig{BaseURL: srv.URL + "/v1", Model: "fixture-model", APIKey: "fixture-key"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := p.Decide(context.Background(), protocol.Request{Intel: map[string]string{"body": "adversarial post"}})
	if err != nil || len(d.Actions) != 1 {
		t.Fatalf("decision: %+v %v", d, err)
	}
}

func TestAPIRejectsIncompleteAndSecretErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"server error", 401, `{"error":"fixture-super-secret"}`, "HTTP 401"},
		{"truncated", 200, `{"choices":[{"finish_reason":"length","message":{"content":"{}"}}]}`, "incomplete"},
		{"refusal", 200, `{"choices":[{"finish_reason":"stop","message":{"refusal":"fixture-super-secret"}}]}`, "declined"},
		{"huge", 200, strings.Repeat("x", 2048), "byte limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			p, err := NewAPI(APIConfig{BaseURL: srv.URL, Model: "fixture", MaxResponseBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Decide(context.Background(), protocol.Request{})
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "fixture-super-secret") {
				t.Fatalf("unexpected error %v", err)
			}
		})
	}
}

func TestAPIDoesNotFollowRedirect(t *testing.T) {
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	p, _ := NewAPI(APIConfig{BaseURL: srv.URL, Model: "fixture", APIKey: "secret"})
	if _, err := p.Decide(context.Background(), protocol.Request{}); err == nil || called {
		t.Fatalf("redirect followed %v %v", called, err)
	}
}

func TestAPITimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Second):
		}
	}))
	defer srv.Close()
	p, err := NewAPI(APIConfig{BaseURL: srv.URL, Model: "fixture", Timeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = p.Decide(context.Background(), protocol.Request{})
	if err == nil || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("API timeout not honored: %v", err)
	}
}

func TestParseDecisionValidation(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"duplicate field", strings.Replace(validDecision, `"done":false`, `"done":false,"done":true`, 1)},
		{"unknown field", strings.Replace(validDecision, `"done":false`, `"done":false,"approval":true`, 1)},
		{"missing mutates", strings.Replace(validDecision, `,"mutates":false`, "", 1)},
		{"missing verification", strings.Replace(validDecision, `"mutates":false`, `"mutates":true`, 1)},
		{"unrecognized action", strings.Replace(validDecision, `"kind":"command"`, `"kind":"shell"`, 1)},
		{"unsupported assessment", strings.Replace(validDecision, `"assessment":"unknown"`, `"assessment":"clean"`, 1)},
		{"done and pending", strings.Replace(validDecision, `"done":false`, `"done":true`, 1)},
		{"trailing", validDecision + ` {}`},
		{"null done", strings.Replace(validDecision, `"done":false`, `"done":null`, 1)},
		{"no evidence", strings.Replace(validDecision, `"assessment":"unknown"`, `"assessment":"confirmed_compromise"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseDecision([]byte(tc.body), 8); err == nil {
				t.Fatal("accepted invalid decision")
			}
		})
	}
	if _, err := ParseDecision([]byte(validDecision), 8); err != nil {
		t.Fatal(err)
	}
}

func TestCommandPlanner(t *testing.T) {
	t.Setenv("FF_TEST_AMBIENT_SECRET", "must-not-inherit")
	cmd, err := NewCommand(CommandConfig{Argv: []string{os.Args[0], "-test.run=^TestCommandHelper$"}, Env: []string{"FF_PLANNER_HELPER=success"}})
	if err != nil {
		t.Fatal(err)
	}
	d, err := cmd.Decide(context.Background(), protocol.Request{IncidentID: "test"})
	if err != nil || len(d.Actions) != 1 {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestCommandTimeoutAndOutputBound(t *testing.T) {
	for _, mode := range []string{"timeout", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 200 * time.Millisecond
			if mode == "overflow" {
				timeout = 2 * time.Second
			}
			cmd, err := NewCommand(CommandConfig{Argv: []string{os.Args[0], "-test.run=^TestCommandHelper$"}, Env: []string{"FF_PLANNER_HELPER=" + mode}, Timeout: timeout, MaxResponseBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			_, err = cmd.Decide(context.Background(), protocol.Request{})
			if err == nil || time.Since(start) > 3*time.Second {
				t.Fatalf("timeout/output limit not honored: %v", err)
			}
			if mode == "overflow" && !strings.Contains(err.Error(), "byte limit") {
				t.Fatalf("expected bounded output rejection: %v", err)
			}
		})
	}
}

func TestCommandHelper(t *testing.T) {
	switch os.Getenv("FF_PLANNER_HELPER") {
	case "success":
		var req protocol.Request
		if json.NewDecoder(os.Stdin).Decode(&req) != nil || !strings.Contains(req.Instructions, "UNTRUSTED DATA") || os.Getenv("FF_TEST_AMBIENT_SECRET") != "" {
			os.Exit(3)
		}
		fmt.Print(validDecision)
		os.Exit(0)
	case "timeout":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	case "overflow":
		fmt.Print(strings.Repeat("x", 2048))
		os.Exit(0)
	}
}

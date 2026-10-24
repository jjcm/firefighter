package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jjcm/firefighter/internal/protocol"
)

func anthropicFixture(stop string, content []map[string]any) string {
	b, _ := json.Marshal(map[string]any{"type": "message", "role": "assistant", "stop_reason": stop, "content": content})
	return string(b)
}

func TestAnthropicNativeStructuredDecision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/messages" || r.Header.Get("X-Api-Key") != "fixture-key" || r.Header.Get("Anthropic-Version") != "2023-06-01" || r.Header.Get("Authorization") != "" {
			t.Error("wrong native API endpoint or authentication")
		}
		var request struct {
			Model     string `json:"model"`
			System    string `json:"system"`
			MaxTokens int    `json:"max_tokens"`
			Messages  []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			OutputConfig struct {
				Format struct {
					Type   string         `json:"type"`
					Schema map[string]any `json:"schema"`
				} `json:"format"`
			} `json:"output_config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Model != "fixture-model" || request.MaxTokens != 8192 || request.OutputConfig.Format.Type != "json_schema" || request.OutputConfig.Format.Schema["additionalProperties"] != false {
			t.Error("missing model, bounded output, or strict decision schema")
		}
		if !strings.HasPrefix(request.System, SystemPrompt) || strings.Contains(request.System, "fixture-untrusted-observation") || len(request.Messages) != 1 || request.Messages[0].Role != "user" || !strings.Contains(request.Messages[0].Content, "fixture-untrusted-observation") {
			t.Error("host observations crossed the system instruction boundary")
		}
		fmt.Fprint(w, anthropicFixture("end_turn", []map[string]any{{"type": "thinking", "thinking": "unused"}, {"type": "text", "text": validDecision}}))
	}))
	defer srv.Close()
	p, err := NewAPI(APIConfig{Backend: "anthropic", BaseURL: srv.URL + "/v1", Model: "fixture-model", APIKey: "fixture-key"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := p.Decide(context.Background(), protocol.Request{Intel: map[string]string{"body": "fixture-untrusted-observation"}})
	if err != nil || len(d.Actions) != 1 {
		t.Fatalf("decision failed: %+v %v", d, err)
	}
}

func TestAnthropicRejectsIncompleteInvalidAndSecretErrors(t *testing.T) {
	text := []map[string]any{{"type": "text", "text": validDecision}}
	for _, tc := range []struct {
		name       string
		status     int
		body, want string
	}{
		{"server", 401, `{"error":"fixture-super-secret"}`, "HTTP 401"},
		{"truncated", 200, anthropicFixture("max_tokens", text), "incomplete"},
		{"refusal", 200, anthropicFixture("refusal", []map[string]any{{"type": "text", "text": "fixture-super-secret"}}), "declined"},
		{"tool", 200, anthropicFixture("tool_use", text), "incomplete"},
		{"empty", 200, anthropicFixture("end_turn", nil), "exactly one"},
		{"ambiguous", 200, anthropicFixture("end_turn", append(text, text...)), "exactly one"},
		{"unexpected block", 200, anthropicFixture("end_turn", []map[string]any{{"type": "tool_use", "input": map[string]string{"command": "fixture-super-secret"}}}), "unexpected"},
		{"bad JSON", 200, `{"type":`, "invalid"},
		{"wrong envelope", 200, `{"type":"error","role":"assistant"}`, "invalid"},
		{"invalid decision", 200, anthropicFixture("end_turn", []map[string]any{{"type": "text", "text": `{"summary":"fixture-super-secret"}`}}), "missing"},
		{"oversize", 200, strings.Repeat("x", 2048), "byte limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			p, err := NewAPI(APIConfig{Backend: "anthropic", BaseURL: srv.URL, Model: "fixture", MaxResponseBytes: 1024})
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Decide(context.Background(), protocol.Request{})
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "fixture-super-secret") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAnthropicDoesNotForwardKeyOnRedirect(t *testing.T) {
	called := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	p, err := NewAPI(APIConfig{Backend: "anthropic", BaseURL: srv.URL, Model: "fixture", APIKey: "fixture-key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Decide(context.Background(), protocol.Request{}); err == nil || called {
		t.Fatalf("redirect followed: %v", err)
	}
}

func TestAPIRejectsUnknownFormatAndAnthropicJSONMode(t *testing.T) {
	for _, cfg := range []APIConfig{
		{Backend: "unknown", BaseURL: "https://example.invalid/v1", Model: "fixture"},
		{Backend: "anthropic", JSONMode: true, BaseURL: "https://example.invalid/v1", Model: "fixture"},
	} {
		if _, err := NewAPI(cfg); err == nil {
			t.Fatal("invalid backend configuration accepted")
		}
	}
}

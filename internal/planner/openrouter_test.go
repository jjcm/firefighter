package planner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jjcm/firefighter/internal/protocol"
)

func TestOpenRouterRequiresSchemaSupportOnlyAtOfficialEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name, baseURL, backend string
		jsonMode, require      bool
	}{
		{"official", "https://openrouter.ai/api/v1", "api", false, true},
		{"trailing slash", "https://openrouter.ai/api/v1/", "", false, true},
		{"explicit JSON-object opt-out", "https://openrouter.ai/api/v1", "api", true, false},
		{"OpenAI", "https://api.openai.com/v1", "api", false, false},
		{"Anthropic", "https://api.anthropic.com/v1", "anthropic", false, false},
		{"different path", "https://openrouter.ai/compatible/v1", "api", false, false},
		{"lookalike host", "https://openrouter.ai.example.test/api/v1", "api", false, false},
		{"local gateway", "http://127.0.0.1:12345/api/v1", "api", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: bodyReadTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				var payload map[string]json.RawMessage
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				provider, exists := payload["provider"]
				if exists != tc.require {
					t.Fatalf("provider routing option present=%v, want %v", exists, tc.require)
				}
				if tc.require && string(provider) != `{"require_parameters":true}` {
					t.Fatalf("incorrect schema routing requirement: %s", provider)
				}
				var model string
				if err := json.Unmarshal(payload["model"], &model); err != nil || model != "requested-model" {
					t.Fatal("request changed the configured model")
				}
				response := openRouterFixture(validDecision)
				if tc.backend == "anthropic" {
					if _, exists := payload["response_format"]; exists {
						t.Fatal("Anthropic received a Chat Completions format")
					}
					response = anthropicFixture("end_turn", []map[string]any{{"type": "text", "text": validDecision}})
				} else {
					var format struct {
						Type       string `json:"type"`
						JSONSchema struct {
							Strict bool `json:"strict"`
						} `json:"json_schema"`
					}
					if err := json.Unmarshal(payload["response_format"], &format); err != nil {
						t.Fatal(err)
					}
					if tc.jsonMode {
						if format.Type != "json_object" {
							t.Fatal("explicit JSON-object opt-out was not honored")
						}
					} else if format.Type != "json_schema" || !format.JSONSchema.Strict {
						t.Fatal("schema-constrained output was not requested")
					}
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
			})}
			api, err := NewAPI(APIConfig{Backend: tc.backend, BaseURL: tc.baseURL, Model: "requested-model", JSONMode: tc.jsonMode, Client: client})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.Decide(context.Background(), protocol.Request{}); err != nil || calls != 1 {
				t.Fatalf("request failed or retried: calls=%d error=%v", calls, err)
			}
		})
	}
}

func TestOpenRouterNeverDowngradesOrRepairsInvalidOutput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"provider rejects schema", 400, `{"error":"private provider response"}`},
		{"duplicate key", 200, openRouterFixture(strings.Replace(validDecision, `"done":false`, `"done":false,"done":true`, 1))},
		{"unknown field", 200, openRouterFixture(strings.Replace(validDecision, `"done":false`, `"done":false,"unexpected":true`, 1))},
		{"null value", 200, openRouterFixture(strings.Replace(validDecision, `"evidence":[]`, `"evidence":null`, 1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: bodyReadTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				var payload struct {
					Provider struct {
						RequireParameters bool `json:"require_parameters"`
					} `json:"provider"`
					Format struct {
						Type string `json:"type"`
					} `json:"response_format"`
				}
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil || !payload.Provider.RequireParameters || payload.Format.Type != "json_schema" {
					t.Fatal("request weakened schema requirements")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})}
			api, err := NewAPI(APIConfig{BaseURL: "https://openrouter.ai/api/v1", Model: "requested-model", Client: client})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.Decide(context.Background(), protocol.Request{}); err == nil || calls != 1 || strings.Contains(err.Error(), "private provider response") {
				t.Fatalf("invalid output accepted, retried, or exposed: calls=%d error=%v", calls, err)
			}
		})
	}
}

func openRouterFixture(content string) string {
	data, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": content}}}})
	return string(data)
}

package planner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/jjcm/firefighter/internal/protocol"
)

const absentWordPressDecision = `{"summary":"WordPress prerequisite is absent within the current deployment scope","assessment":"not_affected","applicability":{"status":"not_affected","product":"WordPress plugin","condition":"The required WordPress installation is absent across inventoried applications and containers","evidence":["Fresh inventory and notebook web.deployment record a complete scoped application check at 2026-10-24T12:00:00Z with no WordPress and no coverage gaps"]},"evidence":["Reused current scoped deployment evidence"],"actions":[],"done":true,"follow_up":"","memory_updates":[]}`

func TestParseApplicability(t *testing.T) {
	for _, tc := range []struct {
		name, claim string
		valid       bool
	}{
		{"legacy omission", "", true},
		{"unknown", `{"status":"unknown","product":"","condition":"","evidence":[]}`, true},
		{"affected", `{"status":"affected","product":"example","condition":"installed version matches the vulnerable revision","evidence":["current local inventory: example 1.2"]}`, true},
		{"absent", `{"status":"not_affected","product":"example","condition":"absent from complete application deployment inventory","evidence":["current complete application inventory"]}`, true},
		{"missing status", `{"product":"example","condition":"absent","evidence":["current local inventory"]}`, false},
		{"missing product", `{"status":"unknown","condition":"","evidence":[]}`, false},
		{"missing condition", `{"status":"unknown","product":"","evidence":[]}`, false},
		{"missing evidence", `{"status":"unknown","product":"","condition":""}`, false},
		{"unsupported status", `{"status":"likely","product":"example","condition":"maybe","evidence":[]}`, false},
		{"no affected proof", `{"status":"affected","product":"example","condition":"vulnerable","evidence":[]}`, false},
		{"blank evidence", `{"status":"affected","product":"example","condition":"vulnerable","evidence":[" "]}`, false},
		{"unexpected field", `{"status":"unknown","product":"","condition":"","evidence":[],"approved":true}`, false},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"duplicate status", `{"status":"affected","status":"unknown","product":"example","condition":"","evidence":[]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := validDecision
			if tc.claim != "" {
				body = strings.Replace(body, `"done":false`, `"done":false,"applicability":`+tc.claim, 1)
			}
			decision, err := ParseDecision([]byte(body), 8)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t, error=%v", tc.valid, err)
			}
			if err == nil && (decision.Applicability == nil) != (tc.claim == "") {
				t.Fatal("applicability claim was lost or invented")
			}
		})
	}
}

func assertApplicabilitySchema(t *testing.T, schema map[string]any) {
	t.Helper()
	// Normalize both schema literals and decoded request bodies.
	encoded, _ := json.Marshal(schema)
	var normalized struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Type                 string   `json:"type"`
			AdditionalProperties bool     `json:"additionalProperties"`
			Required             []string `json:"required"`
			Properties           map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, key := range normalized.Required {
		if key == "applicability" {
			found = true
		}
	}
	claim, present := normalized.Properties["applicability"]
	if !found || !present || claim.Type != "object" || claim.AdditionalProperties || !reflect.DeepEqual(claim.Required, []string{"status", "product", "condition", "evidence"}) || !reflect.DeepEqual(claim.Properties["status"].Enum, []string{"unknown", "affected", "not_affected"}) {
		t.Fatalf("strict schema omitted bounded complete applicability: %s", encoded)
	}
}

func TestApplicabilitySchemaAndProviderRequests(t *testing.T) {
	assertApplicabilitySchema(t, decisionSchema())
	for _, tc := range []struct {
		name, backend string
		jsonMode      bool
	}{
		{"OpenAI", "api", false}, {"OpenRouter", "api", true}, {"Anthropic", "anthropic", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					System         string                           `json:"system"`
					Messages       []struct{ Role, Content string } `json:"messages"`
					ResponseFormat struct {
						Type       string `json:"type"`
						JSONSchema struct {
							Schema map[string]any `json:"schema"`
						} `json:"json_schema"`
					} `json:"response_format"`
					OutputConfig struct {
						Format struct {
							Schema map[string]any `json:"schema"`
						} `json:"format"`
					} `json:"output_config"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatal(err)
				}
				policy, observation := req.System, ""
				for _, message := range req.Messages {
					if message.Role == "system" {
						policy = message.Content
					}
					if message.Role == "user" {
						observation = message.Content
					}
				}
				if !strings.Contains(observation, `"applicability_required":true`) {
					t.Error("request lost applicability requirement")
				}
				for _, boundary := range []string{"Most incoming CVEs will not affect this server", "minimum targeted read-only observations", "local presence AND the affected version/configuration", "no changes, extra scans, or monitoring-channel message", "Missing evidence stays unknown"} {
					if !strings.Contains(policy, boundary) {
						t.Errorf("policy missing %q", boundary)
					}
				}
				if tc.backend == "anthropic" {
					assertApplicabilitySchema(t, req.OutputConfig.Format.Schema)
					json.NewEncoder(w).Encode(map[string]any{"type": "message", "role": "assistant", "stop_reason": "end_turn", "content": []map[string]any{{"type": "text", "text": absentWordPressDecision}}})
				} else {
					if !tc.jsonMode {
						assertApplicabilitySchema(t, req.ResponseFormat.JSONSchema.Schema)
					} else if req.ResponseFormat.Type != "json_object" || !strings.Contains(policy, mustSchemaJSON()) {
						t.Error("JSON mode lost required schema")
					}
					json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": absentWordPressDecision}}}})
				}
			}))
			defer srv.Close()
			p, err := NewAPI(APIConfig{Backend: tc.backend, BaseURL: srv.URL, Model: "fixture", JSONMode: tc.jsonMode})
			if err != nil {
				t.Fatal(err)
			}
			d, err := p.Decide(context.Background(), protocol.Request{ApplicabilityRequired: true})
			if err != nil || d.Applicability == nil || d.Applicability.Status != "not_affected" || len(d.Actions) != 0 || !d.Done {
				t.Fatalf("absence decision did not round trip: %+v %v", d, err)
			}
		})
	}
}

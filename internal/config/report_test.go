package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportProviderFieldCombinations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		report  Report
		enabled bool
	}{
		{"legacy disabled", Report{SecretEnv: "REPORT_SECRET"}, false},
		{"none", Report{Type: "none"}, false},
		{"legacy signed", Report{URL: "https://receiver.example/events", SecretEnv: "REPORT_SECRET", BearerTokenEnv: "REPORT_BEARER"}, true},
		{"signed env endpoint", Report{Type: "webhook", URLEnv: "REPORT_URL", SecretEnv: "REPORT_SECRET"}, true},
		{"slack", Report{Type: "slack", URLEnv: "REPORT_URL"}, true},
		{"discord", Report{Type: "discord", URL: "https://discord.com/api/webhooks/id/token"}, true},
		{"grokbot", Report{Type: "grokbot", URLEnv: "REPORT_URL", BearerTokenEnv: "REPORT_BEARER"}, true},
		{"telegram private", Report{Type: "telegram", TokenEnv: "BOT_TOKEN", ChatID: "123456"}, true},
		{"telegram group", Report{Type: "telegram", TokenEnv: "BOT_TOKEN", ChatID: "-100123456"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.report.Validate(); err != nil {
				t.Fatal(err)
			}
			if tc.report.Enabled() != tc.enabled {
				t.Fatalf("Enabled = %v, want %v", tc.report.Enabled(), tc.enabled)
			}
		})
	}
}

func TestReportRejectsAmbiguousOrUnusedCredentials(t *testing.T) {
	for _, r := range []Report{
		{Type: "slack", URL: "https://hooks.slack.com/services/example", URLEnv: "REPORT_URL"},
		{Type: "slack", URLEnv: "REPORT_URL", BearerTokenEnv: "UNRELATED_TOKEN"},
		{Type: "discord", URLEnv: "REPORT_URL", SecretEnv: "UNRELATED_SECRET"},
		{Type: "grokbot", URLEnv: "REPORT_URL"},
		{Type: "grokbot", URLEnv: "REPORT_URL", TokenEnv: "REPORT_TOKEN"},
		{Type: "telegram", TokenEnv: "BOT_TOKEN", ChatID: "123", URL: "https://other.example"},
		{Type: "telegram", TokenEnv: "BOT_TOKEN", ChatID: "@username"},
		{Type: "telegram", TokenEnv: "BOT_TOKEN", ChatID: "0"},
		{Type: "telegram", TokenEnv: "BOT_TOKEN", ChatID: "9223372036854775808"},
		{Type: "none", TokenEnv: "BOT_TOKEN"},
		{Type: "webhook", URLEnv: "REPORT_URL"},
		{URL: "https://receiver.example/events"},
		{Type: "slack", URLEnv: "actual-secret-not-an-env-name"},
		{Type: "slack", URL: " https://hooks.slack.com/services/example"},
		{Type: "unknown-secret-value"},
	} {
		if err := r.Validate(); err == nil {
			t.Fatalf("invalid report combination accepted: %+v", r)
		} else if strings.Contains(err.Error(), "actual-secret") || strings.Contains(err.Error(), "unknown-secret") {
			t.Fatal("configuration error echoed an untrusted field value")
		}
	}
}

func TestLoadPreservesLegacyReportingWithoutLeakingDefaultsToNewProviders(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantSecret string
		wantError  bool
	}{
		{"legacy default secret", `{"report":{"url":"https://receiver.example/events"}}`, "FIREFIGHTER_REPORT_SECRET", false},
		{"legacy explicit secret", `{"report":{"url":"https://receiver.example/events","secret_env":"CUSTOM_SECRET"}}`, "CUSTOM_SECRET", false},
		{"legacy explicit empty secret", `{"report":{"url":"https://receiver.example/events","secret_env":""}}`, "", true},
		{"slack clean defaults", `{"report":{"type":"slack","url_env":"SLACK_URL"}}`, "", false},
		{"telegram clean defaults", `{"report":{"type":"telegram","token_env":"BOT_TOKEN","chat_id":"123"}}`, "", false},
		{"none clean defaults", `{"report":{"type":"none"}}`, "", false},
		{"unknown reporting field", `{"report":{"type":"none","unknown":true}}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := Load(path)
			if (err != nil) != tc.wantError {
				t.Fatalf("Load error = %v, want error %v", err, tc.wantError)
			}
			if err == nil && c.Report.SecretEnv != tc.wantSecret {
				t.Fatalf("signing env = %q, want %q", c.Report.SecretEnv, tc.wantSecret)
			}
		})
	}
}

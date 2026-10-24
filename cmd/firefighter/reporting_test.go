package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/config"
	"github.com/jjcm/firefighter/internal/protocol"
)

func TestNotifyTestSendsOneEventWithoutStartingAgent(t *testing.T) {
	events := make(chan protocol.Event, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Firefighter-Signature") == "" {
			t.Error("test did not use the configured signed reporter")
		}
		var event protocol.Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
		}
		events <- event
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	c := config.Default()
	c.StateDir = filepath.Join(t.TempDir(), "must-not-create-state")
	c.LLM.APIKeyEnv = "UNSET_FIRE_TEST_LLM"
	t.Setenv(c.LLM.APIKeyEnv, "")
	c.Report = config.Report{URL: server.URL, SecretEnv: "FIRE_TEST_REPORT_SECRET"}
	t.Setenv(c.Report.SecretEnv, strings.Repeat("s", 32))
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	output := captureReportingOutput(t, func() {
		if err := run([]string{"notify-test", "--config", path}); err != nil {
			t.Fatal(err)
		}
	})
	select {
	case event := <-events:
		if event.Type != "report_test" || !strings.HasPrefix(event.ID, "test-") || event.Host == "" || event.Time.IsZero() || time.Since(event.Time) > time.Minute || event.IncidentID != "" {
			t.Fatalf("bad test notification: %+v", event)
		}
	default:
		t.Fatal("no test notification delivered")
	}
	if len(events) != 0 {
		t.Fatal("test sent more than one event")
	}
	if _, err := os.Stat(c.StateDir); !os.IsNotExist(err) {
		t.Fatalf("notification test touched daemon state: %v", err)
	}
	if !strings.Contains(output, "accepted") || !strings.Contains(output, "check your destination") || !strings.Contains(output, "does not confirm") {
		t.Fatalf("test receipt overstated delivery: %q", output)
	}
}

func TestReporterResolvesEnvironmentAndRejectsMissingCredentials(t *testing.T) {
	c := config.Default()
	c.Report = config.Report{Type: "slack", URLEnv: "FIRE_TEST_NOTIFY_URL"}
	t.Setenv(c.Report.URLEnv, "")
	if _, err := buildReporter(c); err == nil {
		t.Fatal("missing private destination accepted")
	}
	secretURL := "https://hooks.slack.com/services/TEAMSECRET/BOTSECRET/PRIVATEWEBHOOKSECRET"
	t.Setenv(c.Report.URLEnv, secretURL)
	if sender, err := buildReporter(c); err != nil || sender == nil {
		t.Fatalf("configured Slack reporter failed: %v", err)
	}
	c.Report = config.Report{Type: "none"}
	if sender, err := buildReporter(c); err != nil || sender != nil {
		t.Fatalf("disabled reporting constructed a sender: %v", err)
	}
	if err := notifyTest(c); err == nil {
		t.Fatal("disabled destination claimed to send a test")
	}
}

func TestReportingSecretsAndWebhookComponentsAreRedacted(t *testing.T) {
	c := config.Default()
	c.LLM.APIKeyEnv = "FIRE_TEST_LLM_KEY"
	t.Setenv(c.LLM.APIKeyEnv, "llm-private-value")
	c.Report = config.Report{Type: "slack", URLEnv: "FIRE_TEST_NOTIFY_URL", SecretEnv: "FIRE_TEST_SIGNING", BearerTokenEnv: "FIRE_TEST_BEARER", TokenEnv: "FIRE_TEST_TOKEN"}
	values := map[string]string{
		c.Report.URLEnv:         "https://hooks.slack.com/services/TEAMSECRET/BOTSECRET/PRIVATEWEBHOOKSECRET",
		c.Report.SecretEnv:      "signing-private-value",
		c.Report.BearerTokenEnv: "bearer-private-value",
		c.Report.TokenEnv:       "bot-private-value",
	}
	for name, value := range values {
		t.Setenv(name, value)
	}
	redact := buildRedactor(c)
	for _, value := range append([]string{"llm-private-value", "TEAMSECRET", "BOTSECRET", "PRIVATEWEBHOOKSECRET"}, values[c.Report.URLEnv], values[c.Report.SecretEnv], values[c.Report.BearerTokenEnv], values[c.Report.TokenEnv]) {
		if strings.Contains(redact("observed "+value+" in output"), value) {
			t.Fatalf("reporting credential was not redacted: field length %d", len(value))
		}
	}
}

func TestReporterErrorDoesNotExposeSecretURL(t *testing.T) {
	c := config.Default()
	c.Report = config.Report{Type: "slack", URLEnv: "FIRE_TEST_BAD_URL"}
	value := "https://untrusted.example/credential-value"
	t.Setenv(c.Report.URLEnv, value)
	_, err := buildReporter(c)
	if err == nil || strings.Contains(err.Error(), value) || strings.Contains(err.Error(), "credential-value") {
		t.Fatalf("invalid private URL error leaked or was accepted: %v", err)
	}
}

func TestDoctorChecksReportingOfflineWithoutPrintingPrivateDestination(t *testing.T) {
	c := config.Default()
	c.Observe = true
	c.LLM.Backend = "command"
	c.LLM.Command = []string{"/usr/bin/true"}
	c.Sources = nil
	c.Report = config.Report{Type: "slack", URLEnv: "FIRE_TEST_DOCTOR_URL"}
	privateURL := "https://hooks.slack.com/services/PRIVATE_TEAM/PRIVATE_BOT/PRIVATE_WEBHOOK"
	t.Setenv(c.Report.URLEnv, privateURL)
	output := captureReportingOutput(t, func() { _ = doctor(c) })
	if !strings.Contains(output, "OK reporting destination: slack") || !strings.Contains(output, "No remote API calls") {
		t.Fatalf("doctor did not perform an offline reporting check: %q", output)
	}
	if strings.Contains(output, privateURL) || strings.Contains(output, "PRIVATE_WEBHOOK") || strings.Contains(output, c.Report.URLEnv) {
		t.Fatal("doctor printed private reporting configuration")
	}
	t.Setenv(c.Report.URLEnv, "")
	output = captureReportingOutput(t, func() { _ = doctor(c) })
	if !strings.Contains(output, "MISSING reporting destination: slack") {
		t.Fatalf("doctor did not detect a missing notification credential: %q", output)
	}
}

func TestTelegramPairPreflightNeedsNoConfigOrLLMCredentials(t *testing.T) {
	t.Setenv("FIRE_TEST_EMPTY_BOT_TOKEN", "")
	err := run([]string{"telegram-pair", "--token-env", "FIRE_TEST_EMPTY_BOT_TOKEN", "--code", "FF-1234567890abcdef12345678"})
	if err == nil || !strings.Contains(err.Error(), "Telegram bot token environment variable is not set") {
		t.Fatalf("pairing tried to load configuration or did not check token: %v", err)
	}
	for _, args := range [][]string{
		{"telegram-pair", "--token-env", "actual-token-value", "--code", "FF-1234567890abcdef12345678"},
		{"telegram-pair", "--token-env", "FIRE_TEST_EMPTY_BOT_TOKEN", "--code", "wrong-code"},
	} {
		err := run(args)
		if err == nil || strings.Contains(err.Error(), "actual-token-value") || strings.Contains(err.Error(), "wrong-code") {
			t.Fatalf("invalid pairing input was accepted or echoed: %v", err)
		}
	}
}

func captureReportingOutput(t *testing.T, call func()) string {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = previous; f.Close() }()
	call()
	os.Stdout = previous
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

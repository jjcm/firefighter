package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/jjcm/firefighter/internal/protocol"
)

const (
	slackFixture    = "https://hooks.slack.com/services/T123456789/B123456789/secret-fixture-slack-token"
	discordFixture  = "https://discord.com/api/v10/webhooks/123456789/secret-fixture-discord-token"
	telegramFixture = "123456789:secret_fixture_telegram_token"
	grokFixture     = "https://routines.example.invalid/hooks/private-routine-identifier"
)

func directFixture(t *testing.T, kind string) *directSender {
	t.Helper()
	options := map[string]Options{
		"slack":    {Type: "slack", URL: slackFixture},
		"discord":  {Type: "discord", URL: discordFixture},
		"telegram": {Type: "telegram", Token: telegramFixture, ChatID: "123456789"},
		"grokbot":  {Type: "grokbot", URL: grokFixture, BearerToken: "secret-fixture-routine-key"},
	}[kind]
	sender, err := NewSender(options)
	if err != nil {
		t.Fatal(err)
	}
	return sender.(*directSender)
}

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func TestDirectProvidersNativePayloadAndAcknowledgement(t *testing.T) {
	for _, kind := range []string{"slack", "discord", "telegram", "grokbot"} {
		t.Run(kind, func(t *testing.T) {
			s := directFixture(t, kind)
			calls := 0
			s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "POST" || r.URL.Scheme != "https" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Idempotency-Key") != "event-fixture" {
					t.Errorf("incorrect request contract: %s %s", r.Method, r.URL.Scheme)
				}
				var payload map[string]any
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				var text string
				switch kind {
				case "slack":
					if r.URL.Host != "hooks.slack.com" || payload["text"] != nil {
						t.Fatal("Slack payload uses an unsafe fallback or incorrect host")
					}
					section := payload["blocks"].([]any)[0].(map[string]any)
					block := section["text"].(map[string]any)
					if section["type"] != "section" || block["type"] != "plain_text" || block["emoji"] != false {
						t.Fatal("Slack text is not explicitly plain")
					}
					text = block["text"].(string)
				case "discord":
					if r.URL.Host != "discord.com" || r.URL.Query().Get("wait") != "true" {
						t.Fatal("Discord does not wait for a confirmed message")
					}
					mentions := payload["allowed_mentions"].(map[string]any)["parse"].([]any)
					if len(mentions) != 0 || payload["flags"] != float64(4) {
						t.Fatal("Discord mentions or embeds enabled")
					}
					text = payload["content"].(string)
					if strings.Contains(text, "@everyone") || strings.Contains(text, "<@1234>") || strings.Contains(text, "**URGENT**") {
						t.Fatal("Discord still interprets model text as mentions or markdown")
					}
				case "telegram":
					if r.URL.Host != "api.telegram.org" || r.URL.Path != "/bot"+telegramFixture+"/sendMessage" || payload["chat_id"] != "123456789" || payload["parse_mode"] != nil || payload["entities"] != nil || payload["link_preview_options"].(map[string]any)["is_disabled"] != true {
						t.Fatal("Telegram native plain-message contract incorrect")
					}
					text = payload["text"].(string)
				case "grokbot":
					if r.URL.Host != "routines.example.invalid" || r.Header.Get("Authorization") != "Bearer secret-fixture-routine-key" || payload["source"] != "firefighter" {
						t.Fatal("Grok Bot routine authentication or envelope incorrect")
					}
					text = payload["message"].(string)
					event := payload["event"].(map[string]any)
					details := event["details"].(map[string]any)
					if event["id"] != "event-fixture" || details["verified"] != true || details["argv"] != nil || details["output"] != nil || details["environment"] != nil {
						t.Fatal("Grok event omitted outcomes or included raw execution details")
					}
				}
				if kind != "grokbot" && r.Header.Get("Authorization") != "" {
					t.Error("unnecessary bearer credential attached")
				}
				for _, expected := range []string{"fixture-host", "event-fixture", "Verification: passed", "Exit: 0"} {
					if kind == "discord" {
						expected = discordPlain(expected)
					}
					if !strings.Contains(text, expected) {
						t.Errorf("missing %s", expected)
					}
				}
				encoded, _ := json.Marshal(payload)
				if strings.Contains(string(encoded), "raw-command-output") || strings.Contains(string(encoded), "raw-command-argv") || strings.Contains(string(encoded), "hidden-environment") {
					t.Fatal("raw execution data escaped into report")
				}
				return response(200, map[string]string{"slack": "ok", "discord": `{"id":"987654321"}`, "telegram": `{"ok":true,"result":{"message_id":1}}`, "grokbot": "accepted"}[kind]), nil
			})
			event := protocol.Event{ID: "event-fixture", Host: "fixture-host", Type: "action_finished", IncidentID: "incident-fixture", Summary: "**URGENT** @everyone <@1234> [click](https://untrusted.invalid)", Details: map[string]any{"phase": "verification", "mutates": false, "verified": true, "exit_code": 0, "argv": []string{"raw-command-argv"}, "output": "raw-command-output", "environment": "hidden-environment"}}
			if err := s.Send(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			if calls != 1 {
				t.Fatalf("sent %d requests", calls)
			}
		})
	}
}

func TestDirectDestinationValidation(t *testing.T) {
	for _, options := range []Options{
		{Type: "slack", URL: "http://hooks.slack.com/services/T/B/token"},
		{Type: "slack", URL: "https://hooks.slack.com.evil.invalid/services/T/B/token"},
		{Type: "slack", URL: "https://hooks.slack.com/services/T/B/token?redirect=1"},
		{Type: "slack", URL: "https://hooks.slack.com/services/T/B/token/more"},
		{Type: "slack", URL: "https://hooks.slack.com/services/T/B/%74oken"},
		{Type: "slack", URL: "https://user:password@hooks.slack.com/services/T/B/token"},
		{Type: "slack", URL: "https://hooks.slack.com:444/services/T/B/token"},
		{Type: "slack", URL: slackFixture + "#fragment"},
		{Type: "discord", URL: "https://discord.com/api/webhooks/not-a-number/token"},
		{Type: "discord", URL: "https://discord.com/api/webhooks/123/token/slack"},
		{Type: "discord", URL: "https://discord.com/api/webhooks/123/token?wait=1"},
		{Type: "discord", URL: "https://discord.com/api/webhooks/123/token?wait=true&wait=false"},
		{Type: "discord", URL: "https://discord.com/api/webhooks/123/token?other=secret"},
		{Type: "discord", URL: "https://discord.com.attacker.invalid/api/webhooks/123/token"},
		{Type: "telegram", Token: "invalid-token", ChatID: "1"},
		{Type: "telegram", Token: telegramFixture, ChatID: "0"},
		{Type: "telegram", Token: telegramFixture, ChatID: "@channel"},
		{Type: "telegram", Token: telegramFixture, ChatID: "9223372036854775808"},
		{Type: "telegram", Token: telegramFixture, ChatID: "1", URL: "https://attacker.invalid"},
		{Type: "telegram", Token: telegramFixture + "/getUpdates", ChatID: "1"},
		{Type: "grokbot", URL: grokFixture},
		{Type: "grokbot", URL: grokFixture, BearerToken: "key\nAuthorization: injected"},
		{Type: "grokbot", URL: "https://user:secret@example.invalid/hook", BearerToken: "key"},
		{Type: "grokbot", URL: "https://example.invalid/hook#secret", BearerToken: "key"},
		{Type: "unsupported", URL: grokFixture},
	} {
		if _, err := NewSender(options); err == nil {
			t.Errorf("accepted invalid %s destination", options.Type)
		} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), options.URL) && options.URL != "" {
			t.Errorf("validation error exposed settings: %s", err)
		}
	}
	for _, options := range []Options{
		{Type: "slack", URL: "https://hooks.slack-gov.com/services/T1/B1/token"},
		{Type: "discord", URL: "https://discord.com/api/webhooks/123/token?wait=false"},
		{Type: "telegram", Token: telegramFixture, ChatID: "-100123456789"},
		{Type: "grokbot", URL: "https://routine.example.invalid:8443/opaque%2Fhook?key=fixture", BearerToken: "fixture-key"},
	} {
		if _, err := NewSender(options); err != nil {
			t.Errorf("valid %s configuration rejected: %v", options.Type, err)
		}
	}
	for _, kind := range []string{"", "webhook"} {
		sender, err := NewSender(Options{Type: kind, URL: "http://127.0.0.1:9087/events", Secret: testSigningSecret})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := sender.(*Webhook); !ok {
			t.Fatal("legacy signed webhook type changed")
		}
		if _, ok := sender.(interface{ ShouldSend(protocol.Event) bool }); ok {
			t.Fatal("legacy webhook gained direct-chat filtering")
		}
	}
}

func TestDirectEventFilterAndHistoricalOutboxSuppression(t *testing.T) {
	s := directFixture(t, "slack")
	for _, tc := range []struct {
		typ     string
		details map[string]any
		want    bool
	}{
		{"started", nil, true}, {"report_test", nil, true}, {"source_error", nil, true}, {"source_recovered", nil, true},
		{"assessment_started", map[string]any{"source": "local-host"}, true}, {"assessment_started", map[string]any{"source": "nvd"}, false},
		{"assessment_finished", map[string]any{"source": "local-host", "assessment": "not_affected"}, true},
		{"assessment_finished", map[string]any{"changed": true}, true}, {"assessment_finished", map[string]any{"status": "deferred"}, true}, {"assessment_finished", map[string]any{"error": "failed"}, true},
		{"assessment_finished", map[string]any{"assessment": "exposed"}, true}, {"assessment_finished", map[string]any{"assessment": "suspected_compromise"}, true}, {"assessment_finished", map[string]any{"assessment": "confirmed_compromise"}, true}, {"assessment_finished", map[string]any{"assessment": "remediated"}, true},
		{"assessment_finished", map[string]any{"status": "completed", "assessment": "not_affected"}, false}, {"assessment_finished", nil, false},
		{"action_started", map[string]any{"mutates": true}, true}, {"action_finished", map[string]any{"mutates": true}, true},
		{"action_started", map[string]any{"phase": "verification"}, false}, {"action_started", map[string]any{"phase": "rollback"}, true}, {"action_finished", map[string]any{"phase": "verification"}, true}, {"action_finished", map[string]any{"phase": "rollback"}, true},
		{"action_finished", map[string]any{"mutates": false, "phase": "action"}, false}, {"source_polled", nil, false}, {"memory_updated", nil, false},
	} {
		event := protocol.Event{Type: tc.typ, Details: tc.details}
		if got := s.ShouldSend(event); got != tc.want {
			t.Errorf("filter %s %+v = %v, want %v", tc.typ, tc.details, got, tc.want)
		}
	}
	s.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("historical low-value event reached transport")
		return nil, nil
	})
	if err := s.Send(context.Background(), protocol.Event{Type: "assessment_finished", Details: map[string]any{"assessment": "not_affected"}}); err != nil {
		t.Fatal(err)
	}
}

func TestDirectStrictAcknowledgementsAndSecretSafeErrors(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		status int
		body   string
	}{
		{"slack", 200, `{"ok":true}`}, {"slack", 200, "not_ok"}, {"slack", 204, "ok"},
		{"discord", 200, `{}`}, {"discord", 200, `{"id":123}`}, {"discord", 204, ""},
		{"telegram", 200, `{"ok":false,"description":"secret-remote-body"}`}, {"telegram", 200, "invalid"},
		{"grokbot", 202, "accepted"}, {"grokbot", 204, ""}, {"grokbot", 401, "secret-remote-body"},
		{"slack", 200, strings.Repeat("x", (64<<10)+1)}, {"telegram", 200, strings.Repeat("x", (64<<10)+1)},
	} {
		t.Run(fmt.Sprintf("%s-%d-%d", tc.kind, tc.status, len(tc.body)), func(t *testing.T) {
			s := directFixture(t, tc.kind)
			s.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(tc.status, tc.body), nil })
			err := s.Send(context.Background(), protocol.Event{ID: "test", Type: "report_test"})
			if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "https://") {
				t.Fatalf("bad acknowledgement accepted or secrets exposed: %v", err)
			}
		})
	}
	for _, kind := range []string{"slack", "discord", "telegram", "grokbot"} {
		s := directFixture(t, kind)
		s.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret URL " + s.endpoint) })
		if err := s.Send(context.Background(), protocol.Event{Type: "report_test"}); err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), s.endpoint) {
			t.Fatalf("network error not scrubbed: %v", err)
		}
	}
}

func TestDirectNeverFollowsRedirect(t *testing.T) {
	for _, kind := range []string{"slack", "discord", "telegram", "grokbot"} {
		s := directFixture(t, kind)
		calls := 0
		s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls > 1 {
				t.Fatal("followed redirect with reporting credentials")
			}
			resp := response(http.StatusTemporaryRedirect, "")
			resp.Header.Set("Location", "https://attacker.invalid/collect")
			return resp, nil
		})
		if err := s.Send(context.Background(), protocol.Event{Type: "report_test"}); err == nil || calls != 1 {
			t.Fatalf("%s redirect accepted: calls=%d err=%v", kind, calls, err)
		}
	}
}

func TestReportingRateLimits(t *testing.T) {
	for _, tc := range []struct {
		header, body string
		want         time.Duration
	}{
		{"120", "", 120 * time.Second}, {"", `{"retry_after":2.5}`, 2500 * time.Millisecond}, {"", `{"parameters":{"retry_after":9}}`, 9 * time.Second},
		{"2", `{"parameters":{"retry_after":9}}`, 9 * time.Second}, {"invalid", `{"retry_after":-1}`, 30 * time.Second},
	} {
		s := directFixture(t, "telegram")
		s.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			resp := response(429, tc.body)
			resp.Header.Set("Retry-After", tc.header)
			return resp, nil
		})
		err := s.Send(context.Background(), protocol.Event{Type: "report_test"})
		var retry *RetryAfterError
		if !errors.As(err, &retry) || retry.RetryAfter() != tc.want {
			t.Fatalf("wrong pause: err=%v duration=%v want=%v", err, retry, tc.want)
		}
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	if got := retryError(http.Header{"Retry-After": []string{now.Add(time.Minute).Format(http.TimeFormat)}}, nil, now).RetryAfter(); got != time.Minute {
		t.Fatalf("HTTP date ignored: %v", got)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "45"); w.WriteHeader(429) }))
	defer srv.Close()
	w, _ := New(srv.URL, testSigningSecret, "")
	err := w.Send(context.Background(), protocol.Event{Type: "report_test"})
	var retry interface{ RetryAfter() time.Duration }
	if !errors.As(err, &retry) || retry.RetryAfter() != 45*time.Second {
		t.Fatalf("legacy destination ignored pause: %v", err)
	}
}

func TestDirectOutputBoundsRedactionAndControlCharacters(t *testing.T) {
	for _, kind := range []string{"slack", "discord", "telegram", "grokbot"} {
		s := directFixture(t, kind)
		event := protocol.Event{ID: "event-constant", Type: "report_test", Host: "host\nFAKE STATUS\u202e", Summary: strings.Repeat("🙂*_", 3000) + " secret-fixture-routine-key", Details: map[string]any{"evidence": []string{strings.Repeat("e", 5000), strings.Repeat("e", 5000), strings.Repeat("e", 5000), "fourth-omitted"}, "error": strings.Repeat("error", 5000), "output": "must-not-appear"}}
		s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			var text string
			maxSize := 4096
			switch kind {
			case "slack":
				text = payload["blocks"].([]any)[0].(map[string]any)["text"].(map[string]any)["text"].(string)
				maxSize = 3000
			case "discord":
				text = payload["content"].(string)
				maxSize = 2000
			case "telegram":
				text = payload["text"].(string)
			case "grokbot":
				text = payload["message"].(string)
			}
			if !utf8.ValidString(text) || len(utf16.Encode([]rune(text))) > maxSize || !strings.Contains(text, "event") || strings.Contains(text, "\u202e") || strings.Contains(text, "must-not-appear") || strings.Contains(text, "fourth-omitted") {
				t.Fatal("unsafe or oversized formatted output")
			}
			return response(200, map[string]string{"slack": "ok", "discord": `{"id":"1"}`, "telegram": `{"ok":true}`, "grokbot": ""}[kind]), nil
		})
		if err := s.Send(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	if got := limitText("abcdef", 4); got != "abc…" {
		t.Fatalf("text truncation lost prefix: %q", got)
	}
	if got := limitText("🙂🙂🙂", 5); got != "🙂🙂…" {
		t.Fatalf("emoji truncation lost text: %q", got)
	}
	if got := plain("one\ntwo\u202e three", 100, func(s string) string { return s }); got != "one two three" {
		t.Fatalf("control characters retained: %q", got)
	}
}

func TestSecretValuesCoverCredentialURLFragments(t *testing.T) {
	for _, tc := range []struct {
		options Options
		secrets []string
	}{
		{Options{Type: "slack", URL: slackFixture}, []string{slackFixture, "T123456789", "B123456789", "secret-fixture-slack-token"}},
		{Options{Type: "discord", URL: discordFixture}, []string{discordFixture, "secret-fixture-discord-token"}},
		{Options{Type: "grokbot", URL: grokFixture + "?token=query-secret", BearerToken: "bearer-fixture"}, []string{"private-routine-identifier", "query-secret", "bearer-fixture"}},
		{Options{Type: "telegram", Token: telegramFixture}, []string{telegramFixture}},
	} {
		values := SecretValues(tc.options)
		redact := Redactor(values...)
		for _, secret := range tc.secrets {
			if got := redact("contains " + secret); strings.Contains(got, secret) {
				t.Errorf("credential fragment not redacted for %s", tc.options.Type)
			}
		}
		if values2 := SecretValues(tc.options); !reflect.DeepEqual(values, values2) && tc.options.Type != "grokbot" {
			t.Fatal("unexpected nondeterministic credential extraction")
		}
	}
}

func TestDirectContextCancellationAndTimeout(t *testing.T) {
	s := directFixture(t, "slack")
	if s.client.Timeout != 20*time.Second {
		t.Fatalf("missing bounded timeout: %v", s.client.Timeout)
	}
	var calls atomic.Int32
	s.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := s.Send(ctx, protocol.Event{Type: "report_test"}); err == nil || time.Since(start) > time.Second || calls.Load() != 1 {
		t.Fatalf("cancellation ignored: calls=%d err=%v", calls.Load(), err)
	}
}

func TestReportDistinguishesChangesVerificationAndEventTime(t *testing.T) {
	when := time.Date(2026, 10, 24, 9, 30, 0, 0, time.FixedZone("fixture", 2*60*60))
	for _, tc := range []struct {
		name         string
		details      map[string]any
		want, absent string
	}{
		{"successful change", map[string]any{"phase": "action", "mutates": true, "exit_code": 0}, "Change command finished; verification pending", "Verification: passed"},
		{"failed change", map[string]any{"phase": "action", "mutates": true, "exit_code": 1}, "Exit: 1", "verification pending"},
		{"timed out change", map[string]any{"phase": "action", "mutates": true, "exit_code": 0, "timed_out": true}, "Command timed out", "verification pending"},
		{"skipped change", map[string]any{"phase": "action", "mutates": true, "exit_code": 0, "skipped": true}, "Command was skipped", "verification pending"},
		{"execution error", map[string]any{"phase": "action", "mutates": true, "exit_code": 0, "error": "exec failed"}, "Error: exec failed", "verification pending"},
		{"successful verification", map[string]any{"phase": "verification", "verified": true, "exit_code": 0}, "Verification: passed", "Verification: failed"},
		{"failed verification", map[string]any{"phase": "verification", "verified": false, "exit_code": 1}, "Verification: failed", "Verification: passed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := safeEvent(protocol.Event{ID: "audit-event-id", Time: when, Host: "fixture", Type: "action_finished", Summary: "Targeted local response", Details: tc.details}, func(s string) string { return s })
			message := formatEvent(event)
			if !strings.Contains(message, tc.want) || strings.Contains(message, tc.absent) || !strings.Contains(message, "Time: 2026-10-24T07:30:00Z") || !strings.Contains(message, "Event: audit-event-id") {
				t.Fatalf("outcome or event time unclear:\n%s", message)
			}
		})
	}
}

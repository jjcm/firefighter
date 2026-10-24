package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

// Options are resolved local settings. URLs and tokens belong in private
// environment files, never model prompts or remotely supplied notices.
type Options struct {
	Type, URL, Secret, BearerToken, Token, ChatID string
}

// RetryAfterError tells the outbox when a destination permits another attempt.
// Its printable error never includes provider response bodies or credentials.
type RetryAfterError struct{ After time.Duration }

func (e *RetryAfterError) Error() string             { return "report destination rate limited; retry later" }
func (e *RetryAfterError) RetryAfter() time.Duration { return e.After }

type directSender struct {
	kind, endpoint, bearer, chatID string
	client                         *http.Client
	redact                         func(string) string
}

var (
	webhookPart = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
	discordPath = regexp.MustCompile(`^/api(?:/v[0-9]+)?/webhooks/[0-9]{1,32}/[A-Za-z0-9._-]{1,256}$`)
	messageID   = regexp.MustCompile(`^[0-9]{1,32}$`)
	botToken    = regexp.MustCompile(`^[0-9]{1,20}:[A-Za-z0-9_-]{10,256}$`)
	chatID      = regexp.MustCompile(`^-?[0-9]{1,20}$`)
)

func directClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// NewSender preserves the original signed webhook contract for existing
// configurations. Direct chat integrations use provider-native authentication.
func NewSender(options Options) (Sender, error) {
	if options.Type == "" || options.Type == "webhook" {
		return New(options.URL, options.Secret, options.BearerToken)
	}
	s := &directSender{kind: options.Type, client: directClient()}
	secrets := SecretValues(options)
	if options.Type == "telegram" {
		id, idErr := strconv.ParseInt(options.ChatID, 10, 64)
		if !botToken.MatchString(options.Token) || !chatID.MatchString(options.ChatID) || idErr != nil || id == 0 || options.URL != "" {
			return nil, errors.New("Telegram requires a valid bot token and chat ID, without a custom URL")
		}
		s.endpoint, s.chatID = "https://api.telegram.org/bot"+options.Token+"/sendMessage", options.ChatID
	} else {
		u, err := url.Parse(options.URL)
		if err != nil || len(options.URL) > 4096 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || (options.Type != "grokbot" && (u.RawPath != "" || (u.Port() != "" && u.Port() != "443"))) {
			return nil, errors.New("report destination requires an HTTPS URL without credentials, fragments, or a custom port")
		}
		switch options.Type {
		case "slack":
			parts := strings.Split(strings.TrimPrefix(u.Path, "/services/"), "/")
			valid := (u.Hostname() == "hooks.slack.com" || u.Hostname() == "hooks.slack-gov.com") && strings.HasPrefix(u.Path, "/services/") && u.RawQuery == "" && len(parts) == 3
			for _, part := range parts {
				valid = valid && webhookPart.MatchString(part)
			}
			if !valid {
				return nil, errors.New("Slack requires an official incoming webhook URL")
			}
		case "discord":
			if u.Hostname() != "discord.com" || !discordPath.MatchString(u.Path) {
				return nil, errors.New("Discord requires an official channel webhook URL")
			}
			query, err := url.ParseQuery(u.RawQuery)
			if err != nil {
				return nil, errors.New("invalid Discord webhook query")
			}
			for name, values := range query {
				if name != "wait" || len(values) != 1 || (values[0] != "true" && values[0] != "false") {
					return nil, errors.New("Discord webhook query may only configure wait")
				}
			}
			query.Set("wait", "true")
			u.RawQuery = query.Encode()
		case "grokbot":
			s.bearer = options.BearerToken
			if s.bearer == "" {
				s.bearer = options.Token
			}
			if !validBearer(s.bearer) {
				return nil, errors.New("Grok Bot requires a routine bearer key")
			}
		default:
			return nil, errors.New("unsupported reporting destination type")
		}
		s.endpoint = u.String()
	}
	s.redact = Redactor(secrets...)
	return s, nil
}

// SecretValues also protects fragments of capability URLs when a local command
// prints only a webhook token or routine identifier instead of the whole URL.
func SecretValues(options Options) []string {
	values := []string{options.URL, options.Secret, options.BearerToken, options.Token}
	if u, err := url.Parse(options.URL); err == nil {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		switch options.Type {
		case "slack":
			if len(parts) == 4 && parts[0] == "services" {
				values = append(values, parts[1:]...)
			}
		case "discord":
			if len(parts) >= 4 {
				values = append(values, parts[len(parts)-1])
			}
		case "grokbot":
			for _, part := range parts {
				if len(part) >= 16 {
					values = append(values, part)
				}
			}
		}
		for _, items := range u.Query() {
			values = append(values, items...)
		}
	}
	unique := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" && !seen[value] {
			unique = append(unique, value)
			seen[value] = true
		}
	}
	return unique
}

func validBearer(value string) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, r := range value {
		if r < '!' || r > '~' {
			return false
		}
	}
	return true
}

// ShouldSend selects operational changes and actionable assessments. The full
// event history still belongs in the local audit, including filtered events.
func (s *directSender) ShouldSend(event protocol.Event) bool {
	source, _ := event.Details["source"].(string)
	phase, _ := event.Details["phase"].(string)
	changed, _ := event.Details["changed"].(bool)
	mutates, _ := event.Details["mutates"].(bool)
	status, _ := event.Details["status"].(string)
	problem, _ := event.Details["error"].(string)
	assessment, _ := event.Details["assessment"].(string)
	switch event.Type {
	case "started", "report_test", "source_error", "source_recovered":
		return true
	case "assessment_started":
		return source == "local-host"
	case "action_started":
		return mutates || phase == "rollback"
	case "action_finished":
		return mutates || phase == "verification" || phase == "rollback"
	case "assessment_finished":
		if source == "local-host" || changed || status == "deferred" || problem != "" {
			return true
		}
		switch assessment {
		case "exposed", "suspected_compromise", "confirmed_compromise", "remediated":
			return true
		}
	}
	return false
}

func (s *directSender) Send(ctx context.Context, event protocol.Event) error {
	if !s.ShouldSend(event) {
		return nil
	}
	event = safeEvent(event, s.redact)
	message := formatEvent(event)
	var payload any
	switch s.kind {
	case "slack":
		payload = map[string]any{"blocks": []any{map[string]any{"type": "section", "text": map[string]any{"type": "plain_text", "text": limitText(message, 2900), "emoji": false}}}, "unfurl_links": false, "unfurl_media": false}
	case "discord":
		payload = map[string]any{"content": limitText(discordPlain(message), 2000), "allowed_mentions": map[string]any{"parse": []string{}}, "flags": 4}
	case "telegram":
		payload = map[string]any{"chat_id": s.chatID, "text": limitText(message, 4096), "link_preview_options": map[string]any{"is_disabled": true}}
	case "grokbot":
		payload = map[string]any{"source": "firefighter", "message": limitText(message, 4096), "event": event}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("cannot encode report")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot construct reporting request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", event.ID)
	if s.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+s.bearer)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.New("report delivery failed (network, timeout, or TLS error)")
	}
	defer resp.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if resp.StatusCode == http.StatusTooManyRequests {
		return retryError(resp.Header, data, time.Now())
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("report destination returned HTTP %d", resp.StatusCode)
	}
	if readErr != nil || len(data) > 64<<10 {
		return errors.New("cannot read bounded report acknowledgement")
	}
	switch s.kind {
	case "slack":
		if strings.TrimSpace(string(data)) != "ok" {
			return errors.New("Slack did not acknowledge the report")
		}
	case "discord":
		var ack struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(data, &ack) != nil || !messageID.MatchString(ack.ID) {
			return errors.New("Discord did not return a message acknowledgement")
		}
	case "telegram":
		var ack struct {
			OK        bool `json:"ok"`
			ErrorCode int  `json:"error_code"`
		}
		if json.Unmarshal(data, &ack) != nil {
			return errors.New("Telegram returned an invalid acknowledgement")
		}
		if ack.ErrorCode == http.StatusTooManyRequests {
			return retryError(resp.Header, data, time.Now())
		}
		if !ack.OK {
			return errors.New("Telegram did not acknowledge the report")
		}
	case "grokbot":
		// Exactly HTTP 200 means the routine accepted the event, not that it
		// completed its work or that a person has seen the notification.
	}
	return nil
}

func retryError(header http.Header, body []byte, now time.Time) *RetryAfterError {
	delay := time.Duration(0)
	if value := header.Get("Retry-After"); value != "" {
		if seconds, err := strconv.ParseFloat(value, 64); err == nil {
			delay = secondsDuration(seconds)
		} else if date, err := http.ParseTime(value); err == nil && date.After(now) {
			delay = date.Sub(now)
		}
	}
	var response struct {
		RetryAfter float64 `json:"retry_after"`
		Parameters struct {
			RetryAfter float64 `json:"retry_after"`
		} `json:"parameters"`
	}
	if len(body) <= 64<<10 && json.Unmarshal(body, &response) == nil {
		delay = max(delay, secondsDuration(response.RetryAfter), secondsDuration(response.Parameters.RetryAfter))
	}
	if delay <= 0 {
		delay = 30 * time.Second
	}
	return &RetryAfterError{After: delay}
}

func secondsDuration(seconds float64) time.Duration {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 {
		return 0
	}
	if seconds >= float64(math.MaxInt64)/float64(time.Second) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(math.Ceil(seconds * float64(time.Second)))
}

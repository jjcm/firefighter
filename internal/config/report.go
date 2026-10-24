package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// A report object replaces the previous defaults. Only the legacy signed
// webhook shape inherits the historical signing environment variable name.
func (r *Report) UnmarshalJSON(data []byte) error {
	type plain Report
	var value plain
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if value.Type == "" && fields["secret_env"] == nil {
		value.SecretEnv = "FIREFIGHTER_REPORT_SECRET"
	}
	*r = Report(value)
	return nil
}

func (r Report) Enabled() bool {
	return r.Type != "none" && (r.Type != "" || r.URL != "" || r.URLEnv != "")
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidEnvName accepts environment variable names, never credential values.
func ValidEnvName(name string) bool { return envName.MatchString(name) }

// Validate checks field combinations without looking up credentials or making
// remote calls. Provider-specific URL validation happens in the reporter.
func (r Report) Validate() error {
	for _, name := range []string{r.URLEnv, r.SecretEnv, r.BearerTokenEnv, r.TokenEnv} {
		if name != "" && !ValidEnvName(name) {
			return errors.New("report credential fields must contain valid environment variable names")
		}
	}
	if r.URL != "" && r.URLEnv != "" {
		return errors.New("report accepts either url or url_env, not both")
	}
	if r.URL != strings.TrimSpace(r.URL) {
		return errors.New("report URL cannot have surrounding whitespace")
	}
	endpoint := r.URL != "" || r.URLEnv != ""
	switch r.Type {
	case "":
		if r.TokenEnv != "" || r.ChatID != "" {
			return errors.New("legacy webhook reporting does not accept token_env or chat_id")
		}
		if endpoint && r.SecretEnv == "" {
			return errors.New("report URL requires secret_env for signed events")
		}
	case "webhook":
		if !endpoint || r.SecretEnv == "" || r.TokenEnv != "" || r.ChatID != "" {
			return errors.New("webhook reporting requires an endpoint and secret_env, with optional bearer_token_env")
		}
	case "none":
		if endpoint || r.SecretEnv != "" || r.BearerTokenEnv != "" || r.TokenEnv != "" || r.ChatID != "" {
			return errors.New("disabled reporting does not accept destination or credential fields")
		}
	case "slack", "discord":
		if !endpoint || r.SecretEnv != "" || r.BearerTokenEnv != "" || r.TokenEnv != "" || r.ChatID != "" {
			return errors.New("Slack and Discord reporting require only a webhook endpoint")
		}
	case "grokbot":
		if !endpoint || r.BearerTokenEnv == "" || r.SecretEnv != "" || r.TokenEnv != "" || r.ChatID != "" {
			return errors.New("Grok Bot reporting requires an endpoint and bearer_token_env only")
		}
	case "telegram":
		chatID, err := strconv.ParseInt(r.ChatID, 10, 64)
		if endpoint || r.SecretEnv != "" || r.BearerTokenEnv != "" || r.TokenEnv == "" || err != nil || chatID == 0 {
			return errors.New("Telegram reporting requires token_env and a nonzero numeric chat_id only")
		}
	default:
		return errors.New("report type must be none, webhook, slack, discord, telegram, or grokbot")
	}
	return nil
}

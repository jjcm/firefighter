package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	StateDir               string              `json:"state_dir"`
	Observe                bool                `json:"observe"`
	RequireRoot            bool                `json:"require_root"`
	TickSeconds            int                 `json:"tick_seconds"`
	InventorySeconds       int                 `json:"inventory_seconds"`
	RecheckSeconds         int                 `json:"recheck_seconds"`
	MaxIncidentsPerTick    int                 `json:"max_incidents_per_tick"`
	MaxRounds              int                 `json:"max_rounds"`
	MaxActionsPerRound     int                 `json:"max_actions_per_round"`
	CommandTimeoutSeconds  int                 `json:"command_timeout_seconds"`
	IncidentTimeoutSeconds int                 `json:"incident_timeout_seconds"`
	MaxOutputBytes         int                 `json:"max_output_bytes"`
	MaxPendingIncidents    int                 `json:"max_pending_incidents"`
	RecordRetentionDays    int                 `json:"record_retention_days"`
	Instructions           string              `json:"instructions"`
	RotationHooks          map[string][]string `json:"rotation_hooks"`
	LLM                    LLM                 `json:"llm"`
	Sources                []Source            `json:"sources"`
	Report                 Report              `json:"report"`
}
type LLM struct {
	Backend        string   `json:"backend"`
	BaseURL        string   `json:"base_url"`
	Model          string   `json:"model"`
	APIKeyEnv      string   `json:"api_key_env"`
	Command        []string `json:"command"`
	Dir            string   `json:"dir"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	JSONMode       bool     `json:"json_mode"`
}
type Source struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	URL             string `json:"url,omitempty"`
	IntervalSeconds int    `json:"interval_seconds"`
	LookbackHours   int    `json:"lookback_hours"`
	TokenEnv        string `json:"token_env,omitempty"`
	Query           string `json:"query,omitempty"`
	Trust           string `json:"trust,omitempty"`
	PublicKey       string `json:"public_key,omitempty"`
	CAFile          string `json:"ca_file,omitempty"`
}
type Report struct {
	URL            string `json:"url"`
	SecretEnv      string `json:"secret_env"`
	BearerTokenEnv string `json:"bearer_token_env"`
}

func Default() Config {
	return Config{
		StateDir: "/var/lib/firefighter", RequireRoot: true, TickSeconds: 15,
		InventorySeconds: 1800, RecheckSeconds: 900, MaxIncidentsPerTick: 4,
		MaxRounds: 8, MaxActionsPerRound: 6, CommandTimeoutSeconds: 300,
		IncidentTimeoutSeconds: 1800, MaxOutputBytes: 32768, MaxPendingIncidents: 10000, RecordRetentionDays: 30,
		Instructions:  "Protect this Linux host and its locally deployed applications. Use installed scanners when available. Prioritize actively exploited and internet-exposed software. Apply fixes and verify service health. Maintain access needed for recovery. If compromise is suspected, preserve evidence and assess persistence before rotating affected credentials using configured hooks. Never infer absence of compromise from a clean vulnerability scan.",
		RotationHooks: map[string][]string{},
		LLM:           LLM{Backend: "api", BaseURL: "https://api.openai.com/v1", Model: "gpt-6.1-sol", APIKeyEnv: "OPENAI_API_KEY", TimeoutSeconds: 120},
		Sources: []Source{
			{Name: "ubuntu-usn", Type: "rss", URL: "https://ubuntu.com/security/notices/rss.xml", IntervalSeconds: 120, Trust: "official"},
			{Name: "cisa-kev", Type: "kev", IntervalSeconds: 300, LookbackHours: 0},
			{Name: "nvd", Type: "nvd", IntervalSeconds: 300, LookbackHours: 24, TokenEnv: "NVD_API_KEY"},
			{Name: "x", Type: "x", IntervalSeconds: 60, LookbackHours: 1, TokenEnv: "X_BEARER_TOKEN", Query: "(CVE OR \"zero day\" OR \"zero-day\" OR \"security advisory\" OR RCE) -is:retweet"},
		}, Report: Report{SecretEnv: "FIREFIGHTER_REPORT_SECRET"},
	}
}

func Load(path string) (Config, error) {
	c := Default()
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	var extra interface{}
	if err = d.Decode(&extra); err != io.EOF {
		return c, errors.New("config must contain exactly one JSON object")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("state_dir must be absolute")
	}
	if c.TickSeconds < 1 || c.InventorySeconds < 60 || c.RecheckSeconds < 60 {
		return errors.New("invalid tick, inventory, or recheck interval")
	}
	if c.MaxIncidentsPerTick < 1 || c.MaxIncidentsPerTick > 100 || c.MaxRounds < 1 || c.MaxRounds > 32 || c.MaxActionsPerRound < 1 || c.MaxActionsPerRound > 32 {
		return errors.New("invalid incident/round/action budget")
	}
	if c.CommandTimeoutSeconds < 1 || c.CommandTimeoutSeconds > 3600 || c.IncidentTimeoutSeconds < 1 || c.IncidentTimeoutSeconds > 14400 {
		return errors.New("invalid execution timeout")
	}
	if c.MaxOutputBytes < 1024 || c.MaxOutputBytes > 1<<20 || c.MaxPendingIncidents < 1 || c.MaxPendingIncidents > 100000 {
		return errors.New("invalid output or queue limit")
	}
	if c.LLM.TimeoutSeconds < 1 || c.LLM.TimeoutSeconds > 1800 {
		return errors.New("invalid LLM timeout")
	}
	if c.RecordRetentionDays < 1 || c.RecordRetentionDays > 365 {
		return errors.New("record_retention_days must be 1..365")
	}
	switch c.LLM.Backend {
	case "api", "anthropic":
		if c.LLM.BaseURL == "" || c.LLM.APIKeyEnv == "" || c.LLM.Model == "" {
			return errors.New("API backend requires base_url, model, and api_key_env")
		}
		if c.LLM.Backend == "anthropic" && c.LLM.JSONMode {
			return errors.New("Anthropic uses native structured output; json_mode must be false")
		}
	case "command":
		if len(c.LLM.Command) == 0 {
			return errors.New("command backend requires llm.command")
		}
	default:
		return errors.New("llm.backend must be api, anthropic, or command")
	}
	names := map[string]bool{}
	for _, s := range c.Sources {
		if s.Name == "" || names[s.Name] {
			return errors.New("source names must be unique and nonempty")
		}
		names[s.Name] = true
		if s.IntervalSeconds < 15 || s.LookbackHours < 0 {
			return fmt.Errorf("source %s: invalid interval/lookback", s.Name)
		}
		switch s.Type {
		case "kev", "nvd":
		case "x":
			if s.TokenEnv == "" {
				return errors.New("X source requires token_env")
			}
		case "rss":
			if s.URL == "" {
				return errors.New("RSS source requires URL")
			}
		case "broadcast":
			key, err := base64.StdEncoding.Strict().DecodeString(s.PublicKey)
			if s.URL == "" || err != nil || len(key) != ed25519.PublicKeySize {
				return errors.New("broadcast source requires URL and a pinned base64 Ed25519 public_key")
			}
			if s.CAFile != "" && !filepath.IsAbs(s.CAFile) {
				return errors.New("broadcast ca_file must be an absolute PEM file path")
			}
		default:
			return fmt.Errorf("unknown source type %q", s.Type)
		}
	}
	for name, argv := range c.RotationHooks {
		if name == "" || len(argv) == 0 || !filepath.IsAbs(argv[0]) {
			return errors.New("rotation hooks require a name and absolute executable path")
		}
	}
	if c.Report.URL != "" && c.Report.SecretEnv == "" {
		return errors.New("report URL requires secret_env for signed events")
	}
	return nil
}
func Seconds(n int) time.Duration { return time.Duration(n) * time.Second }

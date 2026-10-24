package broadcast

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jjcm/firefighter/internal/intel"
)

type SourceConfig struct {
	Name            string `json:"name"`
	Type            string `json:"type"`
	URL             string `json:"url,omitempty"`
	IntervalSeconds int    `json:"interval_seconds"`
	LookbackHours   int    `json:"lookback_hours"`
	TokenEnv        string `json:"token_env,omitempty"`
	Query           string `json:"query,omitempty"`
	MaxPages        int    `json:"max_pages,omitempty"`
	PageSize        int    `json:"page_size,omitempty"`
}
type Config struct {
	Listen             string         `json:"listen"`
	StateDir           string         `json:"state_dir"`
	WebsiteDir         string         `json:"website_dir"`
	RetentionDays      int            `json:"retention_days"`
	MaxNotices         int            `json:"max_notices"`
	PollTimeoutSeconds int            `json:"poll_timeout_seconds"`
	RequestsPerMinute  int            `json:"requests_per_minute"`
	Sources            []SourceConfig `json:"sources"`
}

func DefaultConfig() Config {
	return Config{Listen: "127.0.0.1:8090", StateDir: "/var/lib/firefighter-hub", WebsiteDir: "/opt/firefighter/web", RetentionDays: 7, MaxNotices: 100000, PollTimeoutSeconds: 900, RequestsPerMinute: 300, Sources: []SourceConfig{
		{Name: "ubuntu-usn", Type: "rss", URL: "https://ubuntu.com/security/notices/rss.xml", IntervalSeconds: 120},
		{Name: "cisa-kev", Type: "kev", IntervalSeconds: 300},
		{Name: "nvd", Type: "nvd", IntervalSeconds: 300, LookbackHours: 24, TokenEnv: "NVD_API_KEY", PageSize: 500},
	}}
}

var sourceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return c, err
	}
	if len(b) > 1<<20 {
		return c, errors.New("hub config exceeds 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, fmt.Errorf("hub config: %w", err)
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return c, errors.New("hub config must contain one JSON object")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return errors.New("hub listen must be host:port")
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("hub HTTP listener must bind loopback; publish through an HTTPS reverse proxy")
		}
	}
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("hub state_dir must be absolute")
	}
	if c.WebsiteDir != "" && !filepath.IsAbs(c.WebsiteDir) {
		return errors.New("hub website_dir must be absolute")
	}
	if c.WebsiteDir != "" && (within(c.StateDir, c.WebsiteDir) || within(c.WebsiteDir, c.StateDir)) {
		return errors.New("website_dir and state_dir must not overlap")
	}
	if c.RetentionDays < 1 || c.RetentionDays > 365 || c.MaxNotices < 1 || c.MaxNotices > 1000000 {
		return errors.New("invalid hub retention limits")
	}
	if c.PollTimeoutSeconds < 30 || c.PollTimeoutSeconds > 7200 || c.RequestsPerMinute < 1 || c.RequestsPerMinute > 100000 {
		return errors.New("invalid hub polling or HTTP limits")
	}
	names := map[string]bool{}
	for _, s := range c.Sources {
		if !sourceName.MatchString(s.Name) || names[s.Name] {
			return errors.New("hub source names must be unique safe identifiers")
		}
		names[s.Name] = true
		if s.IntervalSeconds < 15 || s.LookbackHours < 0 || s.MaxPages < 0 || s.MaxPages > 1000 || s.PageSize < 0 || s.PageSize > 2000 {
			return fmt.Errorf("source %s has invalid polling bounds", s.Name)
		}
		if s.TokenEnv != "" && !envName.MatchString(s.TokenEnv) {
			return fmt.Errorf("source %s requires an environment variable NAME, never a credential", s.Name)
		}
		switch s.Type {
		case "kev", "nvd":
		case "x":
			if s.TokenEnv == "" {
				return errors.New("X hub source requires token_env")
			}
		case "rss":
			if s.URL == "" {
				return errors.New("RSS hub source requires URL")
			}
		default:
			return errors.New("hub source type must be kev, nvd, x, or rss")
		}
	}
	return nil
}

func within(parent, child string) bool {
	r, err := filepath.Rel(parent, child)
	return err == nil && (r == "." || (r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))))
}

func BuildSources(cfg Config) ([]ScheduledSource, error) {
	var sources []ScheduledSource
	for _, c := range cfg.Sources {
		var source intel.Source
		var err error
		lookback := time.Duration(c.LookbackHours) * time.Hour
		switch c.Type {
		case "kev":
			source, err = intel.NewKEV(intel.KEVConfig{URL: c.URL, Lookback: lookback})
		case "nvd":
			pageSize := c.PageSize
			if pageSize == 0 {
				pageSize = 500
			}
			source, err = intel.NewNVD(intel.NVDConfig{URL: c.URL, APIKey: os.Getenv(c.TokenEnv), Lookback: lookback, MaxPages: c.MaxPages, PageSize: pageSize})
		case "x":
			token := os.Getenv(c.TokenEnv)
			validation := token
			if validation == "" {
				validation = "configuration-only"
			}
			source, err = intel.NewX(intel.XConfig{URL: c.URL, BearerToken: validation, Query: c.Query, Lookback: lookback, MaxPages: c.MaxPages})
			if token == "" && err == nil {
				source = missingSource{}
			}
		case "rss":
			source, err = intel.NewFeed(intel.FeedConfig{Name: c.Name, URL: c.URL})
		}
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", c.Name, err)
		}
		encoded, _ := json.Marshal(c)
		sources = append(sources, ScheduledSource{Name: c.Name, Every: time.Duration(c.IntervalSeconds) * time.Second, Fingerprint: hash(encoded), Source: source})
	}
	return sources, nil
}

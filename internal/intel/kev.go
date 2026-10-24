package intel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

const KEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type KEVConfig struct {
	URL    string
	Client *http.Client
	Now    func() time.Time
	// Lookback applies only on first ingestion; zero includes the entire KEV.
	Lookback time.Duration
}

type KEV struct {
	u        *url.URL
	client   *http.Client
	now      func() time.Time
	lookback time.Duration
}

func NewKEV(cfg KEVConfig) (*KEV, error) {
	u, err := endpoint(cfg.URL, KEVURL)
	if err != nil {
		return nil, err
	}
	if cfg.Lookback < 0 {
		return nil, errors.New("KEV lookback must not be negative")
	}
	return &KEV{u: u, client: clientFor(cfg.Client), now: nowFunc(cfg.Now), lookback: cfg.Lookback}, nil
}

func (*KEV) Name() string { return "cisa-kev" }

func (s *KEV) Poll(ctx context.Context, cursor string) (Result, error) {
	old, err := snapshot(cursor)
	if err != nil {
		return unchanged(cursor, err)
	}
	b, err := get(ctx, s.client, s.u, nil)
	if err != nil {
		return unchanged(cursor, err)
	}
	var catalog struct {
		Version         string            `json:"catalogVersion"`
		Count           int               `json:"count"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &catalog); err != nil {
		return unchanged(cursor, errors.New("invalid KEV JSON"))
	}
	if catalog.Version == "" || catalog.Count != len(catalog.Vulnerabilities) {
		return unchanged(cursor, errors.New("incomplete KEV catalog"))
	}
	items := make([]Item, 0, len(catalog.Vulnerabilities))
	for _, raw := range catalog.Vulnerabilities {
		var v struct {
			CVE       string `json:"cveID"`
			Title     string `json:"vulnerabilityName"`
			DateAdded string `json:"dateAdded"`
		}
		if err := json.Unmarshal(raw, &v); err != nil || len(ExtractCVEs(v.CVE)) != 1 || date(v.DateAdded).IsZero() {
			return unchanged(cursor, errors.New("invalid KEV vulnerability entry"))
		}
		item := Item{ID: v.CVE, Source: s.Name(), URL: "https://nvd.nist.gov/vuln/detail/" + v.CVE, Title: v.Title, Body: string(raw), CVEs: ExtractCVEs(string(raw)), PublishedAt: date(v.DateAdded), ModifiedAt: date(v.DateAdded), Trust: "official"}
		items = append(items, item)
		// Record skipped initial history in the cursor so it is not emitted on
		// the next poll; a later edit still produces a new event.
		if cursor == "" && s.lookback > 0 && item.PublishedAt.Before(s.now().Add(-s.lookback)) {
			encoded, _ := json.Marshal(item)
			old[item.ID] = digest(encoded)
		}
	}
	result, err := snapshotResult(items, old)
	if err != nil {
		return unchanged(cursor, err)
	}
	return result, nil
}

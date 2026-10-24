package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const NVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

type NVDConfig struct {
	URL      string
	APIKey   string
	Client   *http.Client
	Now      func() time.Time
	Lookback time.Duration
	Overlap  time.Duration
	MaxPages int
	PageSize int
	// RequestInterval defaults to 6s (NVD's unauthenticated request budget).
	RequestInterval time.Duration
}

type NVD struct {
	u                           *url.URL
	client                      *http.Client
	now                         func() time.Time
	apiKey                      string
	lookback, overlap, interval time.Duration
	maxPages, pageSize          int
}

func NewNVD(cfg NVDConfig) (*NVD, error) {
	u, err := endpoint(cfg.URL, NVDURL)
	if err != nil {
		return nil, err
	}
	if cfg.Lookback == 0 {
		cfg.Lookback = 24 * time.Hour
	}
	if cfg.Overlap == 0 {
		cfg.Overlap = 5 * time.Minute
	}
	if cfg.MaxPages == 0 {
		cfg.MaxPages = 100
	}
	if cfg.PageSize == 0 {
		cfg.PageSize = 2000
	}
	if cfg.RequestInterval == 0 {
		cfg.RequestInterval = 6 * time.Second
	}
	if cfg.Lookback < 0 || cfg.Overlap < 0 || cfg.Overlap >= 119*24*time.Hour || cfg.MaxPages < 1 || cfg.PageSize < 1 || cfg.PageSize > 2000 || cfg.RequestInterval < 0 {
		return nil, errors.New("invalid NVD lookback, overlap, pagination, or interval")
	}
	return &NVD{u: u, client: clientFor(cfg.Client), now: nowFunc(cfg.Now), apiKey: cfg.APIKey, lookback: cfg.Lookback, overlap: cfg.Overlap, interval: cfg.RequestInterval, maxPages: cfg.MaxPages, pageSize: cfg.PageSize}, nil
}

func (*NVD) Name() string { return "nvd" }

func (s *NVD) Poll(ctx context.Context, cursor string) (Result, error) {
	end := s.now().UTC().Truncate(time.Millisecond)
	start := end.Add(-s.lookback)
	if cursor != "" {
		previous, err := time.Parse(time.RFC3339Nano, cursor)
		if err != nil {
			return unchanged(cursor, errors.New("invalid NVD time cursor"))
		}
		if previous.After(end) {
			return unchanged(cursor, errors.New("NVD cursor is ahead of system clock"))
		}
		start = previous.Add(-s.overlap)
	}
	// NVD limits date windows to 120 days. Catch up in 119-day windows instead
	// of silently discarding history after an extended outage.
	if end.Sub(start) > 119*24*time.Hour {
		end = start.Add(119 * 24 * time.Hour)
	}
	items := []Item{}
	seen := map[string]bool{}
	index, total := 0, -1
	for page := 0; page < s.maxPages; page++ {
		if page > 0 {
			timer := time.NewTimer(s.interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return unchanged(cursor, ctx.Err())
			case <-timer.C:
			}
		}
		u := *s.u
		q := u.Query()
		q.Set("lastModStartDate", start.Format("2006-01-02T15:04:05.000Z"))
		q.Set("lastModEndDate", end.Format("2006-01-02T15:04:05.000Z"))
		q.Set("startIndex", strconv.Itoa(index))
		q.Set("resultsPerPage", strconv.Itoa(s.pageSize))
		u.RawQuery = q.Encode()
		headers := make(http.Header)
		if s.apiKey != "" {
			headers.Set("apiKey", s.apiKey)
		}
		b, err := get(ctx, s.client, &u, headers)
		if err != nil {
			return unchanged(cursor, fmt.Errorf("NVD page %d: %w", page+1, err))
		}
		var response struct {
			ResultsPerPage  int  `json:"resultsPerPage"`
			StartIndex      int  `json:"startIndex"`
			TotalResults    *int `json:"totalResults"`
			Vulnerabilities []struct {
				CVE json.RawMessage `json:"cve"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(b, &response); err != nil || response.TotalResults == nil {
			return unchanged(cursor, errors.New("invalid NVD JSON"))
		}
		if response.StartIndex != index || *response.TotalResults < 0 || response.ResultsPerPage != len(response.Vulnerabilities) || (total >= 0 && total != *response.TotalResults) {
			return unchanged(cursor, errors.New("NVD pagination changed or was inconsistent; retrying whole window"))
		}
		total = *response.TotalResults
		for _, v := range response.Vulnerabilities {
			var c struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				LastModified string `json:"lastModified"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			}
			if err := json.Unmarshal(v.CVE, &c); err != nil || len(ExtractCVEs(c.ID)) != 1 || date(c.LastModified).IsZero() {
				return unchanged(cursor, errors.New("invalid NVD vulnerability entry"))
			}
			if seen[c.ID] {
				return unchanged(cursor, errors.New("NVD repeated a record across pages; retrying whole window"))
			}
			seen[c.ID] = true
			title := c.ID
			for _, d := range c.Descriptions {
				if d.Lang == "en" {
					title += ": " + strings.TrimSpace(d.Value)
					break
				}
			}
			items = append(items, Item{ID: c.ID, Source: s.Name(), URL: "https://nvd.nist.gov/vuln/detail/" + c.ID, Title: title, Body: string(v.CVE), CVEs: []string{c.ID}, PublishedAt: date(c.Published), ModifiedAt: date(c.LastModified), Trust: "official"})
		}
		index += len(response.Vulnerabilities)
		if index == total {
			return Result{Items: items, Cursor: end.Format(time.RFC3339Nano)}, nil
		}
		if index > total || len(response.Vulnerabilities) == 0 {
			return unchanged(cursor, errors.New("NVD returned an incomplete or inconsistent page"))
		}
	}
	return unchanged(cursor, fmt.Errorf("NVD backlog exceeds %d pages; cursor retained, increase max_pages", s.maxPages))
}

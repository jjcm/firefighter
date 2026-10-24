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

const XURL = "https://api.x.com/2/tweets/search/recent"

// Include early disclosures that do not yet have a CVE assignment. Operators
// should scope this further to relevant products and researchers if needed.
const DefaultXQuery = `(CVE OR "zero-day" OR "0day" OR "security advisory" OR "remote code execution" OR "actively exploited") -is:retweet`

type XConfig struct {
	URL         string
	BearerToken string
	Query       string
	Client      *http.Client
	Now         func() time.Time
	Lookback    time.Duration
	MaxPages    int
}

type X struct {
	u            *url.URL
	client       *http.Client
	now          func() time.Time
	token, query string
	lookback     time.Duration
	maxPages     int
}

func NewX(cfg XConfig) (*X, error) {
	u, err := endpoint(cfg.URL, XURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.BearerToken) == "" {
		return nil, errors.New("X recent search requires a bearer token and API access")
	}
	if cfg.Query == "" {
		cfg.Query = DefaultXQuery
	}
	if cfg.Lookback == 0 {
		cfg.Lookback = 24 * time.Hour
	}
	if cfg.MaxPages == 0 {
		cfg.MaxPages = 100
	}
	if cfg.Lookback < 0 || cfg.Lookback > 7*24*time.Hour-time.Minute || cfg.MaxPages < 1 {
		return nil, errors.New("X lookback must be within the recent-search seven-day window and max pages must be positive")
	}
	return &X{u: u, client: clientFor(cfg.Client), now: nowFunc(cfg.Now), token: cfg.BearerToken, query: cfg.Query, lookback: cfg.Lookback, maxPages: cfg.MaxPages}, nil
}

func (*X) Name() string { return "x" }

func (s *X) Poll(ctx context.Context, cursor string) (Result, error) {
	var high uint64
	if cursor != "" {
		var err error
		high, err = strconv.ParseUint(cursor, 10, 64)
		if err != nil || high == 0 {
			return unchanged(cursor, errors.New("invalid X since_id cursor"))
		}
	}
	// Keep identical time/ID bounds across pagination. X documents a 30-second
	// indexing delay at the newest end of the recent-search window.
	end := s.now().UTC().Add(-30 * time.Second).Truncate(time.Second)
	start := end.Add(-s.lookback)
	next := ""
	seenTokens := map[string]bool{}
	seenItems := map[string]bool{}
	items := []Item{}
	for page := 0; page < s.maxPages; page++ {
		u := *s.u
		q := u.Query()
		q.Set("query", s.query)
		q.Set("max_results", "100")
		q.Set("tweet.fields", "created_at,author_id,entities")
		q.Set("end_time", end.Format(time.RFC3339))
		if cursor != "" {
			q.Set("since_id", cursor)
		} else {
			q.Set("start_time", start.Format(time.RFC3339))
		}
		if next != "" {
			q.Set("next_token", next)
		}
		u.RawQuery = q.Encode()
		b, err := get(ctx, s.client, &u, http.Header{"Authorization": []string{"Bearer " + s.token}})
		if err != nil {
			return unchanged(cursor, fmt.Errorf("X page %d: %w", page+1, err))
		}
		var response struct {
			Data []struct {
				ID        string `json:"id"`
				Text      string `json:"text"`
				CreatedAt string `json:"created_at"`
				Entities  struct {
					URLs []struct {
						ExpandedURL string `json:"expanded_url"`
					} `json:"urls"`
				} `json:"entities"`
			} `json:"data"`
			Meta struct {
				NextToken   string `json:"next_token"`
				ResultCount *int   `json:"result_count"`
			} `json:"meta"`
			Errors []json.RawMessage `json:"errors"`
		}
		if err := json.Unmarshal(b, &response); err != nil || response.Meta.ResultCount == nil {
			return unchanged(cursor, errors.New("invalid X search JSON"))
		}
		if len(response.Errors) > 0 {
			return unchanged(cursor, errors.New("X returned partial API errors; cursor retained"))
		}
		if *response.Meta.ResultCount != len(response.Data) {
			return unchanged(cursor, errors.New("X result count does not match returned posts"))
		}
		for _, post := range response.Data {
			id, err := strconv.ParseUint(post.ID, 10, 64)
			if err != nil || id == 0 || date(post.CreatedAt).IsZero() {
				return unchanged(cursor, errors.New("invalid X post ID or date"))
			}
			if id > high {
				high = id
			}
			if seenItems[post.ID] {
				continue
			}
			seenItems[post.ID] = true
			body := post.Text
			for _, link := range post.Entities.URLs {
				if link.ExpandedURL != "" {
					body += "\nReferenced URL: " + link.ExpandedURL
				}
			}
			items = append(items, Item{ID: post.ID, Source: s.Name(), URL: "https://x.com/i/web/status/" + post.ID, Title: post.Text, Body: body, CVEs: ExtractCVEs(body), PublishedAt: date(post.CreatedAt), ModifiedAt: date(post.CreatedAt), Trust: "unverified"})
		}
		next = response.Meta.NextToken
		if next == "" {
			newCursor := cursor
			if high > 0 {
				newCursor = strconv.FormatUint(high, 10)
			}
			return Result{Items: items, Cursor: newCursor}, nil
		}
		if seenTokens[next] {
			return unchanged(cursor, errors.New("X repeated its pagination token; cursor retained"))
		}
		seenTokens[next] = true
	}
	return unchanged(cursor, fmt.Errorf("X backlog exceeds %d pages; cursor retained, increase max_pages", s.maxPages))
}

package intel

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type FeedConfig struct {
	Name   string
	URL    string
	Trust  string
	Client *http.Client
}

type Feed struct {
	name, trust string
	u           *url.URL
	client      *http.Client
}

func NewFeed(cfg FeedConfig) (*Feed, error) {
	u, err := endpoint(cfg.URL, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Name) == "" {
		return nil, errors.New("feed requires a unique name")
	}
	if cfg.Trust == "" {
		cfg.Trust = "vendor"
	}
	return &Feed{name: cfg.Name, trust: cfg.Trust, u: u, client: clientFor(cfg.Client)}, nil
}

func (s *Feed) Name() string { return s.name }

type rssItem struct {
	GUID        string `xml:"guid"`
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	Content     string `xml:"encoded"`
	PubDate     string `xml:"pubDate"`
	Date        string `xml:"date"`
}

type atomText struct {
	Text  string `xml:",chardata"`
	Inner string `xml:",innerxml"`
}

func (t atomText) value() string {
	if strings.Contains(t.Inner, "<") {
		return t.Inner
	}
	return t.Text
}

func (s *Feed) Poll(ctx context.Context, cursor string) (Result, error) {
	old, err := snapshot(cursor)
	if err != nil {
		return unchanged(cursor, err)
	}
	b, err := get(ctx, s.client, s.u, nil)
	if err != nil {
		return unchanged(cursor, err)
	}
	var doc struct {
		XMLName xml.Name
		Channel struct {
			Items []rssItem `xml:"item"`
		} `xml:"channel"`
		Items   []rssItem `xml:"item"`
		Entries []struct {
			ID        string   `xml:"id"`
			Title     atomText `xml:"title"`
			Summary   atomText `xml:"summary"`
			Content   atomText `xml:"content"`
			Published string   `xml:"published"`
			Updated   string   `xml:"updated"`
			Links     []struct {
				Href string `xml:"href,attr"`
				Rel  string `xml:"rel,attr"`
			} `xml:"link"`
		} `xml:"entry"`
	}
	if err := xml.Unmarshal(b, &doc); err != nil {
		return unchanged(cursor, errors.New("invalid RSS/Atom XML"))
	}
	items := []Item{}
	switch doc.XMLName.Local {
	case "rss", "RDF":
		for _, v := range append(doc.Channel.Items, doc.Items...) {
			body := v.Description
			if v.Content != "" {
				body += "\n" + v.Content
			}
			published := date(v.PubDate)
			if published.IsZero() {
				published = date(v.Date)
			}
			items = append(items, Item{ID: strings.TrimSpace(v.GUID), Source: s.Name(), URL: s.resolve(v.Link), Title: strings.TrimSpace(v.Title), Body: strings.TrimSpace(body), CVEs: ExtractCVEs(v.Title + "\n" + body), PublishedAt: published, ModifiedAt: published, Trust: s.trust})
		}
	case "feed":
		for _, v := range doc.Entries {
			link := ""
			for _, l := range v.Links {
				if l.Rel == "" || l.Rel == "alternate" {
					link = s.resolve(l.Href)
					break
				}
			}
			body := strings.TrimSpace(v.Summary.value() + "\n" + v.Content.value())
			published, modified := date(v.Published), date(v.Updated)
			if published.IsZero() {
				published = modified
			}
			if modified.IsZero() {
				modified = published
			}
			items = append(items, Item{ID: strings.TrimSpace(v.ID), Source: s.Name(), URL: link, Title: strings.TrimSpace(v.Title.value()), Body: body, CVEs: ExtractCVEs(v.Title.value() + "\n" + body), PublishedAt: published, ModifiedAt: modified, Trust: s.trust})
		}
	default:
		return unchanged(cursor, errors.New("response is not an RSS, RDF, or Atom feed"))
	}
	ids := map[string]bool{}
	for i := range items {
		if items[i].ID == "" {
			items[i].ID = items[i].URL
		}
		if items[i].ID == "" && items[i].Title != "" {
			items[i].ID = "sha256:" + digest([]byte(items[i].Title))
		}
		if items[i].ID == "" || ids[items[i].ID] {
			return unchanged(cursor, errors.New("feed contains missing or duplicate item identifiers"))
		}
		ids[items[i].ID] = true
	}
	result, err := snapshotResult(items, old)
	if err != nil {
		return unchanged(cursor, err)
	}
	return result, nil
}

func (s *Feed) resolve(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	u = s.u.ResolveReference(u)
	if (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return ""
	}
	return u.String()
}

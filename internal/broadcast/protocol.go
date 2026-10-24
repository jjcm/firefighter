// Package broadcast publishes signed, untrusted advisory DATA. It deliberately
// has no planner, runner, command, approval, credential-rotation, or remote-control API.
package broadcast

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jjcm/firefighter/internal/intel"
)

type Notice struct {
	Seq         uint64    `json:"seq"`
	Source      string    `json:"source"`
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Summary     string    `json:"summary"`
	URL         string    `json:"url"`
	CVEs        []string  `json:"cves"`
	PublishedAt time.Time `json:"published_at"`
	ObservedAt  time.Time `json:"observed_at"`
	Untrusted   bool      `json:"untrusted"`
}

type Batch struct {
	Version       int       `json:"version"`
	Kind          string    `json:"kind"`
	After         uint64    `json:"after"`
	Oldest        uint64    `json:"oldest"`
	Latest        uint64    `json:"latest"`
	NextCursor    uint64    `json:"next_cursor"`
	HasMore       bool      `json:"has_more"`
	ResetRequired bool      `json:"reset_required"`
	ResetTo       uint64    `json:"reset_to"`
	ServerTime    time.Time `json:"server_time"`
	Notices       []Notice  `json:"notices"`
}

// Payload and Signature use JSON's standard padded base64 encoding. Signatures
// cover the EXACT decoded Payload bytes; clients must not reserialize to verify.
type Envelope struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

func KeyID(public ed25519.PublicKey) string {
	h := sha256.Sum256(public)
	return hex.EncodeToString(h[:8])
}

func Sign(batch Batch, key ed25519.PrivateKey) (Envelope, error) {
	b, err := json.Marshal(batch)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{KeyID: KeyID(key.Public().(ed25519.PublicKey)), Payload: b, Signature: ed25519.Sign(key, b)}, nil
}

func bounded(s string, limit int) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func publicNotice(item intel.Item, source string, now time.Time) Notice {
	u, err := url.Parse(item.URL)
	link := ""
	if err == nil && u.Host != "" && u.User == nil && (u.Scheme == "https" || u.Scheme == "http") && len(item.URL) <= 2048 {
		link = item.URL
	}
	cves := []string{}
	for _, cve := range intel.ExtractCVEs(strings.Join(item.CVEs, " ") + " " + item.Title + " " + item.Body) {
		if len(cve) <= 64 {
			cves = append(cves, cve)
		}
	}
	if len(cves) > 64 {
		cves = cves[:64]
	}
	id := bounded(item.ID, 256)
	if strings.TrimSpace(id) == "" {
		id = "sha256:" + hash([]byte(item.Title+"\n"+item.Body))
	}
	title := bounded(item.Title, 512)
	if strings.TrimSpace(title) == "" {
		title = "Advisory " + id
	}
	return Notice{Source: bounded(source, 128), ID: id, Title: title, Summary: bounded(item.Body, 4096), URL: link, CVEs: cves, PublishedAt: item.PublishedAt.UTC(), ObservedAt: now.UTC(), Untrusted: true}
}

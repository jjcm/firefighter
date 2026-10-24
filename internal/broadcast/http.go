package broadcast

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type allowance struct {
	since time.Time
	used  int
}
type limiter struct {
	mu    sync.Mutex
	peers map[string]allowance
	max   int
}

func (l *limiter) allow(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	// The listener is loopback-only. A configured local HTTPS proxy must
	// overwrite X-Real-IP, not append an untrusted client-supplied value.
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if forwarded := net.ParseIP(r.Header.Get("X-Real-IP")); forwarded != nil {
			host = forwarded.String()
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.peers) > 10000 {
		for ip, b := range l.peers {
			if now.Sub(b.since) > time.Minute {
				delete(l.peers, ip)
			}
		}
	}
	b, exists := l.peers[host]
	if !exists && len(l.peers) > 10000 {
		return false
	}
	if now.Sub(b.since) >= time.Minute {
		b = allowance{since: now}
	}
	if b.used >= l.max {
		return false
	}
	b.used++
	l.peers[host] = b
	return true
}

func (h *Hub) Handler() http.Handler {
	l := &limiter{max: h.config.RequestsPerMinute, peers: map[string]allowance{}}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only endpoint", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte("ok\n"))
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			if !l.allow(r) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "request limit reached", http.StatusTooManyRequests)
				return
			}
			switch r.URL.Path {
			case "/api/v1/status":
				writeJSON(w, r, h.Status())
				return
			case "/api/v1/recent":
				if len(r.URL.RawQuery) > 1024 {
					http.Error(w, "query too long", http.StatusBadRequest)
					return
				}
				q, err := url.ParseQuery(r.URL.RawQuery)
				if err != nil {
					http.Error(w, "invalid query", http.StatusBadRequest)
					return
				}
				for k, v := range q {
					if k != "limit" || len(v) != 1 {
						http.Error(w, "unsupported query parameters", http.StatusBadRequest)
						return
					}
				}
				limit := 60
				if value := q.Get("limit"); value != "" {
					limit, err = strconv.Atoi(value)
					if err != nil {
						http.Error(w, "limit must be 1..100", http.StatusBadRequest)
						return
					}
				}
				recent, err := h.Recent(limit)
				if err != nil {
					http.Error(w, "limit must be 1..100", http.StatusBadRequest)
					return
				}
				writeJSON(w, r, recent)
				return
			case "/api/v1/notices":
				if len(r.URL.RawQuery) > 4096 {
					http.Error(w, "query too long", http.StatusBadRequest)
					return
				}
				q := r.URL.Query()
				for k, v := range q {
					if (k != "after" && k != "limit") || len(v) != 1 {
						http.Error(w, "unsupported query parameters", http.StatusBadRequest)
						return
					}
				}
				after := uint64(0)
				var err error
				if v := q.Get("after"); v != "" {
					after, err = strconv.ParseUint(v, 10, 64)
					if err != nil {
						http.Error(w, "after must be an unsigned sequence", http.StatusBadRequest)
						return
					}
				}
				limit := 100
				if v := q.Get("limit"); v != "" {
					limit, err = strconv.Atoi(v)
					if err != nil {
						http.Error(w, "limit must be 1..500", http.StatusBadRequest)
						return
					}
				}
				batch, err := h.Batch(after, limit)
				if err != nil {
					http.Error(w, "limit must be 1..500", http.StatusBadRequest)
					return
				}
				envelope, err := Sign(batch, h.key)
				if err != nil {
					http.Error(w, "cannot sign notice batch", http.StatusInternalServerError)
					return
				}
				writeJSON(w, r, envelope)
				return
			default:
				http.NotFound(w, r)
				return
			}
		}
		h.serveStatic(w, r)
	})
}
func writeJSON(w http.ResponseWriter, r *http.Request, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "cannot encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(b)
	}
}

var publicExtensions = map[string]bool{".html": true, ".css": true, ".js": true, ".mjs": true, ".json": true, ".svg": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".txt": true, ".webmanifest": true}

func (h *Hub) serveStatic(w http.ResponseWriter, r *http.Request) {
	if h.config.WebsiteDir == "" {
		http.NotFound(w, r)
		return
	}
	root, err := filepath.EvalSymlinks(h.config.WebsiteDir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	staticPath := r.URL.Path
	// Only this named page gets an extensionless alias; unknown routes still
	// pass through the same narrow file allowlist and containment checks.
	if staticPath == "/faq" || staticPath == "/faq/" {
		staticPath = "/faq.html"
	}
	clean := path.Clean("/" + staticPath)
	for _, segment := range strings.Split(clean, "/") {
		if strings.HasPrefix(segment, ".") {
			http.NotFound(w, r)
			return
		}
	}
	file := filepath.Join(root, filepath.FromSlash(clean))
	if strings.HasSuffix(staticPath, "/") || clean == "/" {
		file = filepath.Join(file, "index.html")
	}
	if !publicExtensions[strings.ToLower(filepath.Ext(file))] {
		http.NotFound(w, r)
		return
	}
	resolved, err := filepath.EvalSymlinks(file)
	if err != nil || !within(root, resolved) {
		http.NotFound(w, r)
		return
	}
	// Re-evaluate configured boundaries even if an administrator moved a symlink.
	stateRoot, stateErr := filepath.EvalSymlinks(h.config.StateDir)
	if stateErr != nil || within(root, stateRoot) || within(stateRoot, root) {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(resolved)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32<<20 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

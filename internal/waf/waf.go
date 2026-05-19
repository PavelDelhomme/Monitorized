package waf

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/pactivisme/monitorized/internal/storage"
)

// WAF léger : règles en mémoire + liste IP bloquée en base.
// Extensible vers modsecurity / règles OWASP dans une phase ultérieure.

var suspicious = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(union\s+select|drop\s+table|;\s*--)`),
	regexp.MustCompile(`(?i)<script[^>]*>`),
	regexp.MustCompile(`(?i)(\.\./|%2e%2e)`),
	regexp.MustCompile(`(?i)(/etc/passwd|/proc/self)`),
}

type Guard struct {
	store *storage.Store
	mu    sync.RWMutex
	rules []Rule
}

type Rule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Enabled bool   `json:"enabled"`
	re      *regexp.Regexp
}

func New(store *storage.Store) *Guard {
	g := &Guard{store: store}
	g.rules = []Rule{
		{Name: "sql_injection", Pattern: `(?i)union\s+select`, Enabled: true},
		{Name: "xss", Pattern: `(?i)<script`, Enabled: true},
	}
	for i := range g.rules {
		g.rules[i].re = regexp.MustCompile(g.rules[i].Pattern)
	}
	return g
}

func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		blocked, err := g.store.IsBlocked(ip)
		if err == nil && blocked {
			http.Error(w, `{"error":"accès refusé"}`, http.StatusForbidden)
			return
		}
		target := r.URL.RawQuery + " " + r.URL.Path
		for _, re := range suspicious {
			if re.MatchString(target) {
				_ = g.store.InsertAlert(r.Context(), "critical", "waf", "requête suspecte bloquée", map[string]string{
					"ip": ip, "path": r.URL.Path,
				})
				http.Error(w, `{"error":"requête refusée"}`, http.StatusForbidden)
				return
			}
		}
		g.mu.RLock()
		for _, rule := range g.rules {
			if !rule.Enabled || rule.re == nil {
				continue
			}
			if rule.re.MatchString(target) {
				http.Error(w, `{"error":"règle waf"}`, http.StatusForbidden)
				g.mu.RUnlock()
				return
			}
		}
		g.mu.RUnlock()
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}

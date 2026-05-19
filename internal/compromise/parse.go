package compromise

import (
	"net"
	"regexp"
	"strings"
)

var (
	emailRE  = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	domainRE = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)
)

// ParseTarget ligne d'import : email brut, domain:x, ip:x, ou domaine seul.
func ParseTarget(line string) (kind, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "email:") {
		v := strings.TrimSpace(line[6:])
		return "email", strings.ToLower(v), emailRE.MatchString(v)
	}
	if strings.HasPrefix(lower, "domain:") {
		v := strings.TrimSpace(line[7:])
		return "domain", strings.ToLower(v), domainRE.MatchString(v)
	}
	if strings.HasPrefix(lower, "ip:") {
		v := strings.TrimSpace(line[3:])
		return "ip", v, net.ParseIP(v) != nil
	}
	if emailRE.MatchString(lower) {
		return "email", lower, true
	}
	if net.ParseIP(line) != nil {
		return "ip", line, true
	}
	if domainRE.MatchString(lower) {
		return "domain", lower, true
	}
	return "", "", false
}

func ParseBulk(text string) []struct {
	Kind, Value string
} {
	var out []struct {
		Kind, Value string
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		kind, value, ok := ParseTarget(line)
		if !ok {
			continue
		}
		key := kind + ":" + value
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, struct{ Kind, Value string }{kind, value})
	}
	return out
}

package compromise

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pactivisme/monitorized/internal/config"
	"github.com/pactivisme/monitorized/internal/storage"
)

type Target struct {
	Kind   string
	Value  string
	Source string
}

type Scanner struct {
	cfg    config.Config
	store  *storage.Store
	breach *BreachChecker
	intel  *ThreatIntel
	client *http.Client
}

func NewScanner(cfg config.Config, store *storage.Store) *Scanner {
	return &Scanner{
		cfg:    cfg,
		store:  store,
		breach: NewBreachChecker(),
		intel:  NewThreatIntel(),
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

func (sc *Scanner) Run(ctx context.Context) error {
	if !sc.cfg.CompromiseEnabled {
		return nil
	}
	targets, err := sc.buildTargets(ctx)
	if err != nil {
		return err
	}
	slog.Info("compromise scan", "targets", len(targets))
	for _, t := range targets {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_ = sc.store.UpsertCompromiseTarget(ctx, t.Kind, t.Value, t.Source)
		switch t.Kind {
		case "email":
			sc.scanEmail(ctx, t.Value)
		case "domain":
			sc.scanDomain(ctx, t.Value)
		case "ip":
			sc.scanIP(ctx, t.Value)
		}
	}
	return nil
}

func (sc *Scanner) buildTargets(ctx context.Context) ([]Target, error) {
	var targets []Target
	seen := make(map[string]bool)
	add := func(kind, value, source string) {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			return
		}
		if kind == "email" {
			value = strings.ToLower(value)
		}
		key := kind + ":" + value
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, Target{Kind: kind, Value: value, Source: source})
	}

	// Cibles = base de données (UI), pas le fichier .env
	fromDB, err := sc.store.ListCompromiseTargets(ctx)
	if err == nil {
		for _, t := range fromDB {
			add(t.Kind, t.Value, t.Source)
		}
	}

	if sc.cfg.CompromiseServerIP != "" {
		add("ip", sc.cfg.CompromiseServerIP, "config")
	} else if sc.cfg.CompromiseDetectPublicIP {
		if ip, err := sc.detectPublicIP(ctx); err == nil && ip != "" {
			add("ip", ip, "auto")
		}
	}

	if sc.cfg.CompromiseAutoNPMDomains {
		since := time.Now().Add(-7 * 24 * time.Hour).Unix()
		hosts, err := sc.store.UniqueNPMHosts(ctx, since)
		if err == nil {
			for _, h := range hosts {
				h = strings.TrimSpace(strings.Split(h, ":")[0])
				if domainRE.MatchString(h) {
					add("domain", h, "npm_auto")
				}
			}
		}
	}

	return targets, nil
}

func (sc *Scanner) detectPublicIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org?format=text", nil)
	if err != nil {
		return "", err
	}
	res, err := sc.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ipify: %d", res.StatusCode)
	}
	buf := make([]byte, 64)
	n, _ := res.Body.Read(buf)
	ip := strings.TrimSpace(string(buf[:n]))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("ip publique invalide")
	}
	return ip, nil
}

func (sc *Scanner) record(ctx context.Context, kind, value, provider, severity, title string, details interface{}) {
	var detailsJSON string
	if details != nil {
		b, _ := json.Marshal(details)
		detailsJSON = string(b)
	}
	f := storage.CompromiseFinding{
		TS: time.Now().Unix(), TargetKind: kind, TargetValue: value,
		Provider: provider, Severity: severity, Title: title, Details: detailsJSON,
	}
	newFinding, err := sc.store.InsertCompromiseFinding(ctx, f)
	if err != nil {
		slog.Warn("compromise store", "err", err)
		return
	}
	if newFinding && (severity == "critical" || severity == "warning") {
		_ = sc.store.InsertCompromiseFindingAlert(ctx, f, nil)
	}
}

func (sc *Scanner) scanEmail(ctx context.Context, email string) {
	hits, err := sc.breach.CheckEmail(ctx, email)
	if err != nil {
		slog.Warn("breach check email", "email", email, "err", err)
		return
	}
	if len(hits) == 0 {
		sc.record(ctx, "email", email, "breach", "info", "Aucune fuite connue (sources gratuites)", nil)
		return
	}
	for _, b := range hits {
		sc.record(ctx, "email", email, b.Provider, "critical",
			fmt.Sprintf("Email trouvé dans « %s »", b.Name),
			map[string]interface{}{
				"breach": b.Name, "date": b.Date, "provider": b.Provider, "extra": b.Extra,
			})
	}
}

func (sc *Scanner) scanDomain(ctx context.Context, domain string) {
	uh, err := sc.intel.CheckURLhausHost(ctx, domain)
	if err != nil {
		slog.Debug("urlhaus", "domain", domain, "err", err)
	} else if uh.URLCount > 0 {
		sc.record(ctx, "domain", domain, "urlhaus", "critical",
			"Domaine référencé dans URLhaus (malware)",
			map[string]interface{}{"url_count": uh.URLCount, "status": uh.QueryStatus})
	}

	tf, err := sc.intel.CheckThreatFox(ctx, domain)
	if err != nil {
		slog.Debug("threatfox domain", "err", err)
	} else if tf.QueryStatus == "ok" && len(tf.Data) > 0 {
		sc.record(ctx, "domain", domain, "threatfox", "warning",
			"Domaine connu dans ThreatFox (menace)",
			map[string]interface{}{"hits": len(tf.Data), "sample": tf.Data[0]})
	}

	if phish, err := sc.intel.CheckPhishTank(ctx, "http://"+domain); err == nil && phish {
		sc.record(ctx, "domain", domain, "phishtank", "critical",
			"Domaine signalé comme phishing (PhishTank)", nil)
	}
}

func (sc *Scanner) scanIP(ctx context.Context, ip string) {
	if listed, err := sc.intel.CheckDNSBL(ctx, ip); err == nil && len(listed) > 0 {
		sc.record(ctx, "ip", ip, "dnsbl", "critical",
			"IP listée sur blocklist (réputation compromise)",
			map[string]interface{}{"lists": listed})
	}

	tf, err := sc.intel.CheckThreatFox(ctx, ip)
	if err == nil && tf.QueryStatus == "ok" && len(tf.Data) > 0 {
		sc.record(ctx, "ip", ip, "threatfox", "critical",
			"IP associée à une IOC malware (ThreatFox)",
			map[string]interface{}{"hits": len(tf.Data)})
	}

	sd, err := sc.intel.CheckShodanInternetDB(ctx, ip)
	if err != nil {
		slog.Debug("shodan", "ip", ip, "err", err)
		return
	}
	if len(sd.Vulns) > 0 {
		sc.record(ctx, "ip", ip, "shodan", "warning",
			"CVE connues sur services exposés",
			map[string]interface{}{"vulns": sd.Vulns, "ports": sd.Ports})
	}
	if len(sd.Ports) > 0 {
		sc.record(ctx, "ip", ip, "shodan", "info",
			"Surface d'exposition publique détectée",
			map[string]interface{}{"ports": sd.Ports, "tags": sd.Tags, "hostnames": sd.Hostnames})
	}
}

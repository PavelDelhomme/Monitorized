package compromise

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ThreatIntel struct {
	client *http.Client
}

func NewThreatIntel() *ThreatIntel {
	return &ThreatIntel{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// Shodan InternetDB — exposition publique de l'IP (ports, CVE tags) sans clé API.
type shodanDB struct {
	IP       string   `json:"ip"`
	Ports    []int    `json:"ports"`
	Tags     []string `json:"tags"`
	Vulns    []string `json:"vulns"`
	Hostnames []string `json:"hostnames"`
}

func (t *ThreatIntel) CheckShodanInternetDB(ctx context.Context, ip string) (*shodanDB, error) {
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("ip invalide")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("https://internetdb.shodan.io/%s", ip), nil)
	if err != nil {
		return nil, err
	}
	res, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return &shodanDB{IP: ip}, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("shodan internetdb: %d", res.StatusCode)
	}
	var out shodanDB
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ThreatFox (abuse.ch) — IOCs malware / C2 liés à une IP ou un domaine.
type threatFoxResponse struct {
	QueryStatus string `json:"query_status"`
	Data        []struct {
		ThreatType string `json:"threat_type"`
		Malware    string `json:"malware_printable"`
		Confidence int    `json:"confidence_level"`
		Tags       string `json:"tags"`
		FirstSeen  string `json:"first_seen"`
	} `json:"data"`
}

func (t *ThreatIntel) CheckThreatFox(ctx context.Context, ioc string) (*threatFoxResponse, error) {
	body := fmt.Sprintf(`{"query":"search_ioc","search_term":%q}`, ioc)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://threatfox-api.abuse.ch/api/v1/", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out threatFoxResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// URLhaus (abuse.ch) — domaines hébergeant des URLs malveillantes.
type urlhausHostResponse struct {
	QueryStatus string `json:"query_status"`
	URLCount    int    `json:"url_count"`
	URLs        []struct {
		URLStatus string `json:"url_status"`
		Threat    string `json:"threat"`
	} `json:"urls"`
}

func (t *ThreatIntel) CheckURLhausHost(ctx context.Context, host string) (*urlhausHostResponse, error) {
	form := fmt.Sprintf("host=%s", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://urlhaus-api.abuse.ch/v1/host/", strings.NewReader(form))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var out urlhausHostResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DNSBL — listes anti-spam (réputation IP compromise / botnet).
var dnsblZones = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
}

func (t *ThreatIntel) CheckDNSBL(ctx context.Context, ip string) ([]string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil, fmt.Errorf("ipv4 requise pour dnsbl")
	}
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return nil, fmt.Errorf("ip invalide")
	}
	reversed := fmt.Sprintf("%s.%s.%s.%s", octets[3], octets[2], octets[1], octets[0])

	var listed []string
	for _, zone := range dnsblZones {
		select {
		case <-ctx.Done():
			return listed, ctx.Err()
		default:
		}
		q := reversed + "." + zone
		addrs, err := net.DefaultResolver.LookupHost(ctx, q)
		if err != nil {
			continue
		}
		if len(addrs) > 0 {
			listed = append(listed, zone)
		}
	}
	return listed, nil
}

// PhishTank — vérification URL/domaine phishing (API gratuite).
func (t *ThreatIntel) CheckPhishTank(ctx context.Context, rawURL string) (bool, error) {
	form := fmt.Sprintf("url=%s&format=json", url.QueryEscape(rawURL))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://checkurl.phishtank.com/checkurl/", strings.NewReader(form))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "phishtank/Monitorized")

	res, err := t.client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	var out struct {
		Results struct {
			InDatabase bool   `json:"in_database"`
			Verified   bool   `json:"verified"`
			PhishID    string `json:"phish_id"`
		} `json:"results"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.Results.InDatabase && out.Results.Verified, nil
}

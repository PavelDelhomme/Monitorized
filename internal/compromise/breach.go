package compromise

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Sources gratuites pour fuites d'emails (aucune clé payante).

type BreachChecker struct {
	client *http.Client
	last   time.Time
}

func NewBreachChecker() *BreachChecker {
	return &BreachChecker{
		client: &http.Client{Timeout: 20 * time.Second},
	}
}

func (b *BreachChecker) throttle() {
	wait := 2*time.Second - time.Since(b.last)
	if wait > 0 {
		time.Sleep(wait)
	}
	b.last = time.Now()
}

type BreachHit struct {
	Provider string
	Name     string
	Date     string
	Extra    map[string]interface{}
}

// XposedOrNot — API gratuite, sans clé.
func (b *BreachChecker) CheckEmailXposedOrNot(ctx context.Context, email string) ([]BreachHit, error) {
	b.throttle()
	u := fmt.Sprintf("https://api.xposedornot.com/v1/check-email/%s", url.PathEscape(email))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Monitorized/0.3")

	res, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xposedornot: %d", res.StatusCode)
	}

	var raw struct {
		ExposedBreaches json.RawMessage `json:"ExposedBreaches"`
		BreachesSummary []struct {
			Breach         string `json:"breach"`
			BreachedDate   string `json:"breached_date"`
			ExposedRecords int    `json:"exposed_records"`
		} `json:"breaches_summary"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		// format alternatif : liste de noms de fuites
		var names []string
		if err2 := json.Unmarshal(body, &names); err2 == nil && len(names) > 0 {
			var hits []BreachHit
			for _, n := range names {
				hits = append(hits, BreachHit{Provider: "xposedornot", Name: n})
			}
			return hits, nil
		}
		return nil, err
	}
	var hits []BreachHit
	for _, s := range raw.BreachesSummary {
		hits = append(hits, BreachHit{
			Provider: "xposedornot",
			Name:     s.Breach,
			Date:     s.BreachedDate,
			Extra:    map[string]interface{}{"records": s.ExposedRecords},
		})
	}
	if len(hits) == 0 && len(raw.ExposedBreaches) > 0 && string(raw.ExposedBreaches) != "null" {
		var names []string
		if json.Unmarshal(raw.ExposedBreaches, &names) == nil {
			for _, n := range names {
				hits = append(hits, BreachHit{Provider: "xposedornot", Name: n})
			}
		}
	}
	return hits, nil
}

// EmailRep — tier gratuit sans clé (rate limit côté serveur).
func (b *BreachChecker) CheckEmailRep(ctx context.Context, email string) ([]BreachHit, error) {
	b.throttle()
	u := fmt.Sprintf("https://emailrep.io/%s", url.PathEscape(email))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Monitorized/0.3")

	res, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("emailrep: %d", res.StatusCode)
	}
	var raw struct {
		Email    string   `json:"email"`
		Breaches []string `json:"breaches"`
		Suspect  bool     `json:"suspicious"`
	}
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return nil, err
	}
	var hits []BreachHit
	for _, br := range raw.Breaches {
		if br == "" {
			continue
		}
		hits = append(hits, BreachHit{
			Provider: "emailrep",
			Name:     br,
			Extra:    map[string]interface{}{"suspicious": raw.Suspect},
		})
	}
	return hits, nil
}

func (b *BreachChecker) CheckEmail(ctx context.Context, email string) ([]BreachHit, error) {
	seen := make(map[string]bool)
	var all []BreachHit
	merge := func(hits []BreachHit, err error) {
		if err != nil {
			return
		}
		for _, h := range hits {
			key := h.Name
			if seen[key] {
				continue
			}
			seen[key] = true
			all = append(all, h)
		}
	}
	h1, err1 := b.CheckEmailXposedOrNot(ctx, email)
	merge(h1, err1)
	h2, err2 := b.CheckEmailRep(ctx, email)
	merge(h2, err2)
	if len(all) == 0 && err1 != nil && err2 != nil {
		return nil, err1
	}
	return all, nil
}

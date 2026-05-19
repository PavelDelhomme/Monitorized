package storage

import (
	"context"
	"encoding/json"
	"time"
)

func (s *Store) migrateCompromise() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS compromise_targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'manual',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  UNIQUE(kind, value)
);
CREATE INDEX IF NOT EXISTS idx_compromise_targets_enabled ON compromise_targets(enabled);

CREATE TABLE IF NOT EXISTS compromise_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  target_kind TEXT NOT NULL,
  target_value TEXT NOT NULL,
  provider TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  details TEXT,
  fingerprint TEXT NOT NULL,
  UNIQUE(fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_compromise_findings_ts ON compromise_findings(ts);
CREATE INDEX IF NOT EXISTS idx_compromise_findings_target ON compromise_findings(target_value);
`)
	return err
}

type CompromiseTarget struct {
	ID      int64  `json:"id"`
	Kind    string `json:"kind"`
	Value   string `json:"value"`
	Source  string `json:"source"`
	Enabled bool   `json:"enabled"`
}

type CompromiseFinding struct {
	ID          int64  `json:"id"`
	TS          int64  `json:"ts"`
	TargetKind  string `json:"target_kind"`
	TargetValue string `json:"target_value"`
	Provider    string `json:"provider"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Details     string `json:"details"`
}

func (s *Store) UpsertCompromiseTarget(ctx context.Context, kind, value, source string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO compromise_targets (kind, value, source, enabled, created_at)
VALUES (?, ?, ?, 1, ?)
ON CONFLICT(kind, value) DO UPDATE SET enabled=1, source=excluded.source`,
		kind, value, source, time.Now().Unix())
	return err
}

func (s *Store) ListCompromiseTargets(ctx context.Context) ([]CompromiseTarget, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, kind, value, source, enabled FROM compromise_targets WHERE enabled=1 ORDER BY kind, value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CompromiseTarget
	for rows.Next() {
		var t CompromiseTarget
		var en int
		if err := rows.Scan(&t.ID, &t.Kind, &t.Value, &t.Source, &en); err != nil {
			return nil, err
		}
		t.Enabled = en == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) InsertCompromiseFinding(ctx context.Context, f CompromiseFinding) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT OR IGNORE INTO compromise_findings
  (ts, target_kind, target_value, provider, severity, title, details, fingerprint)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		f.TS, f.TargetKind, f.TargetValue, f.Provider, f.Severity, f.Title, f.Details,
		fingerprint(f))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func fingerprint(f CompromiseFinding) string {
	return f.Provider + "|" + f.TargetKind + "|" + f.TargetValue + "|" + f.Title
}

func (s *Store) RecentCompromiseFindings(ctx context.Context, limit int) ([]CompromiseFinding, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, ts, target_kind, target_value, provider, severity, title, details
FROM compromise_findings ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CompromiseFinding
	for rows.Next() {
		var f CompromiseFinding
		if err := rows.Scan(&f.ID, &f.TS, &f.TargetKind, &f.TargetValue, &f.Provider, &f.Severity, &f.Title, &f.Details); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) CompromiseSummary(ctx context.Context) (map[string]interface{}, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT
  COUNT(*),
  COALESCE(SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN severity='warning' THEN 1 ELSE 0 END), 0)
FROM compromise_findings WHERE ts >= ?`,
		time.Now().Add(-7*24*time.Hour).Unix())
	var total, critical, warning int64
	if err := row.Scan(&total, &critical, &warning); err != nil {
		return nil, err
	}
	targets, _ := s.ListCompromiseTargets(ctx)
	byKind, _ := s.CompromiseTargetCounts(ctx)
	return map[string]interface{}{
		"findings_7d": total, "critical_7d": critical, "warning_7d": warning,
		"targets_watched": len(targets), "targets_by_kind": byKind,
	}, nil
}

func (s *Store) UniqueNPMHosts(ctx context.Context, since int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT DISTINCT host FROM npm_requests WHERE ts >= ? AND host != '' AND host NOT LIKE '%:%'`,
		since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) HasRecentFinding(ctx context.Context, fp string, within time.Duration) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*) FROM compromise_findings WHERE fingerprint=? AND ts >= ?`,
		fp, time.Now().Add(-within).Unix()).Scan(&n)
	return n > 0, err
}

func (s *Store) DeleteCompromiseTarget(ctx context.Context, kind, value string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE compromise_targets SET enabled=0 WHERE kind=? AND value=?`, kind, value)
	return err
}

func (s *Store) DeleteCompromiseTargetByID(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE compromise_targets SET enabled=0 WHERE id=?`, id)
	return err
}

func (s *Store) BulkUpsertCompromiseTargets(ctx context.Context, items []struct{ Kind, Value string }) (int, error) {
	added := 0
	for _, it := range items {
		if err := s.UpsertCompromiseTarget(ctx, it.Kind, it.Value, "import"); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

func (s *Store) CompromiseTargetCounts(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT kind, COUNT(*) FROM compromise_targets WHERE enabled=1 GROUP BY kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{"email": 0, "domain": 0, "ip": 0}
	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return nil, err
		}
		out[kind] = n
	}
	return out, rows.Err()
}

func (s *Store) InsertCompromiseFindingAlert(ctx context.Context, f CompromiseFinding, meta map[string]string) error {
	if meta == nil {
		meta = map[string]string{}
	}
	meta["provider"] = f.Provider
	meta["target"] = f.TargetValue
	b, _ := json.Marshal(meta)
	return s.insertAlertRaw(ctx, "critical", "compromise", f.Title, string(b))
}

func (s *Store) insertAlertRaw(ctx context.Context, level, source, message, metaJSON string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO alerts (ts, level, source, message, meta) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), level, source, message, metaJSON)
	return err
}

func (s *Store) PurgeCompromiseFindings(ctx context.Context, days int) error {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	_, err := s.db.ExecContext(ctx, `DELETE FROM compromise_findings WHERE ts < ?`, cutoff)
	return err
}

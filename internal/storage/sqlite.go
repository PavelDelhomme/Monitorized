package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "monitorized.db")
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.migrateCompromise(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS host_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  cpu_percent REAL,
  mem_used_bytes INTEGER,
  mem_total_bytes INTEGER,
  disk_used_bytes INTEGER,
  disk_total_bytes INTEGER,
  load1 REAL, load5 REAL, load15 REAL,
  net_rx_bytes INTEGER, net_tx_bytes INTEGER
);
CREATE INDEX IF NOT EXISTS idx_host_ts ON host_metrics(ts);

CREATE TABLE IF NOT EXISTS container_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  container_id TEXT NOT NULL,
  name TEXT,
  image TEXT,
  state TEXT,
  cpu_percent REAL,
  mem_usage_bytes INTEGER,
  mem_limit_bytes INTEGER
);
CREATE INDEX IF NOT EXISTS idx_container_ts ON container_snapshots(ts);
CREATE INDEX IF NOT EXISTS idx_container_id ON container_snapshots(container_id, ts);

CREATE TABLE IF NOT EXISTS npm_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  host TEXT,
  method TEXT,
  path TEXT,
  status INTEGER,
  bytes_sent INTEGER,
  remote_addr TEXT,
  user_agent TEXT,
  request_time REAL
);
CREATE INDEX IF NOT EXISTS idx_npm_ts ON npm_requests(ts);
CREATE INDEX IF NOT EXISTS idx_npm_status ON npm_requests(status);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  level TEXT NOT NULL,
  source TEXT,
  message TEXT NOT NULL,
  meta TEXT,
  acknowledged INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS blocked_ips (
  ip TEXT PRIMARY KEY,
  reason TEXT,
  created_at INTEGER NOT NULL
);
`
	_, err := s.db.Exec(schema)
	return err
}

type HostMetric struct {
	TS            int64   `json:"ts"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemUsed       uint64  `json:"mem_used_bytes"`
	MemTotal      uint64  `json:"mem_total_bytes"`
	DiskUsed      uint64  `json:"disk_used_bytes"`
	DiskTotal     uint64  `json:"disk_total_bytes"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
	NetRx         uint64  `json:"net_rx_bytes"`
	NetTx         uint64  `json:"net_tx_bytes"`
}

func (s *Store) InsertHost(ctx context.Context, m HostMetric) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO host_metrics (ts, cpu_percent, mem_used_bytes, mem_total_bytes,
  disk_used_bytes, disk_total_bytes, load1, load5, load15, net_rx_bytes, net_tx_bytes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.TS, m.CPUPercent, m.MemUsed, m.MemTotal, m.DiskUsed, m.DiskTotal,
		m.Load1, m.Load5, m.Load15, m.NetRx, m.NetTx)
	return err
}

type ContainerSnapshot struct {
	TS         int64   `json:"ts"`
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Image      string  `json:"image"`
	State      string  `json:"state"`
	CPUPercent float64 `json:"cpu_percent"`
	MemUsage   uint64  `json:"mem_usage_bytes"`
	MemLimit   uint64  `json:"mem_limit_bytes"`
}

func (s *Store) InsertContainer(ctx context.Context, c ContainerSnapshot) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO container_snapshots (ts, container_id, name, image, state, cpu_percent, mem_usage_bytes, mem_limit_bytes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.TS, c.ID, c.Name, c.Image, c.State, c.CPUPercent, c.MemUsage, c.MemLimit)
	return err
}

type NPMRequest struct {
	TS          int64   `json:"ts"`
	Host        string  `json:"host"`
	Method      string  `json:"method"`
	Path        string  `json:"path"`
	Status      int     `json:"status"`
	BytesSent   int64   `json:"bytes_sent"`
	RemoteAddr  string  `json:"remote_addr"`
	UserAgent   string  `json:"user_agent"`
	RequestTime float64 `json:"request_time"`
}

func (s *Store) InsertNPM(ctx context.Context, r NPMRequest) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO npm_requests (ts, host, method, path, status, bytes_sent, remote_addr, user_agent, request_time)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.TS, r.Host, r.Method, r.Path, r.Status, r.BytesSent, r.RemoteAddr, r.UserAgent, r.RequestTime)
	return err
}

func (s *Store) InsertAlert(ctx context.Context, level, source, message string, meta map[string]string) error {
	var metaJSON string
	if meta != nil {
		b, _ := json.Marshal(meta)
		metaJSON = string(b)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO alerts (ts, level, source, message, meta) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), level, source, message, metaJSON)
	return err
}

func (s *Store) IsBlocked(ip string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM blocked_ips WHERE ip = ?`, ip).Scan(&n)
	return n > 0, err
}

func (s *Store) BlockIP(ip, reason string) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO blocked_ips (ip, reason, created_at) VALUES (?, ?, ?)`,
		ip, reason, time.Now().Unix())
	return err
}

func (s *Store) UnblockIP(ip string) error {
	_, err := s.db.Exec(`DELETE FROM blocked_ips WHERE ip = ?`, ip)
	return err
}

func (s *Store) LatestHost(ctx context.Context) (*HostMetric, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT ts, cpu_percent, mem_used_bytes, mem_total_bytes, disk_used_bytes, disk_total_bytes,
  load1, load5, load15, net_rx_bytes, net_tx_bytes
FROM host_metrics ORDER BY ts DESC LIMIT 1`)
	var m HostMetric
	err := row.Scan(&m.TS, &m.CPUPercent, &m.MemUsed, &m.MemTotal, &m.DiskUsed, &m.DiskTotal,
		&m.Load1, &m.Load5, &m.Load15, &m.NetRx, &m.NetTx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) HostHistory(ctx context.Context, since int64, limit int) ([]HostMetric, error) {
	if limit <= 0 || limit > 500 {
		limit = 120
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT ts, cpu_percent, mem_used_bytes, mem_total_bytes, disk_used_bytes, disk_total_bytes,
  load1, load5, load15, net_rx_bytes, net_tx_bytes
FROM host_metrics WHERE ts >= ? ORDER BY ts ASC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostMetric
	for rows.Next() {
		var m HostMetric
		if err := rows.Scan(&m.TS, &m.CPUPercent, &m.MemUsed, &m.MemTotal, &m.DiskUsed, &m.DiskTotal,
			&m.Load1, &m.Load5, &m.Load15, &m.NetRx, &m.NetTx); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) LatestContainers(ctx context.Context) ([]ContainerSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT c.ts, c.container_id, c.name, c.image, c.state, c.cpu_percent, c.mem_usage_bytes, c.mem_limit_bytes
FROM container_snapshots c
INNER JOIN (
  SELECT container_id, MAX(ts) AS max_ts FROM container_snapshots GROUP BY container_id
) latest ON c.container_id = latest.container_id AND c.ts = latest.max_ts
ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ContainerSnapshot
	for rows.Next() {
		var c ContainerSnapshot
		if err := rows.Scan(&c.TS, &c.ID, &c.Name, &c.Image, &c.State, &c.CPUPercent, &c.MemUsage, &c.MemLimit); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) NPMStats(ctx context.Context, since int64) (map[string]interface{}, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT COUNT(*),
  COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0),
  COALESCE(SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END), 0),
  COALESCE(AVG(request_time), 0)
FROM npm_requests WHERE ts >= ?`, since)
	var total, e5, e4 int64
	var avgRT float64
	if err := row.Scan(&total, &e5, &e4, &avgRT); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"total": total, "errors_5xx": e5, "errors_4xx": e4, "avg_request_time": avgRT,
	}, nil
}

func (s *Store) RecentAlerts(ctx context.Context, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, ts, level, source, message, meta, acknowledged FROM alerts ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, ts, ack int64
		var level, source, message, meta string
		if err := rows.Scan(&id, &ts, &level, &source, &message, &meta, &ack); err != nil {
			return nil, err
		}
		out = append(out, map[string]interface{}{
			"id": id, "ts": ts, "level": level, "source": source,
			"message": message, "meta": meta, "acknowledged": ack == 1,
		})
	}
	return out, rows.Err()
}

func (s *Store) PurgeOlderThan(ctx context.Context, days int) error {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	for _, q := range []string{
		`DELETE FROM host_metrics WHERE ts < ?`,
		`DELETE FROM container_snapshots WHERE ts < ?`,
		`DELETE FROM npm_requests WHERE ts < ?`,
	} {
		if _, err := s.db.ExecContext(ctx, q, cutoff); err != nil {
			return fmt.Errorf("purge: %w", err)
		}
	}
	if err := s.PurgeCompromiseFindings(ctx, days); err != nil {
		return err
	}
	return nil
}

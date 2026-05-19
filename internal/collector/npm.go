package collector

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pactivisme/monitorized/internal/storage"
)

// Format NPM / nginx access log (custom log_format si besoin d'ajuster).
// Exemple: host - remote - [time] "METHOD path HTTP/1.1" status bytes "referer" "ua" rt=0.123
var npmLine = regexp.MustCompile(`^(\S+)\s+-\s+(\S+)\s+.*?"([A-Z]+)\s+(\S+)\s+HTTP[^"]*"\s+(\d{3})\s+(\d+).*"([^"]*)"\s+.*?(?:rt=([\d.]+))?`)

type NPM struct {
	glob   string
	store  *storage.Store
	offset map[string]int64
	mu     sync.Mutex
}

func NewNPM(glob string, store *storage.Store) *NPM {
	return &NPM{glob: glob, store: store, offset: make(map[string]int64)}
}

func (n *NPM) Collect(ctx context.Context) error {
	matches, err := filepath.Glob(n.glob)
	if err != nil {
		return err
	}
	for _, path := range matches {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := n.tailFile(ctx, path); err != nil && ctx.Err() == nil {
			// fichier absent ou vide : ignorer
			continue
		}
	}
	return nil
}

func (n *NPM) tailFile(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	n.mu.Lock()
	off := n.offset[path]
	n.mu.Unlock()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() < off {
		off = 0
	}
	if _, err := f.Seek(off, 0); err != nil {
		return err
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		req := parseNPMLine(line)
		if req == nil {
			continue
		}
		if err := n.store.InsertNPM(ctx, *req); err != nil {
			return err
		}
	}
	pos, _ := f.Seek(0, 1)
	n.mu.Lock()
	n.offset[path] = pos
	n.mu.Unlock()
	return sc.Err()
}

func parseNPMLine(line string) *storage.NPMRequest {
	m := npmLine.FindStringSubmatch(line)
	if m == nil {
		// fallback minimal nginx combined
		return parseCombined(line)
	}
	status, _ := strconv.Atoi(m[5])
	bytes, _ := strconv.ParseInt(m[6], 10, 64)
	rt := 0.0
	if len(m) > 8 && m[8] != "" {
		rt, _ = strconv.ParseFloat(m[8], 64)
	}
	return &storage.NPMRequest{
		TS:          time.Now().Unix(),
		Host:        m[1],
		RemoteAddr:  m[2],
		Method:      m[3],
		Path:        m[4],
		Status:      status,
		BytesSent:   bytes,
		UserAgent:   m[7],
		RequestTime: rt,
	}
}

// combined log format basique
func parseCombined(line string) *storage.NPMRequest {
	if !strings.Contains(line, `"`) {
		return nil
	}
	parts := strings.SplitN(line, `"`, 3)
	if len(parts) < 3 {
		return nil
	}
	req := strings.Fields(parts[1])
	if len(req) < 2 {
		return nil
	}
	after := strings.Fields(parts[2])
	if len(after) < 2 {
		return nil
	}
	status, _ := strconv.Atoi(after[0])
	bytes, _ := strconv.ParseInt(after[1], 10, 64)
	return &storage.NPMRequest{
		TS: time.Now().Unix(), Method: req[0], Path: req[1],
		Status: status, BytesSent: bytes,
	}
}

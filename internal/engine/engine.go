package engine

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/pactivisme/monitorized/internal/collector"
	"github.com/pactivisme/monitorized/internal/compromise"
	"github.com/pactivisme/monitorized/internal/config"
	"github.com/pactivisme/monitorized/internal/storage"
)

type Engine struct {
	cfg      config.Config
	store    *storage.Store
	host     *collector.Host
	docker   *collector.Docker
	npm      *collector.NPM
	compScan *compromise.Scanner
}

func New(cfg config.Config, store *storage.Store, docker *collector.Docker) *Engine {
	return &Engine{
		cfg:      cfg,
		store:    store,
		host:     collector.NewHost(store),
		docker:   docker,
		npm:      collector.NewNPM(cfg.NPMLogGlob, store),
		compScan: compromise.NewScanner(cfg, store),
	}
}

func (e *Engine) Run(ctx context.Context) {
	hostTick := time.NewTicker(e.cfg.HostInterval)
	dockerTick := time.NewTicker(e.cfg.DockerInterval)
	npmTick := time.NewTicker(e.cfg.NPMInterval)
	purgeTick := time.NewTicker(6 * time.Hour)
	var compromiseTick *time.Ticker
	if e.cfg.CompromiseEnabled {
		compromiseTick = time.NewTicker(e.cfg.CompromiseInterval)
		defer compromiseTick.Stop()
	}
	defer hostTick.Stop()
	defer dockerTick.Stop()
	defer npmTick.Stop()
	defer purgeTick.Stop()

	e.collectHost(ctx)
	if e.docker != nil {
		e.collectDocker(ctx)
	}
	e.collectNPM(ctx)
	e.runCompromise(ctx)

	var compCh <-chan time.Time
	if compromiseTick != nil {
		compCh = compromiseTick.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-hostTick.C:
			e.collectHost(ctx)
		case <-dockerTick.C:
			if e.docker != nil {
				e.collectDocker(ctx)
			}
		case <-npmTick.C:
			e.collectNPM(ctx)
		case <-compCh:
			e.runCompromise(ctx)
		case <-purgeTick.C:
			if err := e.store.PurgeOlderThan(ctx, e.cfg.RetentionDays); err != nil {
				slog.Warn("purge", "err", err)
			}
		}
	}
}

func (e *Engine) runCompromise(ctx context.Context) {
	if !e.cfg.CompromiseEnabled || e.compScan == nil {
		return
	}
	go func() {
		if err := e.compScan.Run(ctx); err != nil {
			slog.Warn("compromise scan", "err", err)
		}
	}()
}

func (e *Engine) collectHost(ctx context.Context) {
	if err := e.host.Collect(ctx); err != nil {
		slog.Warn("host collect", "err", err)
		return
	}
	m, _ := e.store.LatestHost(ctx)
	if m != nil && m.CPUPercent > 90 {
		_ = e.store.InsertAlert(ctx, "warning", "host", "CPU élevée", map[string]string{
			"cpu": formatFloat(m.CPUPercent),
		})
	}
}

func (e *Engine) collectDocker(ctx context.Context) {
	if err := e.docker.Collect(ctx); err != nil {
		slog.Warn("docker collect", "err", err)
	}
}

func (e *Engine) collectNPM(ctx context.Context) {
	if err := e.npm.Collect(ctx); err != nil {
		slog.Debug("npm collect", "err", err)
	}
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

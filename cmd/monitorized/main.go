package main

import (
	"context"
	"embed"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pactivisme/monitorized/internal/api"
	"github.com/pactivisme/monitorized/internal/auth"
	"github.com/pactivisme/monitorized/internal/collector"
	"github.com/pactivisme/monitorized/internal/config"
	"github.com/pactivisme/monitorized/internal/engine"
	"github.com/pactivisme/monitorized/internal/storage"
)

//go:embed static/*
var webFS embed.FS

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg := config.Load()
	if err := cfg.Valid(); err != nil {
		slog.Error("configuration", "err", err)
		os.Exit(1)
	}

	store, err := storage.Open(cfg.DataDir)
	if err != nil {
		slog.Error("storage", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	dockerCol, err := collector.NewDocker(cfg.DockerHost, store)
	if err != nil {
		slog.Warn("docker indisponible, collecte conteneurs désactivée", "err", err)
		dockerCol = nil
	} else {
		defer dockerCol.Close()
	}

	authSvc, err := auth.New(cfg.JWTSecret, cfg.AdminUser, cfg.AdminPassword)
	if err != nil {
		slog.Error("auth", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng := engine.New(cfg, store, dockerCol)
	go eng.Run(ctx)

	srv := api.New(cfg, store, authSvc, webFS)
	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("monitorized démarré", "addr", cfg.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http", "err", err)
			cancel()
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	slog.Info("arrêt propre")
}

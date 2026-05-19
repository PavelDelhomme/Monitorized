package api

import (
	"embed"
	"io/fs"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/pactivisme/monitorized/internal/auth"
	"github.com/pactivisme/monitorized/internal/config"
	"github.com/pactivisme/monitorized/internal/storage"
	"github.com/pactivisme/monitorized/internal/waf"
	"golang.org/x/time/rate"
)

type Server struct {
	cfg   config.Config
	store *storage.Store
	auth  *auth.Service
	waf   *waf.Guard
	web   embed.FS
}

func New(cfg config.Config, store *storage.Store, authSvc *auth.Service, web embed.FS) *Server {
	return &Server{cfg: cfg, store: store, auth: authSvc, waf: waf.New(store), web: web}
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(s.waf.Middleware)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   s.cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	limiter := rate.NewLimiter(rate.Limit(20), 40)
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if !limiter.Allow() {
				http.Error(w, `{"error":"trop de requêtes"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, req)
		})
	})

	r.Get("/health", s.health)

	r.Route("/api/v1", func(api chi.Router) {
		api.Post("/auth/login", s.login)
		api.Group(func(pr chi.Router) {
			pr.Use(s.auth.Middleware)
			pr.Get("/overview", s.overview)
			pr.Get("/host/history", s.hostHistory)
			pr.Get("/containers", s.containers)
			pr.Get("/npm/stats", s.npmStats)
			pr.Get("/alerts", s.alerts)
			pr.Post("/security/block", s.blockIP)
			pr.Delete("/security/block/{ip}", s.unblockIP)
			pr.Get("/compromise/providers", s.compromiseProviders)
			pr.Get("/compromise/summary", s.compromiseSummary)
			pr.Get("/compromise/findings", s.compromiseFindings)
			pr.Get("/compromise/targets", s.compromiseTargets)
			pr.Post("/compromise/targets", s.compromiseAddTarget)
			pr.Post("/compromise/targets/bulk", s.compromiseBulkTargets)
			pr.Delete("/compromise/targets/{id}", s.compromiseDeleteTarget)
			pr.Post("/compromise/scan", s.compromiseScanNow)
		})
	})

	static, err := fs.Sub(s.web, "static")
	if err == nil {
		fileServer := http.FileServer(http.FS(static))
		r.Get("/", func(w http.ResponseWriter, req *http.Request) {
			req.URL.Path = "/index.html"
			fileServer.ServeHTTP(w, req)
		})
		r.Handle("/app.js", fileServer)
		r.Handle("/style.css", fileServer)
	}

	return r
}

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/pactivisme/monitorized/internal/compromise"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "corps invalide"})
		return
	}
	token, exp, err := s.auth.Login(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token": token, "expires_at": exp.Unix(),
	})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host, _ := s.store.LatestHost(ctx)
	containers, _ := s.store.LatestContainers(ctx)
	since := time.Now().Add(-1 * time.Hour).Unix()
	npm, _ := s.store.NPMStats(ctx, since)
	alerts, _ := s.store.RecentAlerts(ctx, 10)
	compromise, _ := s.store.CompromiseSummary(ctx)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host": host, "containers": containers, "npm_last_hour": npm, "alerts": alerts,
		"compromise": compromise,
	})
}

func (s *Server) hostHistory(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-2 * time.Hour).Unix()
	if v := r.URL.Query().Get("since"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			since = n
		}
	}
	limit := 120
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	h, err := s.store.HostHistory(r.Context(), since, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) containers(w http.ResponseWriter, r *http.Request) {
	c, err := s.store.LatestContainers(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) npmStats(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour).Unix()
	stats, err := s.store.NPMStats(r.Context(), since)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	a, err := s.store.RecentAlerts(r.Context(), 50)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

type blockReq struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

func (s *Server) blockIP(w http.ResponseWriter, r *http.Request) {
	var req blockReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip requise"})
		return
	}
	if err := s.store.BlockIP(req.IP, req.Reason); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_ = s.store.InsertAlert(r.Context(), "info", "security", "IP bloquée", map[string]string{"ip": req.IP})
	writeJSON(w, http.StatusOK, map[string]string{"status": "blocked"})
}

func (s *Server) unblockIP(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if err := s.store.UnblockIP(ip); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unblocked"})
}

func (s *Server) compromiseFindings(w http.ResponseWriter, r *http.Request) {
	f, err := s.store.RecentCompromiseFindings(r.Context(), 80)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, f)
}

func (s *Server) compromiseTargets(w http.ResponseWriter, r *http.Request) {
	t, err := s.store.ListCompromiseTargets(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) compromiseSummary(w http.ResponseWriter, r *http.Request) {
	sum, err := s.store.CompromiseSummary(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

type watchTargetReq struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (s *Server) compromiseProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, compromise.FreeProviders)
}

func (s *Server) compromiseAddTarget(w http.ResponseWriter, r *http.Request) {
	var req watchTargetReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "kind et value requis"})
		return
	}
	line := strings.TrimSpace(req.Value)
	if req.Kind != "" {
		line = req.Kind + ":" + line
	}
	kind, value, ok := compromise.ParseTarget(line)
	if !ok {
		kind, value, ok = compromise.ParseTarget(strings.TrimSpace(req.Value))
	}
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "format invalide (email, domaine ou ip)"})
		return
	}
	if err := s.store.UpsertCompromiseTarget(r.Context(), kind, value, "manual"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "added", "kind": kind, "value": value})
}

type bulkTargetsReq struct {
	Text string `json:"text"`
}

func (s *Server) compromiseBulkTargets(w http.ResponseWriter, r *http.Request) {
	var req bulkTargetsReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "text requis (une cible par ligne)"})
		return
	}
	parsed := compromise.ParseBulk(req.Text)
	if len(parsed) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "aucune ligne valide"})
		return
	}
	items := make([]struct{ Kind, Value string }, len(parsed))
	for i, p := range parsed {
		items[i] = struct{ Kind, Value string }{p.Kind, p.Value}
	}
	n, err := s.store.BulkUpsertCompromiseTargets(r.Context(), items)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"imported": n, "total_lines": len(parsed)})
}

func (s *Server) compromiseDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id invalide"})
		return
	}
	if err := s.store.DeleteCompromiseTargetByID(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) compromiseScanNow(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.CompromiseEnabled {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "compromission désactivée"})
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		sc := compromise.NewScanner(s.cfg, s.store)
		_ = sc.Run(ctx)
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "scan démarré"})
}

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"domainsentinel/internal/config"
	"domainsentinel/internal/db"
	"domainsentinel/internal/models"
	"domainsentinel/web"
)

// Server is the HTTP server.
type Server struct {
	cfg    *config.Config
	db     *db.DB
	app    interface{ TriggerRefresh(context.Context) }
	router *chi.Mux
	tmpl   *template.Template
	static http.FileSystem
}

// NewServer creates a new API + web server.
func NewServer(cfg *config.Config, database *db.DB, app interface{ TriggerRefresh(context.Context) }) *Server {
	s := &Server{cfg: cfg, db: database, app: app}
	s.loadTemplates()
	s.serveStatic()
	s.setupRouter()
	return s
}

func (s *Server) loadTemplates() {
	funcMap := template.FuncMap{
		"formatAge":    formatAge,
		"statusLabel":  statusLabel,
		"statusClass":  statusClass,
		"cleanTitle":   cleanTitle,
		"httpClass":    httpClass,
		"latencyClass": latencyClass,
		"hostClass":    hostClass,
		"join":         joinFunc,
		"orDash":       orDash,
		"lower":        strings.ToLower,
		"upper":        strings.ToUpper,
	}

	tmpl := template.New("").Funcs(funcMap)

	// First try local disk directories (useful during development)
	possibleDirs := []string{
		"web/templates",
		"/app/web/templates",
		filepath.Join(os.Getenv("PWD"), "web/templates"),
	}

	diskLoaded := false
	for _, dir := range possibleDirs {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			entries, _ := os.ReadDir(dir)
			var files []string
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".html") {
					files = append(files, filepath.Join(dir, e.Name()))
				}
			}
			if len(files) > 0 {
				for _, f := range files {
					name := filepath.Base(f)
					data, err := os.ReadFile(f)
					if err != nil {
						continue
					}
					if _, err := tmpl.New(name).Parse(string(data)); err != nil {
						slog.Warn("template parse error from disk", "file", f, "error", err)
					}
				}
				if len(tmpl.Templates()) > 0 {
					diskLoaded = true
					slog.Info("templates loaded from disk", "dir", dir, "count", len(tmpl.Templates()))
					break
				}
			}
		}
	}

	// Fallback to embedded templates if not loaded from disk
	if !diskLoaded {
		if entries, err := fs.ReadDir(web.FS, "templates"); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".html") {
					data, err := web.FS.ReadFile("templates/" + e.Name())
					if err != nil {
						continue
					}
					if _, err := tmpl.New(e.Name()).Parse(string(data)); err != nil {
						slog.Warn("embedded template parse error", "file", e.Name(), "error", err)
					}
				}
			}
			slog.Info("templates loaded from embedded FS", "count", len(tmpl.Templates()))
		}
	}

	s.tmpl = tmpl
}

func (s *Server) serveStatic() {
	possibleDirs := []string{
		"web/static",
		"/app/web/static",
		filepath.Join(os.Getenv("PWD"), "web/static"),
	}
	for _, dir := range possibleDirs {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			s.static = http.Dir(dir)
			return
		}
	}
	// Fallback to embedded static files
	if sub, err := fs.Sub(web.FS, "static"); err == nil {
		s.static = http.FS(sub)
		return
	}
	s.static = http.Dir("/dev/null")
}

func (s *Server) setupRouter() {
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(middleware.Compress(5))

	// Security headers
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			next.ServeHTTP(w, r)
		})
	})

	// Static files
	r.Handle("/static/*", http.StripPrefix("/static/",
		http.FileServer(s.static)))

	// Pages
	r.Get("/", s.handleIndex)
	r.Get("/domain/{fqdn}", s.handleDomainDetail)

	// API v1
	r.Post("/api/v1/refresh", s.handleRefresh)
	r.Get("/api/v1/domains", s.handleAPIDomains)
	r.Get("/api/v1/domains/{fqdn}", s.handleAPIDomain)
	r.Get("/api/v1/anomalies", s.handleAPIAnomalies)
	r.Get("/api/v1/status", s.handleAPIStatus)
	r.Get("/api/v1/summary", s.handleAPISummary)
	r.Patch("/api/v1/domains/{fqdn}/annotation", s.handleAnnotate)

	// Metrics
	r.Get("/metrics", s.handleMetrics)

	// Health
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	s.router = r
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// ── Handlers ────────────────────────────────────────────────────────────────

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	domains, err := s.db.GetAllDomains()
	if err != nil {
		slog.Error("failed to load domains", "error", err)
		http.Error(w, "Internal error", 500)
		return
	}

	lastScan, _ := s.db.GetLastScanTime()
	summary := buildSummary(domains, &lastScan)

	// Apply filters
	filter := r.URL.Query().Get("filter")
	search := r.URL.Query().Get("q")
	domains = filterDomains(domains, filter, search)

	// Get annotations
	annotations := make(map[string]*models.Annotation)
	for _, d := range domains {
		a, _ := s.db.GetAnnotation(d.FQDN)
		if a != nil {
			annotations[d.FQDN] = a
		}
	}

	data := &IndexData{
		Domains:     domains,
		Summary:     summary,
		Annotations: annotations,
		LastScan:    lastScan,
		Filter:      filter,
		Search:      search,
		Zone:        s.cfg.CloudflareZoneName,
	}

	if err := s.tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		// Fallback to raw HTML if template not loaded
		slog.Error("template execute error", "error", err)
		http.Error(w, "Template error", 500)
	}
}

func (s *Server) handleDomainDetail(w http.ResponseWriter, r *http.Request) {
	fqdn := chi.URLParam(r, "fqdn")
	fqdn = strings.TrimSuffix(fqdn, "/")
	fqdn = strings.TrimSpace(fqdn)

	entry, err := s.db.GetDomain(fqdn)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if entry == nil {
		http.NotFound(w, r)
		return
	}

	annotation, _ := s.db.GetAnnotation(fqdn)
	history, _ := s.getHistory(fqdn, 50)

	if err := s.tmpl.ExecuteTemplate(w, "detail.html", &DetailData{
		Entry:      entry,
		Annotation: annotation,
		History:    history,
	}); err != nil {
		slog.Error("template error", "error", err)
		http.Error(w, "Template error", 500)
	}
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	s.app.TriggerRefresh(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "refreshing"})
}

// ── API Handlers ─────────────────────────────────────────────────────────────

func (s *Server) handleAPIDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := s.db.GetAllDomains()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, domains)
}

func (s *Server) handleAPIDomain(w http.ResponseWriter, r *http.Request) {
	fqdn := chi.URLParam(r, "fqdn")
	entry, err := s.db.GetDomain(fqdn)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if entry == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, entry)
}

func (s *Server) handleAPIAnomalies(w http.ResponseWriter, r *http.Request) {
	domains, err := s.db.GetAllDomains()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var anomalies []map[string]interface{}
	for _, d := range domains {
		for _, a := range d.Anomalies {
			anomalies = append(anomalies, map[string]interface{}{
				"fqdn":     d.FQDN,
				"type":     a.Type,
				"severity": a.Severity,
				"message":  a.Message,
			})
		}
	}
	writeJSON(w, anomalies)
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	domains, err := s.db.GetAllDomains()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	lastScan, _ := s.db.GetLastScanTime()
	writeJSON(w, buildSummary(domains, &lastScan))
}

func (s *Server) handleAPISummary(w http.ResponseWriter, r *http.Request) {
	s.handleAPIStatus(w, r)
}

func (s *Server) handleAnnotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPatch {
		http.Error(w, "PATCH only", 405)
		return
	}
	fqdn := chi.URLParam(r, "fqdn")

	var patch models.AnnotationPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, "invalid JSON", 400)
		return
	}

	annotation := &models.Annotation{
		FQDN:        fqdn,
		Description: patch.Description,
		Criticality: patch.Criticality,
		Owner:       patch.Owner,
		Notes:       patch.Notes,
		Tags:        patch.Tags,
	}

	if err := s.db.UpsertAnnotation(annotation); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// ── Metrics ──────────────────────────────────────────────────────────────────

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	domains, _ := s.db.GetAllDomains()
	var total, up, down, anomalyCnt int
	for _, d := range domains {
		total++
		switch d.Status {
		case models.StatusOK:
			up++
		case models.StatusDown:
			down++
		case models.StatusAnomaly:
			anomalyCnt++
		}
	}
	lastScan, _ := s.db.GetLastScanTime()

	fmt.Fprintf(w, `# HELP domainsentinel_domains_total Total number of tracked domains
# TYPE domainsentinel_domains_total gauge
domainsentinel_domains_total %d
# HELP domainsentinel_domains_up Number of domains with OK status
# TYPE domainsentinel_domains_up gauge
domainsentinel_domains_up %d
# HELP domainsentinel_domains_down Number of domains with DOWN status
# TYPE domainsentinel_domains_down gauge
domainsentinel_domains_down %d
# HELP domainsentinel_anomalies_total Number of domains with anomalies
# TYPE domainsentinel_anomalies_total gauge
domainsentinel_anomalies_total %d
# HELP domainsentinel_last_scan_timestamp Unix timestamp of last scan
# TYPE domainsentinel_last_scan_timestamp gauge
domainsentinel_last_scan_timestamp %d
`, total, up, down, anomalyCnt, lastScan.Unix())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func (s *Server) getHistory(fqdn string, limit int) ([]models.HistoryEntry, error) {
	rows, err := s.db.Query(
		"SELECT id, fqdn, status, anomalies, checked_at FROM history WHERE fqdn = ? ORDER BY checked_at DESC LIMIT ?",
		fqdn, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []models.HistoryEntry
	for rows.Next() {
		var h models.HistoryEntry
		var anomalies string
		if err := rows.Scan(&h.ID, &h.FQDN, &h.Status, &anomalies, &h.CheckedAt); err != nil {
			continue
		}
		h.Anomalies = anomalies
		history = append(history, h)
	}
	return history, rows.Err()
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func buildSummary(domains []*models.DomainEntry, lastScan *time.Time) *models.DashboardSummary {
	s := &models.DashboardSummary{LastScan: lastScan}
	for _, d := range domains {
		s.Total++
		switch d.Status {
		case models.StatusOK:
			s.OK++
		case models.StatusDown:
			s.Down++
		case models.StatusAnomaly:
			s.Anomalies++
			for _, a := range d.Anomalies {
				s.AnomalyList = append(s.AnomalyList, models.AnomalyEntry{
					FQDN:     d.FQDN,
					Type:     a.Type,
					Severity: a.Severity,
				})
			}
		}
	}
	return s
}

func filterDomains(domains []*models.DomainEntry, filter, search string) []*models.DomainEntry {
	result := domains

	if search != "" {
		search = strings.ToLower(search)
		filtered := make([]*models.DomainEntry, 0, len(result))
		for _, d := range result {
			if strings.Contains(strings.ToLower(d.FQDN), search) ||
				strings.Contains(strings.ToLower(d.Docker.ContainerName), search) ||
				strings.Contains(strings.ToLower(d.Docker.Image), search) {
				filtered = append(filtered, d)
			}
		}
		result = filtered
	}

	if filter == "" || filter == "all" {
		return result
	}

	filtered := make([]*models.DomainEntry, 0, len(result))
	for _, d := range result {
		switch filter {
		case "ok":
			if d.Status == models.StatusOK {
				filtered = append(filtered, d)
			}
		case "down":
			if d.Status == models.StatusDown {
				filtered = append(filtered, d)
			}
		case "anomalies":
			if len(d.Anomalies) > 0 {
				filtered = append(filtered, d)
			}
		case "dns-orphan":
			for _, a := range d.Anomalies {
				if a.Type == models.AnomalyDNSOrphan {
					filtered = append(filtered, d)
					break
				}
			}
		case "dns-missing":
			for _, a := range d.Anomalies {
				if a.Type == models.AnomalyMissingDNS {
					filtered = append(filtered, d)
					break
				}
			}
		case "unprotected":
			if !d.Traefik.HasAuthentik && d.Traefik.Exists {
				filtered = append(filtered, d)
			}
		case "coolify":
			if d.Docker.Source == "coolify" {
				filtered = append(filtered, d)
			}
		case "docker-compose":
			if d.Docker.Source == "docker-compose" {
				filtered = append(filtered, d)
			}
		case "neoserver":
			if d.Host == "NEOSERVER" {
				filtered = append(filtered, d)
			}
		case "backend01":
			if d.Host == "BACKEND01" {
				filtered = append(filtered, d)
			}
		}
	}
	return filtered
}

// safeInt converts string to int safely.
func safeInt(s string, fallback int) int {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return fallback
}

// ── Template data ─────────────────────────────────────────────────────────────

type IndexData struct {
	Domains     []*models.DomainEntry
	Summary     *models.DashboardSummary
	Annotations map[string]*models.Annotation
	LastScan    time.Time
	Filter      string
	Search      string
	Zone        string
}

type DetailData struct {
	Entry      *models.DomainEntry
	Annotation *models.Annotation
	History    []models.HistoryEntry
}

// ── Template helper functions ───────────────────────────────────────────────

func formatAge(ts time.Time) string {
	if ts.IsZero() {
		return "jamais"
	}
	diff := time.Since(ts)
	switch {
	case diff < 2*time.Minute:
		return "à l'instant"
	case diff < 2*time.Hour:
		mins := int(diff.Minutes())
		return fmt.Sprintf("%dmin", mins)
	case diff < 48*time.Hour:
		hours := int(diff.Hours())
		return fmt.Sprintf("%dh", hours)
	default:
		days := int(diff.Hours() / 24)
		return fmt.Sprintf("%dj", days)
	}
}

func cleanTitle(d *models.DomainEntry) string {
	if d == nil {
		return ""
	}
	if d.Subdomain != "" && d.Subdomain != "@" {
		return d.Subdomain
	}
	return d.Domain
}

func statusLabel(s models.Status) string {
	switch s {
	case models.StatusOK, models.StatusAnomaly:
		return "En ligne"
	case models.StatusDown:
		return "Hors ligne"
	default:
		return "Inconnu"
	}
}

func statusClass(s models.Status) string {
	return strings.ToLower(string(s))
}

func httpClass(code int) string {
	switch {
	case code >= 200 && code < 300:
		return fmt.Sprintf("%d", code)
	case code == 301 || code == 302:
		return fmt.Sprintf("%d", code)
	case code == 401 || code == 403:
		return fmt.Sprintf("%d", code)
	case code >= 500:
		return fmt.Sprintf("%d", code)
	default:
		return "unknown"
	}
}

func httpClassStr(code string) string {
	return code
}

func latencyClass(ms int) string {
	switch {
	case ms < 200:
		return "fast"
	case ms < 1000:
		return "medium"
	default:
		return "slow"
	}
}

func hostClass(host string) string {
	switch host {
	case "NEOSERVER":
		return "NEOSERVER"
	case "BACKEND01":
		return "BACKEND01"
	default:
		return "unknown"
	}
}

func joinFunc(parts []string, sep string) string {
	return strings.Join(parts, sep)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

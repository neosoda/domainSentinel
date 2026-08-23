package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"domainsentinel/internal/api"
	"domainsentinel/internal/config"
	"domainsentinel/internal/correlator"
	"domainsentinel/internal/db"
	"domainsentinel/internal/healthcheck"
	"domainsentinel/internal/models"
	"domainsentinel/internal/scanner"
)

// App holds all application state.
type App struct {
	cfg        *config.Config
	db         *db.DB
	scanner    *scanner.Scanner
	correlator *correlator.Correlator
	hchecker   *healthcheck.Checker
	router     *http.ServeMux
	apiServer  *api.Server
	stopChan   chan struct{}
}

func main() {
	// ── Config ──────────────────────────────────────────────────────────────
	cfg := config.Load()

	// ── Logging ─────────────────────────────────────────────────────────────
	level := slog.LevelInfo
	if cfg.LogLevel == "DEBUG" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})))

	slog.Info("DomainSentinel starting",
		"zone", cfg.CloudflareZoneName,
		"docker", cfg.DockerHost,
		"traefik_dir", cfg.TraefikDynamicDir,
	)

	// ── Database ───────────────────────────────────────────────────────────
	database, err := db.Open(cfg.DataDir)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
	}
	defer database.Close()
	slog.Info("database ready", "path", cfg.DataDir)

	// ── Core components ────────────────────────────────────────────────────
	hc := healthcheck.NewChecker(cfg.HealthcheckTimeout(), cfg.HealthcheckConcurrency)
	app := &App{
		cfg:        cfg,
		db:         database,
		scanner:    scanner.NewScanner(cfg),
		correlator: correlator.NewCorrelator(cfg),
		hchecker:   hc,
		stopChan:   make(chan struct{}),
	}

	// ── API Server ──────────────────────────────────────────────────────────
	app.apiServer = api.NewServer(cfg, database, app)

	// ── Start background workers ────────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial full scan (blocking)
	app.runFullScan(ctx)

	// Periodic scanner
	go app.runScannerLoop(ctx)

	// Periodic healthchecks
	go app.runHealthcheckLoop(ctx)

	// Periodic history cleanup
	go app.runCleanupLoop(ctx)

	// ── HTTP Server ─────────────────────────────────────────────────────────
	server := &http.Server{
		Addr:        cfg.Host + ":" + cfg.Port,
		Handler:     app.apiServer,
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		slog.Info("shutdown signal received, stopping...")
		cancel()
		close(app.stopChan)

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown error", "error", err)
		}
	}()

	slog.Info("server listening", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
	slog.Info("DomainSentinel stopped")
}

// ── Full scan: sources → correlate → DB ─────────────────────────────────────

func (app *App) runFullScan(ctx context.Context) {
	scanStart := time.Now()
	slog.Info("full scan starting")

	// 1. Scan all sources
	result, err := app.scanner.Run(ctx)
	if err != nil {
		slog.Error("scan failed", "error", err)
		return
	}

	// 2. Get existing entries for timestamp preservation
	existing, err := app.db.GetAllDomains()
	if err != nil {
		slog.Warn("could not load existing domains", "error", err)
		existing = nil
	}

	// 3. Correlate
	entries := app.correlator.Correlate(result, existing)
	slog.Info("correlation complete", "fqdns", len(entries))

	// 4. Persist
	for _, entry := range entries {
		if err := app.db.UpsertDomain(entry); err != nil {
			slog.Error("failed to persist domain", "fqdn", entry.FQDN, "error", err)
		}
	}

	// 5. Update last scan time
	app.db.SetMeta("last_scan", time.Now().Format(time.RFC3339))

	// 6. Healthchecks
	app.runHealthchecks(ctx, entries)

	slog.Info("full scan complete", "duration_ms", time.Since(scanStart).Milliseconds())
}

// ── Healthchecks ─────────────────────────────────────────────────────────────

func (app *App) runHealthchecks(ctx context.Context, entries map[string]*models.DomainEntry) {
	// Build URLs to check (only those with DNS or Traefik)
	urls := make(map[string]string)
	for fqdn, entry := range entries {
		if !entry.DNS.Exists && !entry.Traefik.Exists {
			continue
		}
		// Check HTTPS first, fallback to HTTP
		url := "https://" + fqdn + "/"
		urls[fqdn] = url
	}

	if len(urls) == 0 {
		return
	}

	slog.Info("healthcheck starting", "urls", len(urls))
	results := app.hchecker.BatchCheck(ctx, urls)

	// Update entries with healthcheck results
	for fqdn, httpResult := range results {
		entry, ok := entries[fqdn]
		if !ok {
			continue
		}
		entry.HTTP = httpResult
		entry.LastCheck = time.Now()

		// Re-evaluate status after healthcheck
		entry.Status = app.correlator.ComputeStatus(entry)
		entry.Anomalies = app.correlator.DetectAnomalies(entry)

		// Persist updated entry
		if err := app.db.UpsertDomain(entry); err != nil {
			slog.Error("failed to update domain healthcheck", "fqdn", fqdn, "error", err)
		}
	}
}

// ── Scheduler loops ───────────────────────────────────────────────────────────

func (app *App) runScannerLoop(ctx context.Context) {
	ticker := time.NewTicker(app.cfg.ScannerInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			app.runFullScan(ctx)
		}
	}
}

func (app *App) runHealthcheckLoop(ctx context.Context) {
	ticker := time.NewTicker(app.cfg.HealthcheckInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			entries, err := app.db.GetAllDomains()
			if err != nil {
				slog.Warn("healthcheck loop: failed to load domains", "error", err)
				continue
			}
			entriesMap := make(map[string]*models.DomainEntry)
			for _, e := range entries {
				entriesMap[e.FQDN] = e
			}
			app.runHealthchecks(ctx, entriesMap)
		}
	}
}

func (app *App) runCleanupLoop(ctx context.Context) {
	// Run cleanup once a day
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := app.db.CleanupHistory(app.cfg.HistoryRetentionDays); err != nil {
				slog.Warn("history cleanup failed", "error", err)
			} else {
				slog.Info("history cleanup done", "retention_days", app.cfg.HistoryRetentionDays)
			}
		}
	}
}

// ── Trigger refresh (called by API) ─────────────────────────────────────────

func (app *App) TriggerRefresh(ctx context.Context) {
	go app.runFullScan(ctx)
}

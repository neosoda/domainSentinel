package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"domainsentinel/internal/models"
)

type DB struct {
	*sql.DB
}

func Open(dataDir string) (*DB, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	dbPath := filepath.Join(dataDir, "domainsentinel.db")
	sqlDB, err := sql.Open("sqlite3", dbPath+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	db := &DB{sqlDB}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return db, nil
}

func (db *DB) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS domains (
			fqdn TEXT PRIMARY KEY,
			domain TEXT NOT NULL,
			subdomain TEXT NOT NULL,
			host TEXT,
			first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_check DATETIME,
			dns_exists INTEGER DEFAULT 0,
			dns_type TEXT,
			dns_target TEXT,
			dns_proxied INTEGER DEFAULT 0,
			dns_ttl INTEGER DEFAULT 0,
			dns_record_id TEXT,
			traefik_exists INTEGER DEFAULT 0,
			traefik_routers TEXT,
			traefik_entrypoints TEXT,
			traefik_tls INTEGER DEFAULT 0,
			traefik_middlewares TEXT,
			traefik_has_authentik INTEGER DEFAULT 0,
			traefik_service TEXT,
			docker_container_id TEXT,
			docker_container_name TEXT,
			docker_image TEXT,
			docker_status TEXT,
			docker_health TEXT,
			docker_networks TEXT,
			docker_labels TEXT,
			docker_source TEXT,
			docker_compose_project TEXT,
			docker_compose_service TEXT,
			docker_coolify_name TEXT,
			http_status_code INTEGER DEFAULT 0,
			http_latency_ms INTEGER DEFAULT 0,
			http_tls_valid INTEGER DEFAULT 0,
			http_tls_expire_at DATETIME,
			http_redirects TEXT,
			http_error TEXT,
			http_is_up INTEGER DEFAULT 0,
			status TEXT DEFAULT 'UNKNOWN',
			anomalies TEXT DEFAULT '[]',
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fqdn TEXT NOT NULL,
			status TEXT NOT NULL,
			anomalies TEXT,
			checked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS annotations (
			fqdn TEXT PRIMARY KEY,
			description TEXT DEFAULT '',
			criticality TEXT DEFAULT '',
			owner TEXT DEFAULT '',
			notes TEXT DEFAULT '',
			tags TEXT DEFAULT '',
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_history_fqdn ON history(fqdn)`,
		`CREATE INDEX IF NOT EXISTS idx_history_checked_at ON history(checked_at)`,
	}

	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			return fmt.Errorf("migration: %w\nSQL: %s", err, m)
		}
	}
	return nil
}

// ── Upsert Domain ────────────────────────────────────────────────────────────

func (db *DB) UpsertDomain(entry *models.DomainEntry) error {
	routersJSON, _ := json.Marshal(entry.Traefik.RouterNames)
	entrypointsJSON, _ := json.Marshal(entry.Traefik.Entrypoints)
	middlewaresJSON, _ := json.Marshal(entry.Traefik.MiddlewareNames)
	networksJSON, _ := json.Marshal(entry.Docker.Networks)
	labelsJSON, _ := json.Marshal(entry.Docker.Labels)
	redirectsJSON, _ := json.Marshal(entry.HTTP.Redirects)
	anomaliesJSON, _ := json.Marshal(entry.Anomalies)

	hasAuth := 0
	if entry.Traefik.HasAuthentik {
		hasAuth = 1
	}
	tlsValid := 0
	if entry.HTTP.TLSValid {
		tlsValid = 1
	}
	isUp := 0
	if entry.HTTP.IsUp {
		isUp = 1
	}
	tlsExpire := sql.NullString{}
	if entry.HTTP.TLSExpireAt != nil {
		tlsExpire = sql.NullString{String: entry.HTTP.TLSExpireAt.Format(time.RFC3339), Valid: true}
	}

	query := `
	INSERT INTO domains (
		fqdn, domain, subdomain, host,
		first_seen, last_seen, last_check,
		dns_exists, dns_type, dns_target, dns_proxied, dns_ttl, dns_record_id,
		traefik_exists, traefik_routers, traefik_entrypoints, traefik_tls,
		traefik_middlewares, traefik_has_authentik, traefik_service,
		docker_container_id, docker_container_name, docker_image, docker_status,
		docker_health, docker_networks, docker_labels, docker_source,
		docker_compose_project, docker_compose_service, docker_coolify_name,
		http_status_code, http_latency_ms, http_tls_valid, http_tls_expire_at,
		http_redirects, http_error, http_is_up,
		status, anomalies, updated_at
	) VALUES (
		?, ?, ?, ?,
		?, ?, ?,
		?, ?, ?, ?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?,
		?, ?, CURRENT_TIMESTAMP
	)
	ON CONFLICT(fqdn) DO UPDATE SET
		host = excluded.host,
		last_seen = excluded.last_seen,
		last_check = excluded.last_check,
		dns_exists = excluded.dns_exists, dns_type = excluded.dns_type,
		dns_target = excluded.dns_target, dns_proxied = excluded.dns_proxied,
		dns_ttl = excluded.dns_ttl, dns_record_id = excluded.dns_record_id,
		traefik_exists = excluded.traefik_exists, traefik_routers = excluded.traefik_routers,
		traefik_entrypoints = excluded.traefik_entrypoints, traefik_tls = excluded.traefik_tls,
		traefik_middlewares = excluded.traefik_middlewares,
		traefik_has_authentik = excluded.traefik_has_authentik,
		traefik_service = excluded.traefik_service,
		docker_container_id = excluded.docker_container_id,
		docker_container_name = excluded.docker_container_name,
		docker_image = excluded.docker_image, docker_status = excluded.docker_status,
		docker_health = excluded.docker_health, docker_networks = excluded.docker_networks,
		docker_labels = excluded.docker_labels, docker_source = excluded.docker_source,
		docker_compose_project = excluded.docker_compose_project,
		docker_compose_service = excluded.docker_compose_service,
		docker_coolify_name = excluded.docker_coolify_name,
		http_status_code = excluded.http_status_code, http_latency_ms = excluded.http_latency_ms,
		http_tls_valid = excluded.http_tls_valid, http_tls_expire_at = excluded.http_tls_expire_at,
		http_redirects = excluded.http_redirects, http_error = excluded.http_error,
		http_is_up = excluded.http_is_up,
		status = excluded.status, anomalies = excluded.anomalies,
		updated_at = CURRENT_TIMESTAMP
	`

	_, err := db.Exec(query,
		entry.FQDN, entry.Domain, entry.Subdomain, entry.Host,
		entry.FirstSeen, entry.LastSeen, entry.LastCheck,
		btoi(entry.DNS.Exists), entry.DNS.Type, entry.DNS.Target, btoi(entry.DNS.Proxied), entry.DNS.TTL, entry.DNS.RecordID,
		btoi(entry.Traefik.Exists), string(routersJSON), string(entrypointsJSON), btoi(entry.Traefik.TLS),
		string(middlewaresJSON), hasAuth, entry.Traefik.ServiceName,
		entry.Docker.ContainerID, entry.Docker.ContainerName, entry.Docker.Image, entry.Docker.Status,
		entry.Docker.Health, string(networksJSON), string(labelsJSON), entry.Docker.Source,
		entry.Docker.ComposeProject, entry.Docker.ComposeService, entry.Docker.CoolifyName,
		entry.HTTP.StatusCode, entry.HTTP.LatencyMs, tlsValid, tlsExpire,
		string(redirectsJSON), entry.HTTP.Error, isUp,
		string(entry.Status), string(anomaliesJSON),
	)
	return err
}

// ── Record History ───────────────────────────────────────────────────────────

func (db *DB) RecordHistory(fqdn string, status models.Status, anomalies []models.Anomaly) error {
	anomaliesJSON, _ := json.Marshal(anomalies)
	_, err := db.Exec(
		"INSERT INTO history (fqdn, status, anomalies, checked_at) VALUES (?, ?, ?, ?)",
		fqdn, string(status), string(anomaliesJSON), time.Now(),
	)
	return err
}

// ── Get All Domains ─────────────────────────────────────────────────────────

func (db *DB) GetAllDomains() ([]*models.DomainEntry, error) {
	rows, err := db.Query(`
		SELECT fqdn, domain, subdomain, host, first_seen, last_seen, last_check,
			dns_exists, dns_type, dns_target, dns_proxied, dns_ttl, dns_record_id,
			traefik_exists, traefik_routers, traefik_entrypoints, traefik_tls,
			traefik_middlewares, traefik_has_authentik, traefik_service,
			docker_container_id, docker_container_name, docker_image, docker_status,
			docker_health, docker_networks, docker_labels, docker_source,
			docker_compose_project, docker_compose_service, docker_coolify_name,
			http_status_code, http_latency_ms, http_tls_valid, http_tls_expire_at,
			http_redirects, http_error, http_is_up,
			status, anomalies
		FROM domains ORDER BY subdomain ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*models.DomainEntry
	for rows.Next() {
		e, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (db *DB) GetDomain(fqdn string) (*models.DomainEntry, error) {
	row := db.QueryRow(`
		SELECT fqdn, domain, subdomain, host, first_seen, last_seen, last_check,
			dns_exists, dns_type, dns_target, dns_proxied, dns_ttl, dns_record_id,
			traefik_exists, traefik_routers, traefik_entrypoints, traefik_tls,
			traefik_middlewares, traefik_has_authentik, traefik_service,
			docker_container_id, docker_container_name, docker_image, docker_status,
			docker_health, docker_networks, docker_labels, docker_source,
			docker_compose_project, docker_compose_service, docker_coolify_name,
			http_status_code, http_latency_ms, http_tls_valid, http_tls_expire_at,
			http_redirects, http_error, http_is_up,
			status, anomalies
		FROM domains WHERE fqdn = ?
	`, fqdn)

	e, err := scanDomain(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return e, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDomain(s rowScanner) (*models.DomainEntry, error) {
	var (
		fqdn, domain, subdomain, host                    string
		firstSeen, lastSeen, lastCheck                   sql.NullTime
		dnsExists                                        int
		dnsType, dnsTarget                               string
		dnsProxied                                       int
		dnsTTL                                           int
		dnsRecordID                                      sql.NullString
		traefikExists                                    int
		traefikRouters, traefikEntrypoints, traefikMW    string
		traefikTLS                                       int
		traefikHasAuth                                   int
		traefikService                                   sql.NullString
		dockerCID, dockerName, dockerImage, dockerStatus string
		dockerHealth                                     sql.NullString
		dockerNetworks, dockerLabels, dockerSource       string
		dockerComposeProject, dockerComposeService       sql.NullString
		dockerCoolifyName                                sql.NullString
		httpStatusCode, httpLatencyMs                    int
		httpTLSValid                                     int
		httpTLSExpireAt                                  sql.NullString
		httpRedirects, httpError                         string
		httpIsUp                                         int
		status                                           string
		anomalies                                        string
	)

	err := s.Scan(
		&fqdn, &domain, &subdomain, &host, &firstSeen, &lastSeen, &lastCheck,
		&dnsExists, &dnsType, &dnsTarget, &dnsProxied, &dnsTTL, &dnsRecordID,
		&traefikExists, &traefikRouters, &traefikEntrypoints, &traefikTLS,
		&traefikMW, &traefikHasAuth, &traefikService,
		&dockerCID, &dockerName, &dockerImage, &dockerStatus,
		&dockerHealth, &dockerNetworks, &dockerLabels, &dockerSource,
		&dockerComposeProject, &dockerComposeService, &dockerCoolifyName,
		&httpStatusCode, &httpLatencyMs, &httpTLSValid, &httpTLSExpireAt,
		&httpRedirects, &httpError, &httpIsUp,
		&status, &anomalies,
	)
	if err != nil {
		return nil, err
	}

	e := &models.DomainEntry{
		FQDN:      fqdn,
		Domain:    domain,
		Subdomain: subdomain,
		Host:      host,
		DNS: models.DNSSnapshot{
			Exists:   dnsExists == 1,
			Type:     dnsType,
			Target:   dnsTarget,
			Proxied:  dnsProxied == 1,
			TTL:      dnsTTL,
			RecordID: dnsRecordID.String,
		},
		Traefik: models.TraefikSnapshot{
			Exists:       traefikExists == 1,
			TLS:          traefikTLS == 1,
			HasAuthentik: traefikHasAuth == 1,
			ServiceName:  traefikService.String,
		},
		Docker: models.DockerSnapshot{
			ContainerID:    dockerCID,
			ContainerName:  dockerName,
			Image:          dockerImage,
			Status:         dockerStatus,
			Health:         dockerHealth.String,
			Source:         dockerSource,
			ComposeProject: dockerComposeProject.String,
			ComposeService: dockerComposeService.String,
			CoolifyName:    dockerCoolifyName.String,
		},
		HTTP: models.HTTPSnapshot{
			StatusCode: httpStatusCode,
			LatencyMs:  httpLatencyMs,
			TLSValid:   httpTLSValid == 1,
			Error:      httpError,
			IsUp:       httpIsUp == 1,
		},
		Status: models.Status(status),
	}

	if firstSeen.Valid {
		e.FirstSeen = firstSeen.Time
	}
	if lastSeen.Valid {
		e.LastSeen = lastSeen.Time
	}
	if lastCheck.Valid {
		e.LastCheck = lastCheck.Time
	}

	_ = json.Unmarshal([]byte(traefikRouters), &e.Traefik.RouterNames)
	_ = json.Unmarshal([]byte(traefikEntrypoints), &e.Traefik.Entrypoints)
	_ = json.Unmarshal([]byte(traefikMW), &e.Traefik.MiddlewareNames)
	_ = json.Unmarshal([]byte(dockerNetworks), &e.Docker.Networks)
	_ = json.Unmarshal([]byte(dockerLabels), &e.Docker.Labels)
	_ = json.Unmarshal([]byte(httpRedirects), &e.HTTP.Redirects)
	_ = json.Unmarshal([]byte(anomalies), &e.Anomalies)

	if httpTLSExpireAt.Valid {
		t, err := time.Parse(time.RFC3339, httpTLSExpireAt.String)
		if err == nil {
			e.HTTP.TLSExpireAt = &t
		}
	}

	// Derive Traefik source from existing data (since not stored in DB)
	if e.Traefik.Exists {
		if e.Docker.ContainerName != "" {
			e.Traefik.Sources = []string{"docker:" + e.Docker.ContainerName}
		} else {
			e.Traefik.Sources = []string{"file:traefik-dynamic"}
		}
	}

	return e, nil
}

// ── Annotations ─────────────────────────────────────────────────────────────

func (db *DB) GetAnnotation(fqdn string) (*models.Annotation, error) {
	row := db.QueryRow(
		"SELECT fqdn, description, criticality, owner, notes, tags FROM annotations WHERE fqdn = ?",
		fqdn,
	)
	var a models.Annotation
	err := row.Scan(&a.FQDN, &a.Description, &a.Criticality, &a.Owner, &a.Notes, &a.Tags)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (db *DB) UpsertAnnotation(a *models.Annotation) error {
	_, err := db.Exec(`
		INSERT INTO annotations (fqdn, description, criticality, owner, notes, tags, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(fqdn) DO UPDATE SET
			description = excluded.description,
			criticality = excluded.criticality,
			owner = excluded.owner,
			notes = excluded.notes,
			tags = excluded.tags,
			updated_at = CURRENT_TIMESTAMP
	`, a.FQDN, a.Description, a.Criticality, a.Owner, a.Notes, a.Tags)
	return err
}

// ── Meta ────────────────────────────────────────────────────────────────────

func (db *DB) SetMeta(key, value string) error {
	_, err := db.Exec(
		"INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value,
	)
	return err
}

func (db *DB) GetMeta(key string) (string, error) {
	var value string
	err := db.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

// ── Cleanup ─────────────────────────────────────────────────────────────────

func (db *DB) CleanupHistory(retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format(time.DateOnly)
	_, err := db.Exec("DELETE FROM history WHERE checked_at < ?", cutoff)
	return err
}

// ── Summary ─────────────────────────────────────────────────────────────────

func (db *DB) GetSummary() (*models.DashboardSummary, error) {
	rows, err := db.Query("SELECT fqdn, status, anomalies FROM domains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	s := &models.DashboardSummary{}
	for rows.Next() {
		var fqdn, status, anomalies string
		if err := rows.Scan(&fqdn, &status, &anomalies); err != nil {
			continue
		}

		s.Total++
		switch models.Status(status) {
		case models.StatusOK:
			s.OK++
		case models.StatusDown:
			s.Down++
		case models.StatusAnomaly:
			s.Anomalies++
		}

		var list []models.Anomaly
		_ = json.Unmarshal([]byte(anomalies), &list)
		for _, a := range list {
			s.AnomalyList = append(s.AnomalyList, models.AnomalyEntry{
				FQDN:     fqdn,
				Type:     a.Type,
				Severity: a.Severity,
			})
		}
	}

	lastScan, err := db.GetLastScanTime()
	if err == nil && !lastScan.IsZero() {
		s.LastScan = &lastScan
	}

	return s, nil
}

func (db *DB) GetLastScanTime() (time.Time, error) {
	var nt sql.NullTime
	err := db.QueryRow("SELECT MAX(last_check) FROM domains WHERE last_check IS NOT NULL").Scan(&nt)
	if err == sql.ErrNoRows || !nt.Valid {
		return time.Time{}, nil
	}
	return nt.Time, err
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// splitDomain splits "sub.techsentinel.fr" → ("sub", "techsentinel.fr")
func SplitDomain(fqdn, zoneName string) (subdomain, domain string) {
	domain = zoneName
	subdomain = strings.TrimSuffix(fqdn, "."+zoneName)
	if subdomain == fqdn {
		subdomain = ""
		domain = fqdn
	}
	return
}

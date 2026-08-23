package unit

import (
	"os"
	"testing"
	"time"

	"domainsentinel/internal/db"
	"domainsentinel/internal/models"
)

func setupTestDB(t *testing.T) (*db.DB, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "domainsentinel_test_*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}

	database, err := db.Open(dir)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("open db: %v", err)
	}

	cleanup := func() {
		database.Close()
		os.RemoveAll(dir)
	}

	return database, cleanup
}

func TestDB_EmptyDatabase(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// GetLastScanTime on empty table should return zero time, no error
	lastScan, err := database.GetLastScanTime()
	if err != nil {
		t.Errorf("GetLastScanTime() error = %v, want nil", err)
	}
	if !lastScan.IsZero() {
		t.Errorf("GetLastScanTime() = %v, want zero time", lastScan)
	}

	// GetSummary on empty table
	summary, err := database.GetSummary()
	if err != nil {
		t.Errorf("GetSummary() error = %v, want nil", err)
	}
	if summary.Total != 0 || summary.OK != 0 || summary.Down != 0 || summary.Anomalies != 0 {
		t.Errorf("GetSummary() got %+v, want all zeroes", summary)
	}

	// GetAllDomains on empty table
	domains, err := database.GetAllDomains()
	if err != nil {
		t.Errorf("GetAllDomains() error = %v, want nil", err)
	}
	if len(domains) != 0 {
		t.Errorf("GetAllDomains() got %d items, want 0", len(domains))
	}

	// GetDomain non-existent
	d, err := database.GetDomain("unknown.example.com")
	if err != nil {
		t.Errorf("GetDomain() error = %v, want nil", err)
	}
	if d != nil {
		t.Errorf("GetDomain() = %+v, want nil", d)
	}
}

func TestDB_DomainCRUD(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	expireAt := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	entry := &models.DomainEntry{
		FQDN:      "app.techsentinel.fr",
		Domain:    "techsentinel.fr",
		Subdomain: "app",
		Host:      "NEOSERVER",
		FirstSeen: time.Now().Add(-2 * time.Hour).Truncate(time.Second),
		LastSeen:  time.Now().Truncate(time.Second),
		LastCheck: time.Now().Truncate(time.Second),
		DNS: models.DNSSnapshot{
			Exists:   true,
			Type:     "A",
			Target:   "1.2.3.4",
			Proxied:  true,
			TTL:      1,
			RecordID: "rec123",
		},
		Traefik: models.TraefikSnapshot{
			Exists:          true,
			RouterNames:     []string{"app-router", "app-router-tls"},
			Entrypoints:     []string{"web", "websecure"},
			TLS:             true,
			MiddlewareNames: []string{"authentik@docker", "gzip"},
			HasAuthentik:    true,
			ServiceName:     "app-service",
		},
		Docker: models.DockerSnapshot{
			ContainerID:    "cid123",
			ContainerName:  "app-container",
			Image:          "app:latest",
			Status:         "running",
			Health:         "healthy",
			Networks:       []string{"proxy"},
			Labels:         map[string]string{"coolify.managed": "true"},
			Source:         "coolify",
			ComposeProject: "proj",
			ComposeService: "srv",
			CoolifyName:    "coolapp",
		},
		HTTP: models.HTTPSnapshot{
			StatusCode:  200,
			LatencyMs:   45,
			TLSValid:    true,
			TLSExpireAt: &expireAt,
			Redirects:   []string{"https://app.techsentinel.fr"},
			IsUp:        true,
		},
		Status: models.StatusOK,
		Anomalies: []models.Anomaly{
			{
				Type:     models.AnomalyDNSOrphan,
				Message:  "sample anomaly",
				Severity: models.SeverityWarning,
			},
		},
	}

	// Insert
	if err := database.UpsertDomain(entry); err != nil {
		t.Fatalf("UpsertDomain() insert error = %v", err)
	}

	// Read single
	got, err := database.GetDomain("app.techsentinel.fr")
	if err != nil {
		t.Fatalf("GetDomain() error = %v", err)
	}
	if got == nil {
		t.Fatalf("GetDomain() returned nil")
	}

	if got.FQDN != entry.FQDN || got.Host != "NEOSERVER" {
		t.Errorf("GetDomain().FQDN = %q, Host = %q", got.FQDN, got.Host)
	}
	if !got.DNS.Exists || got.DNS.Type != "A" || got.DNS.Target != "1.2.3.4" || !got.DNS.Proxied {
		t.Errorf("GetDomain().DNS mismatch: %+v", got.DNS)
	}
	if !got.Traefik.Exists || !got.Traefik.HasAuthentik || len(got.Traefik.RouterNames) != 2 {
		t.Errorf("GetDomain().Traefik mismatch: %+v", got.Traefik)
	}
	if got.Docker.ContainerName != "app-container" || got.Docker.Source != "coolify" || got.Docker.CoolifyName != "coolapp" {
		t.Errorf("GetDomain().Docker mismatch: %+v", got.Docker)
	}
	if got.HTTP.StatusCode != 200 || !got.HTTP.TLSValid || !got.HTTP.IsUp {
		t.Errorf("GetDomain().HTTP mismatch: %+v", got.HTTP)
	}
	if got.Status != models.StatusOK {
		t.Errorf("GetDomain().Status = %v, want OK", got.Status)
	}
	if len(got.Anomalies) != 1 || got.Anomalies[0].Type != models.AnomalyDNSOrphan {
		t.Errorf("GetDomain().Anomalies mismatch: %+v", got.Anomalies)
	}

	// Update
	entry.Status = models.StatusDown
	entry.HTTP.StatusCode = 502
	entry.HTTP.IsUp = false
	if err := database.UpsertDomain(entry); err != nil {
		t.Fatalf("UpsertDomain() update error = %v", err)
	}

	updated, err := database.GetDomain("app.techsentinel.fr")
	if err != nil {
		t.Fatalf("GetDomain() after update error = %v", err)
	}
	if updated.Status != models.StatusDown || updated.HTTP.StatusCode != 502 || updated.HTTP.IsUp {
		t.Errorf("GetDomain() updated values mismatch: status=%v, http=%+v", updated.Status, updated.HTTP)
	}

	// Summary check
	summary, err := database.GetSummary()
	if err != nil {
		t.Fatalf("GetSummary() error = %v", err)
	}
	if summary.Total != 1 || summary.Down != 1 {
		t.Errorf("GetSummary() = %+v, want Total=1, Down=1", summary)
	}
}

func TestDB_AnnotationsAndMeta(t *testing.T) {
	database, cleanup := setupTestDB(t)
	defer cleanup()

	// Meta
	if err := database.SetMeta("test_key", "test_val"); err != nil {
		t.Fatalf("SetMeta() error = %v", err)
	}
	val, err := database.GetMeta("test_key")
	if err != nil || val != "test_val" {
		t.Errorf("GetMeta(test_key) = %q, %v, want test_val", val, err)
	}

	// Annotation
	annot := &models.Annotation{
		FQDN:        "demo.techsentinel.fr",
		Description: "Demo service",
		Criticality: "high",
		Owner:       "sysadmin",
		Notes:       "internal only",
		Tags:        "infra,monitoring",
	}

	if err := database.UpsertAnnotation(annot); err != nil {
		t.Fatalf("UpsertAnnotation() error = %v", err)
	}

	got, err := database.GetAnnotation("demo.techsentinel.fr")
	if err != nil || got == nil {
		t.Fatalf("GetAnnotation() error = %v, got = %+v", err, got)
	}
	if got.Description != "Demo service" || got.Criticality != "high" || got.Owner != "sysadmin" {
		t.Errorf("GetAnnotation() = %+v, want %+v", got, annot)
	}
}

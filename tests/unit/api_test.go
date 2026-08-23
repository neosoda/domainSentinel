package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"domainsentinel/internal/api"
	"domainsentinel/internal/config"
	"domainsentinel/internal/db"
	"domainsentinel/internal/models"
)

type mockApp struct {
	refreshed bool
}

func (m *mockApp) TriggerRefresh(ctx context.Context) {
	m.refreshed = true
}

func setupTestServer(t *testing.T) (*httptest.Server, *db.DB, *mockApp, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ds_api_test_*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}

	database, err := db.Open(dir)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("open db: %v", err)
	}

	cfg := &config.Config{
		Host:               "127.0.0.1",
		Port:               "3000",
		CloudflareZoneName: "techsentinel.fr",
	}

	mock := &mockApp{}
	server := api.NewServer(cfg, database, mock)
	ts := httptest.NewServer(server)

	cleanup := func() {
		ts.Close()
		database.Close()
		os.RemoveAll(dir)
	}

	return ts, database, mock, cleanup
}

func TestAPI_Endpoints(t *testing.T) {
	ts, database, mock, cleanup := setupTestServer(t)
	defer cleanup()

	// Seed domain
	entry := &models.DomainEntry{
		FQDN:      "status.techsentinel.fr",
		Domain:    "techsentinel.fr",
		Subdomain: "status",
		Host:      "NEOSERVER",
		FirstSeen: time.Now(),
		LastSeen:  time.Now(),
		LastCheck: time.Now(),
		DNS:       models.DNSSnapshot{Exists: true, Type: "A", Target: "1.2.3.4"},
		Traefik:   models.TraefikSnapshot{Exists: true, TLS: true, HasAuthentik: true},
		Docker:    models.DockerSnapshot{ContainerName: "status-page", Source: "coolify"},
		HTTP:      models.HTTPSnapshot{StatusCode: 200, IsUp: true, TLSValid: true},
		Status:    models.StatusOK,
		Anomalies: []models.Anomaly{
			{
				Type:     models.AnomalyDNSOrphan,
				Message:  "test warning",
				Severity: models.SeverityWarning,
			},
		},
	}
	if err := database.UpsertDomain(entry); err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	// 1. Health check
	t.Run("GET /health", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatalf("GET /health failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})

	// 2. Metrics
	t.Run("GET /metrics", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/metrics")
		if err != nil {
			t.Fatalf("GET /metrics failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})

	// 3. API Domains list
	t.Run("GET /api/v1/domains", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/api/v1/domains")
		if err != nil {
			t.Fatalf("GET /api/v1/domains failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		var list []*models.DomainEntry
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}
		if len(list) != 1 || list[0].FQDN != "status.techsentinel.fr" {
			t.Errorf("list = %+v, want 1 item", list)
		}
	})

	// 4. API Single Domain
	t.Run("GET /api/v1/domains/{fqdn}", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/api/v1/domains/status.techsentinel.fr")
		if err != nil {
			t.Fatalf("GET single domain failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		var d models.DomainEntry
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}
		if d.FQDN != "status.techsentinel.fr" {
			t.Errorf("FQDN = %q, want status.techsentinel.fr", d.FQDN)
		}
	})

	// 5. API Anomalies
	t.Run("GET /api/v1/anomalies", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/api/v1/anomalies")
		if err != nil {
			t.Fatalf("GET anomalies failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	})

	// 6. API Summary
	t.Run("GET /api/v1/summary", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/api/v1/summary")
		if err != nil {
			t.Fatalf("GET summary failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		var summary models.DashboardSummary
		if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
			t.Fatalf("decode JSON: %v", err)
		}
		if summary.Total != 1 {
			t.Errorf("Total = %d, want 1", summary.Total)
		}
	})

	// 7. Refresh trigger
	t.Run("POST /api/v1/refresh", func(t *testing.T) {
		resp, err := http.Post(ts.URL+"/api/v1/refresh", "application/json", nil)
		if err != nil {
			t.Fatalf("POST refresh failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		if !mock.refreshed {
			t.Errorf("expected TriggerRefresh to have been called")
		}
	})

	// 8. Patch Annotation
	t.Run("PATCH /api/v1/domains/{fqdn}/annotation", func(t *testing.T) {
		body := `{"description":"New status page","criticality":"high","owner":"ops"}`
		req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/domains/status.techsentinel.fr/annotation", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PATCH annotation failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}

		a, err := database.GetAnnotation("status.techsentinel.fr")
		if err != nil || a == nil || a.Description != "New status page" || a.Criticality != "high" {
			t.Errorf("annotation not persisted properly: %+v", a)
		}
	})

	// 9. HTML UI Page - Index
	t.Run("GET / (HTML Index)", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/")
		if err != nil {
			t.Fatalf("GET / failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		if !strings.Contains(buf.String(), "DomainSentinel") {
			t.Errorf("HTML body does not contain DomainSentinel")
		}
		if !strings.Contains(buf.String(), "status.techsentinel.fr") {
			t.Errorf("HTML body does not contain status.techsentinel.fr")
		}
	})

	// 10. HTML UI Page - Detail
	t.Run("GET /domain/{fqdn} (HTML Detail)", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/domain/status.techsentinel.fr")
		if err != nil {
			t.Fatalf("GET /domain/status.techsentinel.fr failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		if !strings.Contains(buf.String(), "status.techsentinel.fr") {
			t.Errorf("HTML body does not contain status.techsentinel.fr")
		}
	})
}

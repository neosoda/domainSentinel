package unit

import (
	"testing"
	"time"

	"domainsentinel/internal/config"
	"domainsentinel/internal/correlator"
	"domainsentinel/internal/models"
	"domainsentinel/internal/scanner"
)

func TestCorrelator_DetectAnomalies(t *testing.T) {
	cfg := &config.Config{
		CloudflareZoneName: "techsentinel.fr",
		KnownHosts: map[string]string{
			"192.168.1.200": "NEOSERVER",
			"192.168.1.201": "BACKEND01",
		},
	}
	c := correlator.NewCorrelator(cfg)

	t.Run("DNS Orphan", func(t *testing.T) {
		entry := &models.DomainEntry{
			FQDN: "orphan.techsentinel.fr",
			DNS:  models.DNSSnapshot{Exists: true},
		}
		entry.Anomalies = c.DetectAnomalies(entry)
		if len(entry.Anomalies) != 1 || entry.Anomalies[0].Type != models.AnomalyDNSOrphan {
			t.Errorf("got %v, want AnomalyDNSOrphan", entry.Anomalies)
		}
		if status := c.ComputeStatus(entry); status != models.StatusOK {
			t.Errorf("status = %v, want OK", status)
		}
	})

	t.Run("Missing DNS", func(t *testing.T) {
		entry := &models.DomainEntry{
			FQDN:    "nodns.techsentinel.fr",
			Traefik: models.TraefikSnapshot{Exists: true},
		}
		entry.Anomalies = c.DetectAnomalies(entry)
		if len(entry.Anomalies) != 1 || entry.Anomalies[0].Type != models.AnomalyMissingDNS {
			t.Errorf("got %v, want AnomalyMissingDNS", entry.Anomalies)
		}
		if status := c.ComputeStatus(entry); status != models.StatusOK {
			t.Errorf("status = %v, want OK", status)
		}
	})

	t.Run("Container Down", func(t *testing.T) {
		entry := &models.DomainEntry{
			FQDN:    "down.techsentinel.fr",
			DNS:     models.DNSSnapshot{Exists: true},
			Traefik: models.TraefikSnapshot{Exists: true},
			Docker: models.DockerSnapshot{
				ContainerID: "cid1",
				Status:      "exited",
			},
		}
		entry.Anomalies = c.DetectAnomalies(entry)
		hasContainerDown := false
		for _, a := range entry.Anomalies {
			if a.Type == models.AnomalyContainerDown {
				hasContainerDown = true
			}
		}
		if !hasContainerDown {
			t.Errorf("expected AnomalyContainerDown in %v", entry.Anomalies)
		}
		if status := c.ComputeStatus(entry); status != models.StatusDown {
			t.Errorf("status = %v, want DOWN", status)
		}
	})

	t.Run("Service Down (HTTP 502)", func(t *testing.T) {
		entry := &models.DomainEntry{
			FQDN:    "srv502.techsentinel.fr",
			DNS:     models.DNSSnapshot{Exists: true},
			Traefik: models.TraefikSnapshot{Exists: true},
			HTTP: models.HTTPSnapshot{
				StatusCode: 502,
				IsUp:       false,
			},
		}
		entry.Anomalies = c.DetectAnomalies(entry)
		hasServiceDown := false
		for _, a := range entry.Anomalies {
			if a.Type == models.AnomalyServiceDown {
				hasServiceDown = true
			}
		}
		if !hasServiceDown {
			t.Errorf("expected AnomalyServiceDown in %v", entry.Anomalies)
		}
		if status := c.ComputeStatus(entry); status != models.StatusDown {
			t.Errorf("status = %v, want DOWN", status)
		}
	})

	t.Run("TLS Expired", func(t *testing.T) {
		expired := time.Now().Add(-24 * time.Hour)
		entry := &models.DomainEntry{
			FQDN:    "expired.techsentinel.fr",
			DNS:     models.DNSSnapshot{Exists: true},
			Traefik: models.TraefikSnapshot{Exists: true, Entrypoints: []string{"websecure"}},
			HTTP: models.HTTPSnapshot{
				StatusCode:  200,
				IsUp:        true,
				TLSValid:    true,
				TLSExpireAt: &expired,
			},
		}
		entry.Anomalies = c.DetectAnomalies(entry)
		hasTLSError := false
		for _, a := range entry.Anomalies {
			if a.Type == models.AnomalyTLSError {
				hasTLSError = true
			}
		}
		if !hasTLSError {
			t.Errorf("expected AnomalyTLSError in %v", entry.Anomalies)
		}
	})

	t.Run("Healthy service", func(t *testing.T) {
		expireFuture := time.Now().Add(60 * 24 * time.Hour)
		entry := &models.DomainEntry{
			FQDN:    "healthy.techsentinel.fr",
			DNS:     models.DNSSnapshot{Exists: true},
			Traefik: models.TraefikSnapshot{Exists: true, Entrypoints: []string{"websecure"}},
			Docker: models.DockerSnapshot{
				ContainerID: "cid1",
				Status:      "running",
				Health:      "healthy",
			},
			HTTP: models.HTTPSnapshot{
				StatusCode:  200,
				IsUp:        true,
				TLSValid:    true,
				TLSExpireAt: &expireFuture,
			},
		}
		entry.Anomalies = c.DetectAnomalies(entry)
		if len(entry.Anomalies) != 0 {
			t.Errorf("got unexpected anomalies: %v", entry.Anomalies)
		}
		if status := c.ComputeStatus(entry); status != models.StatusOK {
			t.Errorf("status = %v, want OK", status)
		}
	})
}

func TestCorrelator_Correlate(t *testing.T) {
	cfg := &config.Config{
		CloudflareZoneName: "techsentinel.fr",
		KnownHosts: map[string]string{
			"192.168.1.200": "NEOSERVER",
		},
	}
	c := correlator.NewCorrelator(cfg)

	scanRes := &scanner.ScanResult{
		Timestamp: time.Now(),
		DNS: map[string]*scanner.DNSInfo{
			"app.techsentinel.fr": {
				RecordID: "rec1",
				Type:     "A",
				Target:   "192.168.1.200",
				Proxied:  false,
				TTL:      300,
			},
		},
		Routers: map[string][]scanner.RouterInfo{
			"app.techsentinel.fr": {
				{
					Name:        "app-router",
					Service:     "app-svc",
					Middlewares: []string{"authentik@docker"},
					TLS:         true,
					Entrypoints: []string{"websecure"},
					Source:      "docker:app-container",
				},
			},
		},
		Containers: map[string][]scanner.ContainerInfo{
			"app-container": {
				{
					ID:     "c123",
					Name:   "/app-container",
					Image:  "app:1.0",
					State:  "running",
					Labels: map[string]string{"coolify.managed": "true", "coolify.name": "app-ui"},
				},
			},
		},
	}

	entries := c.Correlate(scanRes, nil)
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}

	entry, ok := entries["app.techsentinel.fr"]
	if !ok {
		t.Fatalf("entry app.techsentinel.fr not found")
	}

	if entry.Subdomain != "app" || entry.Domain != "techsentinel.fr" {
		t.Errorf("split domain mismatch: sub=%q, dom=%q", entry.Subdomain, entry.Domain)
	}
	if !entry.DNS.Exists || entry.DNS.Target != "192.168.1.200" {
		t.Errorf("DNS mismatch: %+v", entry.DNS)
	}
	if !entry.Traefik.Exists || !entry.Traefik.HasAuthentik || !entry.Traefik.TLS {
		t.Errorf("Traefik mismatch: %+v", entry.Traefik)
	}
	if entry.Docker.ContainerName != "app-container" || entry.Docker.Source != "coolify" {
		t.Errorf("Docker mismatch: %+v", entry.Docker)
	}
	if entry.Host != "NEOSERVER" {
		t.Errorf("Host = %q, want NEOSERVER", entry.Host)
	}
}


package unit

import (
	"testing"

	"domainsentinel/internal/models"
)

func TestIsHTTPUp(t *testing.T) {
	tests := []struct {
		code     int
		expected bool
	}{
		{200, true},
		{204, true},
		{301, true},
		{302, true},
		{401, true}, // expected for protected endpoints
		{403, true}, // service works but denies anonymous access
		{404, false},
		{500, false},
		{502, false},
		{503, false},
		{0, false},
	}

	for _, tt := range tests {
		t.Run(httpCode(tt.code), func(t *testing.T) {
			got := models.IsHTTPUp(tt.code)
			if got != tt.expected {
				t.Errorf("IsHTTPUp(%d) = %v, want %v", tt.code, got, tt.expected)
			}
		})
	}
}

func httpCode(n int) string {
	return map[int]string{
		200: "200", 204: "204", 301: "301", 302: "302",
		401: "401", 403: "403", 404: "404", 500: "500",
		502: "502", 503: "503", 0: "0",
	}[n]
}

func TestStatusLabel(t *testing.T) {
	tests := []struct {
		status   models.Status
		expected string
	}{
		{models.StatusOK, "OK"},
		{models.StatusDown, "DOWN"},
		{models.StatusAnomaly, "⚠ Anomalie"},
		{models.StatusUnknown, "?"},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := tt.status.Label()
			if got != tt.expected {
				t.Errorf("Status(%q).Label() = %q, want %q", tt.status, got, tt.expected)
			}
		})
	}
}

func TestAnomalyMessages(t *testing.T) {
	fqdn := "test.techsentinel.fr"

	tests := []struct {
		anomaly  models.AnomalyType
		expected string
	}{
		{models.AnomalyDNSOrphan, fqdn + " : DNS présent mais aucune route Traefik correspondante"},
		{models.AnomalyMissingDNS, fqdn + " : route Traefik présente mais aucun DNS correspondant"},
		{models.AnomalyServiceDown, fqdn + " : DNS + Traefik OK mais endpoint HTTP inacessible"},
		{models.AnomalyContainerDown, fqdn + " : conteneur Docker arrêté"},
		{models.AnomalyUnhealthy, fqdn + " : conteneur Docker unhealthy"},
		{models.AnomalyTLSError, fqdn + " : certificat TLS invalide ou expiré"},
	}

	for _, tt := range tests {
		t.Run(string(tt.anomaly), func(t *testing.T) {
			got := tt.anomaly.Message(fqdn)
			if got != tt.expected {
				t.Errorf("AnomalyType(%q).Message(%q) = %q, want %q", tt.anomaly, fqdn, got, tt.expected)
			}
		})
	}
}

func TestSplitDomain(t *testing.T) {
	tests := []struct {
		fqdn       string
		zoneName   string
		wantSub    string
		wantDomain string
	}{
		{"stats.techsentinel.fr", "techsentinel.fr", "stats", "techsentinel.fr"},
		{"auth.techsentinel.fr", "techsentinel.fr", "auth", "techsentinel.fr"},
		{"a.b.c.techsentinel.fr", "techsentinel.fr", "a.b.c", "techsentinel.fr"},
		{"techsentinel.fr", "techsentinel.fr", "", "techsentinel.fr"},
		{"other.fr", "techsentinel.fr", "", "other.fr"}, // no match — returns whole as domain
	}

	for _, tt := range tests {
		t.Run(tt.fqdn, func(t *testing.T) {
			sub, domain := splitDomain(tt.fqdn, tt.zoneName)
			if sub != tt.wantSub || domain != tt.wantDomain {
				t.Errorf("splitDomain(%q, %q) = (%q, %q), want (%q, %q)",
					tt.fqdn, tt.zoneName, sub, domain, tt.wantSub, tt.wantDomain)
			}
		})
	}
}

func splitDomain(fqdn, zoneName string) (subdomain, domain string) {
	domain = zoneName
	sub := fqdn
	for i := 0; i < len(fqdn); i++ {
		if i+len(zoneName) <= len(fqdn) && fqdn[i:i+len(zoneName)] == zoneName {
			if i > 0 && fqdn[i-1] == '.' {
				sub = fqdn[:i-1]
			}
			break
		}
	}
	if sub == fqdn {
		return "", fqdn
	}
	return sub, domain
}

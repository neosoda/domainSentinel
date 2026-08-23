package correlator

import (
	"strings"
	"time"

	"domainsentinel/internal/config"
	"domainsentinel/internal/models"
	"domainsentinel/internal/scanner"
)

// Correlator merges scan results into normalized DomainEntry objects.
type Correlator struct {
	cfg       *config.Config
	knownZone string
}

// NewCorrelator creates a new correlator.
func NewCorrelator(cfg *config.Config) *Correlator {
	return &Correlator{
		cfg:       cfg,
		knownZone: cfg.CloudflareZoneName,
	}
}

// Correlate merges scan data into a map of FQDN → DomainEntry.
func (c *Correlator) Correlate(result *scanner.ScanResult, existingDB []*models.DomainEntry) map[string]*models.DomainEntry {
	// Build map of existing entries for timestamps
	existing := make(map[string]*models.DomainEntry)
	for _, e := range existingDB {
		existing[e.FQDN] = e
	}

	// Collect all FQDNs seen in any source
	allFQDNs := make(map[string]bool)
	for fqdn := range result.DNS {
		allFQDNs[fqdn] = true
	}
	for fqdn := range result.Routers {
		allFQDNs[fqdn] = true
	}

	entries := make(map[string]*models.DomainEntry)

	for fqdn := range allFQDNs {
		subdomain, domain := c.splitDomain(fqdn)
		entry := &models.DomainEntry{
			FQDN:      fqdn,
			Domain:    domain,
			Subdomain: subdomain,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			LastCheck: time.Now(),
		}

		// Preserve existing timestamps
		if prev, ok := existing[fqdn]; ok {
			entry.FirstSeen = prev.FirstSeen
			entry.Host = prev.Host
		}

		// ── DNS ──
		if dns, ok := result.DNS[fqdn]; ok {
			entry.DNS = models.DNSSnapshot{
				Exists:   true,
				Type:     dns.Type,
				Target:   dns.Target,
				Proxied:  dns.Proxied,
				TTL:      dns.TTL,
				RecordID: dns.RecordID,
			}
		}

		// ── Traefik ──
		if routers, ok := result.Routers[fqdn]; ok {
			entry.Traefik.Exists = true
			var allMW []string
			hasTLS := false
			var allEntryPoints []string
			for _, r := range routers {
				entry.Traefik.RouterNames = append(entry.Traefik.RouterNames, r.Name)
				if r.Service != "" {
					entry.Traefik.ServiceName = r.Service
				}
				if r.TLS {
					hasTLS = true
				}
				for _, ep := range r.Entrypoints {
					if !contains(allEntryPoints, ep) {
						allEntryPoints = append(allEntryPoints, ep)
					}
				}
				for _, mw := range r.Middlewares {
					if !contains(allMW, mw) {
						allMW = append(allMW, mw)
					}
					// Check for Authentik
					if c.isAuthentikMiddleware(mw) {
						entry.Traefik.HasAuthentik = true
					}
				}
				// Track source of this router
				if !contains(entry.Traefik.Sources, r.Source) {
					entry.Traefik.Sources = append(entry.Traefik.Sources, r.Source)
				}
			}
			entry.Traefik.TLS = hasTLS
			entry.Traefik.Entrypoints = allEntryPoints
			entry.Traefik.MiddlewareNames = allMW
		}

		// ── Docker (correlate via container name from router source) ──
		// Find which container owns the router for this FQDN
		if routers, ok := result.Routers[fqdn]; ok {
			for _, r := range routers {
				if strings.HasPrefix(r.Source, "docker:") {
					containerName := strings.TrimPrefix(r.Source, "docker:")
					if cis, ok := result.Containers[containerName]; ok && len(cis) > 0 {
						entry.Docker = c.buildDockerSnapshot(cis[0])
						// Try to determine host from container's network or label
						if entry.Host == "" {
							entry.Host = c.determineHost(cis[0])
						}
					}
				}
			}
		}

		// Determine host from DNS target if not yet set
		if entry.Host == "" && entry.DNS.Target != "" {
			entry.Host = c.resolveHostFromIP(entry.DNS.Target)
		}

		// ── Anomalies ──
		entry.Anomalies = c.detectAnomaliesWithResult(entry, result)

		// ── Status ──
		entry.Status = c.ComputeStatus(entry)

		entries[fqdn] = entry
	}

	return entries
}

// isAuthentikMiddleware returns true if the middleware is an Authentik forwardAuth.
func (c *Correlator) isAuthentikMiddleware(mw string) bool {
	// Authentik middleware in Docker: "authentik@docker"
	// Also check for "authentik-forwardauth" etc.
	lower := strings.ToLower(mw)
	return strings.HasPrefix(lower, "authentik") ||
		strings.Contains(lower, "authentik-forwardauth") ||
		strings.Contains(lower, "authentik-") && strings.Contains(lower, "forwardauth")
}

func (c *Correlator) buildDockerSnapshot(ci scanner.ContainerInfo) models.DockerSnapshot {
	name := ci.Name
	if strings.HasPrefix(name, "/") {
		name = name[1:]
	}
	// Fallback: construct from Docker Compose labels
	if name == "" {
		if project := ci.Labels["com.docker.compose.project"]; project != "" {
			if service := ci.Labels["com.docker.compose.service"]; service != "" {
				num := ci.Labels["com.docker.compose.container-number"]
				if num != "" && num != "1" {
					name = project + "_" + service + "_" + num
				} else {
					name = project + "_" + service
				}
			}
		}
	}
	// Fallback: use coolify.name
	if name == "" {
		name = ci.Labels["coolify.name"]
	}

	source, composeProject, composeService, coolifyName := scanner.ExtractDockerSource(ci.Labels)

	networks := make([]string, 0, len(ci.NetworkSettings.Networks))
	for n := range ci.NetworkSettings.Networks {
		networks = append(networks, n)
	}

	return models.DockerSnapshot{
		ContainerID:    ci.ID,
		ContainerName:  name,
		Image:          ci.Image,
		Status:         ci.State,
		Health:         scanner.ParseContainerHealth(ci.Health),
		Networks:       networks,
		Labels:         ci.Labels,
		Source:         source,
		ComposeProject: composeProject,
		ComposeService: composeService,
		CoolifyName:    coolifyName,
	}
}

func (c *Correlator) determineHost(ci scanner.ContainerInfo) string {
	// Check explicit label
	if h := ci.Labels["domainsentinel.host"]; h != "" {
		return h
	}
	// Coolify-managed services are on NEOSERVER by default
	if ci.Labels["coolify.managed"] == "true" {
		return "NEOSERVER"
	}
	// Docker Compose project mapping
	project := ci.Labels["com.docker.compose.project"]
	switch project {
	case "authentik", "beszel", "traefik", "searxng", "meshcentral",
		"wordpress", "pocketbase", "erugo", "portainer", "libretranslate",
		"goaccess", "piwigo", "browsertools", "bentopdf":
		return "NEOSERVER"
	}
	return "NEOSERVER" // default
}

func (c *Correlator) resolveHostFromIP(ip string) string {
	// Try to match known hosts
	if host, ok := c.cfg.KnownHosts[ip]; ok {
		return host
	}
	// Default for internal IPs
	if strings.HasPrefix(ip, "192.168.1.") {
		return "NEOSERVER"
	}
	return ""
}

// detectAnomaliesWithResult computes anomalies during initial correlation (needs scan result).
func (c *Correlator) detectAnomaliesWithResult(entry *models.DomainEntry, result *scanner.ScanResult) []models.Anomaly {
	return c.DetectAnomalies(entry)
}

// DetectAnomalies returns the list of anomalies for a domain entry.
func (c *Correlator) DetectAnomalies(entry *models.DomainEntry) []models.Anomaly {
	var anomalies []models.Anomaly

	// DNS_ORPHAN: DNS exists but no Traefik route (informational)
	if entry.DNS.Exists && !entry.Traefik.Exists {
		anomalies = append(anomalies, models.Anomaly{
			Type:     models.AnomalyDNSOrphan,
			Message:  models.AnomalyDNSOrphan.Message(entry.FQDN),
			Severity: models.SeverityInfo,
		})
	}

	// MISSING_DNS: Traefik route exists but no direct Cloudflare DNS record found
	// (common if using wildcard DNS or if token is not configured; informational only)
	if !entry.DNS.Exists && entry.Traefik.Exists {
		anomalies = append(anomalies, models.Anomaly{
			Type:     models.AnomalyMissingDNS,
			Message:  models.AnomalyMissingDNS.Message(entry.FQDN),
			Severity: models.SeverityInfo,
		})
	}

	// CONTAINER_DOWN: Traefik exists but container is stopped
	if entry.Traefik.Exists && entry.Docker.ContainerID != "" {
		if entry.Docker.Status != "running" && entry.Docker.Status != "" {
			anomalies = append(anomalies, models.Anomaly{
				Type:     models.AnomalyContainerDown,
				Message:  models.AnomalyContainerDown.Message(entry.FQDN),
				Severity: models.SeverityWarning,
			})
		}
	}

	// UNHEALTHY: container exists but healthcheck failed
	if entry.Docker.Health == "unhealthy" {
		anomalies = append(anomalies, models.Anomaly{
			Type:     models.AnomalyUnhealthy,
			Message:  models.AnomalyUnhealthy.Message(entry.FQDN),
			Severity: models.SeverityWarning,
		})
	}

	// SERVICE_DOWN: HTTP check explicitly returned an error (5xx or network failure)
	if entry.HTTP.StatusCode != 0 && !entry.HTTP.IsUp {
		anomalies = append(anomalies, models.Anomaly{
			Type:     models.AnomalyServiceDown,
			Message:  models.AnomalyServiceDown.Message(entry.FQDN),
			Severity: models.SeverityCritical,
		})
	} else if entry.HTTP.Error != "" && entry.HTTP.StatusCode == 0 {
		anomalies = append(anomalies, models.Anomaly{
			Type:     models.AnomalyServiceDown,
			Message:  models.AnomalyServiceDown.Message(entry.FQDN) + " (" + entry.HTTP.Error + ")",
			Severity: models.SeverityCritical,
		})
	}

	// TLS_ERROR: Certificate expired
	if entry.HTTP.TLSExpireAt != nil {
		if time.Now().After(*entry.HTTP.TLSExpireAt) {
			anomalies = append(anomalies, models.Anomaly{
				Type:     models.AnomalyTLSError,
				Message:  entry.FQDN + " : certificat TLS expiré",
				Severity: models.SeverityCritical,
			})
		}
	}

	return anomalies
}

// ComputeStatus evaluates the overall status of a domain entry.
func (c *Correlator) ComputeStatus(entry *models.DomainEntry) models.Status {
	// 1. If HTTP healthcheck has run, HTTP reachability is the ground truth
	if entry.HTTP.StatusCode > 0 {
		if entry.HTTP.IsUp {
			return models.StatusOK
		}
		return models.StatusDown
	}

	// If HTTP had a network error
	if entry.HTTP.Error != "" {
		return models.StatusDown
	}

	// 2. If Docker container info is available
	if entry.Docker.ContainerID != "" {
		if entry.Docker.Status == "running" {
			return models.StatusOK
		}
		if entry.Docker.Status == "exited" || entry.Docker.Status == "dead" {
			return models.StatusDown
		}
	}

	// 3. If Traefik route or DNS exists, consider active by default
	if entry.Traefik.Exists || entry.DNS.Exists {
		return models.StatusOK
	}

	return models.StatusUnknown
}

func (c *Correlator) splitDomain(fqdn string) (subdomain, domain string) {
	domain = c.knownZone
	subdomain = strings.TrimSuffix(fqdn, "."+domain)
	if subdomain == fqdn {
		subdomain = ""
		domain = fqdn
	}
	return
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

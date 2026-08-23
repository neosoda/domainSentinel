package scanner

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"domainsentinel/internal/config"
)

// ScanResult holds all data collected from all sources.
type ScanResult struct {
	Timestamp  time.Time
	DNS        map[string]*DNSInfo        // FQDN → DNS info from Cloudflare
	Routers    map[string][]RouterInfo    // FQDN → list of routers (from Docker labels + YAML files)
	Containers map[string][]ContainerInfo // containerName → list of containers with that name
}

type DNSInfo struct {
	RecordID string
	Type     string
	Target   string
	Proxied  bool
	TTL      int
}

type RouterInfo struct {
	Name        string
	Service     string
	Middlewares []string
	TLS         bool
	Entrypoints []string
	Source      string // "docker" or "file:<filename>"
}

// Scanner orchestrates all data source scanners.
type Scanner struct {
	cfg       *config.Config
	cf        *CloudflareScanner
	dk        *DockerScanner
	tr        *TraefikFileScanner
	knownZone string
}

func NewScanner(cfg *config.Config) *Scanner {
	return &Scanner{
		cfg:       cfg,
		cf:        NewCloudflareScanner(cfg.CloudflareToken, cfg.CloudflareZoneName, time.Duration(cfg.CloudflareTimeoutS)*time.Second),
		dk:        NewDockerScanner(cfg.DockerHost, time.Duration(cfg.DockerTimeoutS)*time.Second),
		tr:        NewTraefikFileScanner(cfg.TraefikDynamicDir),
		knownZone: cfg.CloudflareZoneName,
	}
}

// Run executes a full scan of all sources.
func (s *Scanner) Run(ctx context.Context) (*ScanResult, error) {
	result := &ScanResult{
		Timestamp:  time.Now(),
		DNS:        make(map[string]*DNSInfo),
		Routers:    make(map[string][]RouterInfo),
		Containers: make(map[string][]ContainerInfo),
	}

	// 1. Cloudflare DNS
	slog.Info("cloudflare scan starting")
	cfRecords, err := s.cf.Scan(ctx)
	if err != nil {
		slog.Warn("cloudflare scan failed", "error", err)
	} else {
		for fqdn, rec := range cfRecords {
			result.DNS[fqdn] = &DNSInfo{
				RecordID: rec.ID,
				Type:     rec.Type,
				Target:   rec.Content,
				Proxied:  rec.Proxied,
				TTL:      rec.TTL,
			}
		}
		slog.Info("cloudflare scan complete", "records", len(cfRecords))
	}

	// 2. Docker containers
	slog.Info("docker scan starting")
	containers, err := s.dk.Scan(ctx)
	if err != nil {
		slog.Warn("docker scan failed", "error", err)
	} else {
		for _, c := range containers {
			name := strings.TrimPrefix(c.Name, "/")
			result.Containers[name] = append(result.Containers[name], c)

			// Extract Traefik routers from Docker labels
			routers := ExtractTraefikRouters(c)
			for _, r := range routers {
				fqdns := ExtractSimpleHostnames(r.Rule, s.knownZone)
				for _, fqdn := range fqdns {
					result.Routers[fqdn] = append(result.Routers[fqdn], RouterInfo{
						Name:        r.Name,
						Service:     r.Service,
						Middlewares: r.Middlewares,
						TLS:         r.TLS,
						Entrypoints: r.Entrypoints,
						Source:      "docker:" + name,
					})
				}
			}
		}
		slog.Info("docker scan complete", "containers", len(containers))
	}

	// 3. Traefik file-based dynamic config
	slog.Info("traefik file scan starting")
	fileRouters, err := s.tr.Scan()
	if err != nil {
		slog.Warn("traefik file scan failed", "error", err)
	} else {
		for _, r := range fileRouters {
			fqdns := ExtractSimpleHostnames(r.Rule, s.knownZone)
			for _, fqdn := range fqdns {
				result.Routers[fqdn] = append(result.Routers[fqdn], RouterInfo{
					Name:        r.RouterName,
					Service:     r.Service,
					Middlewares: r.Middlewares,
					TLS:         r.TLS,
					Entrypoints: r.Entrypoints,
					Source:      "file:" + r.Source,
				})
			}
		}
		slog.Info("traefik file scan complete", "file_routers", len(fileRouters))
	}

	return result, nil
}

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// DockerScanner reads container info via Docker socket (read-only).
type DockerScanner struct {
	baseURL string
	hc      *http.Client
}

// ContainerInfo represents the minimal container data we need.
type ContainerInfo struct {
	ID              string            `json:"Id"`
	Name            string            `json:"Name"`
	Image           string            `json:"Image"`
	Status          string            `json:"Status"`
	State           string            `json:"State"`
	Health          any               `json:"Health"` // Docker API v1.44+ returns an object; use HealthStatus() helper
	Labels          map[string]string `json:"Labels"`
	NetworkSettings struct {
		Networks map[string]struct{} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// HealthStatus extracts a clean health string from the Health field.
// Docker API v1.44+ returns an object like {"Status":"healthy","FailingStreak":0};
// older versions returned a plain string.
func (c ContainerInfo) HealthStatus() string {
	if c.Health == nil {
		return ""
	}
	switch v := c.Health.(type) {
	case string:
		return strings.TrimPrefix(v, "health_status: ")
	case map[string]any:
		if s, ok := v["Status"].(string); ok {
			return s
		}
	}
	return ""
}

// NewDockerScanner creates a scanner that talks to Docker socket (direct or via proxy).
func NewDockerScanner(proxyURL string, timeout time.Duration) *DockerScanner {
	if strings.HasPrefix(proxyURL, "unix://") {
		socketPath := strings.TrimPrefix(proxyURL, "unix://")
		tr := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "unix", socketPath)
			},
		}
		return &DockerScanner{
			baseURL: "http://localhost/containers/json",
			hc:      &http.Client{Timeout: timeout, Transport: tr},
		}
	}
	return &DockerScanner{
		baseURL: strings.TrimSuffix(proxyURL, "/") + "/containers/json",
		hc:      &http.Client{Timeout: timeout, Transport: http.DefaultTransport},
	}
}

// Scan returns all containers.
func (s *DockerScanner) Scan(ctx context.Context) ([]ContainerInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.baseURL+"?all=true", nil)
	if err != nil {
		return nil, fmt.Errorf("docker request: %w", err)
	}

	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("docker returned %s", resp.Status)
	}

	var containers []ContainerInfo
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("decode containers: %w", err)
	}

	return containers, nil
}

// ExtractTraefikRouters extracts Traefik router info from Docker labels.
func ExtractTraefikRouters(container ContainerInfo) []TraefikRouterInfo {
	var routers []TraefikRouterInfo

	// Build a map of router configs from labels
	type routerConfig struct {
		Rule        string
		Entrypoints []string
		Service     string
		Middlewares []string
		TLS         bool
	}
	configs := make(map[string]*routerConfig)

	for key, val := range container.Labels {
		if !strings.HasPrefix(key, "traefik.http.routers.") {
			continue
		}
		rest := strings.TrimPrefix(key, "traefik.http.routers.")
		parts := strings.SplitN(rest, ".", 3)
		if len(parts) < 2 {
			continue
		}
		routerName := parts[0]
		attr := parts[1]

		cfg, ok := configs[routerName]
		if !ok {
			cfg = &routerConfig{}
			configs[routerName] = cfg
		}

		switch {
		case attr == "rule":
			cfg.Rule = val
		case attr == "entrypoints":
			cfg.Entrypoints = splitComma(val)
		case attr == "service":
			cfg.Service = val
		case attr == "tls":
			cfg.TLS = val == "true" || val == "{}"
		case strings.HasPrefix(attr, "tls."):
			cfg.TLS = true
		case attr == "middlewares":
			cfg.Middlewares = splitComma(val)
		}
	}

	for name, cfg := range configs {
		if cfg.Rule == "" {
			continue
		}
		r := TraefikRouterInfo{
			Name:        name,
			Rule:        cfg.Rule,
			Entrypoints: cfg.Entrypoints,
			Service:     cfg.Service,
			TLS:         cfg.TLS,
			Middlewares: cfg.Middlewares,
			Source:      "docker",
		}
		routers = append(routers, r)
	}

	return routers
}

type TraefikRouterInfo struct {
	Name        string
	Rule        string
	Entrypoints []string
	Service     string
	Middlewares []string
	TLS         bool
	Source      string
}

// ExtractDockerSource determines if a container is managed by Coolify or docker-compose.
func ExtractDockerSource(labels map[string]string) (source, composeProject, composeService, coolifyName string) {
	if labels["coolify.managed"] == "true" {
		source = "coolify"
		composeProject = labels["coolify.projectName"]
		composeService = labels["coolify.serviceName"]
		coolifyName = labels["coolify.name"]
		return
	}
	if labels["com.docker.compose.project"] != "" {
		source = "docker-compose"
		composeProject = labels["com.docker.compose.project"]
		composeService = labels["com.docker.compose.service"]
		return
	}
	source = "manual"
	return
}

// ParseContainerHealth returns a clean health string from a raw health value.
func ParseContainerHealth(health any) string {
	if health == nil {
		return ""
	}
	switch v := health.(type) {
	case string:
		return strings.TrimPrefix(v, "health_status: ")
	case map[string]any:
		if s, ok := v["Status"].(string); ok {
			return s
		}
	}
	return ""
}

func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

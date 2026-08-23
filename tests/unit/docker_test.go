package unit

import (
	"testing"

	"domainsentinel/internal/scanner"
)

func TestExtractDockerSource(t *testing.T) {
	tests := []struct {
		name            string
		labels          map[string]string
		wantSource      string
		wantProject     string
		wantService     string
		wantCoolifyName string
	}{
		{
			name: "Coolify managed",
			labels: map[string]string{
				"coolify.managed":     "true",
				"coolify.projectName": "mongithub",
				"coolify.serviceName": "mescourses",
				"coolify.name":        "mescourses",
			},
			wantSource:      "coolify",
			wantProject:     "mongithub",
			wantService:     "mescourses",
			wantCoolifyName: "mescourses",
		},
		{
			name: "Docker Compose",
			labels: map[string]string{
				"com.docker.compose.project": "authentik",
				"com.docker.compose.service": "server",
			},
			wantSource:  "docker-compose",
			wantProject: "authentik",
			wantService: "server",
		},
		{
			name:       "Manual / no labels",
			labels:     map[string]string{},
			wantSource: "manual",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, project, service, coolifyName := scanner.ExtractDockerSource(tt.labels)
			if source != tt.wantSource {
				t.Errorf("source = %q, want %q", source, tt.wantSource)
			}
			if project != tt.wantProject {
				t.Errorf("project = %q, want %q", project, tt.wantProject)
			}
			if service != tt.wantService {
				t.Errorf("service = %q, want %q", service, tt.wantService)
			}
			if coolifyName != tt.wantCoolifyName {
				t.Errorf("coolifyName = %q, want %q", coolifyName, tt.wantCoolifyName)
			}
		})
	}
}

func TestExtractTraefikRouters(t *testing.T) {
	tests := []struct {
		name        string
		container   scanner.ContainerInfo
		wantRouters int
		wantNames   []string
		wantTLS     []bool
	}{
		{
			name: "Simple router with TLS",
			container: scanner.ContainerInfo{
				Name: "beszel",
				Labels: map[string]string{
					"traefik.enable":                                        "true",
					"traefik.http.routers.beszel.rule":                      "Host(`stats.techsentinel.fr`)",
					"traefik.http.routers.beszel.entrypoints":               "web",
					"traefik.http.routers.beszel.tls":                       "true",
					"traefik.http.services.beszel.loadbalancer.server.port": "8090",
				},
			},
			wantRouters: 1,
			wantNames:   []string{"beszel"},
			wantTLS:     []bool{true},
		},
		{
			name: "Coolify app with HTTP + HTTPS routers",
			container: scanner.ContainerInfo{
				Name: "mescourses-container",
				Labels: map[string]string{
					"coolify.managed": "true",
					"traefik.http.routers.http-0-mescourses.entrypoints":                "web",
					"traefik.http.routers.http-0-mescourses.rule":                       "Host(`mescourses.techsentinel.fr`) && PathPrefix(`/`)",
					"traefik.http.routers.http-0-mescourses.middlewares":                "redirect-to-https",
					"traefik.http.routers.https-0-mescourses.entrypoints":               "websecure",
					"traefik.http.routers.https-0-mescourses.rule":                      "Host(`mescourses.techsentinel.fr`) && PathPrefix(`/`)",
					"traefik.http.routers.https-0-mescourses.tls":                       "true",
					"traefik.http.services.https-0-mescourses.loadbalancer.server.port": "3000",
				},
			},
			wantRouters: 2,
			// Order is non-deterministic (map iteration), so we check by name in test
			wantNames: []string{"http-0-mescourses", "https-0-mescourses"},
			wantTLS:   []bool{false, true},
		},
		{
			name: "No traefik labels",
			container: scanner.ContainerInfo{
				Name:   "redis",
				Labels: map[string]string{},
			},
			wantRouters: 0,
		},
		{
			name: "Auth router",
			container: scanner.ContainerInfo{
				Name: "authentik-server",
				Labels: map[string]string{
					"traefik.http.routers.authentik.rule":                    "Host(`auth.techsentinel.fr`)",
					"traefik.http.routers.authentik.entrypoints":             "websecure",
					"traefik.http.routers.authentik.tls":                     "true",
					"traefik.http.routers.authentik.middlewares":             "authentik",
					"traefik.http.middlewares.authentik.forwardauth.address": "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik",
				},
			},
			wantRouters: 1,
			wantNames:   []string{"authentik"},
			wantTLS:     []bool{true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routers := scanner.ExtractTraefikRouters(tt.container)
			if len(routers) != tt.wantRouters {
				t.Errorf("got %d routers, want %d: %+v", len(routers), tt.wantRouters, routers)
				return
			}
			// Build name → TLS map for order-independent checking
			tlsByName := make(map[string]bool)
			for _, r := range routers {
				tlsByName[r.Name] = r.TLS
			}
			for i, name := range tt.wantNames {
				if gotTLS, ok := tlsByName[name]; !ok {
					t.Errorf("router %q not found", name)
				} else if gotTLS != tt.wantTLS[i] {
					t.Errorf("router %q.TLS = %v, want %v", name, gotTLS, tt.wantTLS[i])
				}
			}
		})
	}
}

func TestParseContainerHealth(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"health_status: healthy", "healthy"},
		{"health_status: unhealthy", "unhealthy"},
		// Non-health strings pass through as-is
		{"running", "running"},
		{"exited (0)", "exited (0)"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := scanner.ParseContainerHealth(tt.input)
			if got != tt.expected {
				t.Errorf("ParseContainerHealth(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

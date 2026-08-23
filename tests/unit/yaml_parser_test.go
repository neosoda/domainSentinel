package unit

import (
	"strings"
	"testing"

	"domainsentinel/internal/scanner"
)

func TestParseTraefikYAML(t *testing.T) {
	yamlContent := "http:\n" +
		"  routers:\n" +
		"    appwrite:\n" +
		"      rule: \"Host(`appwrite.techsentinel.fr`) || Host(`appwrite-functions.techsentinel.fr`)\"\n" +
		"      entryPoints:\n" +
		"        - web\n" +
		"      service: appwrite-backend01\n" +
		"      middlewares:\n" +
		"        - authentik@docker\n" +
		"        - gzip\n" +
		"    coolify-web:\n" +
		"      rule: \"Host(`coolify.techsentinel.fr`)\"\n" +
		"      entryPoints:\n" +
		"        - web\n" +
		"        - websecure\n" +
		"      service: coolify\n" +
		"      tls:\n" +
		"        certResolver: letsencrypt\n"

	entries := scanner.ParseTraefikYAML(yamlContent, "test.yml")

	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	entryMap := make(map[string]scanner.TraefikFileEntry)
	for _, e := range entries {
		entryMap[e.RouterName] = e
	}

	appwrite, ok := entryMap["appwrite"]
	if !ok {
		t.Fatalf("appwrite router not found in parsed entries")
	}
	if !strings.Contains(appwrite.Source, "test.yml") {
		t.Errorf("Source = %q, want to contain test.yml", appwrite.Source)
	}
	if appwrite.Service != "appwrite-backend01" {
		t.Errorf("Service = %q, want appwrite-backend01", appwrite.Service)
	}
	if len(appwrite.Middlewares) != 2 || appwrite.Middlewares[0] != "authentik@docker" {
		t.Errorf("Middlewares = %v, want [authentik@docker gzip]", appwrite.Middlewares)
	}
	if len(appwrite.Entrypoints) != 1 || appwrite.Entrypoints[0] != "web" {
		t.Errorf("Entrypoints = %v, want [web]", appwrite.Entrypoints)
	}

	coolify, ok := entryMap["coolify-web"]
	if !ok {
		t.Fatalf("coolify-web router not found in parsed entries")
	}
	if !coolify.TLS {
		t.Errorf("coolify.TLS = false, want true")
	}
	if len(coolify.Entrypoints) != 2 {
		t.Errorf("coolify.Entrypoints = %v, want [web websecure]", coolify.Entrypoints)
	}
}

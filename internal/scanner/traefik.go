package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	// Parses content inside Host(...) — handles backtick, double-quote, or unquoted
	hostRegex = regexp.MustCompile(`(?i)Host\(([^)]+)\)`)

	// Parses sub-parts of complex rules: Host(`x`) && PathPrefix(`/y`)
	rulePartRegex = regexp.MustCompile(`(?i)(Host|PathPrefix|Path)\(([^)]+)\)`)
)

// TraefikFileScanner parses Traefik dynamic config YAML files.
type TraefikFileScanner struct {
	dir string
}

// NewTraefikFileScanner creates a scanner for the dynamic config directory.
func NewTraefikFileScanner(dir string) *TraefikFileScanner {
	return &TraefikFileScanner{dir: dir}
}

// TraefikFileEntry represents a router parsed from a YAML file.
type TraefikFileEntry struct {
	RouterName  string
	Rule        string
	Entrypoints []string
	Service     string
	Middlewares []string
	TLS         bool
	Source      string
}

// Scan reads all *.yml/*.yaml files in the dynamic directory.
func (s *TraefikFileScanner) Scan() ([]TraefikFileEntry, error) {
	if s.dir == "" {
		return nil, nil
	}

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("read traefik dynamic dir: %w", err)
	}

	var allEntries []TraefikFileEntry
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		if strings.HasSuffix(name, ".bak") {
			continue
		}

		path := filepath.Join(s.dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		parsed := ParseTraefikYAML(string(data), name)
		allEntries = append(allEntries, parsed...)
	}

	return allEntries, nil
}

type traefikYAMLDoc struct {
	HTTP struct {
		Routers map[string]struct {
			Rule        string `yaml:"rule"`
			EntryPoints any    `yaml:"entryPoints"`
			Service     string `yaml:"service"`
			Middlewares any    `yaml:"middlewares"`
			TLS         any    `yaml:"tls"`
		} `yaml:"routers"`
	} `yaml:"http"`
}

// ParseTraefikYAML parses Traefik dynamic configuration from YAML.
func ParseTraefikYAML(content string, filename string) []TraefikFileEntry {
	var doc traefikYAMLDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}

	var entries []TraefikFileEntry
	for name, r := range doc.HTTP.Routers {
		if r.Rule == "" {
			continue
		}
		entries = append(entries, TraefikFileEntry{
			RouterName:  name,
			Rule:        r.Rule,
			Entrypoints: parseYAMLStringSlice(r.EntryPoints),
			Service:     r.Service,
			Middlewares: parseYAMLStringSlice(r.Middlewares),
			TLS:         parseYAMLTLS(r.TLS),
			Source:      "file:" + filename,
		})
	}
	return entries
}

func parseYAMLStringSlice(val any) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		return splitComma(v)
	case []any:
		var res []string
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				res = append(res, strings.TrimSpace(s))
			}
		}
		return res
	case []string:
		return v
	}
	return nil
}

func parseYAMLTLS(val any) bool {
	if val == nil {
		return false
	}
	switch v := val.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "{}"
	case map[string]any, map[any]any:
		return true
	}
	return true
}

// ExtractHostnamesFromRule extracts all Host() FQDNs from a Traefik rule string.
// Handles: Host(`x.fr`), Host(`x.fr`,`y.fr`), Host(`x.fr`) && PathPrefix(`/api`)
func ExtractHostnamesFromRule(rule string) []string {
	var hosts []string
	matches := hostRegex.FindAllStringSubmatch(rule, -1)
	for _, m := range matches {
		// m[1] contains the comma-separated hosts inside Host()
		inner := strings.Trim(m[1], "`\" ")
		for _, h := range splitComma(inner) {
			h = strings.TrimSpace(h)
			// Remove surrounding backticks or double quotes
			h = strings.Trim(h, "`\"")
			if h != "" {
				hosts = append(hosts, strings.ToLower(h))
			}
		}
	}
	return hosts
}

// IsValidDomain returns true if the string looks like a valid FQDN literal.
func IsValidDomain(s string) bool {
	if s == "" {
		return false
	}
	// Reject regex patterns, template variables, and unquoted values
	if strings.ContainsAny(s, "{}$^|\\") ||
		strings.Contains(s, "regexp") ||
		strings.Contains(s, "[a-zA-Z]") ||
		strings.Contains(s, " ") {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 63 {
			return false
		}
		// Each label must start/end with alphanumeric
		r := []rune(p)
		if !isAlnum(r[0]) || !isAlnum(r[len(r)-1]) {
			return false
		}
	}
	return true
}

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

// ExtractSimpleHostnames is more conservative — only extracts literal domains.
func ExtractSimpleHostnames(rule string, zoneName string) []string {
	var hosts []string
	for _, h := range ExtractHostnamesFromRule(rule) {
		if IsValidDomain(h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

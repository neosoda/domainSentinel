package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

		parsed := parseTraefikYAML(string(data), name)
		allEntries = append(allEntries, parsed...)
	}

	return allEntries, nil
}

// Simple YAML parser for Traefik dynamic config files.
// Handles the known structure without a full YAML library dependency.
type yamlKV struct {
	key   string
	value string
}

func parseTraefikYAML(content string, filename string) []TraefikFileEntry {
	var entries []TraefikFileEntry

	lines := strings.Split(content, "\n")
	var currentRouter *TraefikFileEntry
	var routerIndent int // indentation level of current router name

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Compute raw indentation (tabs → 4 spaces)
		spaces := countIndent(rawLine)

		// Skip top-level keys like "http:", "tcp:", "udp:"
		if spaces == 0 && strings.HasSuffix(line, ":") {
			currentRouter = nil // reset on new top-level section
			continue
		}

		// Router names appear at "routers:" indent + 2 (e.g. 4 spaces)
		if strings.HasSuffix(line, ":") && !strings.Contains(line, ": ") {
			// Save previous router
			if currentRouter != nil && currentRouter.Rule != "" {
				entries = append(entries, *currentRouter)
			}
			name := strings.TrimSuffix(line, ":")
			currentRouter = &TraefikFileEntry{RouterName: name, Source: "file:" + filename}
			routerIndent = spaces
			continue
		}

		if currentRouter == nil {
			continue
		}

		// Properties inside router block: indented more than the router name
		if spaces > routerIndent {
			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			val := strings.TrimSpace(kv[1])
			val = strings.Trim(val, "\"' ")

			switch key {
			case "rule":
				currentRouter.Rule = val
			case "entrypoints":
				currentRouter.Entrypoints = splitComma(val)
			case "service":
				currentRouter.Service = val
			case "tls":
				currentRouter.TLS = val == "true" || val == "{}"
			case "middlewares":
				currentRouter.Middlewares = splitComma(val)
			}
		}
	}

	// Save last router
	if currentRouter != nil && currentRouter.Rule != "" {
		entries = append(entries, *currentRouter)
	}

	return entries
}

// countIndent returns the number of leading spaces (tabs counted as 4 spaces).
func countIndent(s string) int {
	n := 0
	for _, c := range s {
		if c == '\t' {
			n += 4
		} else if c == ' ' {
			n++
		} else {
			break
		}
	}
	return n
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

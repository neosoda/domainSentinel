package unit

import (
	"testing"

	"domainsentinel/internal/scanner"
)

func TestExtractHostnamesFromRule(t *testing.T) {
	tests := []struct {
		name     string
		rule     string
		expected []string
	}{
		{
			name:     "simple Host",
			rule:     "Host(`stats.techsentinel.fr`)",
			expected: []string{"stats.techsentinel.fr"},
		},
		{
			name:     "Host with double quotes",
			rule:     `Host("auth.techsentinel.fr")`,
			expected: []string{"auth.techsentinel.fr"},
		},
		{
			name:     "multiple hosts",
			rule:     "Host(`a.techsentinel.fr`,`b.techsentinel.fr`)",
			expected: []string{"a.techsentinel.fr", "b.techsentinel.fr"},
		},
		{
			name:     "Host with PathPrefix",
			rule:     "Host(`example.techsentinel.fr`) && PathPrefix(`/api`)",
			expected: []string{"example.techsentinel.fr"},
		},
		{
			name:     "complex rule with Path",
			rule:     "Host(`supabase.techsentinel.fr`) && (PathPrefix(`/auth/v1`) || PathPrefix(`/rest/v1`))",
			expected: []string{"supabase.techsentinel.fr"},
		},
		{
			name:     "mixed case Host",
			rule:     "HOST(`Test.TechSentinel.FR`)",
			expected: []string{"test.techsentinel.fr"},
		},
		{
			name:     "regex pattern — skipped",
			rule:     "HostRegexp(`^[a-zA-Z0-9-]+\\.appwrite-functions\\.techsentinel\\.fr$`)",
			expected: nil, // regex patterns should be filtered
		},
		{
			name:     "empty rule",
			rule:     "",
			expected: nil,
		},
		{
			name:     "rule with variables — treated as valid domain by basic parser",
			rule:     "Host(`{subdomain}.techsentinel.fr`)",
			expected: []string{"{subdomain}.techsentinel.fr"}, // basic host extraction, validation is caller responsibility
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanner.ExtractHostnamesFromRule(tt.rule)
			if len(got) != len(tt.expected) {
				t.Errorf("got %v (%d items), want %v (%d items)", got, len(got), tt.expected, len(tt.expected))
				return
			}
			for i, v := range got {
				if v != tt.expected[i] {
					t.Errorf("got[%d]=%q, want[%d]=%q", i, v, i, tt.expected[i])
				}
			}
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"stats.techsentinel.fr", true},
		{"auth.techsentinel.fr", true},
		{"appwrite.techsentinel.fr", true},
		{"a.b.c.techsentinel.fr", true},
		{"", false},
		{"techsentinel.fr", true}, // root zone is a valid FQDN
		{"^[a-z]+\\.techsentinel.fr$", false},
		{"{sub}.techsentinel.fr", false},
		{"with space .techsentinel.fr", false},
		{".techsentinel.fr", false},
		{"a.", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := scanner.IsValidDomain(tt.input)
			if got != tt.expected {
				t.Errorf("IsValidDomain(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractSimpleHostnames(t *testing.T) {
	zone := "techsentinel.fr"

	tests := []struct {
		name     string
		rule     string
		expected []string
	}{
		{
			name:     "simple valid host",
			rule:     "Host(`beszel.techsentinel.fr`)",
			expected: []string{"beszel.techsentinel.fr"},
		},
		{
			name:     "regex pattern filtered",
			rule:     "HostRegexp(`^[a-zA-Z0-9-]+\\.appwrite-functions\\.techsentinel\\.fr$`)",
			expected: nil,
		},
		{
			name:     "variable pattern filtered",
			rule:     "Host(`{sub}.techsentinel.fr`)",
			expected: nil,
		},
		{
			name:     "mixed valid and invalid",
			rule:     "Host(`valid.techsentinel.fr`,`{var}.techsentinel.fr`)",
			expected: []string{"valid.techsentinel.fr"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanner.ExtractSimpleHostnames(tt.rule, zone)
			if len(got) != len(tt.expected) {
				t.Errorf("got %v, want %v", got, tt.expected)
			}
		})
	}
}

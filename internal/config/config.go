package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	// App
	Host      string
	Port      string
	DataDir   string
	ConfigDir string
	LogLevel  string

	// Cloudflare
	CloudflareToken    string
	CloudflareZoneName string // e.g. "techsentinel.fr"
	CloudflareTimeoutS int

	// Docker
	DockerHost     string // e.g. "http://docker-proxy:2375"
	DockerTimeoutS int

	// Traefik dynamic config (mounted read-only)
	TraefikDynamicDir string

	// Healthcheck
	HealthcheckTimeoutS    int
	HealthcheckConcurrency int
	HealthcheckIntervalS   int

	// Scanner
	ScannerIntervalS int

	// History retention
	HistoryRetentionDays int

	// Server names (known hosts)
	KnownHosts map[string]string // IP → name e.g. "192.168.1.201" → "BACKEND01"
}

func Load() *Config {
	return &Config{
		Host:                   env("DS_HOST", "0.0.0.0"),
		Port:                   env("DS_PORT", "3000"),
		DataDir:                env("DS_DATA_DIR", "/data"),
		ConfigDir:              env("DS_CONFIG_DIR", "/config"),
		LogLevel:               env("DS_LOG_LEVEL", "INFO"),
		CloudflareToken:        os.Getenv("CLOUDFLARE_TOKEN"),
		CloudflareZoneName:     env("CLOUDFLARE_ZONE_NAME", "techsentinel.fr"),
		CloudflareTimeoutS:     intEnv("CLOUDFLARE_TIMEOUT_S", 15),
		DockerHost:             env("DOCKER_HOST", "http://docker-proxy:2375"),
		DockerTimeoutS:         intEnv("DOCKER_TIMEOUT_S", 10),
		TraefikDynamicDir:      env("TRAEFIK_DYNAMIC_DIR", "/traefik-dynamic"),
		HealthcheckTimeoutS:    intEnv("HEALTHCHECK_TIMEOUT_S", 10),
		HealthcheckConcurrency: intEnv("HEALTHCHECK_CONCURRENCY", 10),
		HealthcheckIntervalS:   intEnv("HEALTHCHECK_INTERVAL_S", 60),
		ScannerIntervalS:       intEnv("SCANNER_INTERVAL_S", 30),
		HistoryRetentionDays:   intEnv("HISTORY_RETENTION_DAYS", 30),
		KnownHosts: map[string]string{
			"192.168.1.200": "NEOSERVER",
			"192.168.1.201": "BACKEND01",
		},
	}
}

func (c *Config) HealthcheckTimeout() time.Duration {
	return time.Duration(c.HealthcheckTimeoutS) * time.Second
}

func (c *Config) ScannerInterval() time.Duration {
	return time.Duration(c.ScannerIntervalS) * time.Second
}

func (c *Config) HealthcheckInterval() time.Duration {
	return time.Duration(c.HealthcheckIntervalS) * time.Second
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

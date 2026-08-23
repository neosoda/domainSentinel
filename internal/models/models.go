package models

import (
	"time"
)

// ── Normalized Domain Entry ─────────────────────────────────────────────────

type DomainEntry struct {
	FQDN      string    `json:"fqdn"`
	Domain    string    `json:"domain"`
	Subdomain string    `json:"subdomain"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	LastCheck time.Time `json:"last_check"`
	Host      string    `json:"host"` // NEOSERVER, BACKEND01, etc.

	DNS     DNSSnapshot     `json:"dns"`
	Traefik TraefikSnapshot `json:"traefik"`
	Docker  DockerSnapshot  `json:"docker"`
	HTTP    HTTPSnapshot    `json:"http"`

	Status    Status    `json:"status"`
	Anomalies []Anomaly `json:"anomalies"`
}

// ── DNS ─────────────────────────────────────────────────────────────────────

type DNSSnapshot struct {
	Exists   bool   `json:"exists"`
	Type     string `json:"type"` // A, AAAA, CNAME
	Target   string `json:"target"`
	Proxied  bool   `json:"proxied"` // Cloudflare proxy (orange/cloud)
	TTL      int    `json:"ttl"`
	RecordID string `json:"record_id"`
}

// ── Traefik ─────────────────────────────────────────────────────────────────

type TraefikSnapshot struct {
	Exists          bool     `json:"exists"`
	RouterNames     []string `json:"router_names"` // one FQDN can have multiple routers
	Entrypoints     []string `json:"entrypoints"`  // web, websecure
	TLS             bool     `json:"tls"`
	MiddlewareNames []string `json:"middleware_names"`
	HasAuthentik    bool     `json:"has_authentik"`
	ServiceName     string   `json:"service_name"`
	Sources         []string `json:"sources"` // "docker", "file:coolify.yml", etc.
}

// ── Docker ──────────────────────────────────────────────────────────────────

type DockerSnapshot struct {
	ContainerID    string            `json:"container_id"`
	ContainerName  string            `json:"container_name"`
	Image          string            `json:"image"`
	Status         string            `json:"status"` // running, exited, paused
	Health         string            `json:"health"` // healthy, unhealthy, ""
	Networks       []string          `json:"networks"`
	Labels         map[string]string `json:"labels"`
	Source         string            `json:"source"` // coolify, docker-compose, manual
	ComposeProject string            `json:"compose_project"`
	ComposeService string            `json:"compose_service"`
	CoolifyName    string            `json:"coolify_name"`
}

// ── HTTP ────────────────────────────────────────────────────────────────────

type HTTPSnapshot struct {
	StatusCode  int        `json:"status_code"`
	LatencyMs   int        `json:"latency_ms"`
	TLSValid    bool       `json:"tls_valid"`
	TLSExpireAt *time.Time `json:"tls_expire_at,omitempty"`
	Redirects   []string   `json:"redirects,omitempty"`
	Error       string     `json:"error,omitempty"` // network error, timeout, etc.
	IsUp        bool       `json:"is_up"`           // considered "up" per status classification
}

var (
	// HTTP codes considered "up" even if not 200
	ValidUpStatuses = map[int]bool{
		200: true, 204: true, 301: true, 302: true,
		401: true, // expected for protected endpoints
		403: true, // service works but denies anonymous access
	}
)

func IsHTTPUp(code int) bool { return ValidUpStatuses[code] }

// ── Status ─────────────────────────────────────────────────────────────────

type Status string

const (
	StatusOK      Status = "OK"
	StatusDown    Status = "DOWN"
	StatusAnomaly Status = "ANOMALY"
	StatusUnknown Status = "UNKNOWN"
)

func (s Status) Color() string {
	switch s {
	case StatusOK:
		return "green"
	case StatusDown:
		return "red"
	case StatusAnomaly:
		return "yellow"
	default:
		return "gray"
	}
}

func (s Status) Label() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusDown:
		return "DOWN"
	case StatusAnomaly:
		return "⚠ Anomalie"
	default:
		return "?"
	}
}

// ── Anomalies ────────────────────────────────────────────────────────────────

type Anomaly struct {
	Type     AnomalyType `json:"type"`
	Message  string      `json:"message"`
	Severity Severity    `json:"severity"`
}

type AnomalyType string

const (
	AnomalyDNSOrphan     AnomalyType = "DNS_ORPHAN"
	AnomalyMissingDNS    AnomalyType = "MISSING_DNS"
	AnomalyServiceDown   AnomalyType = "SERVICE_DOWN"
	AnomalyContainerDown AnomalyType = "CONTAINER_DOWN"
	AnomalyUnhealthy     AnomalyType = "UNHEALTHY"
	AnomalyTLSError      AnomalyType = "TLS_ERROR"
	AnomalyHTTPError     AnomalyType = "HTTP_ERROR"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarning  Severity = "warning"
	SeverityInfo     Severity = "info"
)

func (a AnomalyType) Message(fqdn string) string {
	switch a {
	case AnomalyDNSOrphan:
		return fqdn + " : DNS présent mais aucune route Traefik correspondante"
	case AnomalyMissingDNS:
		return fqdn + " : route Traefik présente mais aucun DNS correspondant"
	case AnomalyServiceDown:
		return fqdn + " : DNS + Traefik OK mais endpoint HTTP inacessible"
	case AnomalyContainerDown:
		return fqdn + " : conteneur Docker arrêté"
	case AnomalyUnhealthy:
		return fqdn + " : conteneur Docker unhealthy"
	case AnomalyTLSError:
		return fqdn + " : certificat TLS invalide ou expiré"
	case AnomalyHTTPError:
		return fqdn + " : erreur HTTP inattendue"
	default:
		return string(a) + " sur " + fqdn
	}
}

// ── History ─────────────────────────────────────────────────────────────────

type HistoryEntry struct {
	ID        int64
	FQDN      string
	Status    Status
	Anomalies string // JSON array
	CheckedAt time.Time
}

// ── Annotation (local) ─────────────────────────────────────────────────────

type Annotation struct {
	FQDN        string `json:"fqdn"`
	Description string `json:"description"`
	Criticality string `json:"criticality"` // low, medium, high
	Owner       string `json:"owner"`
	Notes       string `json:"notes"`
	Tags        string `json:"tags"` // comma-separated
}

// ── Dashboard Summary ───────────────────────────────────────────────────────

type DashboardSummary struct {
	Total       int            `json:"total"`
	OK          int            `json:"ok"`
	Down        int            `json:"down"`
	Anomalies   int            `json:"anomalies"`
	LastScan    *time.Time     `json:"last_scan"`
	AnomalyList []AnomalyEntry `json:"anomaly_list"`
}

type AnomalyEntry struct {
	FQDN     string      `json:"fqdn"`
	Type     AnomalyType `json:"type"`
	Severity Severity    `json:"severity"`
}

// ── Raw scanned data ────────────────────────────────────────────────────────

type CloudflareRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

type TraefikRouter struct {
	Name        string   `json:"name"`
	Rule        string   `json:"rule"`
	Entrypoints []string `json:"entrypoints"`
	Service     string   `json:"service"`
	Middlewares []string `json:"middlewares"`
	TLS         bool     `json:"tls"`
	Source      string   `json:"source"` // "docker" or "file"
}

// ── Annotation helpers ─────────────────────────────────────────────────────

type AnnotationPatch struct {
	Description string `json:"description"`
	Criticality string `json:"criticality"`
	Owner       string `json:"owner"`
	Notes       string `json:"notes"`
	Tags        string `json:"tags"`
}

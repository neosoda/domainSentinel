# DomainSentinel — API

## Authentication

L'API n'est **pas** authentifiée individuellement. L'application est protégée par **Authentik ForwardAuth** au niveau de Traefik. Tous les endpoints sont accessibles uniquement aux utilisateurs authentifiés via `domains.techsentinel.fr`.

## Endpoints

### `GET /api/v1/domains`

Retourne la liste de tous les domaines跟踪és.

**Réponse** `200 OK`:
```json
[
  {
    "fqdn": "stats.techsentinel.fr",
    "domain": "techsentinel.fr",
    "subdomain": "stats",
    "host": "NEOSERVER",
    "dns": { "exists": true, "type": "CNAME", "proxied": true, ... },
    "traefik": { "exists": true, "tls": true, "has_authentik": true, ... },
    "docker": { "container_name": "beszel", "source": "docker-compose", ... },
    "http": { "status_code": 200, "latency_ms": 74, "tls_valid": true, "is_up": true },
    "status": "OK",
    "anomalies": []
  }
]
```

### `GET /api/v1/domains/{fqdn}`

Détail d'un domaine spécifique.

### `GET /api/v1/anomalies`

Liste plate de toutes les anomalies actives.

### `GET /api/v1/status` / `GET /api/v1/summary`

Résumé du tableau de bord.

```json
{
  "total": 42,
  "ok": 39,
  "down": 1,
  "anomalies": 2,
  "last_scan": "2026-08-21T12:30:00Z",
  "anomaly_list": [
    { "fqdn": "old.techsentinel.fr", "type": "DNS_ORPHAN", "severity": "warning" }
  ]
}
```

### `POST /api/v1/refresh`

Déclenche un scan complet immédiat. Retourne `202 Accepted`.

### `PATCH /api/v1/domains/{fqdn}/annotation`

Met à jour l'annotation locale.

**Body**:
```json
{
  "description": "Supervision Beszel",
  "criticality": "low",
  "owner": "neo",
  "notes": "Ne pas supprimer",
  "tags": "monitoring, infra"
}
```

### `GET /metrics`

Métriques Prometheus.

```
domainsentinel_domains_total 42
domainsentinel_domains_up 39
domainsentinel_domains_down 1
domainsentinel_anomalies_total 2
domainsentinel_last_scan_timestamp 1724249400
```

### `GET /health`

Healthcheck simple. Retourne `200 OK` avec `OK` dans le body.

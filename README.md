# 🔭 DomainSentinel

**Live inventory of every domain, subdomain and service running on your Docker / Traefik / Cloudflare stack.**

DomainSentinel automatically cross-references four sources to give you a single, consistent view of your infrastructure:

```
   Cloudflare DNS  ←→  Traefik  ←→  Docker  ←→  HTTP / TLS
```

It detects **DNS orphans**, **routes without DNS**, **stopped containers**, **unhealthy apps**, **expired TLS certificates**, and **unprotected admin interfaces** — and shows it all in a dark-mode dashboard with zero SaaS, zero Kubernetes, zero heavy database.

| | |
|---|---|
| ![Dashboard](docs/img/dashboard.png) | ![Detail](docs/img/detail.png) |
| *(Add a screenshot of the dashboard)* | *(Add a screenshot of a domain detail page)* |

---

## ✨ Features

- ✅ **Read-only Cloudflare DNS** — list all records, detect orphans
- ✅ **Traefik route discovery** — Docker labels + dynamic YAML files (`/opt/traefik/dynamic/`)
- ✅ **Container correlation** — match a route to its container, image, network
- ✅ **Coolify vs Docker Compose** auto-detection
- ✅ **HTTP/TLS healthchecks** — code, latency, cert expiry
- ✅ **Authentik ForwardAuth** detection
- ✅ **Anomaly engine** — `DNS_ORPHAN`, `MISSING_DNS`, `CONTAINER_DOWN`, `UNHEALTHY`, `TLS_ERROR`
- ✅ **Local annotations** — description, criticality, owner, tags, notes (per FQDN)
- ✅ **30-day history** with automatic cleanup
- ✅ **REST API** for Homepage / dashboards / scripts
- ✅ **Prometheus metrics** at `/metrics`
- ✅ **Dark mode dashboard** — server-side Go templates + htmx + Alpine.js, no SPA
- ✅ **Container hardening** — `read_only: true`, `cap_drop: ALL`, `no-new-privileges`, non-root user

❌ **What it doesn't do** (by design): write to Cloudflare, restart containers, modify Traefik, expose public ports, or call home.

---

## 🏗 Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Cloudflare API │    │  Docker socket  │    │ Traefik dynamic │
│   (read-only)   │    │  (read-only)    │    │   YAML files    │
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         │                      │                      │
         └──────────┬───────────┴──────────┬───────────┘
                    ▼                      ▼
              ┌──────────────────────────────────┐
              │           Correlator            │
              │  (merge FQDNs across sources)   │
              └─────────────┬────────────────────┘
                            ▼
              ┌──────────────────────────────────┐
              │  SQLite (WAL) + annotations     │
              └─────────────┬────────────────────┘
                            ▼
              ┌──────────────────────────────────┐
              │  HTTP API + Dashboard (Go html)  │
              └──────────────────────────────────┘
                            ▲
                            │
                  ┌─────────┴──────────┐
                  │  Traefik + Authentik│
                  │  ForwardAuth       │
                  └────────────────────┘
```

**Tech stack** : Go 1.23 · SQLite (WAL) · chi (router) · mattn/go-sqlite3 · robfig/cron · htmx 1.9 · Alpine.js 3.14

---

## 📦 Installation

### Option A — Docker Compose (recommended)

```bash
# 1. Clone
git clone https://github.com/techsentinel/domainsentinel.git
cd domainsentinel

# 2. Configure
cp .env.example .env
nano .env  # set CLOUDFLARE_TOKEN

# 3. Build & start
docker compose up -d --build

# 4. Follow logs
docker compose logs -f
```

### Option B — Coolify (one-click)

See [`docs/COOLIFY.md`](docs/COULIFY.md) for the full procedure (Docker Compose, environment variables, persistent storage, Traefik labels).

### Option C — From source

```bash
go install github.com/go-chi/chi/v5@latest
go mod download
go run .
```

The server listens on `:3000` by default. See [Configuration](#-configuration) below.

---

## ⚙️ Configuration

All configuration is read from environment variables. See [`.env.example`](.env.example) for the full list.

| Variable | Default | Description |
|----------|---------|-------------|
| `CLOUDFLARE_TOKEN` | *(empty)* | Read-only API token (`Zone / DNS : Read`) |
| `CLOUDFLARE_ZONE_NAME` | `techsentinel.fr` | Zone to inventory |
| `CLOUDFLARE_TIMEOUT_S` | `15` | API call timeout (seconds) |
| `DS_HOST` | `0.0.0.0` | Listen address |
| `DS_PORT` | `3000` | Listen port |
| `DS_DATA_DIR` | `/data` | SQLite directory |
| `DS_CONFIG_DIR` | `/config` | Annotations directory |
| `DS_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `DOCKER_HOST` | `unix:///var/run/docker.sock` | Or `tcp://socket-proxy:2375` |
| `DOCKER_TIMEOUT_S` | `10` | Docker API call timeout |
| `TRAEFIK_DYNAMIC_DIR` | `/traefik-dynamic` | Path to Traefik YAML files |
| `SCANNER_INTERVAL_S` | `30` | Full scan interval |
| `HEALTHCHECK_TIMEOUT_S` | `10` | HTTP check timeout |
| `HEALTHCHECK_CONCURRENCY` | `10` | Parallel HTTP checks |
| `HEALTHCHECK_INTERVAL_S` | `60` | Healthcheck interval |
| `HISTORY_RETENTION_DAYS` | `30` | History retention |

---

## 🔌 Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard (HTML) |
| `/domain/{fqdn}` | GET | Domain detail page (HTML) |
| `/api/v1/domains` | GET | List all FQDNs (JSON) |
| `/api/v1/domains/{fqdn}` | GET | One FQDN (JSON) |
| `/api/v1/anomalies` | GET | List of detected anomalies (JSON) |
| `/api/v1/status` | GET | Summary counters (JSON) |
| `/api/v1/summary` | GET | Same as `/api/v1/status` |
| `/api/v1/refresh` | POST | Trigger an immediate scan |
| `/api/v1/domains/{fqdn}/annotation` | PATCH | Update local annotation |
| `/metrics` | GET | Prometheus metrics |
| `/health` | GET | Liveness probe (`OK`) |

Full OpenAPI-style docs: [`docs/API.md`](docs/API.md).

---

## 🔐 Security

DomainSentinel is **read-only by design**. See [`SECURITY.md`](SECURITY.md) for the full security policy and threat model.

Highlights:

- **No write access** to Cloudflare, Traefik, Docker, Coolify, or Authentik
- **No public port** — only the `proxy` Docker network is attached
- **Container hardening** : `read_only: true`, `cap_drop: ALL`, `no-new-privileges`, tmpfs for `/tmp`
- **Non-root user** (UID 1000) with supplementary `docker` group (GID 984) for socket access
- **Token never logged** — and never committed (the repo's `.gitignore` excludes `.env`)
- **Authentik ForwardAuth** — no built-in auth, relies on the existing reverse proxy SSO

For production deployments, consider adding a [Docker socket proxy](https://github.com/Tecnativa/docker-socket-proxy) (`GET /containers` and `GET /containers/{id}/json` only) instead of mounting the socket directly.

---

## 💾 Backup & restore

Everything lives in `data/domainsentinel.db` (SQLite, WAL mode).

```bash
# Backup
cp /opt/domainsentinel/data/domainsentinel.db ~/backups/ds-$(date +%Y%m%d).db

# Restore
cp ~/backups/ds-YYYYMMDD.db /opt/domainsentinel/data/domainsentinel.db
docker compose restart
```

For automated backups, use a tool like [`sqlitebackup`](https://github.com/benbjohnson/sqlitebackup) or `restic` against the `data/` directory.

---

## 🧪 Development

```bash
# Run locally
go run .

# Run tests
go test ./...

# Lint
go vet ./...
gofmt -l .

# Build Docker image
docker build -t domainsentinel:dev .
```

**Project structure** :

```
internal/
  api/         HTTP server, templates, middleware
  config/      env var loading
  correlator/  FQDN merge + anomaly detection
  db/          SQLite, migrations
  healthcheck/ HTTP/TLS checker
  models/      domain types
  scanner/     Cloudflare / Docker / Traefik readers
tests/unit/    unit tests (no real infra)
web/
  static/      htmx.min.js, alpine.min.js, style.css
  templates/   index.html, detail.html
```

---

## 🤝 Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The project follows [Conventional Commits](https://www.conventionalcommits.org/).

---

## 📜 License

[MIT](LICENSE) — Neo Soda / TechSentinel, 2026.

---

## 🙏 Acknowledgements

- [Traefik](https://traefik.io/) for the routing engine we read from
- [Authentik](https://goauthentik.io/) for the SSO middleware
- [Coolify](https://coolify.io/) for the deployment platform
- [htmx](https://htmx.org/) and [Alpine.js](https://alpinejs.dev/) for keeping the dashboard lightweight
- [SQLite](https://sqlite.org/) for being the most reliable database in the world

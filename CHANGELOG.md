# Changelog

All notable changes to DomainSentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-08-21

### Added

- Initial public release
- Live inventory tool for domains and subdomains under `*.techsentinel.fr`
- Multi-source correlation: Cloudflare DNS, Traefik (Docker labels + file provider), Docker, HTTP/TLS
- Anomaly detection: `DNS_ORPHAN`, `MISSING_DNS`, `CONTAINER_DOWN`, `UNHEALTHY`, `TLS_ERROR`
- Dark-mode dashboard with search, filters and detail pages (server-side Go templates, no SPA)
- REST API: `/api/v1/domains`, `/api/v1/status`, `/api/v1/summary`, `/api/v1/anomalies`
- Per-domain annotations (description, criticality, owner, tags, notes) — local-only, stored in SQLite
- 30-day history with automatic cleanup
- Prometheus-compatible `/metrics` endpoint
- Authentik ForwardAuth protection (no built-in auth)
- Container hardening: `read_only: true`, `cap_drop: ALL`, `no-new-privileges`, non-root user
- Auto-detection of Docker source: Coolify vs Docker Compose
- Source field in detail page distinguishes `docker:<container>` vs `file:traefik-dynamic`
- Optional `docker-socket-proxy` support via `DOCKER_HOST` env var
- Tests: unit + integration, runnable without real infrastructure

### Security

- Read-only access to Docker socket (`:ro` mount) with non-root user
- All Cloudflare API calls are read-only (`GET` only)
- No write access to Traefik, Docker, Cloudflare, Coolify
- No secrets in logs, docker-compose, or source code
- SQLite database lives in volume mount, survives container recreation

### Notes

- Initial deployment target: `https://domains.techsentinel.fr` (Cloudflare Tunnel + Traefik + Authentik)
- Designed for single-server deployments; multi-server is out of scope for the MVP

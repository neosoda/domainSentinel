# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in DomainSentinel, please **do not** open a public GitHub issue.

Instead, report it privately:

- **Email** : security@techsentinel.fr (preferred)
- **GitHub Security Advisories** : [github.com/techsentinel/domainsentinel/security/advisories/new](https://github.com/techsentinel/domainsentinel/security/advisories/new)

You should receive an initial response within 48 hours. After triage, a CVE will be assigned if appropriate and a fix released as soon as practical.

## Security Architecture

DomainSentinel is designed with **defense in depth** :

1. **Read-only** by default — no write access to Cloudflare, Traefik, Docker, Coolify, Authentik
2. **Cloudflare API** — read-only token with minimum permissions (`Zone / DNS : Read`), scoped to a single zone
3. **Docker socket** — mounted `:ro` with non-root user (UID 1000) and supplementary `docker` group (GID 984)
4. **Container hardening** — `read_only: true`, `cap_drop: ALL`, `no-new-privileges`, tmpfs for `/tmp`
5. **Network isolation** — only the `proxy` Docker network is attached, no public port mapping
6. **TLS only** — Traefik handles HTTPS termination; the app itself listens on HTTP internally
7. **Authentik ForwardAuth** — no built-in auth, relies on the existing reverse proxy SSO
8. **No secrets in code** — token, DB and config live in volumes, never in the image

## Threat Model

| In scope | Out of scope |
|----------|--------------|
| Misconfigured Cloudflare token overreach | Compromised Cloudflare account (use a dedicated read-only token) |
| Container escape from DomainSentinel to host | Compromised host already running privileged containers |
| Information disclosure via dashboard | DDoS against the dashboard (Traefik + Cloudflare handle this) |
| SSRF via healthcheck URLs (none accepted from user input) | Phishing of admin credentials (use SSO + 2FA) |

## Hardening Recommendations

For production deployments, also consider:

1. **Docker socket proxy** — replace the direct socket mount with a `tecnativa/docker-socket-proxy` allowing only `GET /containers` and `GET /containers/{id}/json`
2. **Read-only Cloudflare token** — minimum scope: `Zone / Zone : Read`, `Zone / DNS : Read`, single zone
3. **Rate limit on dashboard** — add Traefik rate-limiting middleware in front of `domains.techsentinel.fr`
4. **Fail2ban** — protect the Traefik + Authentik stack at the host level
5. **Backup encryption** — encrypt the `data/domainsentinel.db` backup before off-site transfer
6. **Audit logs** — pipe DomainSentinel JSON logs to a SIEM and alert on `WARN`/`ERROR` levels

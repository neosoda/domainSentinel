# Contributing to DomainSentinel

Thanks for your interest in DomainSentinel! This is primarily a personal infrastructure tool but external contributions are welcome.

## Ground rules

- **Read the spec first** : the original project brief (in French) is in the git history of the initial commit. It explains the philosophy (lightweight, no SPA, no Kubernetes, no SaaS).
- **Keep it boring** : DomainSentinel intentionally avoids clever code. Prefer simple, readable Go.
- **No new dependencies for trivial things** : the project depends on `chi` (HTTP), `mattn/go-sqlite3` (DB), `robfig/cron` (scheduler). That's it. Don't add a YAML library — the YAML parser is 80 lines of straightforward code.
- **Don't break the read-only contract** : DomainSentinel MUST NOT be able to write to Cloudflare, Traefik, Docker, Coolify, or Authentik.

## Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write code + tests (see below)
4. Run `make test` locally — must pass
5. Run `go vet ./...` — must be clean
6. Run `gofmt -l .` — no files should be listed
7. Commit with a Conventional Commits message (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`)
8. Open a Pull Request against `main`

## Tests

- **Unit tests** go in `tests/unit/` and use the standard `testing` package
- All tests must run **without real infrastructure** — use the existing fixtures in `tests/unit/testdata/` if needed
- New feature → new test case
- New bugfix → regression test in the same PR

## Code style

- Go 1.23+ idioms
- `gofmt` and `go vet` clean
- Comments on exported functions, especially in `internal/scanner/` and `internal/correlator/`
- French or English for user-facing strings (match existing templates)

## Project structure

```
internal/
  api/         # HTTP server, templates, middleware
  config/      # env var loading
  correlator/  # FQDN merge + anomaly detection
  db/          # SQLite, migrations
  healthcheck/ # HTTP/TLS checker
  models/      # domain types
  scanner/     # Cloudflare / Docker / Traefik readers
tests/unit/    # unit tests
web/
  static/      # htmx.min.js, alpine.min.js, style.css
  templates/   # index.html, detail.html
```

## Commit message format

```
<type>(<scope>): <subject>

<body>

<footer>
```

Example:
```
feat(scanner): support Traefik file provider backend URLs

Parse the `services.<name>.loadBalancer.servers[].url` from
Traefik dynamic YAML files and expose them on the TraefikSnapshot.
This lets the dashboard show where a file-based route actually
points to.

Closes #42
```

## Questions?

Open a Discussion on GitHub, not an issue.

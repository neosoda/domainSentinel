## Summary

<!-- One or two sentences describing the change. -->

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (no functional change)

## How has this been tested?

- [ ] `go test ./...` passes
- [ ] `go vet ./...` is clean
- [ ] `gofmt -l .` is empty
- [ ] Tested manually in a Docker container
- [ ] New tests added

## Checklist

- [ ] My code follows the project's style guidelines (see [CONTRIBUTING.md](CONTRIBUTING.md))
- [ ] I have added comments to exported functions, especially in `internal/scanner/` and `internal/correlator/`
- [ ] I have not introduced any new external dependencies
- [ ] I have not added any write capability to Cloudflare / Traefik / Docker / Coolify / Authentik
- [ ] I have updated the relevant documentation (README, CHANGELOG, etc.)

## Screenshots

If the change affects the UI, please add a screenshot.

## Related issues

Fixes #…, relates to #…

---
name: Bug report
about: Something is broken or behaving unexpectedly
title: "[Bug] "
labels: bug
assignees: ''
---

## Description

A clear and concise description of what the bug is.

## Steps to reproduce

1. …
2. …
3. …

## Expected behaviour

What you expected to happen.

## Actual behaviour

What actually happens (logs, error messages, screenshot).

## Environment

- DomainSentinel version (image tag or commit SHA):
- Deployment method (docker compose, Coolify, source):
- OS / Docker version:
- Go version (if from source):
- Cloudflare zone name:
- Traefik version:
- Number of containers / FQDNs being scanned:

## Logs

<details>
<summary>docker logs domainsentinel --tail=200</summary>

```
paste here
```

</details>

## Additional context

Anything else that might help (reverse-proxy config, Authentik config, Cloudflare token permissions, …).

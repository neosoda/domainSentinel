# DomainSentinel on Coolify

This guide shows how to deploy DomainSentinel as a Coolify resource, using Coolify's built-in Traefik + persistent storage + environment-variable management.

The procedure assumes you have:

- A Coolify instance (v4.x) running on a server
- A public domain (e.g. `techsentinel.fr`) managed by Cloudflare and routed through Cloudflare Tunnel
- A Docker `proxy` network that Traefik is already attached to (Coolify creates this automatically — do **not** delete it)

> **Important** : the existing `docker-compose.yml` works for a manual `docker compose up -d` deployment, but Coolify prefers a specific schema. The `docker-compose.coolify.yml` file in this repo is the Coolify-friendly variant. It is **identical in functionality** — only the metadata differs.

---

## 1. Create the resource in Coolify

1. Log in to your Coolify dashboard (e.g. `https://coolify.example.com`)
2. **Projects** → your project → **+ New Resource**
3. Choose **Application** → **Public/Private Repository** (or **Docker Compose** if you push to a Git repo)
4. If using a Git repo:
   - **Repository URL** : `https://github.com/techsentinel/domainsentinel.git`
   - **Branch** : `main`
   - **Build Pack** : `Dockerfile`
5. If using a local directory: choose **Docker Compose** and paste the content of `docker-compose.coolify.yml`

---

## 2. Configure the environment

In Coolify's **Environment Variables** tab, set:

| Key | Value | Notes |
|-----|-------|-------|
| `CLOUDFLARE_TOKEN` | your read-only API token | **mark as Secret / Build Secret** |
| `CLOUDFLARE_ZONE_NAME` | `techsentinel.fr` | |
| `DS_LOG_LEVEL` | `INFO` | `DEBUG` for verbose |
| `DS_HOST` | `0.0.0.0` | |
| `DS_PORT` | `3000` | must match the Traefik load-balancer port below |

> All other variables have sensible defaults — see [`.env.example`](../.env.example) for the full list.

---

## 3. Persistent storage

Map two volumes in Coolify's **Storage** tab :

| Type | Source | Destination |
|------|--------|-------------|
| Volume | `domainsentinel_data` | `/data` |
| Volume | `domainsentinel_config` | `/config` |

**Important** : do **not** map `/opt/traefik/dynamic` or `/var/run/docker.sock` here — those are host-specific paths and need to be set via the `docker-compose.coolify.yml` file if running as a Docker Compose resource.

For a Coolify **Application** (Dockerfile-based) deployment, you have two options:

- **Option A** : use a Dockerfile-only build and mount the host paths via the **Server** tab → **Mounts** (this requires Server-level access)
- **Option B** : use the **Docker Compose** build pack and pass `docker-compose.coolify.yml` directly

Option B is documented here.

---

## 4. Network

The Coolify resource must attach to the `proxy` network (which Traefik uses). In the **Network** tab:

1. Add network `proxy`
2. Disable the default `coolify` network if you don't need it (DomainSentinel does not)

---

## 5. Domain

In the **Domains** tab:

| Field | Value |
|-------|-------|
| Domain | `domains.techsentinel.fr` |
| Service | `domainsentinel:3000` |
| HTTPS | enabled (Traefik + Cloudflare) |
| Force HTTPS | enabled |

Coolify will automatically generate the correct `traefik.http.routers.*` labels.

If you also want Authentik protection, add a **Middleware** in Coolify and reference it from the domain configuration. Coolify will inject the `traefik.http.routers.<service>.middlewares` label.

---

## 6. Healthcheck

Coolify will detect the `HEALTHCHECK` directive in the Dockerfile and use it. The healthcheck calls `GET /health` on the internal port (no Cloudflare / Traefik / Authentik involved).

You can also configure a custom one in the Coolify UI:

- **Command** : `curl -sf http://localhost:3000/health || exit 1`
- **Interval** : `30s`
- **Timeout** : `5s`
- **Retries** : `3`

---

## 7. Deploy

1. Click **Deploy**
2. Watch the build logs
3. Once the container is up, check `https://domains.techsentinel.fr` (after Cloudflare Tunnel + Authentik are configured — see [`DEPLOYMENT.md`](DEPLOYMENT.md))

---

## 8. Coolify resource configuration recap

| Setting | Value |
|---------|-------|
| Build pack | Docker Compose |
| Compose file | `docker-compose.coolify.yml` |
| Base directory | `/` (repo root) |
| Healthcheck | `curl -sf http://localhost:3000/health` |
| Network | `proxy` |
| Volumes | `domainsentinel_data:/data`, `domainsentinel_config:/config` |
| Domain | `domains.techsentinel.fr` → `http://domainsentinel:3000` |
| Read-only root FS | ✅ |
| Drop capabilities | ✅ |
| No new privileges | ✅ |
| Non-root user | ✅ (Coolify `Security` tab) |

---

## 9. Coolify-specific `docker-compose.coolify.yml`

The variant file in the repo root is identical to `docker-compose.yml` except:

- The image is built from the local `Dockerfile` (no `:latest` tag reliance)
- The volume paths are explicit (no `bind` mounts to host paths that wouldn't exist in Coolify)
- The Traefik labels use Coolify's placeholder syntax (`{{ ... }}`) only if you want Coolify to manage the FQDN — otherwise the existing `traefik.http.routers.domainsentinel.*` labels work as-is

> **Tip** : if you want to read Traefik dynamic YAML files and the Docker socket, you need to add those mounts in the **Compose file** tab directly. Coolify cannot expose arbitrary host paths to a Dockerfile build.

---

## 10. Updating

In the Coolify resource, click **Redeploy**. Coolify will:

1. Pull the latest code from GitHub
2. Build the image
3. Stop the old container
4. Start the new one
5. Persistent volumes (`/data`, `/config`) are preserved

---

## 11. Troubleshooting

### "Permission denied" on `/var/run/docker.sock`

The container runs as UID 1000 with supplementary GID 984 (the `docker` group on the host). If your host has a different GID for the docker group, check with `getent group docker` on the host, and update the `group_add:` line in the compose file accordingly.

### Cloudflare scan keeps failing with `400`

- Verify the token permissions: `Zone / Zone : Read` and `Zone / DNS : Read`, scoped to the right zone
- The token is set as a Coolify environment variable — make sure it is not wrapped in extra quotes
- The `CLOUDFLARE_ZONE_NAME` must match exactly (no trailing dot, no `https://`)

### Dashboard not loading through Cloudflare Tunnel

- Make sure the tunnel routes `domains.techsentinel.fr` to `http://localhost:80` (Traefik)
- Make sure the Cloudflare DNS record is a **CNAME** to `<tunnel-id>.cfargotunnel.com` (Cloudflare Zero Trust does this automatically when you add a public hostname)

### Authentik returns 404

- Create the **Application** and **Provider** in the Authentik admin dashboard
- Add the application to the `authentik Embedded Outpost`
- See [`DEPLOYMENT.md`](DEPLOYMENT.md) for the exact procedure

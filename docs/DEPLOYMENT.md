# DomainSentinel — Configuration finale & actions manuelles

État après audit + durcissement du **2026-08-21**.

---

## ✅ Ce qui est en place

| Composant | État | Détail |
|-----------|------|--------|
| Conteneur `domainsentinel` | ✅ | `Up (healthy)` |
| Scan Docker | ✅ | 68 conteneurs détectés |
| Scan Traefik YAML | ✅ | 5 routers fichiers détectés |
| Scan Cloudflare | ⚠️ | Token placeholder `PASTE_YOUR_TOKEN_HERE` |
| Corrélation | ✅ | 52 FQDNs |
| Healthchecks HTTP | ✅ | 52 URLs testées |
| Dashboard HTML | ✅ | `techsentinel.fr` zone, 52 domaines |
| API REST | ✅ | `/api/v1/domains`, `/api/v1/status`, `/health` |
| Source Traefik affichée | ✅ | `docker:<container>` ou `file:traefik-dynamic` |
| Persistance SQLite | ✅ | WAL mode, fichiers conservés sur restart |
| Hardening | ✅ | `read_only`, `cap_drop ALL`, `no-new-privileges`, `tmpfs /tmp` |
| User non-root | ✅ | UID 1000 + groupe docker (GID 984) |
| Authentik middleware | ✅ | `authentik@docker` (vérifié) |
| Traefik routing | ✅ | Traefik ↔ `domainsentinel:3000` via réseau `proxy` |
| Tests unitaires | ✅ | `go test ./tests/unit/...` → OK |

---

## ⚠️ Actions manuelles restantes

### 1. Token Cloudflare (1 minute)

Éditer `/opt/domainsentinel/.env` :

```bash
nano /opt/domainsentinel/.env
```

Remplacer :

```text
CLOUDFLARE_TOKEN=PASTE_YOUR_TOKEN_HERE
```

par le vrai token (permissions minimales recommandées) :

```text
Zone / Zone / Read
Zone / DNS / Read
```

Limité à la zone `techsentinel.fr` côté dashboard Cloudflare.

Puis :

```bash
cd /opt/domainsentinel
docker compose restart
```

Vérifier dans les logs :

```bash
docker logs domainsentinel --tail 20 | grep cloudflare
```

→ doit afficher `cloudflare scan complete records=N` (sans 400).

---

### 2. Cloudflare Tunnel : `domains.techsentinel.fr`

Le tunnel `38ccf014-c8ad-4618-9f43-2b5d95d5a389` est déjà actif sur NEOSERVER (`cloudflared.service`) avec ingress catch-all vers `http://localhost:80` (Traefik).

**Il NE FAUT PAS** créer un enregistrement DNS public pointant vers `192.168.1.200` (IP privée).

À faire dans le **dashboard Cloudflare Zero Trust** ou via `cloudflared` :

#### Option A — Dashboard Cloudflare (recommandé)

1. https://one.dash.cloudflare.com/ → **Zero Trust** → **Networks** → **Tunnels**
2. Sélectionner le tunnel `38ccf014-c8ad-4618-9f43-2b5d95d5a389`
3. **Public Hostname** → **Add a public hostname**
4. Remplir :
   - **Subdomain** : `domains`
   - **Domain** : `techsentinel.fr`
   - **Service** : Type `HTTP`, URL `localhost:80` (Traefik s'occupe du reste par `Host: domains.techsentinel.fr`)
5. Sauvegarder

Le DNS sera automatiquement créé en CNAME vers `<tunnel-id>.cfargotunnel.com`.

#### Option B — CLI `cloudflared`

```bash
cloudflared tunnel route dns 38ccf014-c8ad-4618-9f43-2b5d95d5a389 domains.techsentinel.fr
```

Le record CNAME est créé automatiquement.

#### Vérification

```bash
dig domains.techsentinel.fr CNAME
# → doit pointer vers 38ccf014-c8ad-4618-9f43-2b5d95d5a389.cfargotunnel.com
```

---

### 3. Authentik : application DomainSentinel

Dashboard : `https://auth.techsentinel.fr/if/admin/`

#### A. Créer le Provider

1. **Applications** → **Providers** → **Create**
2. Type : **Proxy Provider**
3. Paramètres :
   - **Name** : `DomainSentinel Provider`
   - **Authorization flow** : `default-provider-authorization-explicit-consent` (ou `default-provider-authorization-implicit-consent`)
   - **Forward auth (single application)** : activé
   - **External host** : `https://domains.techsentinel.fr`
4. Sauvegarder → noter le **slug** (ex: `domainsentinel`)

#### B. Créer l'Application

1. **Applications** → **Applications** → **Create**
2. Paramètres :
   - **Name** : `DomainSentinel`
   - **Slug** : `domainsentinel`
   - **Provider** : `DomainSentinel Provider` (celui créé ci-dessus)
   - **Launch URL** : `https://domains.techsentinel.fr`
3. Sauvegarder

#### C. Vérifier l'Outpost

1. **Applications** → **Outposts** → `authentik Embedded Outpost`
2. Section **Applications** : s'assurer que `DomainSentinel` est listé
3. Sinon, l'ajouter

#### D. Test

```bash
curl -I -L --max-time 10 https://domains.techsentinel.fr
```

Attendu :

```text
HTTP/2 302
Location: https://auth.techsentinel.fr/...
```

(après authentification) :

```text
HTTP/2 200
x-authentik-username: ...
```

---

## 🔄 Rollback

```bash
cd /opt/domainsentinel

# Restaurer les backups
cp docker-compose.yml.bak-20260821-133639 docker-compose.yml
cp .env.bak-20260821-133639 .env
cp data/domainsentinel.db.bak-20260821-133639 data/domainsentinel.db

# Redéployer
docker compose up -d
```

---

## 📝 Notes de sécurité

- **Pas de port public** sur DomainSentinel (uniquement Traefik via `proxy` network)
- **Read-only root FS** : conteneur ne peut pas écrire ailleurs que `/data` et `/config`
- **Capabilities** : toutes supprimées
- **no-new-privileges** : activé
- **User non-root** : UID 1000 (groups: 1000 domainsentinel, 984 docker)
- **Docker socket** : monté en `ro` (lecture seule via système de fichiers, pas d'API write possible)
- **Token Cloudflare** : uniquement dans `.env`, jamais dans compose / logs / Git
- **Logs** : jamais de token / cookie / Authorization header

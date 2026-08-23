# AGENTS.md — DomainSentinel

## Règles d'infrastructure Coolify (NEOSERVER)

Cette infrastructure est administrée via **Coolify** sur Debian 13. Coolify est l'orchestrateur principal — il gère les apps, services, réseaux, reverse proxy, domaines, HTTPS/TLS, env vars, volumes, healthchecks, déploiements.

**Principe fondamental** : utiliser les mécanismes natifs Coolify. Ne pas ajouter de couches, reverse proxy parallèle, scripts système, règles iptables, services systemd, ports host inutiles, chemins absolus serveur-spécifiques, ou modifications manuelles dans les conteneurs.

### Reverse proxy

- Traefik est géré par Coolify. Ne pas en installer un second.
- Pas de mapping `3000:3000` direct sur l'host. L'app écoute sur `0.0.0.0:<port>` et Traefik fait le reste.
- Domaines, HTTPS, certificats Let's Encrypt, redirection HTTP→HTTPS : tout via Coolify.

### Réseau Docker

- Entre services : `service-name:port`, jamais `localhost` (qui désigne le conteneur lui-même).
- Bases de données : `postgresql://user:pass@postgres:5432/app`, jamais `127.0.0.1`.

### Variables d'environnement

- Toute config modifiable via env vars Coolify.
- Jamais de secret hardcodé dans le code ou le Git.

### Stockage persistant

- `/data`, `/config`, etc. via volumes Coolify.
- SQLite en mode WAL avec `busy_timeout` et transactions courtes.

### Healthchecks

- Endpoint léger `/health` retournant `{"status":"ok"}`.
- Pas de traitements lourds.

### Docker socket

- `read_only` (`/var/run/docker.sock:/var/run/docker.sock:ro`).
- Privilégier un `docker-socket-proxy` (Tecnativa) si possible.
- Jamais exposé sur Internet.

### Sécurité conteneurs

- `read_only: true`, `cap_drop: ALL`, `no-new-privileges`, user non-root.
- Pas de `privileged: true`, `network_mode: host`, `cap_add` sans justification.

### Logs

- Vers `stdout`/`stderr` pour exploitation Docker/Coolify.
- Niveaux : `DEBUG`, `INFO`, `WARN`, `ERROR`. Production = `INFO`.

### Validation après chaque modification

1. Analyser l'état actuel
2. Identifier les problèmes d'architecture
3. Proposer la solution la plus simple compatible Coolify
4. Effectuer les modifications
5. Vérifier les logs
6. Vérifier les healthchecks
7. Vérifier le routage HTTPS
8. Vérifier la persistance après recréation
9. Vérifier qu'aucun port ou service sensible n'est exposé inutilement

### Anti-patterns à éviter absolument

- `custom_docker_run_options` avec des flags exotiques que Coolify peut supprimer (--group-add, --user, etc.) → préférer bake les modifications dans le Dockerfile
- `custom_labels` pour fixer ce que Coolify génère mal → signaler le bug plutôt que patcher
- Patcher la base de données Coolify directement → documenter et demander confirmation
- Modifier manuellement des fichiers dans un conteneur après démarrage

#!/usr/bin/env bash
#
# DomainSentinel — Coolify deployment helper
# ------------------------------------------
# This script is meant to be run from a CI/CD pipeline or manually.
# It is NOT needed for the standard Coolify "Redeploy" button workflow.
#
# Use cases:
#   1. Bootstrap a fresh Coolify resource from scratch
#   2. Force-rebuild the image from a specific Git ref
#   3. Verify the deployment post-Coolify-action
#
# Requirements:
#   - curl, jq
#   - COOLIFY_API_URL  (e.g. https://coolify.example.com)
#   - COOLIFY_API_TOKEN (Settings → API Tokens in Coolify)
#   - COOLIFY_UUID     (UUID of the DomainSentinel resource in Coolify)
#
set -euo pipefail

: "${COOLIFY_API_URL:?missing COOLIFY_API_URL}"
: "${COOLIFY_API_TOKEN:?missing COOLIFY_API_TOKEN}"
: "${COOLIFY_UUID:?missing COOLIFY_UUID}"

api() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -fsS -X "$method" -H "Authorization: Bearer ${COOLIFY_API_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$body" "${COOLIFY_API_URL}${path}"
  else
    curl -fsS -X "$method" -H "Authorization: Bearer ${COOLIFY_API_TOKEN}" \
      "${COOLIFY_API_URL}${path}"
  fi
}

action() {
  echo "→ $1"
  api POST "/api/v1/applications/${COOLIFY_UUID}/$1" | jq -r '"  status: \(.status // .message // "ok")"'
}

case "${1:-status}" in
  deploy)
    action "restart" || true
    action "deploy"   || true
    ;;
  status)
    api GET "/api/v1/applications/${COOLIFY_UUID}" | jq '.'
    ;;
  env)
    api GET "/api/v1/applications/${COOLIFY_UUID}/envs" | jq '.'
    ;;
  logs)
    shift
    api GET "/api/v1/applications/${COOLIFY_UUID}/logs?tail=${1:-100}"
    ;;
  *)
    echo "Usage: $0 {deploy|status|env|logs [N]}"
    exit 1
    ;;
esac

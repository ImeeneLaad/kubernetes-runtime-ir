#!/usr/bin/env bash
# Manage the Shuffle SOAR stack (Docker Compose, outside the cluster).
# Usage (Ubuntu, project root):  bash soar/shuffle/shuffle.sh up|down|status|logs
#   down keeps the data volumes. To wipe them as well: docker compose ... down -v
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SECRETS="$DIR/secrets/shuffle-secrets.env"
cd "$DIR"

gen_secrets() {
  mkdir -p "$DIR/secrets"
  [ -s "$SECRETS" ] && return
  # OpenSearch demands upper + lower + digit + special characters.
  local pw; pw="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)Aa1!"
  cat > "$SECRETS" <<EOF
# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by shuffle.sh. Do not commit.
SHUFFLE_OPENSEARCH_PASSWORD=$pw
OPENSEARCH_INITIAL_ADMIN_PASSWORD=$pw
# Encrypts credentials stored in Shuffle. Losing it = re-enter all app credentials.
SHUFFLE_ENCRYPTION_MODIFIER=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40)
EOF
  chmod 600 "$SECRETS"
  echo "Generated $SECRETS"
}

dc() { docker compose --env-file "$DIR/.env" --env-file "$SECRETS" -f "$DIR/docker-compose.yml" "$@"; }

case "${1:-status}" in
  up)
    docker network inspect kind >/dev/null 2>&1 || { echo "kind network missing: create the cluster first"; exit 1; }
    gen_secrets
    dc up -d
    # The frontend's nginx resolves "shuffle-backend" ONCE at start. If the backend
    # was recreated (new IP), the UI shows "Are you sure Shuffle is installed
    # correctly?" (502 Bad Gateway, connection refused). Restarting the frontend
    # makes it resolve the current address.
    docker restart shuffle-frontend >/dev/null
    ;;
  restart-ui) docker restart shuffle-frontend >/dev/null && echo "Shuffle UI restarted" ;;
  down)   dc down ;;
  status) dc ps ;;
  logs)   dc logs --tail=50 "${2:-backend}" ;;
  *) echo "usage: $0 up|down|status|logs [service]|restart-ui"; exit 2 ;;
esac

#!/usr/bin/env bash
# Creates the Falcosidekick Web UI login, replacing the chart default admin:admin.
# Idempotent: an existing local credential is reused.
# Local copy: falco/secrets/ui-credentials.txt (git-ignored).
# Usage (Ubuntu, project root):  bash falco/create-ui-secret.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
CRED="$DIR/secrets/ui-credentials.txt"
mkdir -p "$DIR/secrets"
if [ ! -s "$CRED" ]; then
  echo "admin:$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)" > "$CRED"
  chmod 600 "$CRED"
  echo "Generated new UI credential in $CRED"
fi
kubectl create namespace falco --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# Key name expected by the falcosidekick-ui chart (env FALCOSIDEKICK_UI_USER = login:password)
kubectl -n falco create secret generic falcosidekick-ui-creds \
  --from-literal=FALCOSIDEKICK_UI_USER="$(cat "$CRED")" \
  --dry-run=client -o yaml | kubectl apply -f -

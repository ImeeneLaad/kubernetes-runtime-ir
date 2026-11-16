#!/usr/bin/env bash
# Installs / upgrades Falco with the project's values and custom rules.
# Usage (Ubuntu, project root):  bash falco/install.sh
#
# Safety: an invalid rules file stops Falco from starting, which means NO
# detection. If Falco is already running, the custom rules are first
# validated with `falco -V` inside the running pod. The upgrade only happens
# if they are valid.
set -euo pipefail
CHART_VERSION=9.2.2
DIR="$(cd "$(dirname "$0")" && pwd)"

# --- 1. Pre-deployment rule validation ---------------------------------------------
# A crash-looping pod still reports phase "Running": require a READY falco container.
POD=$(kubectl -n falco get pod -l app.kubernetes.io/name=falco -o \
      jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.containerStatuses[?(@.name=="falco")].ready}{"\n"}{end}' 2>/dev/null \
      | awk '$2=="true"{print $1; exit}' || true)
if [ -n "$POD" ]; then
  for f in "$DIR"/rules/*.yaml; do
    [ -e "$f" ] || continue
    kubectl -n falco cp -c falco "$f" "$POD:/tmp/$(basename "$f")" >/dev/null
    echo "Validating $(basename "$f") in $POD ..."
    if ! kubectl -n falco exec "$POD" -c falco -- \
         falco -c /etc/falco/falco.yaml -V /etc/falco/falco_rules.yaml -V "/tmp/$(basename "$f")" >/tmp/falco-validate.log 2>&1; then
      cat /tmp/falco-validate.log
      echo "ABORT: $(basename "$f") is invalid. Falco was NOT upgraded."; exit 1
    fi
    grep -qi 'warning' /tmp/falco-validate.log && { echo "  (warnings)"; grep -iA8 'warning' /tmp/falco-validate.log; }
    echo "  OK"
  done
else
  echo "WARNING: no ready Falco pod (first install or Falco broken): skipping pre-validation."
fi

# --- 2. Install / upgrade -----------------------------------------------------------------
bash "$DIR/create-ui-secret.sh" >/dev/null
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null 2>&1 || true
helm repo update falcosecurity >/dev/null

ARGS=()
# Falcosidekick -> Shuffle webhook. URL + shared-secret header come from
# soar/shuffle/secrets/ (created by provision_intake.py), so they are never
# written to values.yaml / git. The chart stores them in a Kubernetes Secret.
SHUFFLE_SECRETS="$DIR/../soar/shuffle/secrets"
if [ -s "$SHUFFLE_SECRETS/webhook-url.txt" ] && [ -s "$SHUFFLE_SECRETS/webhook-token.txt" ]; then
  ARGS+=(--set-string "falcosidekick.config.webhook.address=$(tr -d '\r\n' < "$SHUFFLE_SECRETS/webhook-url.txt")")
  ARGS+=(--set-string "falcosidekick.config.webhook.customHeaders=X-IR-Token:$(tr -d '\r\n' < "$SHUFFLE_SECRETS/webhook-token.txt")")
  echo "Shuffle webhook output: enabled"
else
  echo "WARNING: Shuffle webhook secrets not found: webhook output disabled"
fi
# Every falco/rules/*.yaml file becomes a custom rules file in /etc/falco/rules.d
for f in "$DIR"/rules/*.yaml; do
  [ -e "$f" ] || continue
  ARGS+=(--set-file "customRules.$(basename "$f" | sed 's/\./\\./g')=$f")
done

helm upgrade --install falco falcosecurity/falco \
  --version "$CHART_VERSION" \
  --namespace falco --create-namespace \
  -f "$DIR/values.yaml" "${ARGS[@]}" \
  --wait --timeout 10m

kubectl -n falco rollout status ds/falco --timeout=5m

# --- 3. Network isolation of the alert pipeline ---------------------------------------------
kubectl apply -f "$DIR/networkpolicies.yaml"

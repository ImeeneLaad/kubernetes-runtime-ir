#!/usr/bin/env bash
# Health check for Juice Shop. Used after deployment AND after remediation
# (step "verify the application works again").
# Usage (Ubuntu):  bash apps/juice-shop/verify.sh [dev|prod|all]
#
# Retries for up to TIMEOUT seconds (default 60): right after a rollout the
# new pod is Ready a few seconds before endpoints and NodePort routing catch
# up, and a single check would report a false failure.
set -u
TARGET=${1:-all}
TIMEOUT=${TIMEOUT:-60}
FAILS=0
declare -A PORT=( [dev]=3030 [prod]=3031 )

check_env() {
  local env=$1 deadline=$((SECONDS + TIMEOUT)) attempt=1
  while true; do
    if check_once "$env" > /tmp/verify-$env.out; then
      cat /tmp/verify-$env.out; echo "  [PASS] $env healthy (attempt $attempt)"; return
    fi
    if [ $SECONDS -ge $deadline ]; then
      cat /tmp/verify-$env.out; echo "  [FAIL] $env NOT healthy after ${TIMEOUT}s"; FAILS=$((FAILS+1)); return
    fi
    attempt=$((attempt+1)); sleep 5
  done
}

check_once() {
  local env=$1 ns="juice-$1" port=${PORT[$1]}
  echo "== $env (namespace $ns, http://127.0.0.1:$port)"
  local want ready
  want=$(kubectl -n "$ns" get deploy juice-shop -o jsonpath='{.spec.replicas}')
  ready=$(kubectl -n "$ns" get deploy juice-shop -o jsonpath='{.status.availableReplicas}')
  ready=${ready:-0}
  local eps
  eps=$(kubectl -n "$ns" get endpointslices -l kubernetes.io/service-name=juice-shop \
        -o jsonpath='{range .items[*].endpoints[?(@.conditions.ready==true)]}{.addresses[0]}{" "}{end}')
  local code version
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$port/")
  version=$(curl -s --max-time 5 "http://127.0.0.1:$port/rest/admin/application-version")
  printf '  replicas available : %s/%s\n' "$ready" "$want"
  printf '  ready endpoints    : %s\n' "${eps:-none}"
  printf '  GET /              : HTTP %s\n' "$code"
  printf '  app version        : %s\n' "${version:-n/a}"
  # The API must answer too, not just the static page.
  [ "$ready" = "$want" ] && [ "$code" = "200" ] && [ -n "$eps" ] && [[ "$version" == *'"version"'* ]]
}

case "$TARGET" in
  dev|prod) check_env "$TARGET" ;;
  all) check_env dev; check_env prod ;;
  *) echo "usage: $0 [dev|prod|all]"; exit 2 ;;
esac
exit "$FAILS"

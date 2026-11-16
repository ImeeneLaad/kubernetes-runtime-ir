#!/usr/bin/env bash
# Checks that Falco event timestamps match the real (wall-clock) time.
#
# Why: Falco stamps events as boot_time (measured once, at Falco start) plus
# kernel time since boot. When the Docker Desktop / WSL2 VM is paused (e.g.
# the Windows PC sleeps), the kernel clock stops while the wall clock jumps
# ahead after resync, so every later event is stamped too early. Observed:
# -3807 s after a long pause, +0.5 s right after a Falco restart.
# Wrong timestamps break the incident timeline and the evidence chain.
#
# The probe event is generated in the dedicated Falco CANARY pod
# (falco/canary/, rule "IR canary heartbeat", NOTICE). It must never be
# generated in a protected workload: a probe inside Juice Shop fires the real
# detection rules, and the playbook then responds to it (observed: every check
# cost a dev pod).
#
# Usage (Ubuntu, project root):
#   bash falco/check-clock.sh           # exit 0 if |skew| <= MAX_SKEW (default 5 s)
#   bash falco/check-clock.sh --fix     # restart Falco if skewed, then re-check
set -u
MAX_SKEW=${MAX_SKEW:-5}
DIR="$(cd "$(dirname "$0")" && pwd)"

ensure_canary() {
  kubectl --context kind-k8s-ir apply -f "$DIR/canary/falco-canary.yaml" >/dev/null
  kubectl --context kind-k8s-ir -n ir-system wait --for=condition=Ready pod/falco-canary --timeout=90s >/dev/null
}

measure() {
  local mark now t
  mark="irclockcheck$RANDOM$RANDOM"
  now=$(date -u +%s.%N)
  kubectl --context kind-k8s-ir -n ir-system exec falco-canary -- sh -c ": $mark" >/dev/null 2>&1
  for _ in 1 2 3 4 5 6; do
    sleep 2
    t=$(kubectl -n falco logs ds/falco -c falco --since=2m 2>/dev/null | grep "$mark" | head -1 \
        | python3 -c 'import sys,json; l=sys.stdin.readline(); print(json.loads(l)["time"] if l else "")')
    [ -n "$t" ] && break
  done
  [ -n "$t" ] || { echo "NOEVENT"; return; }
  python3 -c "
from datetime import datetime
t = datetime.fromisoformat('$t'[:26] + '+00:00').timestamp()
print(f'{t - float($now):+.1f}')"
}

check() {
  local s; s=$(measure)
  if [ "$s" = "NOEVENT" ]; then echo "  [FAIL] clock check: no Falco event received from the canary"; return 2; fi
  if python3 -c "import sys; sys.exit(0 if abs(float('$s')) <= $MAX_SKEW else 1)"; then
    echo "  [PASS] Falco clock skew ${s}s (|skew| <= ${MAX_SKEW}s)"; return 0
  fi
  echo "  [FAIL] Falco clock skew ${s}s (> ${MAX_SKEW}s): event timestamps are wrong"; return 1
}

ensure_canary
check; rc=$?
if [ $rc -eq 1 ] && [ "${1:-}" = "--fix" ]; then
  echo "  Restarting Falco to re-measure its boot-time reference..."
  kubectl -n falco rollout restart ds/falco >/dev/null
  kubectl -n falco rollout status ds/falco --timeout=300s >/dev/null
  for _ in $(seq 1 30); do kubectl -n falco logs ds/falco -c falco 2>/dev/null | grep -q "Opening 'syscall' source" && break; sleep 3; done
  sleep 3
  check; rc=$?
fi
exit $rc

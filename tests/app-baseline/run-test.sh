#!/usr/bin/env bash
# Verifies the security baseline of the Juice Shop deployment.
#   A. Pod hardening   B. Network baseline   C. Quarantine vs kubelet probes
# Usage (Ubuntu, project root):  bash tests/app-baseline/run-test.sh
#
# The Juice Shop image is distroless (no shell), so network probes are run
# with the image's own `node` binary through `kubectl exec`.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DIR/results"
LOG="$DIR/results/baseline-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1
FAILS=0
pass() { printf '  [PASS] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; FAILS=$((FAILS+1)); }
info() { printf '  [INFO] %s\n' "$*"; }
check() { # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then pass "$1 = $3"; else fail "$1: expected '$2', got '$3'"; fi
}

[ "$(kubectl config current-context)" = "kind-k8s-ir" ] || { echo "wrong context"; exit 99; }
DEV_POD=$(kubectl -n juice-dev get pod -l app.kubernetes.io/name=juice-shop -o jsonpath='{.items[0].metadata.name}')
PROD_POD=$(kubectl -n juice-prod get pod -l app.kubernetes.io/name=juice-shop -o jsonpath='{.items[0].metadata.name}')
PROD_IP=$(kubectl -n juice-prod get pod "$PROD_POD" -o jsonpath='{.status.podIP}')
echo "== Juice Shop baseline test — $(date -Is)"
echo "== dev pod: $DEV_POD   prod pod: $PROD_POD ($PROD_IP)"

# node one-liners executed inside the Juice Shop container
TCP='const s=require("net").connect({host:process.argv[1],port:+process.argv[2],timeout:3000},()=>{console.log("OPEN");process.exit(0)});s.on("timeout",()=>{console.log("TIMEOUT");process.exit(1)});s.on("error",e=>{console.log(e.code);process.exit(1)})'
DNS='require("dns").lookup(process.argv[1],(e,a)=>{console.log(e?e.code:a);process.exit(e?1:0)})'
tcp() { timeout 15 kubectl exec -n "$1" "$2" -- /nodejs/bin/node -e "$TCP" "$3" "$4" 2>/dev/null | tail -1; }
dns() { timeout 25 kubectl exec -n "$1" "$2" -- /nodejs/bin/node -e "$DNS" "$3" 2>/dev/null | tail -1; }

# --- A. Pod hardening ----------------------------------------------------------
echo; echo "-- A. Pod hardening (dev pod)"
j() { kubectl -n juice-dev get pod "$DEV_POD" -o jsonpath="$1"; }
check "runAsUser"                     "65532" "$(j '{.spec.securityContext.runAsUser}')"
check "automountServiceAccountToken"  "false" "$(j '{.spec.automountServiceAccountToken}')"
check "token volume mounted"          ""      "$(j '{.spec.containers[0].volumeMounts[*].mountPath}' | grep -o serviceaccount)"
check "allowPrivilegeEscalation"      "false" "$(j '{.spec.containers[0].securityContext.allowPrivilegeEscalation}')"
check "capabilities dropped"          "ALL"   "$(j '{.spec.containers[0].securityContext.capabilities.drop[0]}')"
check "process uid inside container"  "65532" "$(kubectl exec -n juice-dev "$DEV_POD" -- /nodejs/bin/node -e 'console.log(process.getuid())' 2>/dev/null)"
for ns in juice-dev juice-prod; do
  check "$ns PSA enforce" "restricted" "$(kubectl get ns $ns -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')"
done
if kubectl -n juice-dev run psa-probe --image=busybox:1.36.1 --dry-run=server \
     --overrides='{"spec":{"containers":[{"name":"p","image":"busybox:1.36.1","securityContext":{"privileged":true}}]}}' >/dev/null 2>&1; then
  fail "PSA accepted a privileged pod in juice-dev"
else
  pass "PSA rejects a privileged pod in juice-dev"
fi

# --- B. Network baseline -----------------------------------------------------------
echo; echo "-- B. Network baseline (from the dev Juice Shop pod)"
r=$(dns juice-dev "$DEV_POD" kubernetes.default.svc.cluster.local)
case "$r" in 10.*) pass "DNS resolution allowed ($r)";; *) fail "DNS resolution: $r";; esac
check "egress to prod pod $PROD_IP:3000 (lateral movement)" "TIMEOUT" "$(tcp juice-dev "$DEV_POD" "$PROD_IP" 3000)"
r=$(tcp juice-dev "$DEV_POD" 1.1.1.1 443)
[ "$r" = "OPEN" ] && pass "egress to internet 1.1.1.1:443 allowed" || info "egress to internet 1.1.1.1:443 = $r (no internet?)"
# FINDING: traffic from a pod to its OWN node's IP is host-local. It never
# crosses the forwarding path where kindnet enforces NetworkPolicy, so the
# 172.24.0.0/16 exclusion cannot block it. The NetworkPolicy spec leaves
# pod->node traffic undefined. Mitigation: no SA token + RBAC (docs/05-shuffle.md).
NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
info "egress to API server via Service 10.96.0.1:443 = $(tcp juice-dev "$DEV_POD" 10.96.0.1 443) (pod->own node: not filterable by NetworkPolicy here)"
info "egress to API server on node $NODE_IP:6443 = $(tcp juice-dev "$DEV_POD" "$NODE_IP" 6443) (same reason)"
SHUFFLE_IP=$(grep -E '^SHUFFLE_KIND_IP=' "$DIR/../../soar/shuffle/.env" 2>/dev/null | cut -d= -f2)
[ -n "$SHUFFLE_IP" ] && check "egress to Shuffle SOAR $SHUFFLE_IP:5001" "TIMEOUT" "$(tcp juice-dev "$DEV_POD" "$SHUFFLE_IP" 5001)"
info "ingress from another namespace is allowed on :3000 only (public web app by design)"

# --- C. Quarantine vs kubelet probes -----------------------------------------------------
echo; echo "-- C. Quarantine a PROD pod: are kubelet probes blocked? (waits ~90 s)"
r0=$(kubectl -n juice-prod get pod "$PROD_POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')
kubectl -n juice-prod label pod "$PROD_POD" security.ir/quarantine=true --overwrite >/dev/null
sleep 5
check "quarantined pod: egress DNS" "TIMEOUT_OR_ERR" "$(r=$(dns juice-prod "$PROD_POD" kubernetes.default.svc.cluster.local); case "$r" in 10.*) echo "$r";; *) echo TIMEOUT_OR_ERR;; esac)"
check "quarantined pod: egress internet" "TIMEOUT" "$(tcp juice-prod "$PROD_POD" 1.1.1.1 443)"
up=0; for i in $(seq 1 9); do
  c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:3031/); [ "$c" = 200 ] && up=$((up+1)); sleep 10
done
r1=$(kubectl -n juice-prod get pod "$PROD_POD" -o jsonpath='{.status.containerStatuses[0].restartCount}')
rd=$(kubectl -n juice-prod get pod "$PROD_POD" -o jsonpath='{.status.containerStatuses[0].ready}')
info "prod service answered $up/9 requests during quarantine (other replica)"
info "quarantined pod after 90 s: ready=$rd restarts $r0 -> $r1"
if [ "$r1" != "$r0" ]; then
  echo "  [FINDING] Probes are BLOCKED by quarantine -> liveness kills the container -> volatile evidence LOST."
elif [ "$rd" = "false" ]; then
  echo "  [FINDING] Readiness blocked but no restart yet (liveness would follow)."
else
  echo "  [FINDING] Kubelet probes still pass under quarantine (node->pod traffic not filtered)."
fi
kubectl -n juice-prod label pod "$PROD_POD" security.ir/quarantine- >/dev/null

echo; echo "== Unexpected results: $FAILS  (log: $LOG)"
exit "$FAILS"

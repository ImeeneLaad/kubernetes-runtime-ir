#!/usr/bin/env bash
# Verifies that the cluster CNI really ENFORCES NetworkPolicies.
# Run in Ubuntu (WSL) from the project root:  bash tests/netpol/run-test.sh
#
# Exit code = number of results that did not match expectations
# (test 3 and test 4 are FINDINGS that describe behaviour, not pass/fail).
set -u

NS=netpol-test
DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$DIR/results"
mkdir -p "$RESULTS"
LOG="$RESULTS/netpol-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1

FAILS=0
SETTLE=5   # seconds to let the CNI program a policy change

ctx=$(kubectl config current-context 2>/dev/null)
[ "$ctx" = "kind-k8s-ir" ] || { echo "Wrong kube context '$ctx' (expected kind-k8s-ir)"; exit 99; }

echo "== CNI NetworkPolicy validation — $(date -Is)"
echo "== Context: $ctx"
kubectl get pods -n kube-system -o wide | grep -Ei 'kindnet|calico' || true

# --- helpers -----------------------------------------------------------------
http() {   # http <from-pod> <to-ip>  -> exit 0 if the HTTP request succeeds
  kubectl exec -n "$NS" "$1" -- wget -q -T 3 -O /dev/null "http://$2:8080/" >/dev/null 2>&1
}
dns() {    # dns <from-pod>
  kubectl exec -n "$NS" "$1" -- timeout 5 nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1
}
expect() { # expect <allowed|blocked> <description> <command...>
  local want=$1 desc=$2; shift 2
  local got
  if "$@"; then got=allowed; else got=blocked; fi
  if [ "$got" = "$want" ]; then
    printf '  [PASS] %-45s expected=%-8s got=%s\n' "$desc" "$want" "$got"
  else
    printf '  [FAIL] %-45s expected=%-8s got=%s\n' "$desc" "$want" "$got"
    FAILS=$((FAILS+1))
  fi
}
settle() { sleep "$SETTLE"; }

# --- setup -------------------------------------------------------------------
kubectl apply -f "$DIR/00-namespace-and-pods.yaml" >/dev/null
kubectl wait -n "$NS" --for=condition=Ready pod/alpha pod/beta --timeout=120s >/dev/null || exit 98
A=$(kubectl get pod -n "$NS" alpha -o jsonpath='{.status.podIP}')
B=$(kubectl get pod -n "$NS" beta  -o jsonpath='{.status.podIP}')
echo "== alpha=$A  beta=$B"

# --- Test 0: baseline, no policy --------------------------------------------
echo; echo "-- Test 0: baseline (no NetworkPolicy)"
expect allowed "beta  -> alpha:8080"  http beta  "$A"
expect allowed "alpha -> beta:8080"   http alpha "$B"
expect allowed "alpha -> DNS"         dns  alpha

# --- Test 1: default deny ingress -------------------------------------------
echo; echo "-- Test 1: namespace default-deny INGRESS"
kubectl apply -f "$DIR/01-default-deny-ingress.yaml" >/dev/null; settle
expect blocked "beta  -> alpha:8080"  http beta  "$A"
expect blocked "alpha -> beta:8080"   http alpha "$B"
expect allowed "alpha -> DNS (egress untouched)" dns alpha
kubectl delete -f "$DIR/01-default-deny-ingress.yaml" >/dev/null; settle
expect allowed "beta  -> alpha:8080 (policy removed)" http beta "$A"

# --- Test 2: label-based quarantine (ingress + egress) ----------------------
echo; echo "-- Test 2: quarantine alpha via label (Ingress+Egress deny)"
kubectl apply -f "$DIR/02-quarantine.yaml" >/dev/null; settle
expect allowed "beta -> alpha (policy present, no label)" http beta "$A"
kubectl label pod -n "$NS" alpha security.ir/quarantine=true --overwrite >/dev/null; settle
expect blocked "beta  -> alpha:8080 (ingress)"  http beta  "$A"
expect blocked "alpha -> beta:8080 (egress)"    http alpha "$B"
expect blocked "alpha -> DNS (egress)"          dns  alpha
expect allowed "beta  -> DNS (neighbour unaffected)" dns beta
kubectl label pod -n "$NS" alpha security.ir/quarantine- >/dev/null; settle
expect allowed "beta  -> alpha:8080 (label removed)" http beta "$A"
expect allowed "alpha -> beta:8080 (label removed)"  http alpha "$B"

# --- Test 3 (finding): established connection ---------------------------------
echo; echo "-- Test 3 (finding): is an ALREADY-OPEN connection cut by quarantine?"
echo "   alpha opens a long-lived TCP stream to beta:9000 (simulates a reverse shell)"
kubectl exec -n "$NS" alpha -- sh -c "rm -f /tmp/stream.log; nohup nc $B 9000 > /tmp/stream.log 2>&1 &"
sleep 4
c0=$(kubectl exec -n "$NS" alpha -- sh -c 'wc -l < /tmp/stream.log')
kubectl label pod -n "$NS" alpha security.ir/quarantine=true --overwrite >/dev/null; settle
c1=$(kubectl exec -n "$NS" alpha -- sh -c 'wc -l < /tmp/stream.log')
sleep 6
c2=$(kubectl exec -n "$NS" alpha -- sh -c 'wc -l < /tmp/stream.log')
echo "   lines received: before=$c0  after-quarantine+${SETTLE}s=$c1  +6s later=$c2"
if [ "${c2:-0}" -gt "${c1:-0}" ]; then
  echo "  [FINDING] Established connection SURVIVES quarantine (only NEW connections are blocked)."
else
  echo "  [FINDING] Established connection is CUT by quarantine."
fi

# Test 3b: the policy engine only judges the FIRST packet of a flow; later
# packets are accepted through conntrack. Deleting the pod's conntrack entries
# on the node forces the next packet to be re-evaluated -> dropped.
echo "-- Test 3b (finding): quarantine + conntrack flush of alpha's IP on the node"
NODE=$(kubectl get pod -n "$NS" alpha -o jsonpath='{.spec.nodeName}')
docker exec "$NODE" conntrack -D -s "$A" >/dev/null 2>&1 || true
docker exec "$NODE" conntrack -D -d "$A" >/dev/null 2>&1 || true
sleep 3
c3=$(kubectl exec -n "$NS" alpha -- sh -c 'wc -l < /tmp/stream.log')
sleep 6
c4=$(kubectl exec -n "$NS" alpha -- sh -c 'wc -l < /tmp/stream.log')
echo "   lines received: after-flush+3s=$c3  +6s later=$c4"
if [ "${c4:-0}" -gt "${c3:-0}" ]; then
  echo "  [FINDING] Connection STILL alive after conntrack flush."
else
  echo "  [FINDING] Connection CUT after conntrack flush."
fi
# Lift quarantine BEFORE killing nc so the FIN reaches beta and its listener resets.
kubectl label pod -n "$NS" alpha security.ir/quarantine- >/dev/null; settle
kubectl exec -n "$NS" alpha -- sh -c 'pkill nc' >/dev/null 2>&1 || true
sleep 2

# --- Test 4 (finding): additive semantics --------------------------------------
echo; echo "-- Test 4 (finding): quarantine + another policy allowing ingress to alpha"
kubectl apply -f "$DIR/03-allow-all-ingress-alpha.yaml" >/dev/null
kubectl label pod -n "$NS" alpha security.ir/quarantine=true --overwrite >/dev/null; settle
if http beta "$A"; then
  echo "  [FINDING] beta -> alpha ALLOWED: an allow policy overrides the quarantine (NetworkPolicy is additive, per spec)."
else
  echo "  [FINDING] beta -> alpha BLOCKED (unexpected for standard NetworkPolicy semantics — investigate)."
fi
expect blocked "alpha -> beta:8080 (egress still denied)" http alpha "$B"
kubectl delete -f "$DIR/03-allow-all-ingress-alpha.yaml" >/dev/null
kubectl label pod -n "$NS" alpha security.ir/quarantine- >/dev/null

# --- summary -------------------------------------------------------------------
echo; echo "== Unexpected results: $FAILS   (log: $LOG)"
echo "== Clean up with: kubectl delete namespace $NS"
exit "$FAILS"

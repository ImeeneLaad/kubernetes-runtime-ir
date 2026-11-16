#!/usr/bin/env bash
# Proves the responder's least privilege: RBAC (what it can call at all) and
# the ValidatingAdmissionPolicy (what it can change with patch/delete).
# Uses a throwaway pod created by the admin; Juice Shop is not touched.
# Usage (Ubuntu, project root):  bash tests/response-guardrails/run-test.sh
set -u
cd "$(dirname "$0")/../.."
mkdir -p tests/response-guardrails/results
LOG="tests/response-guardrails/results/guardrails-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1
FAILS=0
RK="response/secrets/ir-responder.kubeconfig"
[ -s "$RK" ] || { echo "run response/make-kubeconfig.sh first"; exit 99; }
R() { kubectl --kubeconfig "$RK" "$@"; }                 # as the responder
A() { kubectl --context kind-k8s-ir "$@"; }              # as admin
expect() {  # expect <allowed|denied> <description> <command...>
  local want=$1 desc=$2; shift 2; local out got
  out=$("$@" 2>&1); [ $? -eq 0 ] && got=allowed || got=denied
  if [ "$got" = "$want" ]; then printf '  [PASS] %-62s %s\n' "$desc" "$got"
  else printf '  [FAIL] %-62s expected=%s got=%s\n         %s\n' "$desc" "$want" "$got" "$(echo "$out" | tail -1)"; FAILS=$((FAILS+1)); fi
}
can() { [ "$(R auth can-i "$@" 2>/dev/null)" = "yes" ]; }

echo "== Responder guardrails test — $(date -Is)"
echo "   identity: $(R auth whoami -o jsonpath='{.status.userInfo.username}')"

echo; echo "-- A. RBAC: what the responder may call"
expect allowed "patch pods in juice-dev"                        can patch pods -n juice-dev
expect allowed "delete pods in juice-prod"                      can delete pods -n juice-prod
expect allowed "read falco sensor logs"                         can get pods/log -n falco
expect denied  "exec into pods (juice-dev)"                     can create pods/exec -n juice-dev
expect denied  "attach to pods (juice-dev)"                     can create pods/attach -n juice-dev
expect denied  "read secrets (juice-dev)"                       can get secrets -n juice-dev
expect denied  "create pods (juice-dev)"                        can create pods -n juice-dev
expect denied  "delete / change NetworkPolicies"                can delete networkpolicies -n juice-dev
expect denied  "patch deployments (e.g. change the image)"      can patch deployments -n juice-dev
expect denied  "patch pods in another namespace (default)"      can patch pods -n default
expect denied  "patch pods in kube-system"                      can patch pods -n kube-system
expect denied  "list pods cluster-wide"                         can list pods -A
expect denied  "create rolebindings (privilege escalation)"     can create rolebindings -n juice-dev
expect denied  "create serviceaccount tokens"                   can create serviceaccounts/token -n ir-system

echo; echo "-- B. Admission policy: what patch/delete may change (throwaway pod)"
A -n juice-dev delete pod guardrail-target --ignore-not-found --wait=true >/dev/null
A -n juice-dev run guardrail-target --image=busybox:1.36.1 --restart=Never \
  --labels=app.kubernetes.io/name=guardrail-test,security.ir/monitored=true \
  --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"}},
    "containers":[{"name":"guardrail-target","image":"busybox:1.36.1","command":["sleep","3600"],
    "securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' >/dev/null
A -n juice-dev wait --for=condition=Ready pod/guardrail-target --timeout=90s >/dev/null
P="pod/guardrail-target"
expect denied  "change the container image"                     R -n juice-dev patch $P --type=json -p='[{"op":"replace","path":"/spec/containers/0/image","value":"busybox:1.37.0"}]'
expect denied  "add an unrelated label (foo=bar)"               R -n juice-dev label $P foo=bar
expect denied  "add an annotation"                              R -n juice-dev annotate $P x=y
expect denied  "delete a pod that is NOT quarantined"           R -n juice-dev delete $P --wait=false
expect allowed "label security.ir/incident=test"                R -n juice-dev label $P security.ir/incident=guardrailtest
expect allowed "quarantine (security.ir/quarantine=true)"       R -n juice-dev label $P security.ir/quarantine=true
expect allowed "orphan: remove app.kubernetes.io/name"          R -n juice-dev label $P app.kubernetes.io/name-
expect denied  "lift the quarantine"                            R -n juice-dev label $P security.ir/quarantine-
expect denied  "set quarantine=false"                           R -n juice-dev label $P security.ir/quarantine=false --overwrite
expect denied  "put the quarantined pod back behind its Service" R -n juice-dev label $P app.kubernetes.io/name=guardrail-test
expect allowed "delete the quarantined pod"                     R -n juice-dev delete $P --wait=false
A -n juice-dev delete pod guardrail-target --ignore-not-found --wait=false >/dev/null

echo; echo "== Unexpected results: $FAILS  (log: $LOG)"
exit "$FAILS"

#!/usr/bin/env bash
# End-to-end test of the response actions (response/ir_respond.py):
#   simulate -> (refuse isolate without evidence) -> collect -> isolate -> verify
#   -> eradicate -> verify recovery; then the prod approval safeguard.
# Usage (Ubuntu, project root):  bash tests/response/run-test.sh
set -u
cd "$(dirname "$0")/../.."
mkdir -p tests/response/results
LOG="tests/response/results/response-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1
FAILS=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAILS=$((FAILS+1)); }
IR() { python3 -I response/ir_respond.py "$@" >/tmp/ir-last.out 2>&1; local rc=$?; tail -1 /tmp/ir-last.out | cut -c1-200; return $rc; }
expect_rc() { # expect_rc <rc> <desc> <ir args...>
  local want=$1 desc=$2; shift 2; local out rc
  out=$(IR "$@"); rc=$?
  [ "$rc" = "$want" ] && pass "$desc (rc=$rc)" || fail "$desc: rc=$rc, expected $want :: $out"
}
A() { kubectl --context kind-k8s-ir "$@"; }
TCP='const s=require("net").connect({host:process.argv[1],port:+process.argv[2],timeout:3000},()=>{console.log("OPEN");process.exit(0)});s.on("timeout",()=>{console.log("TIMEOUT");process.exit(1)});s.on("error",e=>{console.log(e.code);process.exit(1)})'
sim() { bash simulation/simulate-incident.sh "$1" | sed -n 's/^== Incident simulation \(sim[0-9]*\)  target=[a-z-]*\/\(.*\)$/\1 \2/p'; }

[ -s response/secrets/ir-responder.kubeconfig ] || bash response/make-kubeconfig.sh >/dev/null
# This suite drives the responder BY HAND. The live SOAR playbook would otherwise
# react to the same simulated alerts and act on the pods concurrently (observed).
bash response/automation.sh pause "tests/response running" >/dev/null
trap 'bash response/automation.sh resume >/dev/null' EXIT
echo "== Response test — $(date -Is)"

# ===================================================================== DEV
echo; echo "-- DEV: full automatic lifecycle"
read -r INC POD < <(sim dev); echo "   incident=$INC pod=$POD"
IP=$(A -n juice-dev get pod "$POD" -o jsonpath='{.status.podIP}')
expect_rc 3 "isolate BEFORE evidence is refused"         isolate juice-dev "$POD" "$INC"
expect_rc 0 "collect evidence"                           collect juice-dev "$POD" "$INC"
expect_rc 0 "collect again = no-op (idempotent)"         collect juice-dev "$POD" "$INC"
grep -q '"already-done"' /tmp/ir-last.out && pass "second collect reported already-done" || fail "second collect not idempotent"
bash response/verify-evidence.sh "evidence/$INC/juice-dev__$POD.tar.gz" > /tmp/ir-verify.out 2>&1
grep -q 'all .* files match' /tmp/ir-verify.out && pass "evidence package verifies" || fail "evidence package does not verify"
expect_rc 0 "isolate"                                    isolate juice-dev "$POD" "$INC"
L=$(A -n juice-dev get pod "$POD" -o jsonpath='{.metadata.labels}')
[[ "$L" == *'"security.ir/quarantine":"true"'* ]] && pass "pod labelled quarantined" || fail "quarantine label missing: $L"
[[ "$L" != *'app.kubernetes.io/name'* ]] && pass "pod orphaned (app label removed)" || fail "app label still present"
[ "$(A -n juice-dev get pod "$POD" -o jsonpath='{.status.phase}')" = Running ] && pass "isolated pod still running (kept for forensics)" || fail "isolated pod not running"
A -n juice-dev get endpointslices -l kubernetes.io/service-name=juice-shop -o jsonpath='{..addresses}' | grep -q "$IP" \
  && fail "isolated pod still a Service endpoint" || pass "isolated pod removed from Service endpoints"
r=$(timeout 15 kubectl --context kind-k8s-ir -n juice-dev exec "$POD" -- /nodejs/bin/node -e "$TCP" 1.1.1.1 443 2>/dev/null | tail -1)
[ "$r" = TIMEOUT ] && pass "isolated pod: egress to internet blocked" || fail "isolated pod egress: $r"
NEW=$(A -n juice-dev get pod -l app.kubernetes.io/name=juice-shop -o jsonpath='{.items[0].metadata.name}')
[ -n "$NEW" ] && [ "$NEW" != "$POD" ] && pass "replacement pod $NEW serving" || fail "no replacement pod"
bash apps/juice-shop/verify.sh dev | grep -q PASS && pass "application healthy while the suspect pod is isolated" || fail "application unhealthy"
expect_rc 0 "isolate again = no-op (idempotent)"         isolate juice-dev "$POD" "$INC"
grep -q '"already-done"' /tmp/ir-last.out && pass "second isolate reported already-done" || fail "second isolate not idempotent"
expect_rc 0 "eradicate (delete the isolated pod)"        eradicate juice-dev "$POD" "$INC"
A -n juice-dev get pod "$POD" >/dev/null 2>&1 && fail "isolated pod still exists" || pass "isolated pod deleted"
bash apps/juice-shop/verify.sh dev | grep -q PASS && pass "application healthy after eradication" || fail "application unhealthy after eradication"
expect_rc 0 "eradicate again = no-op (idempotent)"       eradicate juice-dev "$POD" "$INC"
echo "   audit trail: $(wc -l < "evidence/$INC/actions.jsonl") entries in evidence/$INC/actions.jsonl"

# ===================================================================== PROD
echo; echo "-- PROD: human approval required"
read -r INC2 POD2 < <(sim prod); echo "   incident=$INC2 pod=$POD2"
expect_rc 0 "collect evidence (no approval needed)"      collect juice-prod "$POD2" "$INC2"
expect_rc 3 "isolate WITHOUT approval is refused"        isolate juice-prod "$POD2" "$INC2"
A -n juice-prod get pod "$POD2" -o jsonpath='{.metadata.labels}' | grep -q quarantine \
  && fail "pod changed despite refusal" || pass "pod untouched after refusal"
# measure user-facing availability during the approved isolation
( for i in $(seq 1 40); do curl -s -o /dev/null -w '%{http_code}\n' --max-time 3 http://127.0.0.1:3031/; sleep 1; done ) > /tmp/prod-avail.txt &
CURLS=$!
expect_rc 0 "isolate WITH approval reference"            isolate juice-prod "$POD2" "$INC2" --approval "TEST-APPROVAL-$INC2"
expect_rc 3 "eradicate WITHOUT approval is refused"      eradicate juice-prod "$POD2" "$INC2"
expect_rc 0 "eradicate WITH approval reference"          eradicate juice-prod "$POD2" "$INC2" --approval "TEST-APPROVAL-$INC2"
wait $CURLS
ok=$(grep -c '^200$' /tmp/prod-avail.txt); tot=$(wc -l < /tmp/prod-avail.txt)
[ "$ok" -ge $((tot - 2)) ] && pass "prod availability during response: $ok/$tot requests OK" || fail "prod availability: only $ok/$tot OK"
grep -q "TEST-APPROVAL-$INC2" "evidence/$INC2/actions.jsonl" && pass "approval reference recorded in the audit trail" || fail "approval not recorded"
bash apps/juice-shop/verify.sh prod | grep -q PASS && pass "prod healthy after response" || fail "prod unhealthy"

# ===================================================================== SCOPE
echo; echo "-- Scope: targets outside the IR perimeter are refused"
FPOD=$(A -n falco get pod -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name}')
expect_rc 3 "collect on a Falco pod (namespace not protected)" collect falco "$FPOD" scopetest001
expect_rc 3 "invalid incident id is refused"             collect juice-dev "$NEW" 'bad id;rm'

echo; echo "== Unexpected results: $FAILS  (log: $LOG)"
exit "$FAILS"

#!/usr/bin/env bash
# End-to-end test of the SOAR playbook with REAL Falco alerts:
#   A. dev  : automatic   (simulate -> Falco -> Sidekick -> Shuffle -> responder)
#   B. prod : approved    (waits for a human; answered here by the test harness)
#   C. prod : rejected    (nothing may be done to the pod)
# Usage (Ubuntu, project root):  bash tests/playbook/run-test.sh
set -u
cd "$(dirname "$0")/../.."
mkdir -p tests/playbook/results
LOG="tests/playbook/results/playbook-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1
FAILS=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAILS=$((FAILS+1)); }
A() { kubectl --context kind-k8s-ir "$@"; }
incid() { python3 -c 'import hashlib,sys;print("inc"+hashlib.sha256(f"{sys.argv[1]}/{sys.argv[2]}".encode()).hexdigest()[:20])' "$1" "$2"; }
sim() { bash simulation/simulate-incident.sh "$1" | sed -n 's#^== Incident simulation sim[0-9]*  target=[a-z-]*/\(.*\)$#\1#p'; }
execs() { python3 -I soar/shuffle/show_executions.py 40 --incident "$1"; }
wait_for() {  # wait_for <seconds> <command...>: retry until the command succeeds
  local t=$1; shift; local end=$((SECONDS + t))
  until "$@" >/dev/null 2>&1; do [ $SECONDS -ge $end ] && return 1; sleep 5; done
}
waiting_exec() { python3 -I soar/shuffle/approve.py list | grep "incident $1" | sed -n 's/^execution \([^ ]*\).*/\1/p' | head -1; }
audit_has() { grep -q "\"action\": \"$2\".*\"result\": \"done\"" "evidence/$1/actions.jsonl" 2>/dev/null; }
final_snapshot_ok() {  # <incident> <ns__pod>: pre-eradicate snapshot exists, verifies, holds the dropped file
  local a="evidence/$1/$2__pre-eradicate.tar.gz"
  bash response/verify-evidence.sh "$a" > /tmp/pb-final.out 2>&1 && pass "pre-eradication snapshot taken and verifies" \
    || fail "pre-eradication snapshot missing or invalid"
  grep -q '/tmp/sim' "evidence/$1/$2__pre-eradicate/filesystem/changed-files.txt" 2>/dev/null \
    && pass "final snapshot contains the file dropped during the incident" || fail "dropped file not in the final snapshot"
}

bash falco/check-clock.sh --fix >/dev/null || { echo "Falco clock check failed"; exit 98; }
[ "$(bash response/automation.sh status)" = active ] || { echo "automated response is PAUSED (bash response/automation.sh resume)"; exit 97; }
echo "== Playbook test — $(date -Is)"

# =========================================================================== A. DEV
echo; echo "-- A. DEV: fully automatic"
POD=$(sim dev); INC=$(incid juice-dev "$POD"); echo "   pod=$POD incident=$INC"
wait_for 240 bash -c "python3 -I soar/shuffle/show_executions.py 40 --incident $INC | grep -q 'dev_verify:SUCCESS(healthy)'" \
  && pass "playbook ran triage -> collect -> isolate -> eradicate -> verify(healthy)" || fail "dev playbook did not complete"
sleep 20   # let the duplicate executions finish
E=$(execs "$INC")
n_resp=$(echo "$E" | grep -c 'triage:SUCCESS(respond-dev'); n_dup=$(echo "$E" | grep -c 'triage:SUCCESS(duplicate')
[ "$n_resp" -eq 1 ] && pass "exactly 1 execution responded ($n_dup duplicates stopped after triage)" || fail "$n_resp executions responded"
echo "$E" | grep -q 'collect:SKIPPED' && pass "duplicates skipped evidence collection" || fail "duplicates not skipped"
SOAR_SHA=$(echo "$E" | grep -o 'collect:SUCCESS(ok sha256=[0-9a-f]*' | head -1 | sed 's/.*sha256=//')
FILE_SHA=$(cut -c1-16 "evidence/$INC/juice-dev__$POD.tar.gz.sha256")
[ -n "$SOAR_SHA" ] && [ "$SOAR_SHA" = "$FILE_SHA" ] && pass "evidence hash recorded in Shuffle matches the archive ($SOAR_SHA...)" \
  || fail "hash in Shuffle '$SOAR_SHA' vs archive '$FILE_SHA'"
bash response/verify-evidence.sh "evidence/$INC/juice-dev__$POD.tar.gz" > /tmp/pb-verify.out 2>&1 \
  && pass "evidence package verifies" || fail "evidence package does not verify"
A -n juice-dev get pod "$POD" >/dev/null 2>&1 && fail "compromised dev pod still exists" || pass "compromised dev pod eradicated"
final_snapshot_ok "$INC" "juice-dev__$POD"
bash apps/juice-shop/verify.sh dev > /tmp/pb-health.out 2>&1 && pass "dev application healthy" || fail "dev unhealthy"

# =========================================================================== B. PROD approve
echo; echo "-- B. PROD: waits for a human, then approved"
POD=$(sim prod); INC=$(incid juice-prod "$POD"); echo "   pod=$POD incident=$INC"
wait_for 180 bash -c "python3 -I soar/shuffle/approve.py list | grep -q 'incident $INC'" \
  && pass "playbook paused at prod_approval (evidence collected first)" || fail "no waiting approval"
[ -f "evidence/$INC/juice-prod__$POD/COMPLETE" ] && pass "evidence complete BEFORE any decision" || fail "evidence missing before decision"
L=$(A -n juice-prod get pod "$POD" -o jsonpath='{.metadata.labels}')
[[ "$L" != *quarantine* && "$L" == *app.kubernetes.io/name* ]] && pass "pod untouched while waiting for approval" || fail "pod changed before approval: $L"
( for i in $(seq 1 75); do curl -s -o /dev/null -w '%{http_code}\n' --max-time 3 http://127.0.0.1:3031/; sleep 1; done ) > /tmp/pb-avail.txt &
CURLS=$!
python3 -I soar/shuffle/approve.py decide "$(waiting_exec "$INC")" approve --approver "automated-test-harness" | tail -1
wait_for 180 audit_has "$INC" eradicate && pass "approved: isolate + eradicate done by the responder" || fail "approved response not completed"
wait $CURLS
ok=$(grep -c '^200$' /tmp/pb-avail.txt); tot=$(wc -l < /tmp/pb-avail.txt)
[ "$ok" -ge $((tot - 2)) ] && pass "prod availability during approved response: $ok/$tot" || fail "prod availability $ok/$tot"
grep '"action": "isolate"' "evidence/$INC/actions.jsonl" | grep -q 'shuffle-userinput user=[^ ]*@' \
  && pass "audit trail names the authenticated Shuffle user who approved" || fail "approver identity missing in audit"
A -n juice-prod get pod "$POD" >/dev/null 2>&1 && fail "approved pod still exists" || pass "compromised prod pod eradicated"
final_snapshot_ok "$INC" "juice-prod__$POD"
bash apps/juice-shop/verify.sh prod > /tmp/pb-health.out 2>&1 && pass "prod application healthy" || fail "prod unhealthy"

# =========================================================================== C. PROD reject
echo; echo "-- C. PROD: rejected by the human"
POD=$(sim prod); INC=$(incid juice-prod "$POD"); echo "   pod=$POD incident=$INC"
wait_for 180 bash -c "python3 -I soar/shuffle/approve.py list | grep -q 'incident $INC'" || fail "no waiting approval"
python3 -I soar/shuffle/approve.py decide "$(waiting_exec "$INC")" reject --approver "automated-test-harness" | tail -1
sleep 40
L=$(A -n juice-prod get pod "$POD" -o jsonpath='{.metadata.labels}')
[[ "$L" != *quarantine* && "$L" == *app.kubernetes.io/name* ]] && pass "rejected: pod NOT quarantined, still serving" || fail "pod changed after rejection: $L"
grep -qE '"action": "(isolate|eradicate)"' "evidence/$INC/actions.jsonl" && fail "an action ran after rejection" || pass "no isolate/eradicate in the audit trail"
[ -f "evidence/$INC/juice-prod__$POD/COMPLETE" ] && pass "evidence kept for the rejected incident" || fail "evidence missing"
echo "   Shuffle: $(execs "$INC" | grep 'respond-prod' | head -1 | cut -c1-48)"
# teardown (admin, not the responder): restore a clean pod for the next runs
A -n juice-prod delete pod "$POD" --wait=true >/dev/null && echo "   teardown: admin deleted the rejected test pod (clean replacement)"

echo; echo "== Unexpected results: $FAILS  (log: $LOG)"
exit "$FAILS"

#!/usr/bin/env bash
# Tests the ir-responder HTTP API from the Shuffle network (where the SOAR calls it).
#   auth, scope checks, correlation under concurrency (9 parallel alerts -> 1 claim),
#   actions through the API (collect -> isolate -> eradicate on dev).
# Usage (Ubuntu, project root):  bash tests/responder-api/run-test.sh
set -u
cd "$(dirname "$0")/../.."
mkdir -p tests/responder-api/results
LOG="tests/responder-api/results/responder-api-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1
FAILS=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAILS=$((FAILS+1)); }
TOK=$(cat response/secrets/responder-token.txt)
# client container on the Shuffle network = same network position as Shuffle's apps
docker rm -f responder-client >/dev/null 2>&1
docker run -d --name responder-client --network shuffle_shuffle python:3.12.14-slim-bookworm sleep 900 >/dev/null
api() {  # api <path> <json> [token]
  docker exec -i responder-client python3 -c '
import sys, json, urllib.request, urllib.error
path, tok = sys.argv[1], sys.argv[2]
req = urllib.request.Request("http://ir-responder:8088" + path, data=sys.stdin.buffer.read(), method="POST",
      headers={"Content-Type": "application/json", "X-Responder-Token": tok})
try:
    r = urllib.request.urlopen(req, timeout=600); print(r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode())' "$1" "${3-$TOK}" <<<"$2"   # ${3-...}: an explicit "" must stay empty
}
alert() {  # alert <ns> <pod> [tags-json]
  printf '{"alert":{"rule":"Juice Shop - Sensitive file read","priority":"Error","output":"test","tags":%s,"output_fields":{"k8s.ns.name":"%s","k8s.pod.name":"%s"}}}' \
    "${3:-[\"juice_shop\",\"ir_response\"]}" "$1" "$2"
}
cleanup() { docker rm -f responder-client >/dev/null 2>&1; }
trap cleanup EXIT

echo "== Responder API test — $(date -Is)"
echo; echo "-- A. Exposure and authentication"
docker port ir-responder 2>/dev/null | grep -q . && fail "ir-responder publishes a host port" || pass "no host port published"
r=$(api /v1/verify '{"namespace":"juice-dev"}' wrongtoken); [[ "$r" == 401* ]] && pass "wrong token -> 401" || fail "wrong token: $r"
r=$(api /v1/verify '{"namespace":"juice-dev"}' "");         [[ "$r" == 401* ]] && pass "no token -> 401"    || fail "no token: $r"
r=$(api /v1/verify '{"namespace":"juice-dev"}');            [[ "$r" == 200*'"healthy": true'* ]] && pass "verify juice-dev healthy" || fail "verify: $r"

echo; echo "-- B. Triage scope"
r=$(api /v1/triage "$(alert juice-dev x '["juice_shop"]')"); [[ "$r" == *'"in_scope": false'* ]] && pass "alert without ir_response tag -> out of scope" || fail "$r"
r=$(api /v1/triage "$(alert kube-system coredns-x)");        [[ "$r" == *'"in_scope": false'* ]] && pass "alert from unprotected namespace -> out of scope" || fail "$r"
r=$(api /v1/triage "$(alert juice-dev 'Bad;Pod')");          [[ "$r" == *'"in_scope": false'* ]] && pass "invalid pod name -> out of scope" || fail "$r"
r=$(api /v1/action '{"action":"delete-everything","incident_id":"x1x","namespace":"juice-dev","pod":"p"}'); [[ "$r" == 400* ]] && pass "unknown action -> 400" || fail "$r"

echo; echo "-- C. Correlation: 9 parallel alerts for one pod -> exactly 1 claim"
FAKEPOD="corrtest-$RANDOM"
# wait on these PIDs only: a bare `wait` would also wait for the tee process substitution (bash >= 5.1)
PIDS=()
for i in $(seq 1 9); do api /v1/triage "$(alert juice-dev "$FAKEPOD")" > "/tmp/corr-$i.out" & PIDS+=($!); done
wait "${PIDS[@]}"
claims=$(grep -l '"claimed": true' /tmp/corr-*.out | wc -l)
ids=$(grep -oh '"incident_id": "[a-z0-9]*"' /tmp/corr-*.out | sort -u | wc -l)
[ "$claims" -eq 1 ] && pass "exactly 1 of 9 concurrent alerts claimed the incident" || fail "$claims claims"
[ "$ids" -eq 1 ] && pass "all 9 alerts mapped to the same incident id" || fail "$ids different incident ids"
INC_FAKE=$(grep -oh '"incident_id": "[a-z0-9]*"' /tmp/corr-1.out | cut -d'"' -f4)
n=$(wc -l < "evidence/$INC_FAKE/alerts-received.jsonl"); [ "$n" -eq 9 ] && pass "all 9 alerts recorded in the incident timeline" || fail "$n alerts recorded"
rm -rf "evidence/$INC_FAKE" /tmp/corr-*.out

echo; echo "-- D. Actions through the API (dev, real pod)"
POD=$(kubectl -n juice-dev get pod -l app.kubernetes.io/name=juice-shop -o jsonpath='{.items[0].metadata.name}')
T=$(api /v1/triage "$(alert juice-dev "$POD")"); INC=$(echo "$T" | grep -o '"incident_id": "[a-z0-9]*"' | cut -d'"' -f4)
[[ "$T" == *'"claimed": true'* ]] && pass "triage claimed incident $INC for $POD" || fail "triage: $T"
for act in isolate collect isolate eradicate; do
  r=$(api /v1/action "{\"action\":\"$act\",\"incident_id\":\"$INC\",\"namespace\":\"juice-dev\",\"pod\":\"$POD\"}")
  o=$(echo "$r" | grep -o '"outcome": "[a-z]*"' | cut -d'"' -f4)
  echo "     $act -> $o"
  case "$act-$o" in
    isolate-refused) pass "isolate before collect refused through the API" ;;
    collect-ok|isolate-ok|eradicate-ok) pass "$act ok" ;;
    *) fail "$act -> $r" ;;
  esac
done
r=$(api /v1/verify '{"namespace":"juice-dev"}'); [[ "$r" == *'"healthy": true'* ]] && pass "juice-dev healthy after API-driven response" || fail "$r"
grep -q 'root@' "evidence/$INC/juice-dev__$POD/custody.log" && pass "custody log records the responder container as operator" || fail "operator not recorded"

echo; echo "== Unexpected results: $FAILS  (log: $LOG)"
exit "$FAILS"

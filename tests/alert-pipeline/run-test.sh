#!/usr/bin/env bash
# End-to-end test of the alert pipeline: Falco -> Falcosidekick -> Web UI,
# plus protection of Sidekick against forged alerts.
# Usage (Ubuntu, project root):  bash tests/alert-pipeline/run-test.sh
set -u
cd "$(dirname "$0")/../.."
mkdir -p tests/alert-pipeline/results
LOG="tests/alert-pipeline/results/pipeline-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1
FAILS=0
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; FAILS=$((FAILS+1)); }
CRED=$(cat falco/secrets/ui-credentials.txt)
PF_PIDS=()
cleanup() { for p in "${PF_PIDS[@]}"; do kill "$p" 2>/dev/null; done; kubectl delete ns pipeline-spoof --wait=false >/dev/null 2>&1; }
trap cleanup EXIT

[ "$(kubectl config current-context)" = "kind-k8s-ir" ] || { echo "wrong context"; exit 99; }
echo "== Alert pipeline test — $(date -Is)"

# --- 0. Components ----------------------------------------------------------------
echo; echo "-- 0. Components ready"
for d in deploy/falco-falcosidekick deploy/falco-falcosidekick-ui statefulset/falco-falcosidekick-ui-redis ds/falco; do
  kubectl -n falco rollout status "$d" --timeout=120s >/dev/null 2>&1 && pass "$d ready" || fail "$d not ready"
done
url=$(kubectl -n falco get cm falco -o jsonpath='{.data.falco\.yaml}' | python3 -c '
import sys,yaml; c=yaml.safe_load(sys.stdin)["http_output"]; print(c["url"] if c.get("enabled") else "disabled")' 2>/dev/null)
[[ "$url" == http://falco-falcosidekick* ]] && pass "Falco http_output -> $url" || fail "Falco http_output: $url"
# Time-window searches below (and every incident timeline) need correct Falco timestamps.
bash falco/check-clock.sh || FAILS=$((FAILS+1))

kubectl -n falco port-forward svc/falco-falcosidekick 12801:2801 >/dev/null 2>&1 & PF_PIDS+=($!)
kubectl -n falco port-forward svc/falco-falcosidekick-ui 12802:2802 >/dev/null 2>&1 & PF_PIDS+=($!)
sleep 3
# metric <fixed-string1> [<fixed-string2>]: sum of matching Sidekick Prometheus samples
metric() {
  curl -s http://127.0.0.1:12801/metrics | grep '^falcosecurity_falcosidekick_outputs_total' \
    | grep -F -- "$1" | grep -F -- "${2:-}" | awk '{s+=$NF} END {print s+0}'
}

# --- 1. Real alert delivered end to end -----------------------------------------------
echo; echo "-- 1. Real alert: Juice Shop (dev) -> Falco -> Sidekick -> Web UI"
ok_before=$(metric 'destination="webui"' 'status="ok"')
# Alphanumeric only: the UI search (RediSearch) treats "-" as a NOT operator.
MARK="pipelinetest$RANDOM$RANDOM"
POD=$(kubectl -n juice-dev get pod -l app.kubernetes.io/name=juice-shop -o jsonpath='{.items[0].metadata.name}')
kubectl -n juice-dev exec "$POD" -- /nodejs/bin/node -e "require('fs').readFileSync('/etc/passwd') /* $MARK */" >/dev/null 2>&1
found=""
for i in $(seq 1 15); do
  sleep 2
  found=$(curl -s -u "$CRED" "http://127.0.0.1:12802/api/v1/events/search?since=5m&filter=$MARK" | grep -o "$MARK" | head -1)
  [ -n "$found" ] && break
done
[ -n "$found" ] && pass "alert with marker $MARK visible in the Web UI (after ~$((i*2))s)" \
                || fail "alert with marker $MARK not found in the Web UI"
ok_after=$(metric 'destination="webui"' 'status="ok"')
[ "$ok_after" -gt "$ok_before" ] && pass "Sidekick webui output counter ok: $ok_before -> $ok_after" \
                               || fail "Sidekick webui output counter did not increase ($ok_before -> $ok_after)"
err=$(metric 'status="error"')
[ "$err" -eq 0 ] && pass "no output errors" || fail "$err output errors in Sidekick metrics"

# --- 2. Web UI authentication ------------------------------------------------------------
echo; echo "-- 2. Web UI authentication"
c=$(curl -s -o /dev/null -w '%{http_code}' -u admin:admin "http://127.0.0.1:12802/api/v1/events/count")
[ "$c" = "401" ] && pass "default admin:admin rejected (HTTP $c)" || fail "admin:admin -> HTTP $c"
c=$(curl -s -o /dev/null -w '%{http_code}' -u "$CRED" "http://127.0.0.1:12802/api/v1/events/count")
[ "$c" = "200" ] && pass "generated credential accepted (HTTP $c)" || fail "generated credential -> HTTP $c"

# --- 3. Forged alert from another namespace ----------------------------------------------
echo; echo "-- 3. Forged alert from another namespace must be blocked"
kubectl create ns pipeline-spoof >/dev/null 2>&1
kubectl -n pipeline-spoof run spoof --image=busybox:1.36.1 --restart=Never -- sleep 300 >/dev/null
kubectl -n pipeline-spoof wait --for=condition=Ready pod/spoof --timeout=90s >/dev/null
FAKE='{"output":"FORGED alert","priority":"Critical","rule":"Juice Shop - Outbound TCP connection","time":"2026-01-01T00:00:00Z","output_fields":{"k8s.ns.name":"juice-prod","k8s.pod.name":"victim"},"tags":["juice_shop","ir_response"]}'
if kubectl -n pipeline-spoof exec spoof -- wget -q -T 5 -O- --header 'Content-Type: application/json' \
     --post-data "$FAKE" http://falco-falcosidekick.falco.svc:2801/ >/dev/null 2>&1; then
  fail "forged alert ACCEPTED by Sidekick from namespace pipeline-spoof"
else
  pass "forged alert from namespace pipeline-spoof blocked (timeout)"
fi
if kubectl -n pipeline-spoof exec spoof -- wget -q -T 5 -O /dev/null http://falco-falcosidekick-ui.falco.svc:2802/ >/dev/null 2>&1; then
  fail "Web UI reachable from namespace pipeline-spoof"
else
  pass "Web UI not reachable from namespace pipeline-spoof"
fi

# --- 4. Falco -> Sidekick -> Shuffle (SOAR) ---------------------------------------
echo; echo "-- 4. Real alert reaches the SOAR: Shuffle workflow 'IR - Falco alert intake'"
if [ -s soar/shuffle/secrets/api-key.txt ] && [ -s soar/shuffle/secrets/webhook-url.txt ]; then
  wh_before=$(metric 'destination="webhook"' 'status="ok"')
  MARK2="soartest$RANDOM$RANDOM"
  kubectl -n juice-dev exec "$POD" -- /nodejs/bin/node -e "require('fs').readFileSync('/etc/passwd') /* $MARK2 */" >/dev/null 2>&1
  res=$(MARK="$MARK2" python3 -I - <<'EOF'
import os, sys, time, json
sys.path.insert(0, "soar/shuffle")
from shuffle_api import call
mark = os.environ["MARK"]
_, wfs = call("GET", "/api/v1/workflows")
wf = next((w for w in wfs if w.get("name") == "IR - Falco alert intake"), None)
if not wf:
    print("NOWORKFLOW"); sys.exit()
for i in range(30):
    time.sleep(3)
    _, ex = call("GET", f"/api/v1/workflows/{wf['id']}/executions")
    ex = ex.get("executions", []) if isinstance(ex, dict) else ex
    for e in ex:
        if mark in json.dumps(e) and e.get("status") == "FINISHED":
            ok = all(r.get("status") == "SUCCESS" for r in e.get("results") or [])
            print(f"FOUND {e['execution_id']} {(i+1)*3}s {'SUCCESS' if ok else 'ACTIONFAIL'}"); sys.exit()
print("NOTFOUND")
EOF
)
  case "$res" in
    FOUND*SUCCESS) pass "Shuffle execution with marker $MARK2 finished OK (${res#FOUND })" ;;
    *) fail "Shuffle execution for marker $MARK2: $res" ;;
  esac
  wh_after=$(metric 'destination="webhook"' 'status="ok"')
  [ "$wh_after" -gt "$wh_before" ] && pass "Sidekick webhook output counter ok: $wh_before -> $wh_after" \
                                   || fail "Sidekick webhook output counter did not increase"
  [ "$(metric 'destination="webhook"' 'status="error"')" -eq 0 ] && pass "no webhook output errors" || fail "webhook output errors"
else
  fail "Shuffle secrets missing (api-key.txt / webhook-url.txt): SOAR delivery not tested"
fi

echo; echo "== Unexpected results: $FAILS  (log: $LOG)"
exit "$FAILS"

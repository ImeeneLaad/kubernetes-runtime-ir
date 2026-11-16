#!/usr/bin/env bash
# Tests the custom Juice Shop Falco rules (falco/rules/juice-shop-rules.yaml).
#   A. False-positive baseline: restart Juice Shop + normal use -> 0 alerts
#   B. True positives: one harmless trigger per rule -> each rule fires
# Usage (Ubuntu, project root):  bash tests/falco-rules/run-test.sh
# The triggers are benign (print, read, short TCP connect, write a test
# file) and run only in juice-dev, through the image's own node binary.
set -u
cd "$(dirname "$0")/../.."
mkdir -p tests/falco-rules/results
LOG="tests/falco-rules/results/falco-rules-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1
FAILS=0
NODE=/nodejs/bin/node
alerts() { kubectl -n falco logs ds/falco -c falco --since-time="$1" 2>/dev/null | grep '"juice_shop"'; }

[ "$(kubectl config current-context)" = "kind-k8s-ir" ] || { echo "wrong context"; exit 99; }
echo "== Falco custom rules test — $(date -Is)"

# --- 0. Sensor health: a dead sensor would make every "no alert" check pass --------
echo; echo "-- 0. Falco health"
ready=$(kubectl -n falco get ds falco -o jsonpath='{.status.numberReady}/{.status.desiredNumberScheduled}')
loaded=$(kubectl -n falco logs ds/falco -c falco 2>/dev/null | grep -c 'juice-shop-rules.yaml | schema validation: ok')
invalid=$(kubectl -n falco logs ds/falco -c falco 2>/dev/null | grep -c 'juice-shop-rules.yaml: Invalid')
if [ "$ready" = "1/1" ] && [ "$loaded" -ge 1 ] && [ "$invalid" -eq 0 ]; then
  echo "  [PASS] Falco ready ($ready), custom rules loaded"
else
  echo "  [FAIL] Falco not healthy (ready=$ready loaded=$loaded invalid=$invalid). Aborting."; exit 98
fi

# --- A. False-positive baseline ----------------------------------------------------
echo; echo "-- A. False positives: restart dev + prod, then normal application use"
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
for ns in juice-dev juice-prod; do kubectl -n $ns rollout restart deploy/juice-shop >/dev/null; done
for ns in juice-dev juice-prod; do kubectl -n $ns rollout status deploy/juice-shop --timeout=300s >/dev/null; done
sleep 10    # let startup checks (precondition fetches) finish
for port in 3030 3031; do
  for path in / /rest/products/search?q=apple /api/Products /rest/languages /api/Challenges /ftp; do
    curl -s -o /dev/null --max-time 10 "http://127.0.0.1:$port$path"
  done
  curl -s -o /dev/null -H 'Content-Type: application/json' \
    -d "{\"email\":\"fp-$RANDOM@example.test\",\"password\":\"FpTest-12345\",\"passwordRepeat\":\"FpTest-12345\",\"securityQuestion\":{\"id\":1},\"securityAnswer\":\"x\"}" \
    "http://127.0.0.1:$port/api/Users"
done
sleep 5
n=$(alerts "$T0" | wc -l)
if [ "$n" -eq 0 ]; then echo "  [PASS] 0 Juice Shop alerts during restart + normal use"
else echo "  [FAIL] $n Juice Shop alerts during restart + normal use:"; alerts "$T0" | python3 falco/show-alerts.py; FAILS=$((FAILS+1)); fi

# --- B. True positives ------------------------------------------------------------------
echo; echo "-- B. True positives (juice-dev): one harmless trigger per rule"
POD=$(kubectl -n juice-dev get pod -l app.kubernetes.io/name=juice-shop -o jsonpath='{.items[0].metadata.name}')
x() { kubectl -n juice-dev exec "$POD" -- $NODE -e "$1" >/dev/null 2>&1; }
T1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
x 'console.log("hello")'                                                         # exec
x 'require("child_process").execFileSync("/nodejs/bin/node",["-v"])'               # child process
x 'require("fs").readFileSync("/etc/passwd")'                                      # sensitive read
x 'const s=require("net").connect(443,"1.1.1.1",()=>s.end());s.on("error",()=>{})' # outbound TCP
x 'require("fs").writeFileSync("/tmp/falco-rule-test.txt","test")'                 # write
sleep 5
OUT=$(alerts "$T1")
for rule in "Exec into container" "Process spawned by the application" "Sensitive file read" \
            "Outbound TCP connection" "Write outside application data directories"; do
  c=$(printf '%s\n' "$OUT" | grep -c "\"rule\":\"Juice Shop - $rule\"")
  if [ "$c" -ge 1 ]; then printf '  [PASS] %-45s fired %s time(s)\n' "$rule" "$c"
  else printf '  [FAIL] %-45s did not fire\n' "$rule"; FAILS=$((FAILS+1)); fi
done
echo; echo "  Alert details:"
printf '%s\n' "$OUT" | python3 falco/show-alerts.py | sed 's/^/  /'

echo; echo "== Unexpected results: $FAILS  (log: $LOG)"
echo "== Note: juice-dev pod $POD now contains /tmp/falco-rule-test.txt; restart it to clean up."
exit "$FAILS"

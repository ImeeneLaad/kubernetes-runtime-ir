#!/usr/bin/env bash
# Controlled, repeatable incident simulation for the Juice Shop target.
#
# It ONLY replays the five harmless triggers already validated in
# tests/falco-rules (Step 3). Each step is benign on its own: it prints a
# value, runs `node -v`, reads /etc/passwd, opens and closes one TCP
# connection to 1.1.1.1:443, and writes one small text file in /tmp.
# Together they produce a realistic alert sequence covering all 5 custom
# rules, which the later steps use to exercise evidence collection,
# isolation, remediation and recovery. No exploit or attack tooling is used.
#
# Usage (Ubuntu, project root):
#   bash simulation/simulate-incident.sh [dev|prod]        (default: dev)
# Output: simulation/results/<incident-id>.json (timeline + detection check)
set -u
cd "$(dirname "$0")/.."
ENV=${1:-dev}
case "$ENV" in dev|prod) ;; *) echo "usage: $0 [dev|prod]"; exit 2 ;; esac
NS="juice-$ENV"
NODE=/nodejs/bin/node
ID="sim$(date -u +%Y%m%d%H%M%S)$RANDOM"      # alphanumeric: also searchable in the Sidekick UI
OUT="simulation/results/$ID.json"
mkdir -p simulation/results

[ "$(kubectl config current-context)" = "kind-k8s-ir" ] || { echo "wrong kube context"; exit 99; }
# Correct timestamps are a precondition for a usable incident timeline.
bash falco/check-clock.sh --fix >/dev/null || { echo "Falco clock check failed: aborting"; exit 98; }

POD=$(kubectl -n "$NS" get pod -l app.kubernetes.io/name=juice-shop -o jsonpath='{.items[0].metadata.name}')
[ -n "$POD" ] || { echo "no Juice Shop pod in $NS"; exit 97; }
echo "== Incident simulation $ID  target=$NS/$POD"

STEPS_JSON=""
step() {  # step <name> <expected rule> <node code>
  local name=$1 rule=$2 code=$3 t
  t=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
  kubectl -n "$NS" exec "$POD" -- $NODE -e "/* $ID */ $code" >/dev/null 2>&1
  echo "  $t  $name"
  STEPS_JSON+="{\"time\":\"$t\",\"step\":\"$name\",\"expected_rule\":\"Juice Shop - $rule\"},"
  sleep 2
}

START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
step "1 execute code in the container"      "Exec into container"  'console.log("hello")'
step "2 application spawns a process"       "Process spawned by the application" \
     'require("child_process").execFileSync("/nodejs/bin/node",["-v"])'
step "3 read an identity file"              "Sensitive file read"  'require("fs").readFileSync("/etc/passwd")'
step "4 open one outbound TCP connection"   "Outbound TCP connection" \
     'const s=require("net").connect(443,"1.1.1.1",()=>s.end());s.on("error",()=>{})'
step "5 write a file outside data dirs"     "Write outside application data directories" \
     "require('fs').writeFileSync('/tmp/$ID.txt','incident simulation marker')"
END=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- detection check: which expected rules fired with this incident's marker?
sleep 5
kubectl -n falco logs ds/falco -c falco --since-time="$START" 2>/dev/null | grep "$ID" \
  | python3 -I simulation/build_report.py "$ID" "$NS" "$POD" "$START" "$END" "$OUT" "[${STEPS_JSON%,}]"

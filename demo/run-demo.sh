#!/usr/bin/env bash
# Interactive end-to-end demonstration:
#   detection -> alerting -> evidence -> isolation -> replacement -> recovery -> report
#   Scenario 1: DEV  (fully automatic)
#   Scenario 2: PROD (YOU approve or reject the response)
# Usage (Ubuntu, project root):  bash demo/run-demo.sh
set -u
cd "$(dirname "$0")/.."
B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'
say()   { echo; echo "${B}== $*${N}"; }
pause() { echo; read -rp "${Y}[press Enter to continue]${N} " _; }
ok()    { echo "  ${G}✔${N} $*"; }
bad()   { echo "  ${R}✘${N} $*"; }
incid() { python3 -c 'import hashlib,sys;print("inc"+hashlib.sha256(f"{sys.argv[1]}/{sys.argv[2]}".encode()).hexdigest()[:20])' "$1" "$2"; }
until_ok() { local t=$1; shift; local e=$((SECONDS+t)); until "$@" >/dev/null 2>&1; do [ $SECONDS -ge $e ] && return 1; sleep 5; done; }

# ------------------------------------------------------------------ preflight
say "0. Preflight"
[ "$(kubectl config current-context)" = kind-k8s-ir ] && ok "kube context kind-k8s-ir" || { bad "wrong kube context"; exit 1; }
kubectl -n falco rollout status ds/falco --timeout=60s >/dev/null && ok "Falco running (modern eBPF)" || bad "Falco not ready"
bash falco/check-clock.sh --fix | sed 's/^ */  /'
bash apps/juice-shop/verify.sh | grep -E 'PASS|FAIL' | sed 's/^ */  /'
docker ps --format '{{.Names}}' | grep -q '^shuffle-backend$' && ok "Shuffle SOAR running" || bad "Shuffle not running (bash soar/shuffle/shuffle.sh up)"
docker exec ir-responder python3 -c 'import urllib.request;urllib.request.urlopen("http://127.0.0.1:8088/healthz")' 2>/dev/null \
  && ok "ir-responder running" || bad "ir-responder not running (bash response/service/run.sh)"
[ "$(bash response/automation.sh status)" = active ] && ok "automated response active (kill switch off)" \
  || bad "automated response PAUSED: bash response/automation.sh resume"
kubectl --kubeconfig response/secrets/ir-responder.kubeconfig auth whoami >/dev/null 2>&1 \
  && ok "responder credential valid" || bad "responder token expired: bash response/service/run.sh"
echo
echo "  Watch along: Sidekick UI  -> kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802  (http://localhost:2802)"
echo "               Shuffle UI   -> http://localhost:3001  (workflow 'IR - Juice Shop response')"
pause

# ------------------------------------------------------------------ scenario 1: dev
say "1. DEV incident: automatic response"
OUT=$(bash simulation/simulate-incident.sh dev); echo "$OUT" | sed -n '1,7p;/DETECTED\|MISSED/p'
POD=$(echo "$OUT" | sed -n 's#^== Incident simulation sim[0-9]*  target=juice-dev/\(.*\)$#\1#p'); INC=$(incid juice-dev "$POD")
echo; echo "  Falco alerts for $POD:"
kubectl -n falco logs ds/falco -c falco --since=2m | grep "$POD" | python3 falco/show-alerts.py --summary | sed 's/^/  /'
pause
say "   SOAR playbook (one execution responds, duplicates stop after triage)"
until_ok 240 bash -c "python3 -I soar/shuffle/show_executions.py 40 --incident $INC | grep -q 'dev_verify:SUCCESS'" \
  && ok "playbook finished" || bad "playbook did not finish in time"
python3 -I soar/shuffle/show_executions.py 40 --incident "$INC" | grep respond-dev | tr ' ' '\n' | grep ':' | sed 's/^/    /'
echo; echo "  Responder audit trail:"; python3 -I response/show-actions.py "$INC" | sed 's/^/    /'
echo; kubectl -n juice-dev get pod "$POD" >/dev/null 2>&1 && bad "compromised pod still present" || ok "compromised pod $POD eradicated"
kubectl -n juice-dev get pods -l app.kubernetes.io/name=juice-shop --no-headers | sed 's/^/    replacement: /'
bash apps/juice-shop/verify.sh dev | grep -E 'PASS|FAIL' | sed 's/^ */  /'
python3 -I response/incident_report.py "$INC" | sed 's/^/  report: /'
pause

# ------------------------------------------------------------------ scenario 2: prod
say "2. PROD incident: the response waits for YOUR decision"
OUT=$(bash simulation/simulate-incident.sh prod); echo "$OUT" | sed -n '1,7p;/DETECTED\|MISSED/p'
POD=$(echo "$OUT" | sed -n 's#^== Incident simulation sim[0-9]*  target=juice-prod/\(.*\)$#\1#p'); INC=$(incid juice-prod "$POD")
until_ok 180 bash -c "python3 -I soar/shuffle/approve.py list | grep -q 'incident $INC'" \
  && ok "evidence collected, playbook paused at 'prod_approval'" || { bad "no approval request appeared"; exit 1; }
echo; python3 -I soar/shuffle/approve.py list | sed -n "/incident $INC/,/^execution/p" | sed 's/^/  /'
echo; echo "  Pod right now (untouched while waiting): $(kubectl -n juice-prod get pod "$POD" -o jsonpath='{.metadata.labels}')"
EX=$(python3 -I soar/shuffle/approve.py list | grep "incident $INC" | sed -n 's/^execution \([^ ]*\).*/\1/p')
echo
read -rp "${Y}Your name (recorded as approver): ${N}" WHO
read -rp "${Y}Approve isolation + replacement of $POD? [y/N] ${N}" ANS
if [[ "$ANS" =~ ^[Yy]$ ]]; then
  python3 -I soar/shuffle/approve.py decide "$EX" approve --approver "$WHO" | tail -1 | sed 's/^/  /'
  until_ok 180 grep -q '"action": "eradicate".*"result": "done"' "evidence/$INC/actions.jsonl" \
    && ok "isolated, connections cut, replacement serving, compromised pod deleted" || bad "response not completed"
else
  python3 -I soar/shuffle/approve.py decide "$EX" reject --approver "$WHO" | tail -1 | sed 's/^/  /'
  ok "rejected: the pod keeps running untouched; evidence is kept for investigation"
fi
echo; echo "  Responder audit trail:"; python3 -I response/show-actions.py "$INC" | sed 's/^/    /'
bash apps/juice-shop/verify.sh prod | grep -E 'PASS|FAIL' | sed 's/^ */  /'
python3 -I response/incident_report.py "$INC" | sed 's/^/  report: /'

say "Done. Reports: evidence/<incident>/report.md   Evidence check: bash response/verify-evidence.sh <archive>"

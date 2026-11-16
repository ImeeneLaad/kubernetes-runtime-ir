#!/usr/bin/env bash
# Builds and (re)starts the ir-responder container.
# Usage (Ubuntu, project root):  bash response/service/run.sh
#
# Network exposure: NO published port. Reachable only by containers on the
# Shuffle network (the SOAR) and on the kind network (needed to reach the API
# server). Juice Shop pods cannot reach 172.24.0.0/16 (egress policy).
# Mounts: project read-only, evidence/ read-write, docker.sock (node-level
# actions: SAME privilege class as Shuffle's own docker.sock mount).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
S="$ROOT/response/secrets"
mkdir -p "$S" "$ROOT/evidence"

# 1. shared secret Shuffle -> responder
[ -s "$S/responder-token.txt" ] || head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 40 > "$S/responder-token.txt"

# 2. responder kubeconfig reachable from INSIDE the kind network (API server by node name)
bash "$ROOT/response/make-kubeconfig.sh" "${TOKEN_TTL:-12h}" >/dev/null
sed -E 's#server: "https://[^"]+"#server: "https://k8s-ir-control-plane:6443"#' \
  "$S/ir-responder.kubeconfig" > "$S/ir-responder-incluster.kubeconfig"

# 3. image + container
#    kubectl = the kind node's own binary (exact cluster version); git-ignored build input
mkdir -p "$ROOT/response/service/bin"
docker cp k8s-ir-control-plane:/usr/bin/kubectl "$ROOT/response/service/bin/kubectl"
#    explicit pulls with a time limit, so a stalled registry fails loudly instead of hanging the build
for img in docker:29.8.1-cli python:3.12.14-slim-bookworm; do
  docker image inspect "$img" >/dev/null 2>&1 || timeout 600 docker pull -q "$img" >/dev/null || { echo "pull of $img failed/timed out"; exit 1; }
done
timeout 600 docker build --progress=plain -t ir-responder:1.0 "$ROOT/response/service" > /tmp/ir-responder-build.log 2>&1 \
  || { tail -20 /tmp/ir-responder-build.log; exit 1; }
docker rm -f ir-responder >/dev/null 2>&1 || true
docker run -d --name ir-responder --restart unless-stopped \
  --network shuffle_shuffle \
  -v "$ROOT:/work:ro" -v "$ROOT/evidence:/work/evidence" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e TZ=UTC \
  ir-responder:1.0 >/dev/null
docker network connect kind ir-responder
for i in $(seq 1 20); do
  docker exec ir-responder python3 -c 'import urllib.request;urllib.request.urlopen("http://127.0.0.1:8088/healthz")' 2>/dev/null && break; sleep 1
done
echo "ir-responder up: http://ir-responder:8088 (Shuffle network only)"
docker exec ir-responder kubectl --kubeconfig /work/response/secrets/ir-responder-incluster.kubeconfig auth whoami -o jsonpath='{.status.userInfo.username}{"\n"}'

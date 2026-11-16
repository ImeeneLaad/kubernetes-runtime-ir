#!/usr/bin/env bash
# Applies the responder RBAC + admission policy, then writes a kubeconfig for
# the ir-responder ServiceAccount with a SHORT-LIVED token (TokenRequest API).
# Run as cluster admin (kind context). Output: response/secrets/ir-responder.kubeconfig
# Usage (Ubuntu, project root):  bash response/make-kubeconfig.sh [duration, default 12h]
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
DUR=${1:-12h}
OUT="$DIR/secrets/ir-responder.kubeconfig"
mkdir -p "$DIR/secrets"

kubectl --context kind-k8s-ir apply -f "$DIR/rbac/ir-responder.yaml"
kubectl --context kind-k8s-ir apply -f "$DIR/rbac/admission-policy.yaml"

SERVER=$(kubectl --context kind-k8s-ir config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA=$(kubectl --context kind-k8s-ir config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
TOKEN=$(kubectl --context kind-k8s-ir -n ir-system create token ir-responder --duration="$DUR")

cat > "$OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: k8s-ir
  cluster: { server: "$SERVER", certificate-authority-data: "$CA" }
users:
- name: ir-responder
  user: { token: "$TOKEN" }
contexts:
- name: ir-responder@k8s-ir
  context: { cluster: k8s-ir, user: ir-responder }
current-context: ir-responder@k8s-ir
EOF
chmod 600 "$OUT" 2>/dev/null || true
echo "wrote $OUT (token valid $DUR)"

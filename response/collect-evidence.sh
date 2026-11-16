#!/usr/bin/env bash
# Evidence collection for a suspected-compromised pod, BEFORE any isolation
# or remediation. Usable by hand and by the SOAR.
#
# Usage (Ubuntu, project root):
#   bash response/collect-evidence.sh <namespace> <pod> <incident-id> [phase]
#   phase: "initial" (default, first alert) or e.g. "pre-eradicate" (final
#   snapshot right before the pod is destroyed: captures activity that
#   happened after the first snapshot, e.g. while a prod approval was pending)
# Output: evidence/<incident-id>/<namespace>__<pod>[__<phase>]/  +  <...>.tar.gz + .sha256
#
# Principles (docs/07-evidence-collection.md):
#   - Never exec into the suspect container: it would modify it, could trigger
#     attacker traps, and pollutes the evidence with our own activity. Volatile
#     data is read from the NODE (/proc of the container's processes, its
#     cgroup, its overlay upperdir).
#   - Order of volatility: processes/connections -> files -> Kubernetes
#     state -> logs/alerts.
#   - Chain of custody: every command, its UTC time and exit code -> custody.log.
#   - Integrity: SHA-256 of every file + of the final archive.
#   - Idempotent: if evidence for this incident+pod is COMPLETE, do nothing.
set -u
VERSION="collect-evidence 1.0"
NS=${1:?namespace}; POD=${2:?pod}; INC=${3:?incident-id}; PHASE=${4:-initial}
[[ "$INC" =~ ^[A-Za-z0-9_-]{4,64}$ ]] || { echo "invalid incident id"; exit 2; }
[[ "$NS$POD" =~ ^[a-z0-9.-]+$ ]] || { echo "invalid namespace/pod name"; exit 2; }
[[ "$PHASE" =~ ^[a-z-]{3,20}$ ]] || { echo "invalid phase"; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BASE="$ROOT/evidence/$INC"
if [ "$PHASE" = initial ]; then PKG="${NS}__${POD}"; else PKG="${NS}__${POD}__${PHASE}"; fi
DIR="$BASE/$PKG"
NODE_CTR_PREFIX=""   # set below from the pod's node name

if [ -f "$DIR/COMPLETE" ]; then
  echo "evidence already collected for $INC $NS/$POD: $(cat "$DIR/COMPLETE")"; exit 0
fi
mkdir -p "$DIR"/{volatile,container,filesystem,kubernetes,alerts}
CUSTODY="$DIR/custody.log"
now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
log() { printf '%s | %s\n' "$(now)" "$*" >> "$CUSTODY"; }

# run <output-file> <description> <command...>: record, execute, capture output
run() {
  local out=$1 desc=$2; shift 2
  local t0; t0=$(now)
  "$@" > "$DIR/$out" 2>> "$DIR/collector-errors.log"; local rc=$?
  printf '%s | %-38s | rc=%s | %s\n' "$t0" "$desc" "$rc" "$*" >> "$CUSTODY"
  return $rc
}

START=$(now)
log "START $VERSION incident=$INC phase=$PHASE target=$NS/$POD operator=$(id -un)@$(hostname) context=$(kubectl config current-context)"

# --- identify the container from the API (before anything changes) -----------------
kubectl -n "$NS" get pod "$POD" -o json > "$DIR/kubernetes/pod-at-start.json" 2>>"$DIR/collector-errors.log" \
  || { log "ABORT pod not found"; echo "pod $NS/$POD not found"; exit 3; }
NODE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["spec"]["nodeName"])' "$DIR/kubernetes/pod-at-start.json")
CID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"]["containerStatuses"][0]["containerID"].split("://")[1])' "$DIR/kubernetes/pod-at-start.json")
# kind: the node is a Docker container with the node's name
N() { docker exec "$NODE" "$@"; }
log "target node=$NODE container_id=$CID"

run container/crictl-inspect.json "container runtime inspect" N crictl inspect "$CID"
PID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["info"]["pid"])' "$DIR/container/crictl-inspect.json")
UPPER=$(N sh -c "grep -m1 ' / / ' /proc/$PID/mountinfo | tr ',' '\n' | sed -n 's/^upperdir=//p'")
log "container init pid (node ns)=$PID overlay upperdir=$UPPER"

# --- 1. VOLATILE: processes + network connections ---------------------------------------
run volatile/cgroup-procs.txt "pids in container cgroup" \
  N sh -c "cat /sys/fs/cgroup\$(cut -d: -f3 /proc/$PID/cgroup)/cgroup.procs"
for p in $(cat "$DIR/volatile/cgroup-procs.txt"); do
  run "volatile/proc-$p.txt" "process $p details" N sh -c "
    echo '## cmdline'; tr '\0' ' ' < /proc/$p/cmdline; echo
    echo '## exe';     readlink /proc/$p/exe
    echo '## cwd';     readlink /proc/$p/cwd
    echo '## status';  cat /proc/$p/status
    echo '## environ'; tr '\0' '\n' < /proc/$p/environ
    echo '## open fds'; ls -l /proc/$p/fd
    echo '## maps';    cat /proc/$p/maps"
done
# the pod's network namespace: every socket of every process in it
for f in tcp tcp6 udp udp6; do
  run "volatile/net-$f.raw" "socket table $f (pod netns)" N cat "/proc/$PID/net/$f"
done
python3 "$ROOT/response/decode_sockets.py" "$DIR/volatile" > "$DIR/volatile/connections.txt" 2>>"$DIR/collector-errors.log"
log "decoded sockets -> volatile/connections.txt"

# --- 2. FILESYSTEM: everything the container added/changed (overlay upperdir) -----------
run filesystem/changed-files.txt "list of changed files (+stat)" \
  N sh -c "cd '$UPPER' && find . -xdev -printf '%TY-%Tm-%TdT%TH:%TM:%TS %u:%g %m %s %p\n' | sort"
run filesystem/upperdir.tar "archive of changed files" N tar -C "$UPPER" --numeric-owner -cf - .

# --- 3. CONTAINER IMAGE identity ------------------------------------------------------------
python3 - "$DIR/container/crictl-inspect.json" > "$DIR/container/image.txt" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
print("image_id :", d["status"]["image"]["image"])
print("image_ref:", d["status"].get("imageRef"))
print("started  :", d["status"].get("startedAt"))
EOF

# --- 4. KUBERNETES state ----------------------------------------------------------------------
run kubernetes/pod.yaml          "pod manifest"                kubectl -n "$NS" get pod "$POD" -o yaml
run kubernetes/describe.txt      "pod describe"                kubectl -n "$NS" describe pod "$POD"
# Kubernetes keeps events ~1 h: an empty result is normal for an older, quiet pod.
run kubernetes/events.txt        "events for the pod (1h TTL)" kubectl -n "$NS" get events --field-selector "involvedObject.name=$POD" -o wide
run kubernetes/networkpolicies.yaml "network policies (namespace)" kubectl -n "$NS" get networkpolicies -o yaml
run kubernetes/owner.yaml        "replicaset/deployment"       kubectl -n "$NS" get rs,deploy -o yaml
run kubernetes/logs.txt          "container logs (current)"    kubectl -n "$NS" logs "$POD" --all-containers --timestamps
kubectl -n "$NS" logs "$POD" --all-containers --timestamps --previous > "$DIR/kubernetes/logs-previous.txt" 2>/dev/null \
  && log "previous container logs saved" || { rm -f "$DIR/kubernetes/logs-previous.txt"; log "no previous container (no restart)"; }

# --- 5. ALERTS: every Falco alert for this pod still in the sensor's log -----------------------
kubectl -n falco logs ds/falco -c falco 2>>"$DIR/collector-errors.log" \
  | python3 -c '
import json, sys
pod = sys.argv[1]
for l in sys.stdin:
    if l.startswith("{"):
        try:
            a = json.loads(l)
        except Exception:
            continue
        if a.get("output_fields", {}).get("k8s.pod.name") == pod:
            print(json.dumps(a))' "$POD" > "$DIR/alerts/falco-alerts.jsonl"
log "falco alerts for pod: $(wc -l < "$DIR/alerts/falco-alerts.jsonl") -> alerts/falco-alerts.jsonl"

# --- 6. INTEGRITY: manifest + hashes + archive ------------------------------------------------
END=$(now)
log "END collection (start=$START end=$END)"
python3 - "$DIR" "$INC" "$NS" "$POD" "$NODE" "$CID" "$START" "$END" "$VERSION" "$PHASE" <<'EOF'
import hashlib, json, os, sys
d, inc, ns, pod, node, cid, start, end, ver, phase = sys.argv[1:11]
files = []
for root, _, names in os.walk(d):
    for n in sorted(names):
        p = os.path.join(root, n); rel = os.path.relpath(p, d)
        if rel in ("manifest.json", "SHA256SUMS", "COMPLETE"):
            continue
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        files.append({"path": rel, "size": os.path.getsize(p), "sha256": h})
files.sort(key=lambda f: f["path"])
json.dump({
    "incident_id": inc, "namespace": ns, "pod": pod, "node": node, "container_id": cid,
    "phase": phase, "collector": ver, "collection_start_utc": start, "collection_end_utc": end,
    "note": "Times are the collector's UTC wall clock. Compare with Falco alert times "
            "(alerts/) to detect sensor clock skew.",
    "files": files}, open(os.path.join(d, "manifest.json"), "w"), indent=2)
with open(os.path.join(d, "SHA256SUMS"), "w") as f:
    for x in files:
        f.write(f"{x['sha256']}  {x['path']}\n")
EOF
ARCHIVE="$BASE/$PKG.tar.gz"
tar -C "$BASE" -czf "$ARCHIVE" "$PKG"
( cd "$BASE" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256" )
AH=$(cut -d' ' -f1 "$ARCHIVE.sha256")
echo "archive sha256=$AH collected_end=$END" > "$DIR/COMPLETE"
# custody.log is sealed (hashed, archived) at END. The archive record cannot go
# inside the archive it describes, so it goes into a custody file beside it.
printf '%s | ARCHIVE %s sha256=%s operator=%s\n' "$(now)" "$(basename "$ARCHIVE")" "$AH" "$(id -un)@$(hostname)" \
  >> "$BASE/$PKG.custody.log"
chmod -R a-w "$DIR" "$ARCHIVE" "$ARCHIVE.sha256" 2>/dev/null || true   # no effect on DrvFs (/mnt/d)

echo "evidence: $DIR"
echo "archive : $ARCHIVE"
echo "sha256  : $AH"
echo "files   : $(wc -l < "$DIR/SHA256SUMS")   errors logged: $(wc -l < "$DIR/collector-errors.log" 2>/dev/null || echo 0)"

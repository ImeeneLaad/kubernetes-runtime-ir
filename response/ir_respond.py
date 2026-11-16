#!/usr/bin/env python3
"""Incident-response actions for Juice Shop pods (called by hand or by the SOAR).

  collect   <ns> <pod> <incident>                  evidence BEFORE anything else
  isolate   <ns> <pod> <incident> [--approval REF] quarantine + orphan + cut connections
  eradicate <ns> <pod> <incident> [--approval REF] delete the quarantined pod
  status    <ns> <pod>

Kubernetes calls use the least-privilege ir-responder kubeconfig
(response/secrets/ir-responder.kubeconfig); the API server additionally
enforces response/rbac/admission-policy.yaml.

Safeguards enforced HERE as well (defence in depth, independent of the SOAR):
  - target namespace must carry security.ir/environment=dev|prod
  - target pod must carry security.ir/monitored=true
  - isolate / eradicate refuse to run until evidence for <incident>+<pod> is COMPLETE
  - prod: isolate / eradicate require --approval <reference of the human approval>
  - eradicate only on a pod that is already isolated
  - every action is idempotent and appended to evidence/<incident>/actions.jsonl

Exit codes: 0 done (or already done), 1 action failed, 3 refused by a safeguard.
Usage (Ubuntu, project root):  python3 -I response/ir_respond.py isolate juice-dev <pod> <incident>
"""
import argparse
import datetime as dt
import getpass
import json
import os
import re
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KUBECONFIG = os.environ.get("IR_KUBECONFIG", os.path.join(ROOT, "response", "secrets", "ir-responder.kubeconfig"))
Q, INC, APP = "security.ir/quarantine", "security.ir/incident", "app.kubernetes.io/name"
NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
INC_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9_.-]{2,61}[A-Za-z0-9])$")   # also a valid label value


class Refused(Exception):
    """A safeguard prevented the action (exit 3)."""


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def kubectl(*args, check=True):
    p = subprocess.run(["kubectl", "--kubeconfig", KUBECONFIG, *args], capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)}: {p.stderr.strip()[:300]}")
    return p


def kjson(*args):
    return json.loads(kubectl(*args, "-o", "json").stdout)


def audit(incident, record):
    d = os.path.join(ROOT, "evidence", incident)
    os.makedirs(d, exist_ok=True)
    record = {"time": now(), "operator": f"{getpass.getuser()}@{socket.gethostname()}", **record}
    with open(os.path.join(d, "actions.jsonl"), "a") as f:
        f.write(json.dumps(record) + "\n")
    print(json.dumps(record))


def evidence_complete(incident, ns, pod):
    return os.path.exists(os.path.join(ROOT, "evidence", incident, f"{ns}__{pod}", "COMPLETE"))


def preflight(ns, pod, incident, approval, action):
    if not NAME_RE.match(ns) or not NAME_RE.match(pod):
        raise Refused("invalid namespace or pod name")
    if not INC_RE.match(incident):
        raise Refused("invalid incident id")
    try:
        env = kjson("get", "namespace", ns)["metadata"].get("labels", {}).get("security.ir/environment")
    except RuntimeError as e:
        if "forbidden" in str(e).lower():   # RBAC: not a namespace the responder protects
            raise Refused(f"namespace {ns} is outside the responder's perimeter (RBAC forbidden)")
        raise
    if env not in ("dev", "prod"):
        raise Refused(f"namespace {ns} is not a protected IR namespace (security.ir/environment={env})")
    p = kjson("-n", ns, "get", "pod", pod)
    if p["metadata"].get("labels", {}).get("security.ir/monitored") != "true":
        raise Refused(f"pod {ns}/{pod} is not in IR scope (security.ir/monitored != true)")
    if action in ("isolate", "eradicate"):
        if not evidence_complete(incident, ns, pod):
            raise Refused("evidence not collected yet: run 'collect' first (evidence before action)")
        if env == "prod" and not approval:
            raise Refused(f"{action} in prod requires --approval <reference of the human approval>")
    return env, p


def endpoints_contain(ns, ip):
    es = kjson("-n", ns, "get", "endpointslices", "-l", "kubernetes.io/service-name=juice-shop")
    return any(ip in (e.get("addresses") or []) for s in es["items"] for e in (s.get("endpoints") or []))


def wait_service_restored(ns, timeout=240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        d = kjson("-n", ns, "get", "deployment", "juice-shop")
        want, avail = d["spec"]["replicas"], d["status"].get("availableReplicas", 0)
        if avail >= want:
            return {"desired": want, "available": avail}
        time.sleep(5)
    raise RuntimeError(f"replacement not ready within {timeout}s")


# ------------------------------------------------------------------ actions
def collect(ns, pod, incident, approval):
    preflight(ns, pod, incident, approval, "collect")
    if evidence_complete(incident, ns, pod):
        audit(incident, {"action": "collect", "target": f"{ns}/{pod}", "result": "already-done"})
        return
    env = dict(os.environ, KUBECONFIG=KUBECONFIG)
    p = subprocess.run(["bash", os.path.join(ROOT, "response", "collect-evidence.sh"), ns, pod, incident],
                       capture_output=True, text=True, env=env)
    sha = next((l.split()[-1] for l in p.stdout.splitlines() if l.startswith("sha256")), None)
    ok = p.returncode == 0 and evidence_complete(incident, ns, pod)
    audit(incident, {"action": "collect", "target": f"{ns}/{pod}", "result": "done" if ok else "failed",
                     "archive_sha256": sha, "stderr": p.stderr[-300:] if not ok else ""})
    if not ok:
        raise RuntimeError("evidence collection failed")


def isolate(ns, pod, incident, approval):
    env, p = preflight(ns, pod, incident, approval, "isolate")
    labels = p["metadata"].get("labels", {})
    ip, node = p["status"].get("podIP"), p["spec"]["nodeName"]
    steps = []
    # 1. quarantine first: from here on, no new connection in or out.
    if labels.get(Q) != "true":
        kubectl("-n", ns, "label", "pod", pod, f"{Q}=true", f"{INC}={incident}", "--overwrite")
        steps.append("quarantine-label")
    # 2. orphan: leaves the Service and the ReplicaSet -> a clean replacement starts.
    if APP in labels:
        kubectl("-n", ns, "label", "pod", pod, f"{APP}-")
        steps.append("orphan")
    # 3. cut connections that were already open (they bypass the policy via conntrack).
    #    Node-level operation: needs Docker access to the kind node (NOT Kubernetes RBAC).
    flushed = 0
    for flag in ("-s", "-d"):
        r = subprocess.run(["docker", "exec", node, "conntrack", "-D", flag, ip], capture_output=True, text=True)
        m = re.search(r"(\d+) flow entries", r.stderr + r.stdout)
        flushed += int(m.group(1)) if m else 0
    steps.append(f"conntrack-flush({flushed})")
    # 4. verify
    time.sleep(3)
    in_eps = endpoints_contain(ns, ip)
    restored = wait_service_restored(ns)
    now_labels = kjson("-n", ns, "get", "pod", pod)["metadata"].get("labels", {})
    ok = now_labels.get(Q) == "true" and APP not in now_labels and not in_eps
    audit(incident, {"action": "isolate", "target": f"{ns}/{pod}", "env": env, "approval": approval,
                     "result": ("done" if steps[:-1] else "already-done") if ok else "failed",
                     "steps": steps, "pod_ip": ip, "pod_in_service_endpoints": in_eps, "service": restored})
    if not ok:
        raise RuntimeError("isolation verification failed")


def eradicate(ns, pod, incident, approval):
    try:
        env, p = preflight(ns, pod, incident, approval, "eradicate")
    except RuntimeError as e:
        if "NotFound" in str(e) or "not found" in str(e):
            audit(incident, {"action": "eradicate", "target": f"{ns}/{pod}", "result": "already-done"})
            return
        raise
    if p["metadata"].get("labels", {}).get(Q) != "true":
        raise Refused("pod is not isolated: run 'isolate' first")
    # Final snapshot right before destruction: the first snapshot is taken at the
    # FIRST alert, and activity can continue afterwards (observed: the last steps of
    # an incident happened after it, and in prod the pod runs until approval).
    final = os.path.join(ROOT, "evidence", incident, f"{ns}__{pod}__pre-eradicate", "COMPLETE")
    if not os.path.exists(final):
        r = subprocess.run(["bash", os.path.join(ROOT, "response", "collect-evidence.sh"), ns, pod, incident,
                            "pre-eradicate"], capture_output=True, text=True, env=dict(os.environ, KUBECONFIG=KUBECONFIG))
        if r.returncode != 0 or not os.path.exists(final):
            raise RuntimeError("pre-eradication evidence snapshot failed: pod NOT deleted")
    final_sha = open(final).read().split()[1].split("=")[1]
    kubectl("-n", ns, "delete", "pod", pod, "--wait=true", "--timeout=120s")
    restored = wait_service_restored(ns)
    audit(incident, {"action": "eradicate", "target": f"{ns}/{pod}", "env": env, "approval": approval,
                     "result": "done", "pre_eradicate_archive_sha256": final_sha, "service": restored})


def status(ns, pod, *_):
    p = kubectl("-n", ns, "get", "pod", pod, "-o", "json", check=False)
    if p.returncode != 0:
        print(json.dumps({"target": f"{ns}/{pod}", "exists": False}))
        return
    pj = json.loads(p.stdout)
    lb = pj["metadata"].get("labels", {})
    print(json.dumps({"target": f"{ns}/{pod}", "exists": True, "quarantined": lb.get(Q) == "true",
                      "incident": lb.get(INC), "in_service": APP in lb, "ip": pj["status"].get("podIP"),
                      "phase": pj["status"].get("phase")}))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["collect", "isolate", "eradicate", "status"])
    ap.add_argument("namespace")
    ap.add_argument("pod")
    ap.add_argument("incident", nargs="?", default="")
    ap.add_argument("--approval", default="", help="reference of the human approval (required in prod)")
    a = ap.parse_args()
    fn = {"collect": collect, "isolate": isolate, "eradicate": eradicate, "status": status}[a.action]
    try:
        fn(a.namespace, a.pod, a.incident, a.approval)
    except Refused as e:
        if a.incident and INC_RE.match(a.incident):
            audit(a.incident, {"action": a.action, "target": f"{a.namespace}/{a.pod}", "result": "refused", "reason": str(e)})
        else:
            print(f"REFUSED: {e}", file=sys.stderr)
        sys.exit(3)
    except Exception as e:  # noqa: BLE001
        if a.incident and INC_RE.match(a.incident):
            audit(a.incident, {"action": a.action, "target": f"{a.namespace}/{a.pod}", "result": "failed", "error": str(e)[:300]})
        else:
            print(f"FAILED: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

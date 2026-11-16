#!/usr/bin/env python3
"""ir-responder HTTP API (standard library only). Called by the SOAR (Shuffle).

Every request needs header  X-Responder-Token: <response/secrets/responder-token.txt>

  GET  /healthz
  POST /v1/triage  {"alert": <Falco alert as sent by Falcosidekick>}
       -> validates scope, derives ONE incident id per pod, atomically claims it.
          {"in_scope", "reason", "incident_id", "namespace", "pod", "environment",
           "claimed", "rule", "priority"}
          claimed=true only for the FIRST alert of an incident; every alert is logged.
  POST /v1/action  {"action": "collect|isolate|eradicate", "incident_id", "namespace",
                    "pod", "approval"?}
       -> runs response/ir_respond.py (all its safeguards apply), returns its audit record.
  POST /v1/respond-approved {"incident_id", "namespace", "pod", "approval"}
       -> PROD only, after the human approval: isolate + eradicate in the background
          (returns at once; see respond_approved for why)
  POST /v1/verify  {"namespace"}  -> application health (deployment + endpoints)

Concurrency: one lock per (namespace, pod). The ~9 SOAR executions of one
incident are serialised, never interleaved.
"""
import hashlib
import hmac
import json
import os
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.environ.get("IR_ROOT", "/work")
TOKEN = open(os.path.join(ROOT, "response", "secrets", "responder-token.txt")).read().strip()
KUBECONFIG = os.path.join(ROOT, "response", "secrets", "ir-responder-incluster.kubeconfig")
EVIDENCE = os.path.join(ROOT, "evidence")
PAUSE_FLAG = os.path.join(EVIDENCE, ".automation-paused")   # evidence/ is the only writable mount
PROTECTED = {"juice-dev": "dev", "juice-prod": "prod"}      # mirrors namespace labels; re-checked by ir_respond.py
REQUIRED_TAGS = {"juice_shop", "ir_response"}
POD_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
MAX_BODY = 256 * 1024

_locks, _locks_guard = {}, threading.Lock()


def lock_for(key):
    with _locks_guard:
        return _locks.setdefault(key, threading.Lock())


def incident_id(ns, pod):
    # Deterministic: every alert about the same pod maps to the same incident.
    return "inc" + hashlib.sha256(f"{ns}/{pod}".encode()).hexdigest()[:20]


def triage(body):
    a = body.get("alert") or {}
    f = a.get("output_fields") or {}
    ns, pod = f.get("k8s.ns.name"), f.get("k8s.pod.name")
    res = {"in_scope": False, "claimed": False, "decision": "out-of-scope", "namespace": ns, "pod": pod,
           "rule": a.get("rule"), "priority": a.get("priority")}
    tags = set(a.get("tags") or [])
    if not REQUIRED_TAGS <= tags:
        return {**res, "reason": f"missing tags {sorted(REQUIRED_TAGS - tags)}"}
    if ns not in PROTECTED:
        return {**res, "reason": f"namespace {ns} not protected"}
    if not pod or not POD_RE.match(pod):
        return {**res, "reason": "invalid or missing pod name"}
    inc = incident_id(ns, pod)
    d = os.path.join(EVIDENCE, inc)
    os.makedirs(d, exist_ok=True)
    with lock_for((ns, pod)):
        with open(os.path.join(d, "alerts-received.jsonl"), "a") as fh:
            fh.write(json.dumps(a) + "\n")
        # Kill switch (response/automation.sh pause): alerts are still recorded,
        # but the SOAR is told not to act. No claim is taken, so the incident can
        # still be handled automatically once automation is resumed.
        if os.path.exists(PAUSE_FLAG):
            return {**res, "in_scope": True, "reason": "automation paused", "incident_id": inc,
                    "environment": PROTECTED[ns], "decision": "paused"}
        try:  # atomic claim: only the first alert of the incident gets claimed=true
            fd = os.open(os.path.join(d, "claim.json"), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w") as fh:
                json.dump({"first_alert": a, "namespace": ns, "pod": pod}, fh)
            claimed = True
        except FileExistsError:
            claimed = False
    env = PROTECTED[ns]
    return {**res, "in_scope": True, "reason": "ok", "incident_id": inc, "environment": env,
            "claimed": claimed,
            # single string for SOAR branching (string comparison, no boolean ambiguity)
            "decision": f"respond-{env}" if claimed else "duplicate"}


def action(body):
    act, inc, ns, pod = (body.get(k) for k in ("action", "incident_id", "namespace", "pod"))
    if act not in ("collect", "isolate", "eradicate"):
        return 400, {"error": "unknown action"}
    if ns not in PROTECTED or not pod or not POD_RE.match(pod) or not inc:
        return 400, {"error": "invalid target"}
    cmd = ["python3", "-I", os.path.join(ROOT, "response", "ir_respond.py"), act, ns, pod, inc]
    if body.get("approval"):
        cmd += ["--approval", str(body["approval"])[:200]]
    with lock_for((ns, pod)):
        p = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, IR_KUBECONFIG=KUBECONFIG))
    last = (p.stdout.strip().splitlines() or [""])[-1]
    try:
        record = json.loads(last)
    except json.JSONDecodeError:
        record = {"raw": (p.stdout + p.stderr)[-400:]}
    outcome = {0: "ok", 3: "refused"}.get(p.returncode, "failed")
    return 200, {"action": act, "incident_id": inc, "outcome": outcome, "rc": p.returncode, "record": record}


def respond_approved(body):
    """PROD, after the human approval in the SOAR: isolate then eradicate, in the background.

    Returns at once. Shuffle swaps its worker a few seconds after a User Input is
    answered, and a long synchronous action started in that window loses its
    result (observed). Progress goes to evidence/<incident>/actions.jsonl as usual.
    """
    inc, ns, pod, approval = (body.get(k) for k in ("incident_id", "namespace", "pod", "approval"))
    if PROTECTED.get(ns) != "prod" or not pod or not POD_RE.match(pod) or not inc or not approval:
        return 400, {"error": "prod target and approval required"}

    def job():
        for act in ("isolate", "eradicate"):
            code, res = action({"action": act, "incident_id": inc, "namespace": ns, "pod": pod, "approval": approval})
            print(f"approved job {inc} {act}: {res.get('outcome')}", flush=True)
            if res.get("outcome") != "ok":
                break

    threading.Thread(target=job, daemon=True).start()
    return 200, {"outcome": "accepted", "incident_id": inc, "namespace": ns, "pod": pod,
                 "steps": ["isolate", "eradicate"], "approval": approval[:200]}


def verify(body):
    ns = body.get("namespace")
    if ns not in PROTECTED:
        return 400, {"error": "invalid namespace"}
    k = ["kubectl", "--kubeconfig", KUBECONFIG, "-n", ns]
    d = json.loads(subprocess.run(k + ["get", "deploy", "juice-shop", "-o", "json"], capture_output=True, text=True).stdout or "{}")
    es = json.loads(subprocess.run(k + ["get", "endpointslices", "-l", "kubernetes.io/service-name=juice-shop", "-o", "json"],
                                   capture_output=True, text=True).stdout or "{}")
    ready = sum(1 for s in es.get("items", []) for e in (s.get("endpoints") or []) if (e.get("conditions") or {}).get("ready"))
    want = (d.get("spec") or {}).get("replicas")
    avail = (d.get("status") or {}).get("availableReplicas", 0)
    return 200, {"namespace": ns, "desired": want, "available": avail, "ready_endpoints": ready,
                 "healthy": bool(want) and avail >= want and ready >= want}


class Handler(BaseHTTPRequestHandler):
    server_version = "ir-responder/1.0"

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorised(self):
        return hmac.compare_digest(self.headers.get("X-Responder-Token", ""), TOKEN)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorised():
            return self._send(401, {"error": "unauthorised"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return self._send(413, {"error": "body too large"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self._send(400, {"error": "invalid JSON"})
        if self.path == "/v1/triage":
            return self._send(200, triage(body))
        if self.path == "/v1/action":
            return self._send(*action(body))
        if self.path == "/v1/respond-approved":
            return self._send(*respond_approved(body))
        if self.path == "/v1/verify":
            return self._send(*verify(body))
        self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):   # one line per request, no bodies (they can contain alert data)
        print(f"{self.log_date_time_string()} {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    print("ir-responder listening on :8088", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8088), Handler).serve_forever()

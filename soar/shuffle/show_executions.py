#!/usr/bin/env python3
"""Show recent executions of the IR playbook with per-node results.

Usage (Ubuntu, project root):
  python3 -I soar/shuffle/show_executions.py [N]            # last N executions (default 12)
  python3 -I soar/shuffle/show_executions.py --incident ID  # only executions of one incident
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shuffle_api import call  # noqa: E402

NAME = "IR - Juice Shop response"


def body(result):
    """http app result -> parsed responder body (dict) when possible."""
    try:
        r = json.loads(result) if isinstance(result, str) else result
        b = r.get("body", r) if isinstance(r, dict) else r
        return json.loads(b) if isinstance(b, str) else b
    except (ValueError, TypeError, AttributeError):
        return result


def executions():
    _, wfs = call("GET", "/api/v1/workflows")
    wf = next(w for w in wfs if w["name"] == NAME)
    _, ex = call("GET", f"/api/v1/workflows/{wf['id']}/executions")
    return wf, (ex.get("executions", []) if isinstance(ex, dict) else ex) or []


def summary(e):
    out = []
    for r in sorted(e.get("results") or [], key=lambda r: r.get("started_at", 0)):
        label = (r.get("action") or {}).get("label")
        b = body(r.get("result"))
        key = ""
        if isinstance(b, dict):
            key = b.get("decision") or b.get("outcome") or ("healthy" if b.get("healthy") else "") or ""
            if label == "triage":
                key += f" inc={b.get('incident_id')} {b.get('namespace')}/{b.get('pod')}"
            if label == "collect" and isinstance(b.get("record"), dict):
                key += f" sha256={str(b['record'].get('archive_sha256'))[:16]}..."
        out.append(f"{label}:{r.get('status')}({key.strip()})")
    return out


def main(argv):
    inc = argv[argv.index("--incident") + 1] if "--incident" in argv else None
    n = int(argv[0]) if argv and argv[0].isdigit() else 12
    _, ex = executions()
    shown = 0
    for e in ex:
        if inc and inc not in json.dumps(e.get("results") or []):
            continue
        print(f"{e.get('execution_id')}  {e.get('status'):9}  " + "  ".join(summary(e)))
        shown += 1
        if shown >= n:
            break


if __name__ == "__main__":
    main(sys.argv[1:])

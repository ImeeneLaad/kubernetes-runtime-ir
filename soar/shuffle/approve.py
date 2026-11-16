#!/usr/bin/env python3
"""Human approval of PROD response actions waiting in the Shuffle playbook.

  python3 -I soar/shuffle/approve.py list
  python3 -I soar/shuffle/approve.py decide <execution-id> approve|reject --approver "<your name>"

Answers the playbook's User Input node ("prod_approval") through the same
endpoint the Shuffle UI uses (GET /api/v1/workflows/<wf>/run?answer=...), with
the decision and the approver recorded as the answer's note. The call is made
with the Shuffle admin's API key (soar/shuffle/secrets/api-key.txt), so the
decision is tied to the authenticated admin, not only to the execution link.

Equivalent in the UI: open the waiting execution in Shuffle and answer the
"prod_approval" question.
"""
import argparse
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shuffle_api import call            # noqa: E402
from show_executions import body, executions   # noqa: E402


def waiting():
    wf, ex = executions()
    out = []
    for e in ex:
        if e.get("status") != "WAITING":
            continue
        res = {(r.get("action") or {}).get("label"): r for r in (e.get("results") or [])}
        a = res.get("prod_approval")
        if not a or a.get("status") != "WAITING":
            continue
        t = body((res.get("triage") or {}).get("result")) or {}
        info = json.loads(a["result"]).get("information", "") if isinstance(a.get("result"), str) else ""
        out.append({"execution_id": e["execution_id"], "authorization": e["authorization"],
                    "node": a["action"]["id"], "workflow": wf["id"], "incident": t.get("incident_id"),
                    "target": f"{t.get('namespace')}/{t.get('pod')}", "info": info})
    return out


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    d = sub.add_parser("decide")
    d.add_argument("execution_id")
    d.add_argument("decision", choices=["approve", "reject"])
    d.add_argument("--approver", required=True)
    a = ap.parse_args()

    pending = waiting()
    if a.cmd == "list":
        if not pending:
            print("no PROD decision waiting")
        for p in pending:
            print(f"execution {p['execution_id']}  incident {p['incident']}  target {p['target']}")
            print("   " + p["info"].replace("\n", "\n   "))
        return

    p = next((p for p in pending if p["execution_id"] == a.execution_id), None)
    if p is None:
        sys.exit("that execution is not waiting for a decision (already answered, or wrong id)")
    note = json.dumps({"decision": a.decision, "approver": a.approver, "incident": p["incident"]})
    q = urllib.parse.urlencode({
        "reference_execution": p["execution_id"], "authorization": p["authorization"],
        "answer": "true" if a.decision == "approve" else "false",
        "source_node": p["node"], "note": note,
    })
    s, r = call("GET", f"/api/v1/workflows/{p['workflow']}/run?{q}")
    print(f"HTTP {s}: {str(r)[:300]}")
    print(f"{a.decision.upper()} recorded for incident {p['incident']} ({p['target']}) by {a.approver}")


if __name__ == "__main__":
    main()

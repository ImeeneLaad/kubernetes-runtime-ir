#!/usr/bin/env python3
"""Print an incident's response audit trail (evidence/<incident>/actions.jsonl) compactly.
Usage (Ubuntu, project root):  python3 -I response/show-actions.py <incident-id>
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
path = os.path.join(ROOT, "evidence", sys.argv[1], "actions.jsonl")
for line in open(path):
    d = json.loads(line)
    extra = {k: d[k] for k in ("steps", "reason", "approval", "pod_in_service_endpoints", "service", "archive_sha256")
             if d.get(k) not in (None, "")}
    print(f"{d['time']}  {d['action']:9} {d['result']:12} {d['target']}  {json.dumps(extra) if extra else ''}")

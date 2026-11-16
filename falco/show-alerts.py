#!/usr/bin/env python3
"""Pretty-print Falco JSON alerts read from stdin.

Usage (Ubuntu):
  kubectl -n falco logs ds/falco -c falco --since=10m | python3 falco/show-alerts.py
  ... | python3 falco/show-alerts.py --summary      # count per rule / namespace
  ... | python3 falco/show-alerts.py --k8s-only     # hide non-Kubernetes events
"""
import collections
import json
import sys

summary = "--summary" in sys.argv
k8s_only = "--k8s-only" in sys.argv
counts = collections.Counter()

for line in sys.stdin:
    line = line.strip()
    if not line.startswith("{"):
        continue                      # Falco start-up / info lines
    try:
        alert = json.loads(line)
    except json.JSONDecodeError:
        continue
    f = alert.get("output_fields", {})
    ns = f.get("k8s.ns.name")
    if k8s_only and not ns:
        continue
    if summary:
        counts[(alert.get("rule"), ns or "<no-k8s>", f.get("container.name") or f.get("container.id"))] += 1
        continue
    print(f'{alert.get("time", "")[:19]}  {alert.get("priority", ""):8}  {alert.get("rule")}')
    print(f'    ns={ns}  pod={f.get("k8s.pod.name")}  container={f.get("container.name")} ({f.get("container.id")})')
    print(f'    proc={f.get("proc.cmdline")}  parent={f.get("proc.pname")}  user={f.get("user.name")}')
    extra = {k: v for k, v in f.items() if k in ("fd.name", "fd.sip", "fd.sport", "evt.type", "proc.exepath")}
    if extra:
        print(f'    {extra}')
    print(f'    tags={alert.get("tags")}')

if summary:
    for (rule, ns, ctr), n in counts.most_common():
        print(f"{n:5}  {rule:45} ns={ns:15} container={ctr}")

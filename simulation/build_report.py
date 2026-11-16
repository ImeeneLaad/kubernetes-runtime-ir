#!/usr/bin/env python3
"""Builds the simulation report: which expected rules fired for an incident ID.

Reads Falco JSON alerts on stdin.
Args: incident_id namespace pod start_utc end_utc out_file steps_json
"""
import json
import sys

inc, ns, pod, start, end, out, steps = sys.argv[1:8]
steps = json.loads(steps)
alerts = [json.loads(line) for line in sys.stdin if line.startswith("{")]

fired = {}
for a in alerts:
    fired.setdefault(a["rule"], []).append({"time": a["time"], "priority": a["priority"]})
for s in steps:
    s["detected"] = s["expected_rule"] in fired
    s["alerts"] = fired.get(s["expected_rule"], [])

report = {
    "incident_id": inc,
    "namespace": ns,
    "pod": pod,
    "simulation_start_utc": start,
    "simulation_end_utc": end,
    "steps": steps,
    "detected_rules": sorted(fired),
    "alert_count": len(alerts),
    "all_steps_detected": all(s["detected"] for s in steps),
}
with open(out, "w") as f:
    json.dump(report, f, indent=2)

print()
for s in steps:
    print(f"  [{'DETECTED' if s['detected'] else 'MISSED  '}] {s['expected_rule']}")
print(f"\n  {len(alerts)} alerts carry the marker {inc}; report: {out}")
sys.exit(0 if report["all_steps_detected"] else 1)

#!/usr/bin/env python3
"""Generate the incident report for one incident: evidence/<incident>/report.md

Usage (Ubuntu, project root):  python3 -I response/incident_report.py <incident-id>

Sources (all already on disk, nothing is modified):
  evidence/<id>/alerts-received.jsonl   alerts the SOAR received (responder triage)
  evidence/<id>/claim.json              first alert = incident opening
  evidence/<id>/actions.jsonl           every response attempt (incl. refusals)
  evidence/<id>/<ns>__<pod>/            evidence package (manifest, custody log)
  evidence/<id>/<ns>__<pod>.tar.gz(.sha256)  -> re-verified now
  live cluster                          current application health (admin context)
"""
import datetime as dt
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_time(s):
    s = s.replace("Z", "")
    if "." in s:
        head, frac = s.split(".", 1)
        frac = "".join(c for c in frac if c.isdigit())[:6]
        s = f"{head}.{frac}"
    return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)


def fmt(d):
    return d.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + "Z"


def dur(a, b):
    if not a or not b:
        return "n/a"
    s = (b - a).total_seconds()
    return f"{s:.1f} s" if s < 120 else f"{s / 60:.1f} min"


def jsonl(path):
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path) if l.strip()]


def main(inc):
    d = os.path.join(ROOT, "evidence", inc)
    if not os.path.isdir(d):
        sys.exit(f"no incident {inc}")
    claim = json.load(open(os.path.join(d, "claim.json"))) if os.path.exists(os.path.join(d, "claim.json")) else {}
    received = jsonl(os.path.join(d, "alerts-received.jsonl"))
    actions = jsonl(os.path.join(d, "actions.jsonl"))
    pkgs = sorted((p for p in glob.glob(os.path.join(d, "*__*")) if os.path.isdir(p)
                   and os.path.exists(os.path.join(p, "manifest.json"))), key=lambda p: "__pre-" in p)
    manifests = {p: json.load(open(os.path.join(p, "manifest.json"))) for p in pkgs}
    pkg = pkgs[0] if pkgs else None                     # the initial snapshot
    manifest = manifests.get(pkg, {})
    ns = claim.get("namespace") or manifest.get("namespace")
    pod = claim.get("pod") or manifest.get("pod")

    # ---------------- timeline
    ev = []
    for a in received:
        ev.append((parse_time(a["time"]), "detection", f"Falco: **{a['rule']}** ({a['priority']})"))
    for m in manifests.values():
        ph = m.get("phase", "initial")
        ev.append((parse_time(m["collection_start_utc"]), "evidence", f"evidence snapshot **{ph}** started"))
        ev.append((parse_time(m["collection_end_utc"]), "evidence", f"evidence snapshot **{ph}** finished ({len(m['files'])} files)"))
    for a in actions:
        extra = a.get("reason") or (", ".join(a["steps"]) if a.get("steps") else "")
        if a.get("approval"):
            extra += (" — " if extra else "") + f"approval: `{a['approval'][:110]}`"
        ev.append((parse_time(a["time"]), "response", f"`{a['action']}` → **{a['result']}**" + (f" ({extra})" if extra else "")))
    ev.sort(key=lambda e: e[0])

    first_alert = min((e[0] for e in ev if e[1] == "detection"), default=None)
    contained = next((parse_time(a["time"]) for a in actions if a["action"] == "isolate" and a["result"] in ("done", "already-done")), None)
    recovered = next((parse_time(a["time"]) for a in actions if a["action"] == "eradicate" and a["result"] == "done"), None)
    approval = next((a.get("approval") for a in actions if a.get("approval")), None)
    refused = [a for a in actions if a["result"] == "refused"]
    env = next((a.get("env") for a in actions if a.get("env")), "dev" if ns == "juice-dev" else "prod")
    outcome = ("contained and eradicated" if recovered else "contained (isolated), not yet eradicated" if contained
               else "evidence collected, no containment (pending or rejected decision)" if manifest else "open")

    # ---------------- evidence verification (now), every package
    verified = {}
    for p_ in pkgs:
        arch = p_ + ".tar.gz"
        sha = open(arch + ".sha256").read().split()[0] if os.path.exists(arch + ".sha256") else None
        r = subprocess.run(["bash", os.path.join(ROOT, "response", "verify-evidence.sh"), arch], capture_output=True, text=True)
        verified[p_] = (sha, (r.stdout + r.stderr).strip())

    # ---------------- current application health
    health = "n/a"
    if ns:
        p = subprocess.run(["bash", os.path.join(ROOT, "apps", "juice-shop", "verify.sh"), ns.replace("juice-", "")],
                           capture_output=True, text=True, env=dict(os.environ, TIMEOUT="20"))
        health = p.stdout.strip()

    # ---------------- report
    first = claim.get("first_alert") or (received[0] if received else {})
    f = first.get("output_fields", {})
    L = []
    L += [f"# Incident report `{inc}`", "",
          f"_Generated {fmt(dt.datetime.now(dt.timezone.utc))} by response/incident_report.py — times are UTC._", "",
          "## Summary", "",
          "| | |", "|---|---|",
          f"| Target | `{ns}/{pod}` (environment **{env}**) |",
          f"| Opening alert | {first.get('rule')} ({first.get('priority')}) |",
          f"| Alerts received by the SOAR | {len(received)} (rules: {', '.join(sorted({a['rule'].replace('Juice Shop - ', '') for a in received}))}) |",
          # Falcosidekick renames some fields when forwarding (proc.cmdline -> proc_cmdline)
          f"| Process / user | `{f.get('proc.cmdline') or f.get('proc_cmdline')}` / "
          f"`{f.get('user.name') or f.get('user_name') or f.get('user.uid') or f.get('user_uid')}` |",
          f"| Outcome | **{outcome}** |",
          f"| Human approval | {('`' + approval[:120] + '`') if approval else ('not required (dev)' if env == 'dev' else 'none recorded')} |",
          f"| Safeguard refusals | {len(refused)}" + (" — " + "; ".join(r['reason'] for r in refused) if refused else "") + " |",
          "", "## Key metrics", "",
          "| Metric | Value |", "|---|---|",
          f"| First alert → evidence complete | {dur(first_alert, parse_time(manifest['collection_end_utc']) if manifest else None)} |",
          f"| First alert → contained (isolated) | {dur(first_alert, contained)} |",
          f"| First alert → recovered (compromised pod eradicated, service healthy) | {dur(first_alert, recovered)} |",
          "", "For PROD, the containment time includes the wait for the human decision.", "",
          "## Timeline", "", "| Time (UTC) | Phase | Event |", "|---|---|---|"]
    L += [f"| {fmt(e[0])} | {e[1]} | {e[2]} |" for e in ev]
    L += ["", "Falco event times come from the sensor. Evidence and response times come from the collector/responder "
              "wall clock. Sensor clock skew is checked by `falco/check-clock.sh` before simulations (see docs/04).", "",
          "## Evidence", ""]
    if not pkgs:
        L += ["No evidence package."]
    for p_ in pkgs:
        m = manifests[p_]; sha, vtxt = verified[p_]
        L += [f"### Snapshot `{m.get('phase', 'initial')}`", "",
              f"- Package: `evidence/{inc}/{os.path.basename(p_)}.tar.gz`",
              f"- Archive SHA-256: `{sha}`" + (" (also recorded in the SOAR execution: `collect` result)"
                                               if m.get("phase", "initial") == "initial" else ""),
              f"- Collected {m['collection_start_utc']} → {m['collection_end_utc']} by `{m['collector']}` "
              f"from node `{m['node']}`, container `{m['container_id'][:12]}`, {len(m['files'])} files", "",
              "Verification at report time:", "", "```", vtxt, "```"]
        cf = os.path.join(p_, "filesystem", "changed-files.txt")
        if os.path.exists(cf):
            interesting = [l.strip() for l in open(cf) if "/tmp/" in l and not l.rstrip().endswith("./tmp")]
            L += ["", "Files written outside the application directories (filesystem delta):", "", "```"] + \
                 (interesting[:15] or ["(none)"]) + ["```"]
        cx = os.path.join(p_, "volatile", "connections.txt")
        if os.path.exists(cx):
            L += ["", "Network sockets at collection time:", "", "```", open(cx).read().strip(), "```", ""]
    L += ["", "## Response actions (audit trail)", "", "| Time (UTC) | Action | Result | Operator | Details |", "|---|---|---|---|---|"]
    for a in actions:
        det = (a.get("reason") or ", ".join(a.get("steps") or [])
               or (f"sha256 {a['archive_sha256'][:16]}…" if a.get("archive_sha256") else "")
               or (f"final snapshot sha256 {a['pre_eradicate_archive_sha256'][:16]}…" if a.get("pre_eradicate_archive_sha256") else ""))
        L.append(f"| {a['time']} | {a['action']} | {a['result']} | {a.get('operator')} | {det} |")
    L += ["", "## Recovery check (now)", "", "```", health, "```", ""]

    out = os.path.join(d, "report.md")
    with open(out, "w") as fh:
        fh.write("\n".join(L) + "\n")
    print(out)


if __name__ == "__main__":
    main(sys.argv[1])

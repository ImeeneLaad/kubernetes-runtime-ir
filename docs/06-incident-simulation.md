# 06 — Controlled incident simulation

**Date:** 2026-11-10. Files: `simulation/simulate-incident.sh`,
`simulation/build_report.py`. Results: `simulation/results/<id>.json`
(git-ignored).

```bash
bash simulation/simulate-incident.sh dev     # or: prod
```

## Principle

The simulation **only replays the five harmless triggers validated in Step 3**
(`tests/falco-rules`). No exploit code, attack tool or attacker
infrastructure is used. Each step is benign on its own. Together they
produce the alert sequence that a compromised Node.js application would
generate, which is what the response steps need. The goal of the project is
to demonstrate **detection and response**, not offensive technique.

| # | Action, run through the image's own `/nodejs/bin/node` | Expected rule |
|---|---|---|
| 1 | Print a value | Juice Shop - Exec into container |
| 2 | Start `node -v` as a child process | Juice Shop - Process spawned by the application |
| 3 | Read `/etc/passwd` | Juice Shop - Sensitive file read |
| 4 | Open and close one TCP connection to `1.1.1.1:443` | Juice Shop - Outbound TCP connection |
| 5 | Write `/tmp/<incident-id>.txt` | Juice Shop - Write outside application data directories |

## Repeatability features

- **Incident ID** (`sim<UTC timestamp><random>`, alphanumeric) is embedded
  in every command, so each alert can be attributed to one run. It's also
  searchable in the Sidekick UI, where `-` would be a NOT operator.
- **Preconditions:** correct kube context, and the Falco clock check
  (`falco/check-clock.sh --fix`). Without correct timestamps, the incident
  timeline would be wrong.
- **Report:** per step, the UTC time of the action, the expected rule,
  whether it fired, and the alert times. Exit code 0 only if every step was
  detected.

## Results (3 runs)

| Run | Target | Steps detected | Falco alerts | Shuffle executions |
|---|---|---|---|---|
| 1 | juice-dev | 5/5 | 9 | 9 (all FINISHED) |
| 2 | juice-prod | 5/5 | 9 | 9 (all FINISHED) |
| 3 | juice-dev | 5/5 | 9 | 9 received |

There are 9 alerts, not 5, because steps 2–5 are started with `kubectl exec`,
so each also matches "Exec into container".

## Design requirement for the response (Steps 7–8)

**One incident produces about 9 alerts, and each starts its own SOAR
execution.** If every execution isolated, collected evidence and replaced the
pod on its own, the same pod would be handled 9 times in parallel, with
duplicate evidence, races on labels, and possibly several replacements. The
response must therefore:

1. **Correlate** alerts per pod (namespace + pod name): one incident per pod.
2. Make each action **idempotent**. "Already quarantined" or "evidence already
   collected for this incident" must be a no-op, not an error or a repeat.
3. Record every alert in the incident's timeline even when no new action is
   taken.

## Simulation limits

- Steps run through `kubectl exec`, so the parent process is the container
  runtime. A real remote-code-execution attack would run inside the Juice
  Shop process (PID 1), and "Exec into container" would not fire. The other 4
  rules are written to fire either way.
- The outbound connection goes to a public resolver and carries no data. It
  demonstrates detection and network isolation, not exfiltration.

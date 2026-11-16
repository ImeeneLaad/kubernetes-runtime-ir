# 10 — Demonstration

One command, interactive, about 6 minutes:

```bash
cd /mnt/d/Kubernetes-IR
bash demo/run-demo.sh
```

Optionally, in other windows, so the audience can watch:

```bash
kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802   # alerts: http://localhost:2802
```
Shuffle: http://localhost:3001 → workflow **IR - Juice Shop response** → executions.

**All commands run in Ubuntu** (`wsl -d Ubuntu-24.04`, then
`cd /mnt/d/Kubernetes-IR`), not in PowerShell. From PowerShell, in one line:
`wsl -d Ubuntu-24.04 --cd /mnt/d/Kubernetes-IR -- bash demo/run-demo.sh`.
Troubleshooting: [docs/12 §9](12-project-journal.md#9-operations-runbook).

## Before the demo (after a reboot or a sleep)

```bash
bash falco/check-clock.sh --fix          # Falco timestamps drift after the VM was paused
                                         #  (a Falco restart can take ~10 min: slow ghcr.io download)
bash soar/shuffle/shuffle.sh up          # if Shuffle is stopped (also restarts its UI)
bash response/service/run.sh             # renews the 12 h responder token, restarts the service
bash apps/juice-shop/verify.sh           # dev + prod healthy
```

## What the script shows

| Phase | What you see | Lifecycle step |
|---|---|---|
| 0. Preflight | Context, Falco, clock skew, app health, Shuffle, responder, credential | — |
| 1. DEV | The 5 simulation steps and their detections | detection |
| | Falco alert summary for the pod (9 alerts, 5 rules) | alerting |
| | The single responding Shuffle execution: triage → collect → isolate → eradicate → verify | SOAR |
| | Responder audit trail: evidence hash, isolation steps (quarantine, orphan, conntrack flush), final snapshot, deletion | evidence, isolation, remediation |
| | Replacement pod serving; `verify.sh` PASS; incident report path | recovery |
| 2. PROD | Simulation, then **the playbook pauses**: incident, pod, first alert, evidence hash | evidence before decision |
| | The pod is still untouched while waiting | human control |
| | **You type your name and approve or reject** | approval |
| | Approve: isolation + replacement + deletion with **zero downtime** (2 replicas). Reject: nothing touched, evidence kept | remediation / rejection |
| | Audit trail with the approval reference; prod health; report | recovery, accountability |

## Talking points

- **Evidence before action** is enforced in three places (workflow order,
  responder precondition, final snapshot before deletion). It's never just
  "good practice".
- **The SOAR has no Kubernetes credential.** It asks the responder, and the
  API server itself limits what the responder can do (try it:
  `bash tests/response-guardrails/run-test.sh`).
- **Why isolation has three steps:** NetworkPolicy only blocks *new*
  connections (Step 1 finding), and a quarantined pod would still receive
  Service traffic (Step 2 finding).
- **Correlation:** 9 alerts → 1 response, proven under concurrency.
- **Honest limits:** the Docker socket (docs/11), approval links that carry a
  secret, and the Falco clock drift after sleep.

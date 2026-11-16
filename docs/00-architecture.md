# 00 — Architecture

## Goal

Detect suspicious runtime activity in a Kubernetes workload (OWASP Juice
Shop) and run the full incident-response lifecycle automatically:
**detection → alerting → evidence preservation → isolation → replacement →
recovery → report**. In production, the destructive part needs human
approval.

## Components

| Layer | Component | Version | Where | Doc |
|---|---|---|---|---|
| Platform | kind cluster `k8s-ir` (1 node), kindnet CNI | kind 0.30, Kubernetes 1.34.0 | Docker Desktop (WSL2 kernel 6.6) | 01 |
| Target | OWASP Juice Shop, `juice-dev` (1 replica) / `juice-prod` (2 replicas) | v20.3.0 (digest-pinned) | cluster | 02 |
| Detection | Falco, modern eBPF, 5 custom rules | 0.45.2 (chart 9.2.2) | cluster (DaemonSet) | 03 |
| Alerting | Falcosidekick + Web UI | 2.35.1 / UI 2.2.0 | cluster (`falco` ns) | 04 |
| SOAR | Shuffle (backend, frontend, Orborus, OpenSearch) | 2.3.0 | Docker Compose, outside the cluster | 05, 09 |
| Response | `ir-responder` (HTTP API → `ir_respond.py`) | own code | container on the Shuffle + kind networks | 08, 09 |
| Response identity | ServiceAccount `ir-system/ir-responder` + RBAC + ValidatingAdmissionPolicy | — | cluster | 08 |
| Forensics | `collect-evidence.sh` (node-level, no exec into the pod) | own code | run by the responder | 07 |

## Data flow

```
 ┌─────────────────────────────── kind cluster (k8s-ir) ───────────────────────────────┐
 │                                                                                      │
 │  juice-dev / juice-prod                       falco namespace                        │
 │  ┌──────────────┐   syscalls (eBPF)   ┌───────┐  JSON   ┌───────────┐   ┌─────────┐ │
 │  │  Juice Shop  │ ──────────────────► │ Falco │ ──────► │ Sidekick  │──►│ Web UI  │ │
 │  │ (distroless) │                     └───────┘ :2801   └─────┬─────┘   └─────────┘ │
 │  └──────▲───────┘                     NetworkPolicy: only Falco may post │          │
 │         │ labels / delete (RBAC + VAP)                                   │          │
 │  ┌──────┴────────┐                                                       │          │
 │  │  API server   │◄──────────────────────────────────┐                   │          │
 │  └───────────────┘                                    │                  │          │
 └───────────────────────────────────────────────────────┼──────────────────┼──────────┘
          kind Docker network 172.24.0.0/16               │ SA token (12 h)  │ webhook + X-IR-Token
                                                          │                  ▼ (172.24.255.10:5001)
 ┌────────────── Docker (outside the cluster) ────────────┼──────────────────────────────┐
 │  ┌───────────────┐  X-Responder-Token   ┌──────────────┴──┐                           │
 │  │ Shuffle       │ ───────────────────► │  ir-responder   │── docker exec ──► kind node│
 │  │ playbook      │   (Shuffle network)  │  (no host port) │   (/proc, upperdir,        │
 │  │ + approval    │                      └────────┬────────┘    conntrack)              │
 │  └──────┬────────┘                               │ evidence/ (hashes, custody)        │
 │         │ 127.0.0.1:3001 (UI), :5001             ▼                                    │
 └─────────┼────────────────────────────────────── host disk ───────────────────────────┘
           ▼
      analyst / approver (browser or approve.py)
```

## Lifecycle of one incident

| # | Phase | What happens | Where |
|---|---|---|---|
| 1 | Detection | Falco rule fires (e.g. "Process spawned by the application"). About 9 alerts per incident | Falco |
| 2 | Alerting | Sidekick forwards warning+ alerts to the UI and to Shuffle (token header) | Sidekick |
| 3 | Triage | One incident per pod; atomic claim. Duplicates stop here but are still recorded | Shuffle → responder `/v1/triage` |
| 4 | Evidence | Node-level snapshot (processes, sockets, filesystem delta, image, Kubernetes state, alerts), SHA-256, custody log. Hash stored in Shuffle | responder → `collect-evidence.sh` |
| 5 | Decision | dev: automatic. prod: Shuffle User Input, **human approves or rejects** | Shuffle |
| 6 | Isolation | Quarantine label (deny-all policy) → orphan (out of the Service, replacement starts) → conntrack flush (open connections cut) | responder `isolate` |
| 7 | Remediation | Final `pre-eradicate` snapshot, then delete the quarantined pod | responder `eradicate` |
| 8 | Recovery | Deployment available = desired, endpoints ready, HTTP + API answer | responder `/v1/verify`, `verify.sh` |
| 9 | Report | Timeline, metrics, evidence verification, audit trail, current health | `incident_report.py` |

## Trust boundaries and least privilege

| Boundary | Control | Verified by |
|---|---|---|
| Workload → anything | Default-deny NetworkPolicies; egress only DNS + the internet (no pods, services or kind network); no SA token; PSA `restricted`, non-root, all capabilities dropped | `tests/app-baseline` |
| Anyone → alert pipeline | Only Falco pods can reach Sidekick; UI password generated | `tests/alert-pipeline` |
| Sidekick → SOAR | Webhook rejects requests without `X-IR-Token` | Step 4 tests |
| SOAR → responder | Responder on the Shuffle network only, token required, per-pod lock, scope checks | `tests/responder-api` |
| Responder → Kubernetes | RBAC (namespaced, no exec, secrets, pod creation or policy changes) + admission policy (labels only, delete only quarantined pods, never un-quarantine) | `tests/response-guardrails` |
| Human → prod actions | Shuffle User Input; approver identity (`click_info.user`) recorded in the audit trail | `tests/playbook` |
| Evidence | Per-file + archive SHA-256, hash also in the SOAR, custody log, idempotent | `tests/response`, Step 6 tamper tests |

Residual risks, especially the Docker socket used by Shuffle and the
responder, are analysed in **docs/11-soar-compromise-risk.md**.

## Documentation index

| Doc | Topic |
|---|---|
| 01 | CNI NetworkPolicy validation (kindnet, conntrack, additive policies) |
| 02 | Juice Shop deployment (dev/prod, hardening, probes vs quarantine) |
| 03 | Falco on WSL2 (modern eBPF), custom rules, false-positive tuning, safe rule deployment |
| 04 | Falcosidekick, anti-forgery, Shuffle webhook, **clock-skew finding** |
| 05 | Shuffle deployment and hardening, vendored apps, Orborus fixes |
| 06 | Controlled incident simulation |
| 07 | Evidence collection and preservation |
| 08 | Response actions, RBAC, admission policy |
| 09 | SOAR playbook, correlation, prod approval, Shuffle resume race |
| 10 | Demonstration script |
| 11 | Risk analysis: compromised SOAR |
| **12** | **Project journal: the complete story, every decision, problem and fix, runbook, file inventory, glossary** |
| **13** | **Complete technical reference: architecture, source code explained, install steps, scenarios, testing, troubleshooting, presentation guide** |
| examples/ | `sample-incident-report-prod.md`: a real generated report (approved prod incident, identities redacted) |

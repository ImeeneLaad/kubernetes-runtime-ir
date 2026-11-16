# Réponse à l'exécution dans Kubernetes

Academic project: detect suspicious runtime activity in a Kubernetes workload
and run the **complete incident-response lifecycle** through a SOAR:
detection (Falco) → alerting (Falcosidekick) → triage and correlation →
**evidence preservation** → **isolation** (NetworkPolicy + conntrack) →
**replacement** → **recovery verification** → incident report.
In **production**, the response waits for **human approval**.

> Lab only. OWASP Juice Shop is deliberately vulnerable. Everything is bound
> to `127.0.0.1`. Never expose it to a network.

**Start here:** [docs/13-technical-reference.md](docs/13-technical-reference.md) (complete technical reference: architecture, source code, install steps, scenarios, testing, troubleshooting, presentation guide) ·
[docs/12-project-journal.md](docs/12-project-journal.md) (project journal: every decision, problem and fix, runbook, glossary) ·
[docs/00-architecture.md](docs/00-architecture.md) (architecture and doc index) ·
[docs/10-demo.md](docs/10-demo.md) (demonstration) ·
[docs/11-soar-compromise-risk.md](docs/11-soar-compromise-risk.md) (risks if the SOAR is compromised)

## Environment (checked 2026-11-10)

| Component | Version / state |
|---|---|
| Host | Windows 11 Pro, 32 GB RAM, Docker Desktop 4.93.0 (Engine 29.8.1) |
| WSL distro | Ubuntu 24.04.5 LTS. Kernel 6.6.114.1-microsoft-standard-WSL2 (BTF), shared by WSL, Docker and the kind node |
| Cluster | kind 0.30.0 `k8s-ir`, 1 node, Kubernetes v1.34.0, kindnet `v20250512-df8de77b` |
| Tools | kubectl v1.37.2 (host), Helm v3.22.1, Python 3.12 |
| Stack | Juice Shop v20.3.0 · Falco 0.45.2 (chart 9.2.2) · Falcosidekick 2.35.1 · Shuffle 2.3.0 |

## Repository layout

| Path | Contents |
|---|---|
| `cluster/` | kind cluster definition |
| `apps/juice-shop/` | Kustomize base + dev/prod overlays, `verify.sh` (health check) |
| `falco/` | Helm values, custom rules, `install.sh` (validates rules first), clock check, alert viewer |
| `soar/shuffle/` | hardened compose, vendored apps, API client, playbook provisioning, approval tool |
| `response/` | evidence collector, responder (`ir_respond.py`), RBAC + admission policy, HTTP service, incident report |
| `simulation/` | harmless, repeatable incident simulation |
| `demo/` | interactive demonstration |
| `tests/` | one test suite per component (see below) |
| `docs/` | 00–11: architecture, one document per step, demo, risk analysis |
| `evidence/` | incident evidence + reports (git-ignored) |

Secrets live only in `*/secrets/` directories (git-ignored); exports are redacted.

## Build from scratch

All commands run in **Ubuntu (WSL)**, from `/mnt/d/Kubernetes-IR`.

```bash
# 1. cluster + CNI validation
kind create cluster --config cluster/kind-config.yaml
bash tests/netpol/run-test.sh && kubectl delete namespace netpol-test

# 2. target application
kubectl apply -k apps/juice-shop/overlays/dev
kubectl apply -k apps/juice-shop/overlays/prod
bash apps/juice-shop/verify.sh

# 3. detection + alert pipeline (Falco, custom rules, Sidekick, Web UI)
bash falco/install.sh

# 4. SOAR
bash soar/shuffle/fetch-apps.sh
bash soar/shuffle/shuffle.sh up
#   -> open http://localhost:3001, create the admin account,
#      Settings -> API key -> save it in soar/shuffle/secrets/api-key.txt (e.g. with Notepad)
python3 -I soar/shuffle/workflows/provision_intake.py    # webhook + token
bash falco/install.sh                                     # re-run: Sidekick -> Shuffle webhook

# 5. response: RBAC + admission policy + responder service + playbook
bash response/service/run.sh
python3 -I soar/shuffle/workflows/provision_playbook.py
```

Demo: `bash demo/run-demo.sh`. Incident report: `python3 -I response/incident_report.py <incident>`.
Kill switch: `bash response/automation.sh pause|resume`. After a reboot or sleep:
`bash falco/check-clock.sh --fix` and `bash response/service/run.sh`
(renews the 12 h responder token).

## Tests

| Suite | Proves | Result |
|---|---|---|
| `tests/netpol` | kindnet enforces NetworkPolicies; open connections survive until a conntrack flush; policies are additive | 0 unexpected |
| `tests/app-baseline` | Pod hardening, PSA, network baseline, quarantine doesn't break probes | 0 unexpected |
| `tests/falco-rules` | Sensor healthy, 0 false positives, 5/5 custom rules fire | 0 unexpected |
| `tests/alert-pipeline` | Falco → Sidekick → UI + Shuffle; forgery blocked; clock skew ≤ 5 s | 0 unexpected |
| `tests/response-guardrails` | What the responder can and cannot do (RBAC + admission policy) | 25/25 |
| `tests/response` | collect → isolate → eradicate, idempotency, prod approval, scope | 0 unexpected |
| `tests/responder-api` | Service auth, scope, **9 concurrent alerts → 1 claim** | 18/18 |
| `tests/playbook` | Real alerts through Shuffle: dev automatic, prod approved, prod rejected; final snapshot holds the dropped file | 22/22 |

## Decision log (details in docs/)

1. **Single-node kind**: the kernel is shared, so multi-node would duplicate every Falco alert (01).
2. **Falco modern eBPF**: no kernel headers for WSL2, BTF available (03).
3. **kindnet kept** after proving it enforces policies. **Isolation = quarantine
   label + orphan + conntrack flush**, because open connections survive a
   policy (01) and a quarantined pod still gets Service traffic (02).
4. **Custom rules for a distroless app**: no shell exists, so the generic rules
   can't fire. Exceptions are tuned on observed data (03).
5. **Rules validated before every deploy**: a bad rules file once stopped Falco completely (03).
6. **Anti-forgery**: only Falco may post to Sidekick; the webhook requires a token (04).
7. **Clock-skew guard**: Falco timestamps drifted 63 min after the VM was
   paused (04). The check probes a dedicated **canary pod**, never a protected
   workload: a probe inside Juice Shop triggered the real response (04).
8. **Shuffle outside the cluster, hardened**: 127.0.0.1 only, no public DB
   port, generated secrets, 2 vendored apps (GitHub too slow here) (05).
9. **Evidence from the node**, never exec into the suspect pod; hashed, with a
   custody log; a second snapshot right before deletion (07, 09).
10. **The SOAR holds no Kubernetes credential.** `ir-responder` acts with a
    short-lived ServiceAccount, limited by RBAC **and a ValidatingAdmissionPolicy**
    (labels only, delete only quarantined pods) (08).
11. **One incident per pod**, atomic claim, idempotent actions: 9 alerts → 1 response (06, 09).
12. **Prod approval in Shuffle** (User Input). After approval, one fast call,
    because of a Shuffle worker-swap race (09).
13. Accepted lab trade-offs: kubectl 1.37 vs cluster 1.34 skew; dev has about
    25 s with no endpoint during isolation (1 replica); Docker-socket access by
    Shuffle and the responder (11).

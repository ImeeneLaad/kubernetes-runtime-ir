# 11 — Risk analysis: what if the SOAR platform is compromised?

A SOAR is trusted to **act** on production: it isolates, deletes and reads
sensitive data. That makes it a high-value target. An attacker who controls
it inherits its powers, and can also blind or mislead the response. This
analysis covers the architecture **as built and tested** in this project.
Every control marked *verified* has a test in `tests/`.

## 1. Assets and trust boundaries

```
             ┌──────────────────────── Docker Desktop VM (one Linux kernel) ─────────────────────────┐
             │                                                                                        │
  Falco ─► Sidekick ══(X-IR-Token)══► Shuffle (backend, Orborus, workers, apps) ══(X-Responder-Token)══► ir-responder
  (kind)   (kind, NetworkPolicy)      │  mounts /var/run/docker.sock  ◄── TB-2                           │  docker.sock + SA token
             │                        │                                                                  ▼
             │                        └── OpenSearch (workflows, executions, results, secrets)    Kubernetes API (RBAC + VAP) ◄── TB-3
             │                                                                                    kind node (docker exec)    ◄── TB-4
             └────────────────────────────────────────────────────────────────────────────────────────┘
  TB-1: alert path (Falco → Sidekick → Shuffle)   TB-2: Docker socket   TB-3: API server   TB-4: node-level access
```

| Asset | Where | Why it matters |
|---|---|---|
| Docker socket | mounted into Shuffle backend + Orborus, and ir-responder | **root on the Docker VM**: every container, including the kind node and so the whole cluster |
| Responder token (`X-Responder-Token`) | Shuffle workflow parameters (OpenSearch), `response/secrets/` | Lets the holder ask the responder to act |
| Kubernetes SA token (ir-responder) | `response/secrets/*.kubeconfig`, mounted read-only into ir-responder | Direct API access with the responder's rights, 12 h |
| Webhook token (`X-IR-Token`) | Sidekick config Secret, Helm release, Shuffle trigger | Lets the holder inject "alerts" into the SOAR |
| Approval secret | each waiting execution's `authorization`, embedded in the approval links | Lets the holder answer a PROD approval |
| Evidence | `evidence/` (host disk), hashes also in Shuffle executions | Integrity of the investigation |

## 2. Threat scenarios

Impact: **C** = critical, **H** = high, **M** = medium, **L** = low.

| # | Scenario (attacker controls…) | What they can do | Controls in place | Residual | Impact |
|---|---|---|---|---|---|
| T1 | **Shuffle backend / Orborus / any Shuffle app container** | Use the mounted **docker.sock** = root on the Docker VM: `docker exec` into the kind node, read `/etc/kubernetes/admin.conf` = **cluster-admin**, and also read or alter every other container on the machine | Shuffle bound to `127.0.0.1` only (verified `docker port`); OpenSearch not published (verified); only 2 vendored, pinned apps (SHA256SUMS); images pinned to 2.3.0 | **Total compromise.** Required by Shuffle's Docker design (it starts worker and app containers) | **C** |
| T2 | **Responder token** (read from Shuffle's DB or UI) | Call `ir-responder`: collect, isolate, eradicate. In dev: isolate and delete any monitored Juice Shop pod (DoS). In prod: `respond-approved` with an **invented approval string** | Responder only on the Shuffle network, no host port (verified); scope checks (verified); RBAC + admission policy bound the effect: no exec, no secrets, no image change, no un-quarantine, delete only quarantined pods (25/25 verified) | **Availability attack on Juice Shop** (delete or replace pods). No code execution, no data access through this path. Approval can't be verified by the responder (it's a string) | **M** |
| T3 | **Kubernetes SA token** (from `response/secrets/`) | Same Kubernetes actions directly against the API, with no responder checks (evidence-first, approval) | **API-server-side** guardrails still hold (VAP: labels only, delete only quarantined pods, never un-quarantine; verified). Token is short-lived (12 h, TokenRequest) | Can quarantine and then delete monitored pods without evidence or approval, so **availability + loss of evidence** for those pods | **M** |
| T4 | **Webhook token** (Helm release values, Sidekick Secret) | Post forged "Falco alerts": the SOAR triages them and acts on a chosen pod | Only Falco pods may reach Sidekick (NetworkPolicy, verified); Shuffle rejects requests without the token (401, verified); triage only accepts protected namespaces, valid pod names and the required tags (verified) | A forged alert naming a real pod triggers a real response: **DoS**. The responder doesn't cross-check the alert against the sensor's own log | **M** |
| T5 | **An approval link** (from a notification e-mail/chat, browser history, logs) | Approve a PROD response without logging in: the link carries the execution's `authorization` secret | `click_info.user` records the logged-in Shuffle user when there is one; `approve.py` answers with the admin's API key; the evidence is collected *before* the question is asked | **The human approval in prod can be bypassed** by whoever holds the link, or by anyone controlling Shuffle (T1/T2). The control is procedural, not cryptographic | **H** |
| T6 | Shuffle (T1) **and** wants to hide the incident | Alter or delete `evidence/` (via docker.sock → ir-responder mount), recompute SHA256SUMS **and** edit the hash stored in Shuffle's own executions | Inner + outer hashes (tamper tests verified); hash recorded out of band **in Shuffle** | Both copies are inside the attacker's reach in T1: integrity **can be defeated**. Detectable only if the hash was exported elsewhere first | **H** |
| T7 | Shuffle, and wants to **blind** the response | Stop Shuffle / ir-responder, delete the playbook, change branch conditions so nothing matches | **Detection is independent of the SOAR**: Falco and Sidekick still raise and display alerts (UI, 7-day TTL). Responses can still be run by hand with `ir_respond.py` | No automated response, and no alarm that the SOAR is down | **H** |
| T8 | Shuffle, and wants to **mislead** analysts | Write fake execution results ("isolated", "healthy") | The responder's own audit trail (`actions.jsonl`) and the API server's state are the ground truth; the incident report is built from them, not from Shuffle | Analysts who only look at Shuffle can be fooled | **M** |
| T9 | ir-responder container | docker.sock → same as T1; plus the SA token | No host port; reachable only from the Shuffle network; project mounted read-only | Same as T1: node-level access (evidence, conntrack) is inherently privileged | **C** |
| T10 | **Supply chain** of the SOAR | Malicious update of Shuffle images or apps | Versions pinned (2.3.0, apps at commit `4a3d7209…` with SHA256SUMS, kubectl v1.34.0 taken from the node, base images by exact tag) | Tags are not digests: a re-pushed tag would be pulled on the next rebuild | **M** |

### Kill switch

`bash response/automation.sh pause "<reason>"` stops all automated action
immediately. Triage still records every alert, but answers
`decision: paused`, so the playbook does nothing. `resume` restores it. The
switch is a file that the responder reads. Shuffle has no API to flip it, but
an attacker with the Docker socket (T1) could remove it. Use it if the
automation misbehaves or the SOAR is suspected compromised. (It was
introduced after a component test and the live playbook acted on the same
pod concurrently: automation that's always on also needs a way to stop it.)

## 3. What the design already limits

The core idea is **defence in depth, with the last layer outside the SOAR**:

1. **The SOAR never holds a Kubernetes credential.** It holds only a token
   for the responder.
2. **The responder re-checks** scope, evidence-first and prod approval,
   independently of the workflow logic.
3. **The API server enforces the final limits** (RBAC + ValidatingAdmissionPolicy),
   which hold even if both the SOAR and the responder are malicious. Through
   the Kubernetes credential, the worst a compromised SOAR can do is
   **availability damage to the monitored app**. It can't run code in pods,
   read Secrets, swap images, open the network (it can't change
   NetworkPolicies) or lift a quarantine.
4. **Detection doesn't depend on the SOAR** (T7).

The weak point is **T1/T9: the Docker socket**. Through it, the SOAR host can
skip all of the above. In this lab that's a deliberate, documented trade-off:
Shuffle's runner needs it, and node-level forensics need host access.

## 4. Recommendations (by priority)

| Priority | Recommendation | Addresses |
|---|---|---|
| 1 | **Run the SOAR on a separate host/VM**, not on the Docker engine that runs the cluster. Use Orborus's Kubernetes mode with its own restricted ServiceAccount, or put a filtering proxy in front of the Docker API (`docker-socket-proxy`, containers + exec only) | T1, T9 |
| 2 | **Verify approvals cryptographically at the responder**: the approver signs `{incident, decision, time}` with a personal key, or the responder queries the Shuffle API to check `click_info.user` against an approver list. Require two people for eradication in prod | T2, T5 |
| 3 | **Ship evidence hashes off-host immediately** (append-only log, WORM/object-lock bucket, or a signed message to a separate system) | T6 |
| 4 | **Cross-check alerts**: before acting, the responder confirms the alert exists in the Falco sensor's own log (same rule, pod and time) | T4 |
| 5 | **Watchdog**: alert a human when the SOAR or the responder misses a heartbeat, or when the playbook definition changes (hash the export) | T7, T8 |
| 6 | **Rotate and shorten tokens**: the responder and webhook tokens in a secret manager, with the SA token under 1 h and renewed automatically | T2–T4 |
| 7 | **Pin images by digest**, and verify signatures (cosign) where the vendor publishes them | T10 |
| 8 | **Replace node-level `docker exec`** with a minimal, audited forensic DaemonSet with its own narrow permissions; mTLS between Falco and Sidekick | T9, T4 |

## 5. Conclusion

A compromised SOAR is a **privileged insider**. In this architecture, the
Kubernetes-facing blast radius is deliberately bounded, and verified: through
its credential, a compromised SOAR can make the application unavailable, but
it can't use the response channel to take over workloads or read their data.
The remaining critical path is the **host-level Docker access** shared by
Shuffle and the responder. Production deployments should remove it first
(recommendation 1) and make approvals verifiable (recommendation 2).

# 08 — Response actions, RBAC and guardrails

**Date:** 2026-11-10. Files: `response/rbac/ir-responder.yaml`,
`response/rbac/admission-policy.yaml`, `response/make-kubeconfig.sh`,
`response/ir_respond.py`, `response/show-actions.py`.
Tests: `tests/response-guardrails/run-test.sh` (25/25),
`tests/response/run-test.sh` (30/30).

```bash
bash response/make-kubeconfig.sh                       # RBAC + policy + 12 h token (admin)
python3 -I response/ir_respond.py collect   juice-dev <pod> <incident>
python3 -I response/ir_respond.py isolate   juice-dev <pod> <incident>
python3 -I response/ir_respond.py eradicate juice-dev <pod> <incident>
python3 -I response/ir_respond.py isolate   juice-prod <pod> <incident> --approval <ref>
python3 -I response/show-actions.py <incident>         # audit trail
```

## Architecture choice: a responder, not the SOAR, holds the cluster credential

The SOAR (Step 8) orchestrates, and `ir_respond.py` acts. This means:
- the Kubernetes credential is a **dedicated ServiceAccount** with a
  **short-lived token** (TokenRequest, 12 h), not a long-lived secret inside
  Shuffle;
- safeguards are enforced **in three independent places**: the SOAR workflow
  (Step 8), the responder (below), and the **API server** (RBAC + admission
  policy). The last one holds even if both the SOAR and the responder are
  compromised.

## Least privilege

| Layer | Allows | Denies (tested) |
|---|---|---|
| **RBAC** (Role in `juice-dev`, `juice-prod`; log reading in `falco`) | get/list/watch/patch/delete pods; read logs, events, namespace, rs/deploy, endpointslices, networkpolicies | pods/exec, pods/attach, secrets, create pods, change NetworkPolicies, patch deployments, other namespaces, cluster-wide list, rolebindings, token creation |
| **ValidatingAdmissionPolicy** `ir-responder-guardrails` (only for the responder's identity) | change only `security.ir/quarantine`, `security.ir/incident`, `app.kubernetes.io/name`; delete quarantined pods | **change pod spec (image swap)**, other labels, annotations, ownerReferences, **lift a quarantine**, **put a quarantined pod back in the Service**, **delete a non-quarantined pod** |

Why the admission policy matters: RBAC can't scope `patch pods` to "labels
only". Without the policy, a stolen responder token could replace a running
container's image in place.

## Actions (`ir_respond.py`)

| Action | Preconditions | Steps | Verification |
|---|---|---|---|
| `collect` | namespace protected, pod `security.ir/monitored=true` | `collect-evidence.sh` with the responder kubeconfig | `COMPLETE` + archive SHA-256 recorded |
| `isolate` | + **evidence COMPLETE**; prod: **`--approval`** | 1. `security.ir/quarantine=true` + `security.ir/incident=<id>` → new connections blocked. 2. Remove `app.kubernetes.io/name` → out of the Service and ReplicaSet → replacement starts. 3. `conntrack -D -s/-d <pod IP>` on the node → open connections cut | pod quarantined, not an endpoint; Deployment available = desired |
| `eradicate` | + pod already isolated; prod: **`--approval`** | delete the quarantined pod | Deployment available = desired |

The ordering is deliberate: quarantine **before** orphaning, so the pod is
never reachable without a Service. Collection comes **before** both.

All actions are **idempotent** ("already-done" instead of a repeat), which is
required because one incident produces about 9 SOAR executions (Step 5).
Every attempt, including refusals with their reason, goes to
`evidence/<incident>/actions.jsonl`. Exit codes: 0 done, 1 failed, 3 refused.

## Results

Audit trail of the dev incident (shortened):
```
isolate   refused      evidence not collected yet
collect   done         archive_sha256=087e695f…
collect   already-done
isolate   done         steps=[quarantine-label, orphan, conntrack-flush(19)] pod_in_service_endpoints=false
isolate   already-done
eradicate done
eradicate already-done
```

Prod incident: `isolate refused (approval required)` → `isolate done
(approval=TEST-APPROVAL-…)` → `eradicate refused` → `eradicate done`.
**40/40 user requests succeeded** during the whole prod response.

Verified on the isolated pod: still `Running` (kept for forensics), labelled,
not a Service endpoint, **internet egress blocked**. Replacement serving and
`verify.sh` PASS, both during isolation and after eradication.

## Trade-offs and limits

- **Dev availability:** with 1 replica, the Service has no endpoint between
  the orphaning and the replacement being Ready (about 25 s, Juice Shop
  start-up). Prod (2 replicas) had no interruption. Scaling up first would
  need `patch deployments`, deliberately not granted.
- **conntrack flush needs node access** (`docker exec` into the kind node),
  outside Kubernetes RBAC. The same is true for evidence collection. On a real
  cluster this would be a small privileged node agent. Both are privileged
  paths for the SOAR-compromise analysis.
- **The approval reference is a string.** The responder records it but can't
  verify that a human really approved. Real verification happens in the
  SOAR's approval step (Step 8), and the policy layer can't check it. A
  compromised SOAR could invent an approval reference, so the residual risk is
  documented.
- **Releasing a false positive** (un-quarantine) is admin-only by design. The
  normal path for a false positive is `eradicate`: the replacement is already
  serving.
- The responder token lasts 12 h. Re-run `make-kubeconfig.sh` to renew it.

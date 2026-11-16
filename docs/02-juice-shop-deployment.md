# 02 — Juice Shop deployment (target application)

**Date:** 2026-11-10. **Image:** `bkimminich/juice-shop:v20.3.0`, pinned by
digest `sha256:cea5a4af…bf27`, used as published (source code not modified).

## Layout

```
apps/juice-shop/
├── base/                 common to both environments
│   ├── serviceaccount.yaml   no API token mounted
│   ├── deployment.yaml       hardened pod, probes, resources
│   ├── service.yaml          NodePort
│   └── networkpolicies.yaml  default-deny + allows + quarantine
├── overlays/dev/         ns juice-dev,  1 replica, NodePort 30000 -> 127.0.0.1:3030
├── overlays/prod/        ns juice-prod, 2 replicas, NodePort 30001 -> 127.0.0.1:3031
└── verify.sh             health check (also used after remediation)
```

Deploy: `kubectl apply -k apps/juice-shop/overlays/dev` (and `.../prod`).

## dev vs prod

| | dev | prod |
|---|---|---|
| Namespace label `security.ir/environment` | `dev` → automatic response | `prod` → human approval |
| Replicas | 1 | 2: the service stays up while one pod is isolated |
| URL | http://localhost:3030 | http://localhost:3031 |

## Labels used by the response

| Label | Purpose |
|---|---|
| `app.kubernetes.io/name=juice-shop` | Deployment and Service selector. **Removing it orphans the pod**: the ReplicaSet creates a clean replacement and the Service stops routing to it, while the compromised pod stays alive for forensics. |
| `security.ir/monitored=true` | Workload is in scope for the IR playbook |
| `security.ir/quarantine=true` | Set only by the response; selects the `quarantine` NetworkPolicy and is excluded by every allow policy |

## Hardening

- Runs as non-root UID 65532, all capabilities dropped, no privilege
  escalation, seccomp `RuntimeDefault`.
- Pod Security Admission `restricted` is enforced on both namespaces. A
  privileged pod is rejected.
- `automountServiceAccountToken: false`: no Kubernetes credential to steal.
- The root filesystem stays **writable on purpose**. Juice Shop writes its
  SQLite DB there, and attacker file writes must be possible to detect and to
  collect as evidence.

## Network baseline

| Flow | Policy |
|---|---|
| Any → Juice Shop :3000 | allowed (public web app) |
| Juice Shop → CoreDNS :53 | allowed |
| Juice Shop → other pods and services (10.244/16, 10.96/12) | **blocked** (no lateral movement) |
| Juice Shop → outside the cluster (internet, Docker network) | allowed, so that isolation has a visible effect in the demo |
| Quarantined pod → anything / anything → quarantined pod | **blocked** |

## Test results (`bash tests/app-baseline/run-test.sh`): 0 unexpected results

Findings that shape the incident response:

1. **Kubelet probes are not blocked by quarantine** (0 restarts after 90 s).
   Quarantine therefore does not trigger a liveness restart, which would
   destroy volatile evidence (processes, memory, `/proc`).
2. **A quarantined pod still receives Service traffic**, because it stays
   Ready. 1 request in 9 timed out during the test. The isolation action must
   also remove the `app.kubernetes.io/name` label (orphaning). That removes the
   pod from the endpoints and starts a replacement.
3. **The API server is reachable from the pod** at TCP level. After DNAT, the
   Service IP becomes the node IP, which the `0.0.0.0/0` rule allows. This is
   accepted for the lab because no token is mounted. It could be hardened by
   excluding the node IP.
4. **Distroless image**: there is no shell and `node` is not on `PATH`
   (`/nodejs/bin/node`). Consequences:
   - the attack simulation must run through `node` itself, which is realistic
     for Node.js RCE;
   - evidence collection must bring its own tools (an ephemeral debug
     container, or node-level collection).
5. `kind load docker-image` fails with Docker Desktop's containerd image store
   (`content digest … not found`). The node pulls the image from Docker Hub
   instead, pinned by digest.

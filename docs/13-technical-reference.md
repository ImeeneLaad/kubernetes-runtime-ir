# 13 — Complete Technical Reference

> One document. Everything needed to understand, reproduce, and confidently explain this project.
> Written from the actual source files, not from memory.

---

## Table of Contents

1. [What the project is](#1-what-the-project-is)
2. [Technologies and tools](#2-technologies-and-tools)
3. [Architecture](#3-architecture)
4. [How the full workflow works, step by step](#4-how-the-full-workflow-works-step-by-step)
5. [File structure and every important file](#5-file-structure-and-every-important-file)
6. [Source code explained](#6-source-code-explained)
7. [Complete installation from scratch](#7-complete-installation-from-scratch)
8. [Running the demo](#8-running-the-demo)
9. [Implemented scenarios](#9-implemented-scenarios)
10. [Testing — what each suite proves and how to run it](#10-testing)
11. [Troubleshooting](#11-troubleshooting)
12. [Design decisions and their reasons](#12-design-decisions-and-their-reasons)
13. [Security controls](#13-security-controls)
14. [What to say during your presentation](#14-what-to-say-during-your-presentation)

---

## 1. What the project is

### In one sentence
An automated security-incident-response system built on Kubernetes: Falco detects suspicious activity in a running container, Falcosidekick sends the alert to a SOAR (Shuffle), and the SOAR drives an automated playbook that **preserves evidence first**, then **isolates** the container, **replaces** it, and **verifies** that the application recovered — all without touching the suspect container from inside it.

### The target workload
**OWASP Juice Shop** (`bkimminich/juice-shop:v20.3.0`) — a deliberately vulnerable Node.js web application used for security training. It runs in two Kubernetes namespaces: `juice-dev` (1 replica, fully automatic response) and `juice-prod` (2 replicas, human approval required before the destructive response). The source of Juice Shop is not modified.

### Why Kubernetes?
Kubernetes is the standard platform for running containerised applications in production. This project demonstrates that security operations (detection, evidence, isolation, response) can be automated inside a Kubernetes environment using native primitives (NetworkPolicies, RBAC, admission policies, labels) instead of external firewall rules.

### What is a SOAR?
A Security Orchestration, Automation and Response platform. It connects security tools together and runs automated workflows (called playbooks) when an alert fires. Here, Shuffle (the SOAR) receives every Falco alert, decides whether it needs a response, calls the responder service to collect evidence, and either responds automatically (dev) or waits for a human to approve (prod).

### The incident-response lifecycle
```
Detection  →  Alerting  →  Triage  →  Evidence  →  Decision  →  Isolation  →  Replacement  →  Recovery  →  Report
  (Falco)     (Sidekick)   (SOAR)    (node-level)   (dev:auto   (quarantine   (new pod        (verify      (incident_report.py)
                                                      prod:human)  +conntrack)   starts)         health)
```

---

## 2. Technologies and tools

### Platform
| Component | Version | Purpose |
|---|---|---|
| **kind** (Kubernetes in Docker) | 0.30.0 | Creates a single-node Kubernetes cluster inside Docker |
| **Kubernetes** | v1.34.0 | Orchestration platform; runs the workload and the sensor |
| **kindnet** | v20250512-df8de77b | Default CNI; proven to enforce NetworkPolicies (tests/netpol) |
| **Docker Desktop** | 4.93.0 (Engine 29.8.1) | Runs the kind node and the Shuffle stack |
| **WSL2 Ubuntu 24.04** | kernel 6.6.114 (BTF present) | Execution environment for all bash/python scripts |

### Detection
| Component | Version | Purpose |
|---|---|---|
| **Falco** | 0.45.2 (Helm chart 9.2.2) | eBPF-based syscall sensor; runs as a DaemonSet inside the cluster |
| **Falco modern eBPF driver** | — | Reads kernel syscalls without kernel modules; works on WSL2 because BTF is present |
| **falcosidekick** | 2.35.1 | Receives JSON alerts from Falco; fans them out to the UI and to the SOAR webhook |
| **falcosidekick-ui** | 2.2.0 | Visual alert timeline; reached via `kubectl port-forward` |
| **falco-rules artifact** | version 5 | Official rule set downloaded by falcoctl at startup |

### SOAR
| Component | Version | Purpose |
|---|---|---|
| **Shuffle backend** | 2.3.0 | Workflow engine; receives the Falco webhook |
| **Shuffle frontend** | 2.3.0 | Web UI at `http://localhost:3001` |
| **Shuffle Orborus** | 2.3.0 | Scheduler; starts worker containers for each step |
| **OpenSearch** | 3.2.0 | Storage backend for Shuffle (workflows, executions) |
| **HTTP app** | 1.4.0 | Shuffle built-in app used to call the responder API |
| **Shuffle-tools app** | 1.2.0 | Utility functions used in the workflow |

### Response
| Component | Version | Purpose |
|---|---|---|
| **ir-responder** | own code | HTTP API container; the only component that touches Kubernetes |
| **ir_respond.py** | own code | Implements `collect`, `isolate`, `eradicate`, `status` |
| **collect-evidence.sh** | own code | Reads volatile data, filesystem delta, and K8s state from the NODE |
| **ValidatingAdmissionPolicy** | Kubernetes GA since 1.30 | CEL rules enforced by the API server: limits what the responder can do |

### Client tools
| Tool | Version | Used for |
|---|---|---|
| **kubectl** | v1.37.2 (host) / v1.34.0 (inside container) | Kubernetes API |
| **Helm** | v3.22.1 | Install Falco chart |
| **Python 3** | 3.12 | Provisioning scripts, API client, incident report |
| **bash** | — | All install and test scripts |
| **crictl** | bundled in kind node | Container runtime inspect (evidence collection) |
| **conntrack** | bundled in kind node | Delete tracked connections (isolation step 3) |

---

## 3. Architecture

### Component layout
```
 ┌─────────────────────────── kind cluster k8s-ir ──────────────────────────┐
 │                                                                            │
 │  juice-dev (1 pod)   juice-prod (2 pods)         falco namespace           │
 │  ┌────────────┐  syscalls (eBPF)  ┌───────┐ JSON ┌───────────┐ ┌────────┐│
 │  │ Juice Shop │─────────────────► │ Falco │─────►│ Sidekick  │►│Web UI  ││
 │  │ (Node.js,  │                   │DaemonS│:2801 └─────┬─────┘ └────────┘│
 │  │ distroless)│                   └───────┘            │ X-IR-Token       │
 │  └──────▲─────┘                                        │ webhook          │
 │         │ patch/delete (RBAC + VAP)                     │                  │
 │  ┌──────┴──────┐                                        │                  │
 │  │  API server │◄────────────────────────┐             │                  │
 │  └─────────────┘   SA token (12h,        │             │                  │
 └───────────────────── ir-system/ir-responder)────────────┼──────────────────┘
              kind Docker network 172.24.0.0/16             ▼
 ┌────────── Docker Compose (outside the cluster) ──────────────────────────┐
 │  ┌─────────────┐  X-Responder-Token  ┌───────────────┐                   │
 │  │ Shuffle     │────────────────────►│  ir-responder │── docker exec ──► node │
 │  │ (backend +  │   Shuffle network   │  :8088        │   (/proc, upperdir,     │
 │  │  Orborus)   │                     └───────┬───────┘    conntrack)           │
 │  └─────┬───────┘                             │ evidence/ (hashes, custody)    │
 │        │ http://localhost:3001                ▼                                │
 └────────┼────────────────────────────── host disk ─────────────────────────────┘
          ▼
     analyst / approver (browser or approve.py)
```

### Key isolation insight
NetworkPolicies are **additive allow-lists**, not deny-first rules. The quarantine policy only selects already-labelled pods and has no rules, so with every allow policy excluding quarantined pods (via `DoesNotExist` on `security.ir/quarantine`), there is no allow left and the pod is fully cut off. **But** the kernel's connection tracking (conntrack) keeps established flows alive — a NetworkPolicy only judges the first packet of a new flow. The isolation step therefore has three parts: apply the quarantine label, orphan the pod, and explicitly flush conntrack entries for the pod's IP on the node.

### Two environments, two response modes

| | juice-dev | juice-prod |
|---|---|---|
| Replicas | 1 | 2 |
| NodePort | 30000 → localhost:3030 | 30001 → localhost:3031 |
| Namespace label | `security.ir/environment=dev` | `security.ir/environment=prod` |
| Response | Fully automatic | Waits for human approval in Shuffle |
| Zero downtime during isolation | No (1 replica, ~25 s gap) | Yes (2 replicas) |

---

## 4. How the full workflow works, step by step

This is what actually happens when the simulation runs. Each step corresponds to a code location.

### Step 1 — Incident simulation (`simulation/simulate-incident.sh`)
The script uses `kubectl exec` to run five Node.js one-liners inside the target pod:
1. `console.log(...)` — a process executed inside the container via the runtime
2. `child_process.execFileSync("/nodejs/bin/node", ["-v"])` — application spawns a child
3. `fs.readFileSync("/etc/passwd")` — read a sensitive file
4. `net.connect(443, "1.1.1.1", ...)` — outbound TCP connection
5. `fs.writeFileSync("/tmp/<id>.txt", ...)` — write outside application directories

No real exploit is used. The marker `<id>` in every step is unique so alerts can be correlated to this run.

### Step 2 — Detection (Falco + custom rules, `falco/rules/juice-shop-rules.yaml`)
Falco's eBPF sensor intercepts the system calls made by those five steps:
- Steps 1 and 2 trigger rules on process spawning
- Step 3 triggers the sensitive file read rule
- Step 4 triggers the outbound TCP rule
- Step 5 triggers the filesystem write rule

Each rule fires as a JSON alert with fields: `rule`, `priority`, `output_fields.k8s.ns.name`, `output_fields.k8s.pod.name`, `tags` (must include `juice_shop` and `ir_response`).

### Step 3 — Alert forwarding (Falcosidekick, `falco/values.yaml`)
Falco writes JSON to stdout. Falcosidekick reads it and forwards `warning`+ priority alerts to:
- the UI (Redis cache, 7-day TTL)
- the Shuffle webhook (`POST http://<SHUFFLE_KIND_IP>:5001/api/v1/hooks/<hook-id>`) with header `X-IR-Token: <secret>`

### Step 4 — Triage (`response/service/server.py` → function `triage`)
Shuffle's first workflow node calls `POST /v1/triage` on the responder with the Falco alert as the body. The responder:
1. Validates the alert has tags `juice_shop` and `ir_response`
2. Validates the namespace is `juice-dev` or `juice-prod`
3. Derives a **deterministic incident id**: `"inc" + sha256("namespace/pod")[:20]` — all 9 alerts from one pod map to the same id
4. Logs every alert to `evidence/<incident>/alerts-received.jsonl`
5. Checks the kill switch (`evidence/.automation-paused`) — if set, returns `decision=paused`
6. Tries to atomically create `evidence/<incident>/claim.json` with `O_EXCL` — succeeds for the first alert only
7. Returns `decision=respond-dev` or `respond-prod` for the winning alert; `duplicate` for the rest

### Step 5 — Evidence collection (`response/collect-evidence.sh`)
Called from `ir_respond.py collect`, which is called by the workflow's `collect` node. The script **never execs into the container**. It reads from the node:

| What is collected | How | Where saved |
|---|---|---|
| PIDs in the container's cgroup | `cat /sys/fs/cgroup/…/cgroup.procs` on the node | `volatile/cgroup-procs.txt` |
| `/proc/<pid>` for each PID | cmdline, exe, cwd, status, environ, fd, maps | `volatile/proc-<pid>.txt` |
| TCP/UDP socket tables | `/proc/<pid>/net/tcp tcp6 udp udp6` | `volatile/net-*.raw` |
| Decoded connections | `decode_sockets.py` reads the raw tables | `volatile/connections.txt` |
| Changed files (overlay upperdir) | `find` on the overlay upperdir | `filesystem/changed-files.txt` |
| Changed files content | `tar` of the overlay upperdir | `filesystem/upperdir.tar` |
| Container image identity | `crictl inspect` → parsed | `container/crictl-inspect.json`, `container/image.txt` |
| Pod manifest, describe, events | `kubectl get pod -o yaml`, `kubectl describe`, `kubectl get events` | `kubernetes/` |
| Container logs | `kubectl logs --timestamps` | `kubernetes/logs.txt` |
| Falco alerts for this pod | Filter `falco` DaemonSet logs | `alerts/falco-alerts.jsonl` |

After collection:
- A `manifest.json` is written with metadata and SHA-256 of every file
- `SHA256SUMS` is written
- The whole directory is archived as `<incident>/<ns>__<pod>.tar.gz`
- A SHA-256 of the archive is written to `<ns>__<pod>.tar.gz.sha256`
- `COMPLETE` is written (this is the flag `ir_respond.py` checks before allowing isolation)
- A `<ns>__<pod>.custody.log` is written alongside the archive with the archive hash

### Step 6 — Isolation (`ir_respond.py` → `isolate`, `response/service/server.py`)
Only runs after evidence is `COMPLETE`. Three sub-steps:

**6a. Quarantine label**
```
kubectl -n <ns> label pod <pod> security.ir/quarantine=true security.ir/incident=<id>
```
This matches the `quarantine` NetworkPolicy, which has no rules (deny-all). Every `allow` policy excludes pods with `security.ir/quarantine` via `DoesNotExist`. No new connections in or out.

**6b. Orphan (remove the Service selector label)**
```
kubectl -n <ns> label pod <pod> app.kubernetes.io/name-
```
Removing this label causes:
- The Service stops routing traffic to this pod immediately
- The ReplicaSet sees one pod missing its selector label and starts a fresh replacement
- The old pod stays alive (for forensics), running its processes

**6c. conntrack flush**
```
docker exec k8s-ir-control-plane conntrack -D -s <pod-ip>
docker exec k8s-ir-control-plane conntrack -D -d <pod-ip>
```
Runs directly on the kind node container. Deletes all tracked connections to or from the pod's IP. After this, the next packet of any existing TCP session hits the policy again and is dropped.

**6d. Verification**
Checks: quarantine label present, app label absent, pod not in EndpointSlices, replacement deployment reaches `availableReplicas >= desiredReplicas`.

### Step 7 — Human approval (prod only, Shuffle User Input node)
Shuffle pauses the workflow and displays to the analyst:
- Incident id, pod name, first alert rule and priority
- Evidence archive SHA-256 (proves evidence was collected before this decision)
- Options: Approve or Reject

The approver's identity and timestamp are recorded by Shuffle in `click_info.user` and `click_info.time`. These become the `--approval` reference string stored in the audit trail.

The workflow calls `POST /v1/respond-approved` immediately after approval. The responder starts `isolate + eradicate` in a background thread and returns at once — this avoids a Shuffle worker-swap race that loses the result of a long synchronous call.

### Step 8 — Eradication (`ir_respond.py` → `eradicate`)
1. Checks the pod is quarantined (refuses otherwise)
2. Takes a **second evidence snapshot** (`phase=pre-eradicate`) — captures any activity that happened after the first snapshot (e.g. while prod approval was pending)
3. Waits for the pre-eradicate snapshot to be `COMPLETE` (refuses to delete if it fails)
4. `kubectl -n <ns> delete pod <pod> --wait=true --timeout=120s`
5. Waits for the deployment to reach `availableReplicas >= desiredReplicas`

### Step 9 — Verification and report
The workflow's `dev_verify` node calls `POST /v1/verify {"namespace": "juice-dev"}`. The responder checks:
- Deployment's `spec.replicas` vs `status.availableReplicas`
- Ready endpoints in EndpointSlices
- Returns `{"healthy": true/false, ...}`

The incident report is generated by `python3 -I response/incident_report.py <incident>`.

---

## 5. File structure and every important file

```
D:\Kubernetes-IR\
├── cluster/
│   └── kind-config.yaml           ← cluster definition: 1 node, port mappings 30000→3030 and 30001→3031
├── apps/juice-shop/
│   ├── base/
│   │   ├── deployment.yaml        ← Juice Shop pod spec; hardened; labels for IR
│   │   ├── service.yaml           ← NodePort service (selector: app.kubernetes.io/name=juice-shop)
│   │   ├── serviceaccount.yaml    ← dedicated SA, automount=false
│   │   ├── networkpolicies.yaml   ← default-deny + allow-ingress + allow-egress + quarantine
│   │   └── kustomization.yaml
│   ├── overlays/dev/
│   │   ├── namespace.yaml         ← juice-dev, security.ir/environment=dev, PSA restricted
│   │   └── kustomization.yaml
│   ├── overlays/prod/
│   │   ├── namespace.yaml         ← juice-prod, security.ir/environment=prod, PSA restricted
│   │   └── kustomization.yaml     ← replicas: 2, NodePort: 30001
│   └── verify.sh                  ← health check: replicas, endpoints, HTTP 200, app-version API
├── falco/
│   ├── values.yaml                ← Helm values: modern_ebpf, CRI only, JSON output, Sidekick
│   ├── install.sh                 ← validates rules first, then helm upgrade
│   ├── networkpolicies.yaml       ← only Falco pods may POST to Sidekick
│   ├── create-ui-secret.sh        ← generates the falcosidekick-ui-creds Secret
│   ├── check-clock.sh             ← detects Falco clock drift; --fix restarts DaemonSet
│   ├── show-alerts.py             ← filter and summarise Falco log output
│   ├── canary/
│   │   └── falco-canary.yaml      ← busybox pod in ir-system used by check-clock.sh
│   └── rules/
│       ├── juice-shop-rules.yaml  ← 5 custom detection rules
│       └── ir-canary-rules.yaml   ← 1 rule matching the canary pod (clock check test)
├── soar/shuffle/
│   ├── docker-compose.yml         ← hardened Shuffle stack (backend, frontend, orborus, opensearch)
│   ├── .env                       ← non-secret config (committed): SHUFFLE_KIND_IP, ports, switches
│   ├── shuffle.sh                 ← up/down/status/logs/restart-ui
│   ├── fetch-apps.sh              ← vendor HTTP 1.4.0 and shuffle-tools 1.2.0 from GitHub
│   ├── shuffle_api.py             ← Python client (reads key from secrets/api-key.txt)
│   ├── approve.py                 ← list and decide pending approvals
│   ├── show_executions.py         ← filter executions by incident id
│   ├── apps/                      ← vendored app bundles (git-tracked, SHA256SUMS verified)
│   ├── workflows/
│   │   ├── provision_intake.py    ← creates the webhook trigger
│   │   ├── provision_playbook.py  ← creates/replaces the full IR playbook in Shuffle
│   │   ├── ir-falco-intake.json   ← exported intake workflow (tokens redacted)
│   │   └── ir-juice-shop-playbook.json ← exported playbook (tokens and email redacted)
│   └── upstream-v2.3.0/           ← unmodified upstream files (reference)
├── response/
│   ├── ir_respond.py              ← collect / isolate / eradicate / status (all safeguards)
│   ├── collect-evidence.sh        ← node-level evidence collection (never execs into the pod)
│   ├── decode_sockets.py          ← decodes /proc/<pid>/net/tcp* into human-readable connections
│   ├── verify-evidence.sh         ← verify archive hash + inner SHA256SUMS
│   ├── automation.sh              ← kill switch: pause / resume / status
│   ├── make-kubeconfig.sh         ← applies RBAC + VAP; writes a 12h token kubeconfig
│   ├── show-actions.py            ← print evidence/<incident>/actions.jsonl
│   ├── incident_report.py         ← full incident report (timeline, metrics, health, audit trail)
│   ├── rbac/
│   │   ├── ir-responder.yaml      ← Namespace ir-system + SA + Roles in juice-dev, juice-prod, falco
│   │   └── admission-policy.yaml  ← ValidatingAdmissionPolicy + binding (5 CEL rules)
│   └── service/
│       ├── Dockerfile             ← python:3.12-slim + docker CLI + kubectl from the node
│       ├── run.sh                 ← builds and starts ir-responder container
│       └── server.py              ← HTTP API: /healthz, /v1/triage, /v1/action, /v1/respond-approved, /v1/verify
├── simulation/
│   ├── simulate-incident.sh       ← 5 harmless steps, all 5 rules covered, incident id in every step
│   └── build_report.py            ← detection report (which rules fired)
├── demo/
│   └── run-demo.sh                ← interactive end-to-end demo (dev + prod)
├── tests/
│   ├── netpol/                    ← 4 tests + run-test.sh; proves kindnet enforces NetworkPolicies
│   ├── app-baseline/              ← pod hardening, PSA, quarantine behaviour
│   ├── falco-rules/               ← sensor health, 0 false positives, 5/5 rules fire
│   ├── alert-pipeline/            ← Falco→Sidekick→UI+Shuffle; forgery blocked; clock skew
│   ├── response-guardrails/       ← 25 tests: what RBAC + VAP allow and deny
│   ├── response/                  ← collect→isolate→eradicate, idempotency, prod approval
│   ├── responder-api/             ← 18 tests: auth, scope, 9 concurrent alerts → 1 claim
│   └── playbook/                  ← 22 tests: dev auto, prod approved, prod rejected
├── docs/                          ← 00-13 markdown documentation
├── evidence/                      ← git-ignored; evidence packages and incident reports live here
├── .gitignore
└── README.md
```

---

## 6. Source code explained

### `apps/juice-shop/base/deployment.yaml` — The target pod
Key design choices visible in the file:
- **Image pin**: `bkimminich/juice-shop:v20.3.0@sha256:cea5a4af4...` — both a tag (readable) and a digest (immutable). Without the digest, `IfNotPresent` would use a local cache, but `latest` might pull a different image.
- **Label `app.kubernetes.io/name=juice-shop`** is the Service selector. Removing it from a pod (the orphan step) causes the ReplicaSet to start a replacement and the Service to stop routing to that pod — without deleting it.
- **Label `security.ir/monitored=true`** is checked by `ir_respond.py` before every action. Any pod without it is refused.
- **`automountServiceAccountToken: false`** and **`enableServiceLinks: false`** mean the pod carries no Kubernetes credentials and no knowledge of other services as environment variables.
- **`readOnlyRootFilesystem: false`** is intentional: Juice Shop writes its SQLite database under `/juice-shop`. Without writes, the Falco file-write rule would not detect attacker activity.
- **All capabilities dropped**, `runAsNonRoot: true`, `runAsUser: 65532`, `seccompProfile: RuntimeDefault` — PSA `restricted` profile.

### `apps/juice-shop/base/networkpolicies.yaml` — Four policies
```
default-deny-all         → {} podSelector, Ingress+Egress: no traffic by default
allow-juice-shop-http-ingress → allows TCP :3000 to pods with app label AND no quarantine label
allow-juice-shop-egress  → allows UDP/TCP :53 to CoreDNS + all IPs except pod/service/kind networks
quarantine               → selects security.ir/quarantine=true pods, no rules (deny-all)
```
The critical line in the two allow policies:
```yaml
matchExpressions:
  - { key: security.ir/quarantine, operator: DoesNotExist }
```
Without this, a quarantined pod would still be selected by the allow policy (NetworkPolicy is additive — the most permissive rule wins).

### `falco/rules/juice-shop-rules.yaml` — 5 custom rules
Juice Shop is a **distroless** image: the only binary is `/nodejs/bin/node`. Generic Falco rules match shell names (`bash`, `sh`) or standard binaries — they would never fire here. The custom rules match on the namespace and container name via the `juice_shop_container` macro.

| Rule | Trigger | Priority | MITRE |
|---|---|---|---|
| Exec into container | A process whose parent is a container runtime (runc, containerd-shim) and `vpid != 1` | WARNING | T1609 |
| Process spawned by application | A process spawned from inside the container, parent is not the runtime | CRITICAL | T1059 |
| Sensitive file read | Read of `/etc/shadow`, `/etc/passwd`, `/etc/group`, `/var/run/secrets/`, `/proc/*/environ` | ERROR | T1552 |
| Outbound TCP connection | `evt.type=connect`, `fd.l4proto=tcp`, not loopback, not PID 1 to alchemy.com:443 | CRITICAL | T1071 |
| Write outside application data dirs | `open_write` to any file not under the known write paths, by PID 1 only | ERROR | T1505 |

The `kind_oci_hook` macro exempts a kind-specific setup script (`mount-product-files.sh`) that runs in every container's context at creation. Without this exception, every new pod would generate false positives.

### `response/service/server.py` — The responder API
A pure-stdlib Python HTTP server (`ThreadingHTTPServer`). No frameworks, no external packages. Five endpoints:

**`GET /healthz`** — returns `{"ok": true}`. Used by `run.sh` to wait for startup.

**`POST /v1/triage`** — the most complex:
```python
def incident_id(ns, pod):
    return "inc" + hashlib.sha256(f"{ns}/{pod}".encode()).hexdigest()[:20]
```
The hash is deterministic: 9 Falco alerts for one pod all produce the same id. The `O_EXCL` flag on `os.open` for `claim.json` is atomic: only the first alert can create the file. All threads trying to create it simultaneously will get `FileExistsError` for all but one — no race condition.

**`POST /v1/action`** — calls `ir_respond.py` as a subprocess with per-(namespace,pod) locking. This prevents two concurrent SOAR executions from running `isolate` simultaneously on the same pod.

**`POST /v1/respond-approved`** — prod only. Launches `isolate + eradicate` in a `threading.Thread(daemon=True)` and returns immediately. This is because Shuffle replaces its worker container a few seconds after a User Input node is answered, and a synchronous call started in that window loses its result.

**`POST /v1/verify`** — reads deployment status and EndpointSlices from the Kubernetes API.

### `response/ir_respond.py` — Response logic with safeguards
The `preflight` function runs before every action:
1. Validates namespace name and pod name against a regex
2. Checks the namespace has `security.ir/environment=dev|prod` (RBAC Forbidden is mapped to Refused, exit 3)
3. Checks the pod has `security.ir/monitored=true`
4. For `isolate`/`eradicate`: checks evidence `COMPLETE` file exists
5. For `isolate`/`eradicate` in prod: checks `--approval` is present

The `eradicate` function refuses to delete if the pre-eradicate snapshot fails:
```python
if r.returncode != 0 or not os.path.exists(final):
    raise RuntimeError("pre-eradication evidence snapshot failed: pod NOT deleted")
```

Every action result is appended to `evidence/<incident>/actions.jsonl` with a UTC timestamp and `operator@hostname`.

### `response/rbac/admission-policy.yaml` — The API-server guardrails
A `ValidatingAdmissionPolicy` (CEL expressions, evaluated by the Kubernetes API server itself) applies only to requests from `system:serviceaccount:ir-system:ir-responder`. It enforces 5 rules:

1. `object.spec == oldObject.spec` — cannot change a pod's spec (no image swap)
2. Only the three allowed label keys may change (`security.ir/quarantine`, `security.ir/incident`, `app.kubernetes.io/name`)
3. Annotations and ownerReferences cannot change
4. `wasQuarantined → isQuarantined` — once quarantined, cannot be un-quarantined
5. A quarantined pod cannot have the `app.kubernetes.io/name` label added back (would put it back in the Service)
6. `DELETE` only if the pod was already quarantined

These rules are enforced **even if the responder code or the SOAR is compromised**: the API server rejects the request before it reaches any storage.

### `soar/shuffle/workflows/provision_playbook.py` — The playbook
Creates the following DAG in Shuffle via API calls:

```
webhook → triage → collect → dev_isolate → dev_eradicate → dev_verify
                           ↘ prod_approval (User Input)  → prod_respond
```

Branch conditions (string comparisons, not booleans, to avoid Shuffle JSON parsing ambiguity):
- `triage → collect`: `$triage.body.decision startswith "respond-"` (i.e. not duplicate/paused)
- `collect → dev_isolate`: `$triage.body.decision == "respond-dev"` AND `$collect.body.outcome == "ok"`
- `collect → prod_approval`: `$triage.body.decision == "respond-prod"` AND `$collect.body.outcome == "ok"`

The approval message shown to the analyst includes:
- The incident id, pod, first alert rule and priority
- The evidence archive SHA-256 (from `$collect.body.record.archive_sha256`)

The exported playbook file has tokens and email addresses redacted by regex substitution before being written to disk.

---

## 7. Complete installation from scratch

**All commands run in Ubuntu (`wsl -d Ubuntu-24.04`), from `/mnt/d/Kubernetes-IR`.** Never use PowerShell or the docker-desktop distro.

### Prerequisites
- Docker Desktop 4.x running
- kind installed in Ubuntu: `curl -Lo /usr/local/bin/kind https://kind.sigs.k8s.io/dl/v0.30.0/kind-linux-amd64 && chmod +x /usr/local/bin/kind`
- kubectl, helm, python3 installed in Ubuntu
- Project cloned to `D:\Kubernetes-IR`

### Step 1 — Cluster + CNI validation

```bash
kind create cluster --config cluster/kind-config.yaml
```

This creates a single-node kind cluster named `k8s-ir` with two port mappings (3030 and 3031 on 127.0.0.1).

```bash
bash tests/netpol/run-test.sh
kubectl delete namespace netpol-test
```

Proves kindnet enforces NetworkPolicies. Must see 0 unexpected results.

### Step 2 — Target application

```bash
kubectl apply -k apps/juice-shop/overlays/dev
kubectl apply -k apps/juice-shop/overlays/prod
bash apps/juice-shop/verify.sh
```

Creates namespaces `juice-dev` and `juice-prod`, deploys Juice Shop in both. The verify script retries for 60 seconds (pod takes 20–60 s to start).

### Step 3 — Falco + alert pipeline

```bash
bash falco/install.sh
```

This script:
1. Validates every `falco/rules/*.yaml` with `falco -V` inside the running pod (if one exists)
2. Creates the `falcosidekick-ui-creds` Secret
3. Runs `helm upgrade --install falco falcosecurity/falco --version 9.2.2 -f falco/values.yaml` plus custom rules and (optionally) the Shuffle webhook settings
4. Applies `falco/networkpolicies.yaml`

The first install downloads the official rules from ghcr.io and can take **5–15 minutes**.

### Step 4 — SOAR (Shuffle)

```bash
bash soar/shuffle/fetch-apps.sh
```
Downloads and verifies (SHA256) the vendored app bundles (HTTP 1.4.0 and shuffle-tools 1.2.0).

```bash
bash soar/shuffle/shuffle.sh up
```
Starts the Docker Compose stack. Generates secrets in `soar/shuffle/secrets/shuffle-secrets.env` (OpenSearch password and encryption key).

**Manual step** — open `http://localhost:3001` and create the admin account (first visit only).

**Manual step** — go to Settings → API key, copy the key, save it:
```bash
notepad.exe soar/shuffle/secrets/api-key.txt
# paste the key, save, close
```

```bash
python3 -I soar/shuffle/workflows/provision_intake.py
```
Creates the webhook trigger in Shuffle and writes the webhook URL and token to `soar/shuffle/secrets/`.

```bash
bash falco/install.sh
```
Re-run to inject the webhook URL and token into the Falcosidekick Helm values.

### Step 5 — Response service + playbook

```bash
bash response/service/run.sh
```
This script:
1. Generates a random responder token in `response/secrets/responder-token.txt`
2. Calls `make-kubeconfig.sh` to apply RBAC + VAP and write a 12h token kubeconfig
3. Copies kubectl from the kind node
4. Builds the `ir-responder:1.0` Docker image (no package manager downloads)
5. Starts the container on the shuffle + kind networks
6. Waits for `/healthz`
7. Verifies the credential with `kubectl auth whoami`

```bash
python3 -I soar/shuffle/workflows/provision_playbook.py
```
Replaces the intake workflow with the full IR playbook (triage + collect + dev branches + prod approval).

### Verification

```bash
bash apps/juice-shop/verify.sh       # both environments healthy
bash falco/check-clock.sh            # Falco clock within 5s of wall clock
bash response/automation.sh status   # should print "active"
```

---

## 8. Running the demo

**Before the demo (after any reboot or sleep):**

```bash
bash falco/check-clock.sh --fix
bash soar/shuffle/shuffle.sh up
bash response/service/run.sh
bash apps/juice-shop/verify.sh
```

The `--fix` flag restarts the Falco DaemonSet if the clock drift exceeds 5 seconds. After sleep, the drift can be many minutes. A Falco restart downloads the official rules from ghcr.io and takes 5–15 minutes.

**Run the demo:**

```bash
bash demo/run-demo.sh
```

**Optional monitoring windows:**
```bash
kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802
# open http://localhost:2802  (Falco UI)
# open http://localhost:3001  (Shuffle)
```

**Demo phases:**

| Phase | What happens | What to watch |
|---|---|---|
| 0. Preflight | Checks all 6 components are healthy | Green checkmarks or error messages |
| 1. DEV scenario | 5 simulation steps fire → Falco detects → Shuffle runs the playbook automatically | Shuffle executions page; responder audit trail |
| 2. PROD scenario | Same 5 steps → playbook pauses at "prod_approval" → **you type your name and approve or reject** | Pod is untouched while you decide; audit trail records your identity |

The demo script computes the incident id from the pod name the same way the responder does:
```python
"inc" + hashlib.sha256(f"{ns}/{pod}".encode()).hexdigest()[:20]
```
This is used to find the right approval and execution.

---

## 9. Implemented scenarios

### Scenario A — Fully automatic (dev)
Trigger: `bash simulation/simulate-incident.sh dev`

What happens automatically, without any human intervention:
1. Falco fires 5–9 alerts (5 rules × some firing multiple times)
2. Falcosidekick forwards them to Shuffle
3. Shuffle runs the playbook: triage (1 claim, rest are duplicates) → collect evidence → isolate (quarantine + orphan + conntrack) → eradicate (pre-eradicate snapshot + delete) → verify
4. Total elapsed time from first alert to report: about 2–3 minutes

### Scenario B — Human-approved response (prod)
Trigger: `bash simulation/simulate-incident.sh prod`

What happens:
1. Same detection and alerting as scenario A
2. Playbook runs triage and collects evidence
3. Playbook **pauses** at the User Input node with the evidence hash
4. Analyst sees: incident id, pod, first alert, evidence SHA-256
5. If **approved**: pod is quarantined, connections cut, replacement starts (zero downtime — 2 replicas), compromised pod deleted; approver identity recorded
6. If **rejected**: pod is untouched; evidence package is preserved for investigation

### Scenario C — Kill switch (manual override)
```bash
bash response/automation.sh pause "testing rules"
# ... run tests that drive the responder by hand ...
bash response/automation.sh resume
```
While paused, every alert is recorded but `triage` returns `decision=paused`, so the SOAR workflow stops after the first node and takes no action.

---

## 10. Testing

All commands run in Ubuntu from `/mnt/d/Kubernetes-IR`.

### `tests/netpol/` — CNI validation
```bash
bash tests/netpol/run-test.sh
kubectl delete namespace netpol-test
```
**Proves:** kindnet enforces NetworkPolicies. Exit code = number of failures.

| Test | What it checks |
|---|---|
| Test 0 | Baseline: all traffic flows with no policy |
| Test 1 | Default deny ingress blocks all in-cluster traffic |
| Test 2 | Quarantine label (ingress+egress deny) works; removing the label restores traffic |
| Test 3 (finding) | An established TCP connection **survives** quarantine — it stays open until conntrack flush |
| Test 3b (finding) | After `conntrack -D`, the connection is cut |
| Test 4 (finding) | An allow policy overrides the quarantine — confirming that every allow policy must exclude quarantined pods |

**Last result:** 0 unexpected

### `tests/app-baseline/`
```bash
bash tests/app-baseline/run-test.sh
```
Checks pod hardening (PSA restricted, no SA token, non-root, dropped capabilities), network baseline, and that the quarantine policy does not break readiness probes.

**Last result:** 0 unexpected

### `tests/falco-rules/`
```bash
bash tests/falco-rules/run-test.sh
```
Runs each of the 5 simulation steps individually, waits for the matching alert, verifies 0 false positives against the baseline traffic.

**Last result:** 0 unexpected

### `tests/alert-pipeline/`
```bash
bash tests/alert-pipeline/run-test.sh
```
Verifies the full Falco → Sidekick → Shuffle path; checks that a request without the `X-IR-Token` header is rejected (forgery protection); checks Falco clock skew ≤ 5s.

**Last result:** 0 unexpected

### `tests/response-guardrails/`
```bash
bash tests/response-guardrails/run-test.sh
```
25 tests against RBAC and the ValidatingAdmissionPolicy. Examples:
- Responder can patch labels (expected: allowed)
- Responder cannot patch spec (expected: forbidden by VAP)
- Responder cannot un-quarantine a pod (expected: forbidden by VAP)
- Responder cannot delete a non-quarantined pod (expected: forbidden by VAP)
- Responder cannot create pods (expected: forbidden by RBAC)
- Responder cannot read secrets (expected: forbidden by RBAC)

**Last result:** 25/25

### `tests/response/`
```bash
bash tests/response/run-test.sh
```
Full collect → isolate → eradicate cycle, idempotency (running collect twice leaves COMPLETE unchanged), prod approval requirement (isolate without `--approval` in prod must be refused, exit 3).

**Last result:** 0 unexpected

### `tests/responder-api/`
```bash
bash tests/responder-api/run-test.sh
```
18 tests: authentication (missing token → 401), scope (unknown namespace → out-of-scope), and a **concurrency test** (9 simultaneous triage calls → exactly 1 claim, 8 duplicates).

**Last result:** 18/18

### `tests/playbook/`
```bash
bash tests/playbook/run-test.sh
```
22 tests driven against the live Shuffle playbook: dev automatic response, prod approved response, prod rejected response. Verifies that the final evidence package contains the file written by the incident simulation (the `writeFileSync` step leaves a marker file in the overlay upperdir).

**Last result:** 22/22

---

## 11. Troubleshooting

### Falco clock drift after sleep/reboot
**Symptom:** `bash falco/check-clock.sh` says `FAIL: no Falco event received` or `clock skew > 5s`.  
**Fix:** `bash falco/check-clock.sh --fix` — restarts the Falco DaemonSet. Wait 5–15 minutes (ghcr.io download).  
**Root cause:** The WSL2 VM clock resets after the host sleeps. The Falco kernel driver's clock doesn't re-sync automatically.

### Shuffle UI shows "Are you sure Shuffle is installed correctly?"
**Symptom:** `http://localhost:3001` shows the error page.  
**Fix:** `bash soar/shuffle/shuffle.sh restart-ui` (or `up` runs this automatically).  
**Root cause:** nginx in the frontend resolves `shuffle-backend` once at startup. If the backend container was recreated (new IP), nginx has a stale address. Restarting the frontend forces re-resolution.

### ir-responder not running / token expired
**Symptom:** demo preflight says `responder not running` or `responder credential valid [FAIL]`.  
**Fix:** `bash response/service/run.sh` — renews the 12h token and restarts the container.  
**Root cause:** The ServiceAccount token has a 12-hour TTL (set by `make-kubeconfig.sh`).

### Falco port-forward "Network Error" in the UI
**Symptom:** `http://localhost:2802` shows "Network Error".  
**Fix:** Restart the port-forward: `kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802`  
**Root cause:** The port-forward process died (e.g. after a sleep).

### Demo commands fail in PowerShell
**Fix:** Always run in Ubuntu: open a terminal, run `wsl -d Ubuntu-24.04`, then `cd /mnt/d/Kubernetes-IR`.  
Or from PowerShell: `wsl -d Ubuntu-24.04 --cd /mnt/d/Kubernetes-IR -- bash demo/run-demo.sh`

### Juice Shop pod not ready
**Symptom:** `verify.sh` fails; deployment shows 0 available.  
**Fix:** `kubectl -n juice-dev rollout status deploy/juice-shop --timeout=3m`  
**Root cause:** The startup probe checks `/rest/admin/application-version` every 5s, up to 36 times (3 min). Normal on first pull.

### Playbook approval request doesn't appear
**Symptom:** `python3 -I soar/shuffle/approve.py list` shows nothing for the incident.  
**Fix:** Check evidence was collected: `ls evidence/<incident>/<ns>__<pod>/COMPLETE`. Check the playbook is not in an error state: open Shuffle → Workflow → executions.

### Automation kill switch left on from tests
**Symptom:** demo triage returns `decision=paused`.  
**Fix:** `bash response/automation.sh resume`

---

## 12. Design decisions and their reasons

| Decision | Why |
|---|---|
| **Single-node kind cluster** | Every kind "node" is a Docker container. With N nodes, N Falco pods would each see the same syscalls and emit N identical alerts. One node = one Falco = no duplicates. |
| **Falco modern eBPF driver** | WSL2 has no kernel headers (required for the kernel module driver). It does have BTF (BPF Type Format), which modern eBPF needs. |
| **kindnet kept (not Calico)** | The first step proved kindnet enforces NetworkPolicies (tests/netpol passes). Installing Calico would have added complexity without benefit. |
| **Isolation = quarantine label + orphan + conntrack flush** | NetworkPolicy blocks new connections. Orphaning removes the pod from the Service. conntrack flush cuts already-open connections (Test 3 finding: they survive the policy alone). All three are needed for complete isolation. |
| **Custom Falco rules (not generic)** | Juice Shop is distroless. Generic rules match shell names. A distroless app produces a very clean syscall profile — the first observed false-positive run was used to tune every exception. |
| **Rules validated before every deploy** | A bad rules YAML once put Falco in a CrashLoop. All detection stopped. Pre-validation with `falco -V` inside the running pod makes the upgrade safe. |
| **Anti-forgery X-IR-Token** | The Sidekick webhook is accessible on the kind network. A `NetworkPolicy` restricts who can POST to it, but the token header provides a second layer of authentication at the application level. |
| **Clock-skew canary pod** | The first check-clock implementation exec'd into a Juice Shop pod to run a test command. That triggered the "Exec into container" rule, which started a real incident response. The canary is a dedicated pod in `ir-system` that the canary rule matches by namespace and pod name — it cannot accidentally trigger the juice-shop rules. |
| **Evidence from the node, not exec** | Exec into a suspect container modifies it (attaches a process, may trigger traps), invalidates the forensic chain of custody, and would itself fire Falco's "Exec into container" rule. All data is read from `/proc` and the overlay upperdir on the **node**. |
| **Two evidence snapshots** | The first snapshot is taken immediately (at the first alert). In production, the pod can run for minutes while awaiting approval. Activity that happens after the first snapshot would be lost. The pre-eradicate snapshot captures the full post-compromise state. |
| **SOAR holds no Kubernetes credential** | Shuffle mounts `docker.sock`, which gives root on the host. If the SOAR is compromised, it must not also hold a Kubernetes SA token. The responder holds the token, runs on the same Docker host, but is a separate process with its own RBAC scope. |
| **ValidatingAdmissionPolicy (VAP)** | RBAC alone would allow the responder to `kubectl patch pod <pod> --type=json -p '[{"op":"replace","path":"/spec/containers/0/image","value":"..."}]'`. The VAP's `object.spec == oldObject.spec` rule blocks this at the API server, independent of the responder code. |
| **One incident per pod, atomic O_EXCL claim** | 9 Falco alerts fire for one incident. Without deduplication, the SOAR would start 9 parallel evidence collections and 9 isolation attempts. The `O_EXCL` create is atomic in POSIX and handles the concurrent case without locks at the filesystem level. |
| **Shuffle outside the cluster** | Shuffle needs `docker.sock` to start its workers. Running it inside the cluster would require a privileged pod. Outside, in Docker Compose, it stays isolated from the cluster's control plane. |
| **Ports bound to 127.0.0.1 only** | Juice Shop is deliberately vulnerable. It must never be reachable from the LAN. All `kind-config.yaml` port mappings use `listenAddress: "127.0.0.1"`. |

---

## 13. Security controls

| Threat | Control | Verified by |
|---|---|---|
| Lateral movement from a compromised pod to other pods | Default-deny NetworkPolicy + no SA token + no service links | `tests/app-baseline` |
| Compromised pod reaching the SOAR (172.24.x) | Egress policy blocks the kind Docker network | `tests/app-baseline` |
| Forged Falco alert to Shuffle | `X-IR-Token` header; only Falco pods can reach Sidekick (NetworkPolicy) | `tests/alert-pipeline` |
| Stale Falco timestamps (clock drift after sleep) | Clock-skew guard: canary pod fires a known rule; compares event time to wall clock | `tests/alert-pipeline` |
| Responder escalating privilege (image swap, exec) | ValidatingAdmissionPolicy: 5 CEL rules enforced by the API server | `tests/response-guardrails` |
| Responder operating outside its scope | RBAC: namespaced Roles in juice-dev, juice-prod, falco only | `tests/response-guardrails` |
| Multiple parallel responses to one incident | Per-(ns,pod) threading lock + `O_EXCL` atomic claim | `tests/responder-api` (concurrency test) |
| Isolation that leaves existing connections open | conntrack flush after quarantine label | `tests/netpol` (Test 3/3b) |
| Evidence tampered after collection | SHA-256 per file + archive SHA-256 + custody log | `tests/response` (tamper tests) |
| Prod response without authorisation | `preflight` checks `--approval` present; VAP rejects DELETE of non-quarantined pods | `tests/response`, `tests/response-guardrails` |
| SOAR compromised (worst case) | Kill switch (`evidence/.automation-paused`); responder has no delete permission on non-quarantined pods (VAP); no Kubernetes credential in Shuffle | `docs/11-soar-compromise-risk.md` |

---

## 14. What to say during your presentation

### "What does the project do?"
> "We detect suspicious runtime activity in a containerised web application using Falco, which reads kernel system calls via eBPF. When an alert fires, it's sent to a SOAR platform that automatically runs an incident response playbook: collect forensic evidence from the host, isolate the compromised container with a network policy and by cutting open connections, then replace it with a clean pod. In production, a human must approve the destructive steps before they run."

### "Why Kubernetes?"
> "Kubernetes provides the primitives we need: NetworkPolicies for programmable isolation, RBAC for least-privilege access, and admission policies for API-server-level enforcement. It's also the standard platform for containerised workloads, so the problem is realistic."

### "Why do you flush conntrack? Isn't a NetworkPolicy enough?"
> "NetworkPolicy works by injecting rules into the kernel's packet filter. The packet filter only evaluates the first packet of a TCP connection — later packets are accepted from the connection-tracking table (conntrack). We proved this empirically in Step 1: a live TCP connection survived a quarantine label for several seconds. Flushing the pod's conntrack entries forces every existing connection to be re-evaluated by the policy, which then drops them."

### "How is evidence collected?"
> "We never exec into the suspect container — that would modify its state, could trigger attacker traps, and pollutes the forensic chain of custody. Instead, we read from the kernel interfaces on the node: /proc for processes and open files, the overlay filesystem's upperdir for changed files, and crictl inspect for container metadata. Everything is hashed (SHA-256 per file and per archive) and a custody log records every command and timestamp."

### "What stops the SOAR from doing anything it wants in Kubernetes?"
> "Two things. First, RBAC: the responder's ServiceAccount has namespaced Roles in only the two target namespaces. It cannot read secrets, exec into pods, or touch any other namespace. Second, a ValidatingAdmissionPolicy with CEL expressions: even with the RBAC permission to patch pods, the policy blocks changes to the pod's spec, blocks un-quarantining, and blocks deleting non-quarantined pods. These rules are evaluated by the API server itself — the responder code doesn't even see the request."

### "What if the SOAR is compromised?"
> "The kill switch (`evidence/.automation-paused`) pauses automation immediately. The SOAR holds no Kubernetes credential, so it cannot act on the cluster directly. The responder enforces its own safeguards independently of the SOAR. These residual risks — especially the Docker socket — are documented in `docs/11-soar-compromise-risk.md`."

### "What tests do you have?"
> "Eight suites. The most important: (1) CNI validation proves NetworkPolicies are actually enforced — kindnet passes; (2) response-guardrails has 25 tests that verify every RBAC deny and every VAP rule fires correctly; (3) responder-api has a concurrency test: 9 simultaneous triage calls for the same pod produce exactly 1 claim and 8 duplicates; (4) the playbook suite drives a real Shuffle execution and verifies that the final evidence package contains the marker file written by the incident simulation."

### "What are the limitations?"
> "The Docker socket is mounted by both Shuffle and the responder — this is root on the Docker host. Falco restarts depend on ghcr.io (10+ minutes if slow). Approval links in Shuffle carry the execution secret in the URL. The 12-hour token must be renewed after a reboot. These are documented as future work in `docs/12-project-journal.md §11`."

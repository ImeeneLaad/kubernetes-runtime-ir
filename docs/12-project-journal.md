# 12 — Project journal: everything that was done, and why

This is the complete record of how the project was built: every step, every
design decision (with the alternatives that were rejected), every problem met
(with its real root cause and its fix), and how each claim was verified. It
was written so that someone who did not build the project can understand it,
run it, defend it and extend it.

The other documents (00–11) are the per-topic reference. This journal tells
the whole story in order, and links to them.

**Contents**
1. [Objective and requirements](#1-objective-and-requirements)
2. [Starting point: environment inspection](#2-starting-point-environment-inspection)
3. [Final architecture in one page](#3-final-architecture-in-one-page)
4. [Step-by-step journal](#4-step-by-step-journal) (steps 1–10)
5. [After completion: demo preparation and fixes](#5-after-completion-demo-preparation-and-fixes)
6. [Every problem met, with root cause and fix](#6-every-problem-met-with-root-cause-and-fix)
7. [Security controls inventory](#7-security-controls-inventory)
8. [Test suites](#8-test-suites)
9. [Operations runbook](#9-operations-runbook)
10. [File inventory](#10-file-inventory)
11. [Limitations and future work](#11-limitations-and-future-work)
12. [Glossary](#12-glossary)

---

## 1. Objective and requirements

**Subject:** *Réponse à l'exécution dans Kubernetes* (runtime incident response
in Kubernetes).

**Objective:** build a local Kubernetes environment that detects suspicious
runtime activity inside containers and responds to it automatically, covering
the complete incident-response lifecycle.

Required lifecycle (from the brief) and where each item is implemented:

| # | Requirement | Implemented in |
|---|---|---|
| 1 | Local Kubernetes cluster | Step 1: kind cluster `k8s-ir` |
| 2 | Vulnerable web application | Step 2: OWASP Juice Shop, dev + prod |
| 3 | Falco for runtime detection | Step 3: Falco 0.45.2, modern eBPF, custom rules |
| 4 | Controlled suspicious activity | Step 5: harmless, repeatable simulation |
| 5 | Detection and alerts | Steps 3–4: Falco → Falcosidekick |
| 6 | Collect and preserve evidence before acting | Step 6: node-level collector, hashes, custody |
| 7 | Automated response through a SOAR | Steps 4, 8: Shuffle playbook |
| 8 | Isolate the pod with NetworkPolicies | Steps 1, 2, 7: quarantine label + orphan + conntrack flush |
| 9 | Replace or restart the compromised pod | Step 7: orphan → automatic replacement → eradicate |
| 10 | Verify the application works again | Steps 2, 9: `verify.sh`, responder `/v1/verify`, report |
| — | Dev vs prod; human approval in prod | Steps 7–8: responder safeguard + Shuffle User Input |
| — | Analysis of a compromised SOAR | Step 10: docs/11 |

**Technical constraints imposed by the brief, and how they were handled:**

| Constraint | How it was handled |
|---|---|
| Check that Falco can see kernel events on Docker Desktop + WSL2 + kind | Verified BTF availability, chose modern eBPF, confirmed `Opening 'syscall' source with modern BPF probe` and real detections (Step 3) |
| Don't assume kind's CNI enforces NetworkPolicies | Wrote an enforcement test suite **before** relying on policies (Step 1) |
| RBAC and least privilege for the SOAR integration | The SOAR holds no Kubernetes credential; a responder with namespaced RBAC **plus** a ValidatingAdmissionPolicy (Step 7) |
| Preserve evidence before isolating or replacing | Enforced in the workflow order, in the responder, and with a final snapshot before deletion (Steps 6–9) |
| No automatic destructive actions without safeguards | Evidence-first, scope checks, prod approval, idempotency, kill switch, and API-server guardrails |
| Test every response action in a controlled environment | 8 test suites; the simulation is harmless (Step 5) |
| Never modify Juice Shop's source code | The image is used as published, pinned by digest; only its runtime environment is configured |

**Working rules agreed with the student:** run everything and keep them
informed; explain before changing; troubleshoot real errors rather than guess;
**never commit to Git** (the student commits).

---

## 2. Starting point: environment inspection

Inspected before anything was built:

| Item | Found | Consequence |
|---|---|---|
| OS / RAM | Windows 11 Pro, 32 GB | Enough for cluster + SOAR |
| WSL | Ubuntu-24.04 (and `docker-desktop`, the **default** distro) | Plain `wsl` opens `docker-desktop`, not Ubuntu. Always use `wsl -d Ubuntu-24.04` |
| Kernel | `6.6.114.1-microsoft-standard-WSL2`, `/sys/kernel/btf/vmlinux` present | Modern eBPF possible; the kernel module isn't (no headers) |
| Docker | Desktop 4.93.0 / Engine 29.8.1, cgroup v2, about 15.5 GiB for the VM | OK |
| Tools | kind 0.30.0, kubectl 1.37.2, Helm 3.22.1, Python 3.12 (no pip, no jq) | Python stdlib used everywhere; no extra packages |
| Project folder | Only a stray 62 MB `kubectl` (identical SHA-256 to `/usr/local/bin/kubectl`) | Deleted; `git init` |
| Other workloads | Another project's stacks (Tracecat, SmartVuln) using about 5 GB, and **host port 3000** taken | Never touched them. Juice Shop moved to ports 3030/3031. Falco rules only match Kubernetes-labelled events |
| Network | Docker Hub fast; **GitHub / ghcr.io very slow** (10–34 KB/s), Alpine/apt mirrors about 80 KB/s, dl.k8s.io about 187 KB/s | Shaped many later decisions: pinned and vendored artefacts, no package installs in image builds |

---

## 3. Final architecture in one page

```
 Juice Shop pod ──syscalls──► Falco (eBPF) ──► Falcosidekick ──► Web UI
 (juice-dev / juice-prod)                          │
                                                   │ webhook + X-IR-Token (warning+)
                                                   ▼
                                      Shuffle playbook "IR - Juice Shop response"
                                      triage → collect → dev: isolate → eradicate → verify
                                                         prod: human approval → respond
                                                   │ X-Responder-Token (Shuffle network only)
                                                   ▼
                                      ir-responder (HTTP API) → ir_respond.py
                                         │ short-lived ServiceAccount   │ docker exec (node)
                                         ▼                              ▼
                                Kubernetes API (RBAC + VAP)     /proc, overlay upperdir, conntrack
```

**Design principle: decisions and power are separated.**
- **Falco** only detects.
- **Shuffle** decides (branching, approval), but holds **no Kubernetes
  credential**.
- **ir-responder** acts, re-checks every safeguard, and is itself limited by
  the **API server** (RBAC + admission policy).
- **Evidence** is taken from the node, never from inside the suspect
  container.

Full diagrams and trust boundaries: [docs/00-architecture.md](00-architecture.md).

---

## 4. Step-by-step journal

Each step lists: **goal**, **what was built**, **why** (decisions and
rejected alternatives), **verification**, and **problems met**.

### Step 1: Cluster and CNI validation ([docs/01](01-cni-validation.md))

**Goal:** a local Kubernetes cluster whose network isolation is *proven* to
work.

**Built:**
- `cluster/kind-config.yaml`: one node, explicit pod/service subnets, port
  mappings bound to `127.0.0.1` only.
- `tests/netpol/`: two busybox pods (`alpha` = the suspect, `beta` = a
  neighbour) and three policies: default-deny ingress, `quarantine`
  (selects `security.ir/quarantine=true`, denies ingress and egress), and an
  allow-all-ingress policy for alpha.
- `tests/netpol/run-test.sh`: tests 0–4, plus 3b.

**Why:**
- **Single node.** kind nodes are containers sharing **one kernel**. Falco's
  eBPF probe sees every syscall on that kernel, so with N nodes each of the N
  Falco pods would report the same event (N duplicates).
- **Keep kindnet or install Calico?** The student chose to *test kindnet
  first*. Calico would only be added if kindnet failed. Rejected: assuming
  enforcement (the brief explicitly forbids it).
- **Quarantine by label**, not by creating a policy during the incident:
  isolation becomes one reversible API call, and the policy is reviewed in
  advance.

**Verification (all passed):**

| Test | Result |
|---|---|
| 0 baseline | traffic and DNS allowed |
| 1 default-deny ingress | ingress blocked, DNS still OK, reversible |
| 2 quarantine label | in, out and DNS blocked; neighbour unaffected; reversible |
| 3 connection opened **before** quarantine | **survives** |
| 3b + `conntrack -D` on the node | **cut** |
| 4 quarantine + another allow policy | ingress **still allowed** (NetworkPolicy is additive) |

**Key findings that shaped the response:**
1. A NetworkPolicy only blocks **new** connections. kindnet's
   `kube-network-policies` judges the first packet; later packets are
   accepted through conntrack. So isolation must also **flush conntrack**.
2. NetworkPolicies are **additive allow-lists**. Every allow policy must
   exclude quarantined pods (`matchExpressions: security.ir/quarantine
   DoesNotExist`).

**Problems:**
- `kind create` failed: host port 3000 was taken by another project →
  Juice Shop moved to 3030.
- The first conntrack test was inconclusive: beta's listener was stuck on the
  dead connection from Test 3 (quarantine dropped the FIN) → recreated pods;
  Test 3 now lifts the quarantine *before* killing the connection.
- kindnet log `reading nfqueue stats … no such file`: it only affects
  statistics, not enforcement (proved by the tests).

### Step 2: Juice Shop dev and prod ([docs/02](02-juice-shop-deployment.md))

**Goal:** the target application in two environments, hardened, with labels
designed for the response.

**Built:**
- `apps/juice-shop/base/`: ServiceAccount (no token), Deployment (hardened,
  probes, resources), NodePort Service, 4 NetworkPolicies.
- `apps/juice-shop/overlays/dev` (1 replica, :3030) and `overlays/prod`
  (2 replicas, :3031). Namespace label `security.ir/environment` and Pod
  Security Admission `restricted`.
- `apps/juice-shop/verify.sh`: health check, later used for recovery.
- `tests/app-baseline/run-test.sh`.

**Why:**
- **Kustomize** base + overlays: no duplicated YAML between environments.
- **Prod has 2 replicas**, so the service survives while one pod is
  isolated (verified later: zero downtime).
- **Label scheme:** `app.kubernetes.io/name` is both the Deployment and the
  Service selector. **Removing it "orphans" the pod**: the ReplicaSet starts a
  clean replacement and the Service stops routing to it, while the suspect
  pod stays alive for forensics.
- **Hardening:** non-root UID 65532, all capabilities dropped, no privilege
  escalation, seccomp RuntimeDefault, no ServiceAccount token, PSA
  `restricted`.
- **Writable root filesystem, on purpose:** Juice Shop writes its SQLite
  database there, and attacker file writes must be possible to detect and to
  collect as evidence.
- **Image pinned by digest** (`v20.3.0@sha256:cea5a4af…`); source untouched.
- **Network baseline:** default deny; allow :3000 in; allow DNS; allow egress
  outside the pod and service CIDRs (no lateral movement, but the internet
  stays reachable, so isolation has a visible effect).

**Verification:** health PASS for both environments from WSL and Windows;
baseline test 0 unexpected.

**Key findings:**
1. **Kubelet probes are not blocked by quarantine** (0 restarts in 90 s), so
   quarantine doesn't trigger a liveness restart that would destroy volatile
   evidence.
2. **A quarantined pod still receives Service traffic** (1 request in 9 lost)
   → isolation must also orphan the pod.
3. **Distroless image:** no shell, and `node` isn't on `PATH`
   (`/nodejs/bin/node`) → simulation through `node`, and evidence taken from
   the node.

**Problems:**
- `kind load docker-image` failed with Docker Desktop's containerd image
  store (`content digest … not found`) → the image is pulled from Docker Hub,
  pinned by digest.
- The cluster was recreated once (while still empty) to add the prod port
  mapping.
- The test's `node -e` calls returned nothing: `node` isn't on `PATH` → use
  the absolute path.

### Step 3: Falco detection ([docs/03](03-falco.md))

**Goal:** runtime detection that works on WSL2, with rules that fit a
distroless Node.js app.

**Built:**
- `falco/values.yaml`: chart 9.2.2, `driver.kind: modern_ebpf`, only the CRI
  container engine, rules pinned (no `falcoctl follow`), JSON output,
  `priority: notice`.
- `falco/rules/juice-shop-rules.yaml`: 5 rules, tagged `juice_shop`,
  `ir_response` and MITRE ATT&CK.
- `falco/install.sh` (validates the rules before deploying),
  `falco/show-alerts.py` (readable alerts), `tests/falco-rules/run-test.sh`.

**The 5 custom rules:**

| Rule | Priority | Detects | MITRE |
|---|---|---|---|
| Exec into container | Warning | a process started via the runtime (`kubectl exec`) | T1609 |
| Process spawned by the application | Critical | `node` spawning a child process (typical RCE) | T1059 |
| Sensitive file read | Error | `/etc/shadow`, `/etc/passwd`, SA token, `/proc/*/environ` | T1552 |
| Outbound TCP connection | Critical | any outbound TCP (reverse shell, exfiltration) | T1071 |
| Write outside application data directories | Error | dropped tools, web shells, code tampering | T1505 |

**Why:**
- **modern eBPF** is the only working driver: no kernel headers for WSL2,
  but BTF is present. `auto` could have tried kmod, so it's set explicitly.
- **Custom rules:** a distroless app has no shell, so Falco's most common
  default rules can never fire on it. An attacker would act *through Node.js*.
  So the rules describe what this app normally does and alert on everything
  else.
- **No k8s-metacollector:** the container plugin already provides pod name,
  namespace and labels.
- **Rules pinned:** no silent weekly updates, so detection is reproducible.

**False-positive tuning on observed data:** about 190 alerts at first, all at
container **start**:

| Source | Exception (as narrow as possible) |
|---|---|
| kind's OCI hook `/kind/bin/mount-product-files.sh` (bash, jq, cp) | exact command line (macro `kind_oci_hook`) |
| `runc` reading `/etc/passwd` | `proc.name startswith "runc"` |
| Juice Shop writing `i18n/`, `frontend/dist/`, `.well-known/` | only for **PID 1** |
| `validatePreconditions.js` fetching `https://www.alchemy.com/` (confirmed in the image source) | only PID 1, port 443, that domain |
| LLM check on `localhost:11434` | loopback excluded |

Result: **0 false positives** during restart and normal use.

**Verification:** default rules fired on a test pod; custom rules 5/5 fired
on harmless triggers; 0 false positives; the pre-validation guard rejects a
broken rules file without touching the running Falco.

**Problems:**
- **A `#` comment inside a YAML folded block** (`condition: >`) became part
  of the condition. Falco refused the rules file and went into
  CrashLoopBackOff: **no detection at all**. Fixed the comment, added
  `falco -V` pre-validation inside the running pod, and a sensor-health check
  in the test (otherwise a dead Falco makes "no false positive" pass).
- Pre-validation also had to require a **ready** container: a crash-looping
  pod still reports phase `Running`.
- `evt.dir` is deprecated in Falco 0.45 (warning) → removed.
- The shell-rule test needed a real TTY (`script -qec`).
- A safety filter cut off part of a response during this step; it was resumed
  without reproducing the cut content.

### Step 4: Alert forwarding and SOAR intake ([docs/04](04-alert-forwarding.md), [docs/05](05-shuffle.md))

**Goal:** get alerts out of the cluster to a SOAR, securely.

**Built:**
- Falcosidekick + Web UI as the Falco chart's sub-chart. The UI password is
  generated (`falco/create-ui-secret.sh`, not `admin:admin`).
- `falco/networkpolicies.yaml`: only Falco may post to Sidekick; only
  Sidekick may reach the UI; only the UI may reach Redis.
- Shuffle 2.3.0 with Docker Compose (`soar/shuffle/`), hardened.
- `soar/shuffle/fetch-apps.sh`: only 2 vendored apps.
- `soar/shuffle/shuffle_api.py`.
- `soar/shuffle/workflows/provision_intake.py`: the workflow and an
  authenticated webhook.
- The Sidekick webhook output, with the token injected at install time.
- `falco/check-clock.sh`, `tests/alert-pipeline/run-test.sh`.

**Why:**
- **Sidekick** decouples Falco from consumers. Falco knows one endpoint, and
  outputs are added without touching the sensor.
- **Anti-forgery:** Sidekick accepts any JSON. A forged "Critical, prod"
  alert could make the SOAR delete healthy pods, so the network path is
  locked to Falco.
- **Shuffle outside the cluster:** the component that acts on the cluster
  shouldn't live inside it. Shuffle also expects a Docker host.
- **Hardening Shuffle** (versus upstream):

  | Upstream | Changed to |
  |---|---|
  | `:latest` | `2.3.0` |
  | ports on `0.0.0.0` | `127.0.0.1` |
  | OpenSearch `:9200` published with public default password | not published; random password |
  | empty encryption modifier | generated |
  | `shuffle-security` (needs source build) | removed |
  | 3 GB heap | 1 GB |
  | bind mounts on `/mnt/d` | named volumes |
  | `TZ=Europe/Amsterdam` | `UTC` |
- **Connectivity:** pods resolve DNS through Docker Desktop's host resolver,
  so container names don't resolve. The backend is attached to the `kind`
  network at a **fixed IP 172.24.255.10**.
- **Webhook authentication:** Shuffle's `auth_headers` rejects any request
  without `X-IR-Token` (format read from the Shuffle UI's own code).

**Verification:** Juice Shop alert → UI in about 2 s; `admin:admin`
rejected; forged alert from another namespace blocked; webhook: no token →
401, wrong token → 401, correct → execution FINISHED; full chain Juice Shop →
Falco → Sidekick → Shuffle in about 12 s.

**Problems (in order):**
- **Shuffle images pulled very slowly from ghcr.io** (about 30 min). It
  first looked like a Docker hang; diagnosis showed the daemon was fine and
  ghcr was slow. The compose run was restarted with progress logging.
- **A quoting bug meant `shuffle.sh up` was printed, not run** → re-run.
- Backend startup race with OpenSearch (`connection refused`) → transient,
  retried by itself.
- **The admin account had to be created by the student** (account creation
  and credential handling are not delegated). The API key file wasn't saved
  on the first two tries: the command ran in a shell where `/mnt/d` wasn't the
  D: drive → saved with Notepad. Reading the key out of the browser session
  was blocked by the permission system → the student copied it.
- **0 apps loaded:** Shuffle clones about 200 apps from GitHub at 10–34 KB/s
  → vendored only `http` and `shuffle-tools`, pinned to commit `4a3d7209…`,
  with runtime images from Docker Hub.
- **Orborus never checked in:** it was blocked pulling the unpinned
  `tenzir/tenzir:main` and configured for Swarm → `SHUFFLE_SKIP_PIPELINES`,
  `SHUFFLE_PIPELINE_ENABLED=false` (names found in the Orborus binary), Swarm
  mode removed.
- Juice Shop could reach Shuffle at first → the egress policy now excludes
  the kind network `172.24.0.0/16` (Shuffle verified blocked). **Pod →
  own-node IP** (API server) is host-local, so kindnet can't filter it. It
  stays mitigated by no token and RBAC; documented.
- Test bugs: wrong metric name; a RediSearch `-` in the marker acting as NOT.
- **Falco timestamps 3807 s too early** after the VM was paused. Falco's
  boot-time reference went stale. Restarting Falco fixes it, and
  `check-clock.sh --fix` guards it.
- Personal data: the Shuffle export contained the admin's e-mail → exports
  are now redacted.

### Step 5: Controlled incident simulation ([docs/06](06-incident-simulation.md))

**Goal:** a repeatable incident that fires all rules, without any real attack
code.

**Built:** `simulation/simulate-incident.sh` (5 steps, incident ID, clock
precondition) and `simulation/build_report.py`.

**Why:**
- The simulation **only replays the 5 harmless triggers validated in Step
  3**: print a value, `node -v`, read `/etc/passwd`, one TCP connect/close to
  1.1.1.1:443, write a file in `/tmp`.
- An earlier attempt at a richer attack simulation was stopped by a safety
  filter. The scope was then deliberately limited, which also fits the
  project: the subject is the *response*, not offensive technique.
- The incident ID is alphanumeric, so it's searchable in the Sidekick UI.

**Verification:** 3 runs (dev, prod, dev): 5/5 detected each time, 9 alerts
each, all reaching Shuffle.

**Key finding:** **1 incident = 9 alerts = 9 SOAR executions.** Steps 2–5 go
through `kubectl exec`, so they also fire "Exec". The response must therefore
**correlate per pod** and be **idempotent**.

**Problem:** a Python step was given two stdin inputs at once → moved to
`build_report.py`.

### Step 6: Evidence collection and preservation ([docs/07](07-evidence-collection.md))

**Goal:** preserve evidence before any action, in a verifiable way.

**Built:** `response/collect-evidence.sh`, `response/decode_sockets.py` and
`response/verify-evidence.sh`.

**Why:**
- **Never exec into the suspect container.** It would modify it, could
  trigger attacker traps, and fires our own Falco rule. A debug container
  permanently changes the pod spec. Everything is read **from the node**:
  `crictl inspect` (PID, image digest), the container's cgroup (every PID),
  `/proc/<pid>` (cmdline, exe, environ, fds, maps), the pod network
  namespace's socket tables, and the **overlay upperdir** (exactly the files
  added or changed: an exact delta, not 500 MB of image).
- **Order of volatility** (RFC 3227): processes and sockets → files → image
  → Kubernetes state → logs and alerts.
- **Chain of custody:** every command, its UTC time and exit code; the
  operator; the kube context.
- **Integrity:** SHA-256 per file (`SHA256SUMS`, `manifest.json`) and per
  archive (`.sha256`).
- **Idempotent:** `COMPLETE` marker per incident + pod.

**Verification:** 0 Falco alerts caused by collection; 0 restarts; no
ephemeral container; the simulated connection (`TIME_WAIT` to 1.1.1.1:443)
and the dropped file were captured, as were files from **earlier**
simulations (showing how long the pod had been compromised); a changed
archive was detected; a changed file inside a repacked and re-hashed archive
was detected.

**Problems:**
- `custody.log` failed its own verification: a line was appended *after*
  hashing. A file can't contain the hash of the archive that contains it →
  that record goes to a custody file beside the archive.
- The first tampering test was invalid (the copied archive was read-only, so
  the "tampering" never happened) → redone with a writable copy.
- A Python f-string quoting bug in the verifier → heredoc.
- `kubernetes/events.txt` was empty: events last about 1 h; documented.

**Limit (honest):** someone who controls the evidence folder can regenerate
the hashes too. The archive hash must also be recorded out of band → stored
in Shuffle (Step 8).

### Step 7: Response actions with least privilege ([docs/08](08-response-actions.md))

**Goal:** isolate and replace a pod, with the smallest possible power.

**Built:**
- `response/rbac/ir-responder.yaml`: namespace `ir-system`, ServiceAccount,
  Roles in `juice-dev`, `juice-prod` and `falco` (logs only).
- `response/rbac/admission-policy.yaml`: ValidatingAdmissionPolicy
  `ir-responder-guardrails`.
- `response/make-kubeconfig.sh`: 12 h token via the TokenRequest API.
- `response/ir_respond.py`: `collect`, `isolate`, `eradicate`, `status`.
- `response/show-actions.py`, `tests/response-guardrails/`, `tests/response/`.

**Why:**
- **The SOAR holds no Kubernetes credential.** A dedicated responder holds a
  short-lived ServiceAccount token.
- **RBAC is too coarse:** "patch pods" would also allow **replacing a
  container's image**. A **ValidatingAdmissionPolicy** (GA since 1.30),
  enforced by the API server for this identity only, allows changing *only*
  the 3 IR labels, never the spec, annotations or ownerReferences; **never
  lifting a quarantine**; never putting a quarantined pod back in the Service;
  and **deleting only quarantined pods**.
- **Isolation order:** quarantine label (no new connections) **→** remove the
  app label (out of the Service + replacement starts) **→** conntrack flush
  (open connections cut) **→** verify. Quarantine comes first so the pod is
  never reachable outside the Service.
- **Safeguards in the responder too** (defence in depth): namespace
  allowlist, `security.ir/monitored=true`, **evidence before isolate and
  eradicate**, **`--approval` required in prod**, idempotency, audit trail
  (`evidence/<incident>/actions.jsonl`), exit code 3 = refused.

**Verification:**
- **Guardrails 25/25:** RBAC allowed versus denied (exec, attach, secrets,
  create pods, NetworkPolicies, Deployments, other namespaces, cluster-wide,
  rolebindings, tokens), and admission allowed versus denied (image change,
  foreign labels, annotations, delete non-quarantined, lift quarantine,
  re-add to Service).
- **Lifecycle 30/30:**
  - dev: refused before evidence → collect → idempotent → isolate (pod still
    Running for forensics, out of endpoints, egress blocked, replacement
    serving, app healthy) → eradicate;
  - prod: refused without approval → approved → **40/40 user requests OK**;
  - out of scope: refused.

**Problems:**
- YAML anchors don't cross `---` documents → rules written out in full.
- CEL syntax for keys containing `/`: `map[?'key']`, not `.?'key'` (the API
  server validated and rejected the first version).
- A target outside the perimeter returned "failed" instead of "refused" →
  RBAC `Forbidden` on the scope check is now mapped to a refusal.
- Test bug: `timeout` can't run a shell function.

**Trade-off:** dev (1 replica) has about 25 s with no endpoint during
isolation. Scaling up first would need `patch deployments`, deliberately not
granted.

### Step 8: SOAR playbook ([docs/09](09-soar-playbook.md))

**Goal:** the full automated response in Shuffle, with prod approval.

**Built:**
- `response/service/` (Dockerfile, `server.py`, `run.sh`): the `ir-responder`
  HTTP API, on the Shuffle network only, with no host port, token-protected
  and locked per pod.
- `soar/shuffle/workflows/provision_playbook.py`: the playbook "IR - Juice
  Shop response".
- `soar/shuffle/approve.py`, `soar/shuffle/show_executions.py`.
- `tests/responder-api/`, `tests/playbook/`.

**Why:**
- Shuffle actions run in containers and need an HTTP endpoint, hence the
  service.
- **Image built without package managers** (the mirrors were too slow; the
  first build hung 11 min): `python:3.12.14-slim` + Docker CLI copied from
  `docker:29.8.1-cli` + **the kind node's own kubectl** (exact cluster
  version). Project mounted read-only, `evidence/` writable.
- **Correlation:** `/v1/triage` derives **one incident ID per pod** and
  **atomically claims** it (`O_EXCL`). Only the first alert responds; all are
  recorded.
- **String decisions** (`respond-dev`, `respond-prod`, `duplicate`,
  `out-of-scope`, later `paused`) avoid boolean ambiguity in Shuffle
  conditions.
- **Prod approval with Shuffle's User Input**, so the decision is made by an
  authenticated Shuffle user (`click_info.user`) and recorded.
- **The evidence hash is shown in the approval request** and stored in the
  Shuffle execution: the out-of-band record.

**Verification:** API 18/18 (including **9 concurrent alerts → exactly 1
claim**); playbook **22/22**:
- dev automatic: 1 responder, 10 duplicates stopped, hash in Shuffle =
  archive, final snapshot holds the dropped file;
- prod approved: paused, evidence before decision, pod untouched while
  waiting, **75/75 requests OK**, approver identity in the audit trail;
- prod rejected: pod untouched, no action, evidence kept.

**Problems:**
- **Shuffle resume race:** after a User Input is answered, Shuffle resumes
  with a **new worker** and kills the old one. `prod_isolate`, started by the
  old worker, finished on the cluster but its result went to a dead address,
  and the execution hung before eradication. That incident was finished by
  CLI, citing the recorded approval. **Fix:** after approval, one fast call,
  `/v1/respond-approved`; the responder runs isolate → eradicate in the
  background.
- **User Input `type: subflow` is a notification channel**, not an "on
  approve" hook (proved with a probe workflow, then deleted). It revealed that
  **approval links carry the execution's secret**: whoever holds a link can
  approve. That's risk T5.
- `$exec_id` isn't a Shuffle variable → `$prod_approval.click_info.*`.
- Test bugs: `${3:-$TOK}` replaced an explicit empty token; a bare `wait` in
  bash ≥ 5.1 also waits for the `tee` process substitution (hang).
- `pkill -f` matched its own command line.

### Step 9: Recovery and incident report

**Goal:** prove recovery and produce a report per incident.

**Built:** `response/incident_report.py` writes `evidence/<incident>/report.md`:
- summary;
- metrics: first alert → evidence, → contained, → recovered;
- a unified timeline (Falco, SOAR, evidence, responder);
- each snapshot, re-verified at report time;
- files and sockets found, the audit trail, current health.

A redacted example is in `docs/examples/sample-incident-report-prod.md`.

**Finding → improvement:** the report's timeline showed **the first snapshot
finished before the last steps of the incident** (the outbound connection and
the file drop came 1–4 s later and weren't captured). In prod the pod runs
until approval. **Added a `pre-eradicate` snapshot**, and `eradicate`
**refuses to delete if it fails**. Verified: the final snapshot contains the
dropped file (dev and prod).

**Problems:**
- Sidekick renames fields (`proc.cmdline` → `proc_cmdline`) → the report
  reads both forms (triage uses `k8s.ns.name`, whose dots are kept).
- **Component test versus live automation:** `tests/response` drives the
  responder by hand, while the live playbook reacted to the same simulated
  alerts and deleted the pod mid-test. Added the **kill switch**
  `response/automation.sh pause|resume`. Paused, triage records alerts but
  answers `paused`. The test pauses automation for its duration.
- **A test script was edited while running.** bash reads scripts
  incrementally, so the run was corrupted (`ve: command not found`). It was
  discarded and everything re-run. Rule: never edit a running script.

### Step 10: Documentation, demo and risk analysis

**Built:**
- `docs/00-architecture.md`, `docs/10-demo.md` + `demo/run-demo.sh`
  (interactive; prod decision by the presenter);
- `docs/11-soar-compromise-risk.md` (10 scenarios, controls, residual risk,
  8 recommendations);
- the final README.

**Risk analysis conclusion:** through its Kubernetes credential, a
compromised SOAR can at worst make Juice Shop **unavailable**. It can't run
code in pods, read secrets, swap images, open the network or lift a
quarantine (verified). The critical remaining path is the **Docker socket**
used by Shuffle and the responder. Approvals are procedural, not
cryptographic.

**Pre-commit scan:** `git add --dry-run` (87 files) scanned for secret
values and personal data → the e-mail in workflow exports was redacted, and
exports now redact automatically; no secret values.

---

## 5. After completion: demo preparation and fixes

| Event | Root cause | Fix |
|---|---|---|
| **Two dev pods deleted with no simulation running** | `check-clock.sh` probed Falco with a harmless `node -e` **inside a Juice Shop dev pod**, which fired the real "Exec" rule, and the live playbook responded. Every clock check cost a pod | Dedicated **Falco canary** pod in `ir-system` + rule `IR canary heartbeat` (NOTICE: below the SOAR threshold, not `ir_response`). Rejected: an exception for the marker in Juice Shop rules (an attacker bypass). Verified: 3 checks → 0 incidents, 0 SOAR executions, 0 webhook posts |
| Demo "didn't move" | Keypresses went to another window | Explained; demo restarted in the right shell |
| Paths "not found" | Commands typed in **PowerShell** instead of Ubuntu | `wsl -d Ubuntu-24.04`, or `wsl -d Ubuntu-24.04 --cd /mnt/d/Kubernetes-IR -- bash demo/run-demo.sh` |
| `kubectl: not found` | Shell opened in the `docker-desktop` distro (WSL default) | Use Ubuntu; optionally `wsl --set-default Ubuntu-24.04` |
| Clock skew −5453 s at demo start | PC sleep (VM paused) | `check-clock.sh --fix` restarted Falco, as designed |
| **Falco took about 10 min to restart; meanwhile no detection** | At every start, falcoctl downloads the rules and container plugin from **ghcr.io** (very slow here) | Waited; recorded as future work (cache artefacts locally) |
| Two demos running at once | A demo tab plus a manual run | Closed the extra one |
| Falco UI "Network Error" | The `port-forward` tunnel wasn't running | Tunnel started in a terminal tab. Note: the UI password was shared in chat → rotation recommended |
| **Shuffle UI: "Are you sure Shuffle is installed correctly?"** | 502: the frontend's nginx resolves `shuffle-backend` **once at start**; the backend had been recreated with a new IP | `docker restart shuffle-frontend`. `shuffle.sh up` now always restarts it; `shuffle.sh restart-ui` added. The page's own suggestions (`chown`, `swapoff`) didn't apply and weren't run |
| `soar/shuffle/.env` would not be committed | `.gitignore` excluded every `.env` | Explicit exception (it holds no secrets; secrets are in `soar/shuffle/secrets/`) |

**Demo result (run by the student):** dev automatic response; prod paused,
approved by the student, isolated and replaced with prod healthy; two
incident reports generated.

---

## 6. Every problem met, with root cause and fix

| # | Symptom | Root cause | Fix | Lesson |
|---|---|---|---|---|
| 1 | `kind create` port error | host port 3000 used by another project | ports 3030/3031 | Check the host before choosing ports |
| 2 | Open connection survives quarantine | policy judges new connections only | conntrack flush in `isolate` | Test enforcement, don't assume |
| 3 | Quarantine overridden by another policy | NetworkPolicy is additive | allow policies exclude quarantined pods | Design policies as a set |
| 4 | Quarantined pod still served users | still a Service endpoint | orphan (remove app label) | Isolation ≠ network policy alone |
| 5 | `kind load` failed | containerd image store incompatibility | pull from Docker Hub by digest | — |
| 6 | Falco CrashLoop, no detection | `#` inside a YAML folded block | pre-validation + health check | A bad rule = a blind sensor |
| 7 | Pre-validation crashed | crash-looping pod reports `Running` | require a ready container | — |
| 8 | ~190 false positives at start | kind hook, runc, app startup writes, precondition fetch | narrow, evidence-based exceptions | Tune on data, document the gaps |
| 9 | ghcr/GitHub downloads take hours | slow network path | vendored apps, Docker Hub images, no package installs | Pin and vendor |
| 10 | Orborus never checked in | unpinned Tenzir pull, Swarm mode | `SHUFFLE_SKIP_PIPELINES`, no Swarm | Read the binary for real settings |
| 11 | Juice Shop could reach Shuffle | egress allowed the kind network | exclude `172.24.0.0/16` | — |
| 12 | Pod can reach the API server | pod → own node IP not filtered by kindnet | documented; no token + RBAC | Know your CNI's limits |
| 13 | Alerts "missing" from the UI | Falco clock −3807 s after VM pause | `check-clock.sh --fix` | Time integrity matters for evidence |
| 14 | custody.log fails verification | appended after hashing | separate custody file for the archive | A file can't contain its own container's hash |
| 15 | Tamper test passed wrongly | read-only copy, no tampering | redo with a writable copy | Test the test |
| 16 | Responder image build hung | slow apk/apt mirrors | build without package managers | — |
| 17 | 9 alerts → 9 responses | one execution per alert | atomic claim per pod | Correlate before acting |
| 18 | Prod playbook hung after approval | Shuffle worker swap loses results | one fast call, background job | Don't trust long sync actions after resume |
| 19 | Approval link = approval | link carries the execution secret | documented (T5), admin-key tool | Procedural ≠ cryptographic control |
| 20 | Snapshot missed the end of the incident | collected at the first alert | pre-eradicate snapshot | Evidence is a timeline, not a moment |
| 21 | Test and automation acted on the same pod | always-on automation | kill switch | Automation needs an off switch |
| 22 | Corrupted test run | edited a running bash script | re-run; never edit running scripts | — |
| 23 | Health check deleted pods | probe inside a protected workload | Falco canary | Monitoring must not trigger the response |
| 24 | Falco restart about 10 min | artefacts downloaded from ghcr at every start | future work: local artefacts | Recovery shouldn't depend on the internet |
| 25 | Shuffle UI 502 | nginx resolved the backend IP once | restart frontend after `up` | — |
| 26 | Personal data in exports | Shuffle `updated_by` | automatic redaction | Scan before committing |
| 27 | `.env` not committed | `.gitignore` too broad | explicit exception | Verify what Git will actually include |

---

## 7. Security controls inventory

| Area | Control | Verified by |
|---|---|---|
| Workload | non-root, caps dropped, seccomp, PSA restricted, no SA token, image by digest | app-baseline |
| Workload network | default deny; egress only DNS + internet (no pods, services or kind network) | app-baseline |
| Exposure | everything on `127.0.0.1`; OpenSearch not published; responder has no host port | docker port, responder-api |
| Alert path | only Falco → Sidekick; UI and Redis restricted; UI password generated | alert-pipeline |
| SOAR intake | webhook requires `X-IR-Token` | Step 4 |
| SOAR → responder | `X-Responder-Token`, Shuffle network only, scope checks, per-pod lock | responder-api |
| Responder → Kubernetes | namespaced RBAC + ValidatingAdmissionPolicy | response-guardrails (25/25) |
| Response logic | evidence first, prod approval, idempotency, audit trail, refusals logged | response, playbook |
| Human control | Shuffle User Input with authenticated `click_info.user` | playbook |
| Evidence | node-level, never in the pod; SHA-256 per file and archive; custody log; hash in Shuffle; final snapshot | Step 6, playbook |
| Time | clock-skew check before simulations/demos (canary) | check-clock |
| Operations | kill switch; rules validated before deploy; secrets git-ignored; redacted exports | — |
| Supply chain | pinned versions, vendored apps with SHA256SUMS, kubectl from the node | — |

---

## 8. Test suites

Run in Ubuntu from the project root.

| Suite | Command | What it proves | Last result |
|---|---|---|---|
| CNI | `bash tests/netpol/run-test.sh` | enforcement, conntrack, additive policies | 0 unexpected |
| App baseline | `bash tests/app-baseline/run-test.sh` | hardening, network baseline, probes vs quarantine | 0 unexpected |
| Falco rules | `bash tests/falco-rules/run-test.sh` | sensor health, 0 false positives, 5/5 rules | 0 unexpected |
| Alert pipeline | `bash tests/alert-pipeline/run-test.sh` | Falco → Sidekick → UI + Shuffle, anti-forgery, clock | 0 unexpected |
| Guardrails | `bash tests/response-guardrails/run-test.sh` | responder can / cannot | 25/25 |
| Response | `bash tests/response/run-test.sh` | collect / isolate / eradicate, approval, scope | 0 unexpected |
| Responder API | `bash tests/responder-api/run-test.sh` | auth, scope, 9 → 1 correlation | 18/18 |
| Playbook | `bash tests/playbook/run-test.sh` | dev auto, prod approve, prod reject, real alerts | 22/22 |

Notes: tests that simulate incidents start real responses (that's the point).
`tests/response` pauses automation itself. Each suite writes a log under
`tests/<suite>/results/` (git-ignored).

---

## 9. Operations runbook

**Golden rule:** every project command runs in **Ubuntu**:
```bash
wsl -d Ubuntu-24.04
cd /mnt/d/Kubernetes-IR
```
Ubuntu's prompt looks like `imene@DESKTOP-…:…$`. `PS …>` is PowerShell, and
`docker-desktop:…#` is Docker's VM (type `exit`).

### Daily start (Docker Desktop running)
```bash
bash falco/check-clock.sh --fix     # Falco timestamps (after sleep/reboot)
bash soar/shuffle/shuffle.sh up     # Shuffle (also restarts its UI)
bash response/service/run.sh        # responder + renew its 12 h token
bash apps/juice-shop/verify.sh      # dev + prod healthy
```

### Demo
```bash
bash demo/run-demo.sh
```

### UIs
| UI | How |
|---|---|
| Juice Shop | http://localhost:3030 (dev), http://localhost:3031 (prod) |
| Shuffle | http://localhost:3001 (admin account created by the student) |
| Falco / Sidekick UI | run `kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802` (keep it open), then http://localhost:2802; user `admin`, password = the part after `:` in `falco/secrets/ui-credentials.txt` |

### Useful commands
| Purpose | Command |
|---|---|
| Recent alerts | `kubectl -n falco logs ds/falco -c falco --since=10m \| python3 falco/show-alerts.py --k8s-only` |
| What the SOAR did | `python3 -I soar/shuffle/show_executions.py` |
| Pending prod decisions | `python3 -I soar/shuffle/approve.py list` |
| Approve / reject | `python3 -I soar/shuffle/approve.py decide <execution> approve\|reject --approver "<name>"` |
| Incident audit trail | `python3 -I response/show-actions.py <incident>` |
| Incident report | `python3 -I response/incident_report.py <incident>` |
| Verify evidence | `bash response/verify-evidence.sh evidence/<incident>/<ns>__<pod>.tar.gz` |
| Pause / resume automation | `bash response/automation.sh pause "<reason>"` / `resume` / `status` |

### Troubleshooting
| Symptom | Cause | Fix |
|---|---|---|
| `cd /mnt/d/...` not found, `Set-Location` error | You're in PowerShell | `wsl -d Ubuntu-24.04` first |
| `kubectl: not found` | `docker-desktop` shell | `exit`, then `wsl -d Ubuntu-24.04` |
| `[FAIL] Falco clock skew …` | PC slept | `bash falco/check-clock.sh --fix` (wait for the restart) |
| `no Falco event received from the canary` | Falco still restarting (slow ghcr download) | wait, check `kubectl -n falco get pods`, retry |
| `✘ responder credential valid` | 12 h token expired | `bash response/service/run.sh` |
| Shuffle: "Are you sure Shuffle is installed correctly?" | UI pointing at the old backend IP | `bash soar/shuffle/shuffle.sh restart-ui` |
| Falco UI "Network Error" | tunnel closed | re-run the port-forward and keep that window open |
| Playbook does nothing | automation paused | `bash response/automation.sh status` / `resume` |
| A prod decision stays waiting | nobody answered | `approve.py list` then `decide …` |

### Stop
```bash
bash soar/shuffle/shuffle.sh down    # keeps data
kind delete cluster --name k8s-ir    # removes the whole cluster (rebuild with the README)
```

---

## 10. File inventory

| Path | Role |
|---|---|
| `README.md` | Overview, build from scratch, tests, decision log |
| `.gitignore`, `.gitattributes` | Keep secrets, evidence and results out of Git; LF line endings for WSL |
| `cluster/kind-config.yaml` | One-node kind cluster, `127.0.0.1` port mappings 3030/3031 |
| `apps/juice-shop/base/*.yaml` | ServiceAccount (no token), hardened Deployment, NodePort Service, 4 NetworkPolicies (incl. quarantine) |
| `apps/juice-shop/overlays/{dev,prod}/` | Namespaces (PSA restricted, environment label), replicas, NodePorts |
| `apps/juice-shop/verify.sh` | Health check with retries (replicas, endpoints, HTTP, API) |
| `falco/values.yaml` | Falco + Sidekick + UI configuration |
| `falco/install.sh` | Validates rules in the running Falco, then Helm upgrade; injects the Shuffle webhook secrets; applies pipeline policies |
| `falco/rules/juice-shop-rules.yaml` | The 5 detection rules |
| `falco/rules/ir-canary-rules.yaml` | Canary heartbeat rule (NOTICE) |
| `falco/canary/falco-canary.yaml` | Canary pod in `ir-system` |
| `falco/check-clock.sh` | Falco clock-skew check (`--fix` restarts Falco) |
| `falco/create-ui-secret.sh` | Generates the UI password Secret |
| `falco/networkpolicies.yaml` | Only Falco → Sidekick → UI → Redis |
| `falco/show-alerts.py` | Readable / summarised alerts |
| `soar/shuffle/docker-compose.yml`, `.env` | Hardened Shuffle 2.3.0 (non-secret config) |
| `soar/shuffle/upstream-v2.3.0/` | Unmodified official files, for traceability |
| `soar/shuffle/shuffle.sh` | up / down / status / logs / restart-ui; generates secrets |
| `soar/shuffle/fetch-apps.sh`, `apps/` | The 2 vendored Shuffle apps, pinned, with SHA256SUMS |
| `soar/shuffle/shuffle_api.py` | Minimal Shuffle API client (key from file, never printed) |
| `soar/shuffle/workflows/provision_intake.py` | Step-4 intake workflow + authenticated webhook |
| `soar/shuffle/workflows/provision_playbook.py` | The playbook "IR - Juice Shop response" |
| `soar/shuffle/workflows/*.json` | Exports (secrets and identities redacted) |
| `soar/shuffle/approve.py` | List and answer prod approvals |
| `soar/shuffle/show_executions.py` | Per-node view of playbook executions |
| `simulation/simulate-incident.sh`, `build_report.py` | Harmless 5-step incident + detection report |
| `response/collect-evidence.sh` | Node-level evidence (phases `initial`, `pre-eradicate`) |
| `response/decode_sockets.py` | Decodes `/proc/net/*` socket tables |
| `response/verify-evidence.sh` | Verifies an evidence archive (outer + inner hashes) |
| `response/rbac/ir-responder.yaml` | Responder namespace, SA, Roles, RoleBindings |
| `response/rbac/admission-policy.yaml` | API-server guardrails for the responder |
| `response/make-kubeconfig.sh` | Applies RBAC + policy; writes a 12 h kubeconfig |
| `response/ir_respond.py` | collect / isolate / eradicate / status with safeguards |
| `response/service/` | ir-responder container (Dockerfile, HTTP API, run script) |
| `response/automation.sh` | Kill switch |
| `response/show-actions.py` | Audit trail viewer |
| `response/incident_report.py` | Incident report generator |
| `demo/run-demo.sh` | Interactive demonstration |
| `tests/*/run-test.sh` | The 8 test suites (+ `tests/netpol/*.yaml`) |
| `docs/00–12`, `docs/examples/` | Documentation |
| `evidence/` | Incident data and reports (git-ignored except `.gitkeep`) |

Git-ignored on purpose: `*/secrets/` (API key, tokens, kubeconfigs, UI and
DB passwords), `evidence/*`, `tests/*/results/`, `simulation/results/`,
`response/service/bin/` (kubectl copied from the node).

---

## 11. Limitations and future work

**Known limitations (documented, accepted for the lab):**
- **Docker socket** mounted in Shuffle and the responder: host-level power
  (docs/11, T1/T9).
- **Approvals are procedural:** links carry a secret, and the responder
  can't cryptographically verify an approval (T5).
- Evidence hashes stored in the evidence folder and in Shuffle, both on the
  same host (T6).
- Pod → own-node IP not filterable by kindnet (API server reachable, no
  token).
- Dev downtime of about 25 s during isolation (1 replica).
- No memory dump of processes (maps only).
- A remote code execution acting *inside* the Node.js process and writing to
  `frontend/dist/` evades the write rule (documented gap).
- kubectl 1.37 on the host versus cluster 1.34 (skew warning).
- The simulation uses `kubectl exec`; a real RCE wouldn't fire "Exec into
  container" (the other 4 rules still fire).
- Secrets on `/mnt/d` (DrvFs ignores `chmod`).

**Future work, by priority:**
1. Run the SOAR on a separate host/VM, or behind a filtering Docker API proxy.
2. Cryptographically verified (and two-person) approvals at the responder.
3. Ship evidence hashes off-host immediately (WORM / signed).
4. Cross-check alerts against the Falco sensor's own log before acting.
5. **Cache Falco's rules and container plugin locally**, so a Falco restart
   doesn't depend on a 10-minute ghcr.io download (no detection meanwhile).
6. SOAR / responder heartbeat watchdog; hash the playbook export to detect
   changes.
7. Shorter, auto-rotated tokens in a secret manager; digest-pinned,
   signature-verified images.
8. A minimal forensic DaemonSet instead of `docker exec`; mTLS Falco ↔
   Sidekick.
9. Rotate the Falco UI password (it was shared in a chat).

---

## 12. Glossary

| Term | Meaning in this project |
|---|---|
| **Kubernetes** | Runs and supervises containers; recreates pods automatically; Services route traffic; NetworkPolicies filter it; RBAC controls permissions |
| **kind** | "Kubernetes in Docker": a real cluster running in a Docker container on the PC |
| **Pod** | One running instance of Juice Shop (one container here) |
| **Deployment / ReplicaSet** | "Keep N pods running"; recreates a pod that disappears or is orphaned |
| **Service / endpoints** | The stable address that load-balances to ready pods |
| **Namespace** | A partition of the cluster (`juice-dev`, `juice-prod`, `falco`, `ir-system`) |
| **NetworkPolicy** | Firewall rules for pods; here: default deny, allows, quarantine |
| **CNI (kindnet)** | The cluster's network plugin, which enforces NetworkPolicies |
| **conntrack** | The kernel's table of open connections; flushing it cuts existing flows |
| **RBAC** | Kubernetes permissions (who may do which verb on which resource) |
| **ValidatingAdmissionPolicy (VAP)** | API-server rules (CEL) that check each request's *content*, e.g. "labels only" |
| **ServiceAccount / token** | An identity for software; here a 12 h token for the responder |
| **PSA restricted** | Pod Security Admission profile that rejects privileged or unsafe pods |
| **Falco** | Runtime security sensor reading syscalls via eBPF and matching rules |
| **eBPF / modern eBPF / BTF** | Safe kernel programs; "modern" uses BTF (kernel type info) so no kernel headers are needed |
| **Falcosidekick** | Forwards Falco alerts to outputs (UI, webhook) |
| **SOAR** | Security Orchestration, Automation and Response: runs playbooks on alerts |
| **Shuffle** | The SOAR used here (backend, frontend, Orborus runner, OpenSearch DB) |
| **Playbook / workflow** | The automated sequence: triage → collect → isolate → eradicate → verify |
| **User Input** | Shuffle's human approval step |
| **ir-responder** | Our service that performs the actions with limited rights |
| **Triage / correlation / claim** | Deciding whether an alert needs a response, and making sure one incident gets one response |
| **Quarantine / orphan / eradicate** | Network isolation label / removal from Service and ReplicaSet / deletion |
| **Evidence package** | The node-level snapshot, with manifest, hashes and custody log |
| **Chain of custody** | The record of who collected what, when, and how |
| **SHA-256** | Cryptographic fingerprint; any change produces a different value |
| **Overlay upperdir** | The container's writable layer = exactly the files it added or changed |
| **Idempotent** | Running an action twice has the same effect as once |
| **Kill switch** | `response/automation.sh pause`: stops automated actions, keeps recording |
| **Canary** | A dummy pod used only to test the sensor without triggering a response |
| **Clock skew** | Difference between Falco's timestamps and real time |

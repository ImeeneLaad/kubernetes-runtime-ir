# 03 — Runtime detection with Falco

**Date:** 2026-11-10. **Chart:** `falcosecurity/falco` 9.2.2, **Falco** 0.45.2,
**rules** `falco-rules:5` (digest `sha256:213c9bb2…`, signature verified by
falcoctl), **container plugin** 0.7.6.

Files: `falco/values.yaml`, `falco/install.sh`,
`falco/rules/juice-shop-rules.yaml`, `falco/show-alerts.py`,
`tests/falco-rules/run-test.sh`.

## 1. Can Falco see kernel events on Docker Desktop + WSL2 + kind?

**Yes, with the modern eBPF driver.**

| Requirement | This environment |
|---|---|
| Kernel module (kmod) | ❌ No headers for `6.6.114.1-microsoft-standard-WSL2`, so it can't be built |
| Modern eBPF (CO-RE) | ✅ Kernel ≥ 5.8, and `/sys/kernel/btf/vmlinux` is present |

Falco log: `Opening 'syscall' source with modern BPF probe.` with no error.
`driver.kind` is set explicitly to `modern_ebpf`, because `auto` could try
kmod.

**One kernel for everything.** WSL, Docker Desktop and the kind node all share
the same kernel, so Falco receives the syscalls of **every** container on the
machine, including the other local projects. Kubernetes metadata
(`k8s.ns.name`, `k8s.pod.name`) comes only from the kind node's containerd (CRI
socket), so events from outside kind carry none. All custom rules require a
Juice Shop namespace, which removes that noise by design.

`libpman: disabled BPF iterators (not running in the root PID namespace)` is
expected. Falco runs in the kind node's PID namespace, and process state falls
back to `/proc`.

## 2. Configuration choices (`falco/values.yaml`)

| Setting | Why |
|---|---|
| `driver.kind: modern_ebpf` | The only driver that works here |
| Only the `cri` engine, socket `/run/containerd/containerd.sock` | The kind node runs containerd and nothing else. Disabled engines can't be mis-detected |
| `collectors.kubernetes.enabled: false` | The container plugin already provides pod name, namespace and labels. No extra k8s-metacollector deployment |
| `falcoctl ... follow.enabled: false` | No silent weekly rule updates: the detection is reproducible |
| `json_output: true`, tags included | Machine-readable alerts for Falcosidekick and the SOAR (Step 4) |
| `priority: notice` | Drops informational output |

## 3. Default rules: verified

On a throwaway busybox pod, `Terminal shell in container` (T1059) and
`Read sensitive file untrusted` on `/etc/shadow` (T1555) fired, both with pod
and namespace metadata. Note: the shell rule needs a real TTY (`kubectl exec
-it`), and a non-interactive script needs `script -qec` to provide one.

**Why custom rules anyway?** Juice Shop is **distroless**: there's no shell,
and `node` isn't on `PATH`. The most common default rules (shell spawned,
package manager, etc.) could never fire on it. An attacker with remote code
execution would act **through the Node.js process**. So the rules below
describe what *this* application normally does, and alert on anything else.

## 4. Custom rules (`falco/rules/juice-shop-rules.yaml`)

All scoped by the macro `juice_shop_container` (namespaces `juice-dev` and
`juice-prod`, container `juice-shop`). All tagged `juice_shop` and
`ir_response` (for SOAR routing) plus MITRE ATT&CK.

| Rule | Priority | Detects | MITRE |
|---|---|---|---|
| Exec into container | WARNING | A process started through the runtime (`kubectl exec`) | T1609 |
| Process spawned by the application | CRITICAL | The app (`node`) spawning a child process, the typical RCE result | T1059 |
| Sensitive file read | ERROR | `/etc/shadow`, `/etc/passwd`, `/etc/group`, SA token paths, `/proc/*/environ` | T1552 |
| Outbound TCP connection | CRITICAL | Any outbound TCP (reverse shell, exfiltration, download) | T1071 |
| Write outside application data directories | ERROR | Dropped files, web shells, code tampering | T1505 |

A sixth, operational rule lives in `falco/rules/ir-canary-rules.yaml`:
**IR canary heartbeat** (NOTICE), which matches only the `falco-canary` pod
in `ir-system`. It's used by `falco/check-clock.sh` to measure the sensor
without touching a protected workload (see docs/04).

### False-positive tuning, based on observed data

Restarting the pods and using the app normally initially produced about 190
alerts. Every one of them happened at **container start**:

| Source | Exception, kept as narrow as possible |
|---|---|
| kind OCI hook `/kind/bin/mount-product-files.sh` (bash, jq, cp) runs in every new container | Excluded by its **exact command line** (macro `kind_oci_hook`). Lab-only: it doesn't exist on real clusters |
| `runc` reads `/etc/passwd` to resolve the container user | `proc.name startswith "runc"` |
| Juice Shop's startup customization writes `i18n/`, `frontend/dist/`, `.well-known/` | Allowed **only for PID 1** (the app). A child process (an attacker's tool) writing there still alerts |
| `validatePreconditions.js` fetches `https://www.alchemy.com/` (confirmed in the image source) | Allowed **only for PID 1, port 443, that domain** (`fd.sip.name`) |
| The LLM availability check on `localhost:11434` | Loopback excluded |

Result: **0 alerts** during restart and normal use (registration, search,
API, FTP listing).

### Known detection gaps (documented, accepted)

- A remote-code-execution flaw that runs **inside the Node.js process**
  (e.g. `eval`) and writes to `frontend/dist/` is not caught by the write rule,
  because it's indistinguishable from the app. Spawning a process, reading
  secrets or opening a connection is still caught.
- The exceptions match on names (`runc*`, the kind hook command line). An
  attacker who can rename a process could try to imitate them. The
  command-line match makes this harder.
- Exfiltration *to* `www.alchemy.com:443` from PID 1 would not alert.

## 5. Safe rule deployment

During development, a `#` comment inside a YAML folded block (`condition: >`)
became part of the condition. Falco refused the rules file and the DaemonSet
went into `CrashLoopBackOff`. **There was no detection at all** until the fix.

Lessons applied:
- `falco/install.sh` validates every custom rules file with `falco -V`
  **inside the running Falco pod before upgrading**. Tested: a broken file is
  rejected, the Helm revision doesn't change, and Falco keeps running.
- The rules test starts with a **sensor-health check**. Otherwise a dead Falco
  would make every "no false positive" check pass.

## 6. Test results (`bash tests/falco-rules/run-test.sh`): 0 unexpected

| Part | Result |
|---|---|
| 0. Falco ready, custom rules loaded | PASS |
| A. Restart dev+prod + normal use → 0 alerts | PASS |
| B. Each rule fires on a harmless trigger (print, `node -v`, read `/etc/passwd`, TCP to 1.1.1.1:443, write `/tmp`) | 5/5 PASS |

Viewing alerts:
```bash
kubectl -n falco logs ds/falco -c falco --since=10m | python3 falco/show-alerts.py --k8s-only
```

## 7. Related improvement: `apps/juice-shop/verify.sh`

The health check now retries for up to 60 s, and it also requires the API
(`/rest/admin/application-version`) to answer, not just the static page.
Right after a rollout the new pod is Ready a few seconds before routing and
the API are. A single check gave a false "unhealthy" result.

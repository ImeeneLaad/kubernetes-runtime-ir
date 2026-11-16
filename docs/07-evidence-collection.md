# 07 — Evidence collection and preservation

**Date:** 2026-11-10. Files: `response/collect-evidence.sh`,
`response/decode_sockets.py`, `response/verify-evidence.sh`.
Output: `evidence/<incident-id>/` (git-ignored).

```bash
bash response/collect-evidence.sh <namespace> <pod> <incident-id>
bash response/verify-evidence.sh evidence/<incident-id>/<namespace>__<pod>.tar.gz
```

## Principles

| Principle | Implementation |
|---|---|
| **Collect before acting.** Isolation and replacement change or destroy state | The collector is the first response action. Steps 7–8 call it before any label or deletion |
| **Don't touch the suspect container** | No `kubectl exec`, no debug container. Everything is read **from the node**: the container's `/proc`, its cgroup, its overlay *upperdir*. `exec` would modify the container, could trigger attacker traps, and fires our own Falco rule. A debug container permanently changes the pod spec |
| **Order of volatility** (RFC 3227) | 1 processes + sockets → 2 changed files → 3 image identity → 4 Kubernetes state → 5 logs and alerts |
| **Chain of custody** | `custody.log`: UTC time, description, exit code and exact command for every step, plus operator `user@host` and kube context. The archive record goes to `<ns>__<pod>.custody.log` beside the archive |
| **Integrity** | SHA-256 of every file (`SHA256SUMS`, `manifest.json`) and of the final `.tar.gz` (`.sha256`) |
| **Idempotent** | If `COMPLETE` exists for incident + pod, the collector exits 0 and does nothing. Needed because one incident triggers about 9 SOAR executions (Step 5) |
| **Time reference** | All times are the collector's UTC wall clock, recorded next to the Falco alert times, so sensor clock skew (Step 4 finding) is visible |

## Package contents

| Path | Source | Content |
|---|---|---|
| `volatile/cgroup-procs.txt` | node: container cgroup | Every PID of the container |
| `volatile/proc-<pid>.txt` | node: `/proc/<pid>` | cmdline, exe, cwd, status, **environ**, open fds, memory maps |
| `volatile/net-*.raw`, `connections.txt` | node: `/proc/<pid>/net/*` (pod netns) | All sockets, decoded |
| `filesystem/changed-files.txt` | node: overlay upperdir | Every added or modified file with mtime, owner, mode, size |
| `filesystem/upperdir.tar` | node: overlay upperdir | **The added/modified files themselves**: only the delta, not the 500 MB image |
| `container/crictl-inspect.json`, `image.txt` | containerd | Runtime spec, PID, **image digest** |
| `kubernetes/*` | API server | Pod (at start and at end), describe, events, NetworkPolicies, owners, container logs (+ previous) |
| `alerts/falco-alerts.jsonl` | Falco sensor log | Every alert for the pod still in the sensor's log |
| `custody.log`, `manifest.json`, `SHA256SUMS`, `COMPLETE` | collector | Custody and integrity |

## Results (simulated incident, `juice-dev`)

| Check | Result |
|---|---|
| Duration | about 6 s, 21 files, archive about 1 MB (6.5 MB tar of changes, compressed) |
| Process list | `/nodejs/bin/node /juice-shop/build/app.js` (PID 1 only: simulation commands had ended) |
| Network | **`10.244.0.25:41372 → 1.1.1.1:443 TIME_WAIT`**: the simulated outbound connection, still visible |
| Files | **`/tmp/<incident-id>.txt`**, content recovered from the archive. Files from the two **earlier** simulations were also present: the evidence shows how long this pod had been compromised |
| Alerts | 37 for the pod, including the 9 of this incident |
| Side effects of collection | **0 Falco alerts**, restartCount unchanged, no ephemeral container |
| Idempotency | Second run: "evidence already collected …", no new package |
| Integrity: genuine package | archive hash OK, 21/21 files OK |
| Tamper: archive bytes changed | **detected** (outer hash) |
| Tamper: file changed, archive repacked and outer hash recomputed | **detected** (inner `SHA256SUMS`) |

Bugs found during testing (fixed):
- `custody.log` failed verification: the archive line was appended *after*
  the file had been hashed. A file can't contain the hash of the archive that
  contains it, so that record now goes to a custody file beside the archive.
- The first tampering test was invalid: the copied archive was read-only, so
  the "tampering" write failed. Redone with a writable copy.

## Two snapshots per incident (added in Step 9)

The incident report's timeline showed that the first snapshot, triggered by
the **first** alert, finished **before** the last steps of the incident: the
outbound connection and the file drop happened 1–4 s later, and weren't in
it. In prod the gap is larger, because the pod keeps running until a human
approves. So there are now two snapshots:

| Phase | When | Package |
|---|---|---|
| `initial` | at the first alert, before any action | `<ns>__<pod>/` |
| `pre-eradicate` | right before the pod is deleted (after isolation) | `<ns>__<pod>__pre-eradicate/` |

`eradicate` **refuses to delete the pod if the final snapshot fails**, and
its hash is recorded in the audit trail. Verified: the final snapshot
contains the file dropped during the incident (`tests/playbook`).

## Limits and risks

- **Hashes stored with the evidence only detect accidental or naive
  changes.** Someone who controls `evidence/` can regenerate everything. The
  archive hash must also be recorded **out of band**: Step 8 sends it to the
  SOAR incident record. In production: WORM / object-lock storage, or a signed
  hash.
- **Privilege:** the collector needs node-level access (`docker exec` into the
  kind node). On a real cluster that's a privileged forensic DaemonSet: a
  high-value target that belongs in the SOAR-compromise analysis.
- **No memory image** of the processes. `/proc/<pid>/maps` is collected, not
  their contents. A full dump would need extra tooling (e.g. CRIU or gcore on
  the node) and is out of scope.
- `environ` can contain secrets. The evidence store must be protected like
  the system itself. On `/mnt/d` (DrvFs), `chmod a-w` has no effect.
- `kubernetes/events.txt` may be empty: the API server keeps events about
  1 hour.
- Falco alerts are read from the sensor pod's log, which **is lost when Falco
  restarts** (e.g. `check-clock.sh --fix`). Durable copies exist in the
  Sidekick UI (7-day TTL) and in the SOAR executions.

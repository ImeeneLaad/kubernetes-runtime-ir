# 04 — Alert forwarding with Falcosidekick

**Date:** 2026-11-10. Deployed as the Falco chart's sub-chart (9.2.2):
**Falcosidekick 2.35.1**, **Falcosidekick UI 2.2.0**, Redis Stack (UI storage).

Files: `falco/values.yaml` (section `falcosidekick`),
`falco/create-ui-secret.sh`, `falco/networkpolicies.yaml`,
`tests/alert-pipeline/run-test.sh`.

## Pipeline

```
Juice Shop pod ──syscalls──> Falco (eBPF, DaemonSet)
                               │ http_output (JSON), set automatically by the chart
                               ▼
                       Falcosidekick :2801  ── metrics: /metrics
                         │            │
                webui ───┘            └─── webhook ──> Shuffle (SOAR)   [next step]
                  ▼
        Falcosidekick UI :2802 ──> Redis :6379 (7-day TTL)
```

Falcosidekick decouples Falco from its consumers. Falco only knows one
endpoint, and outputs (UI, SOAR, chat, SIEM…) are added in Sidekick
without touching the sensor. Each output can have its own minimum priority.
Every event gets `cluster: k8s-ir` added (`customfields`).

## Webhook output to the SOAR

`falcosidekick.config.webhook`: `minimumpriority: warning` (all 5 Juice Shop
rules qualify, Notice noise doesn't). `address` and the `X-IR-Token`
`customHeaders` are injected by `falco/install.sh` from
`soar/shuffle/secrets/` with `--set-string`, so they are never in
`values.yaml` or git. They do end up in the Helm release record and the
Sidekick config Secret. Sidekick log: `Enabled Outputs: [Webhook WebUI]`.

## Finding: Falco timestamps drift when the VM is paused

During this step, every new alert was stamped **3807 s (about 63 min) too
early**. The host and node clocks were correct (identical), but Falco's
weren't. Falco computes event time as *boot time measured at Falco start* +
*kernel time since boot*. The Docker Desktop / WSL2 VM was paused during a
long wait (PC sleep), the kernel clock stopped while the wall clock was
resynced, and the reference went stale. A Falco restart fixed it
(skew +0.5 s).

**Second finding: the probe must not touch a protected workload.** The
first version of `check-clock.sh` generated its probe event with a harmless
`node -e` inside a Juice Shop **dev** pod. Once the automated playbook was
live, that probe fired the real "Exec into container" rule, and the playbook
correctly isolated and deleted the pod. **Every clock check cost a dev pod**
(two incidents during the demo preparation, with no simulation running). An
exception for the probe's marker in the Juice Shop rules would also be a
detection bypass for an attacker. Fix: a dedicated **Falco canary**
(`falco/canary/falco-canary.yaml`, a busybox pod in `ir-system`, outside the
IR perimeter) and its own rule `IR canary heartbeat` (**NOTICE**: below the
SOAR webhook threshold `warning`, not tagged `ir_response`). Verified with 3
consecutive checks: the dev pod was untouched, there were 0 new incidents,
0 new SOAR executions and 0 webhook posts.

Impact of the clock skew: the UI's "last N minutes" view hid new alerts. Worse, **incident
timelines and evidence would carry wrong times**. Controls:
- `bash falco/check-clock.sh [--fix]` measures the skew with a real event,
  fails above 5 s, and `--fix` restarts Falco.
- The pipeline test runs it first.
- The evidence collector (next steps) records its own UTC wall-clock time
  next to Falco's event time, so any skew is visible in the report.

## Security of the pipeline

| Risk | Control | Verified |
|---|---|---|
| **Alert forgery:** Sidekick accepts any JSON POST. A forged "Critical, juice-prod" alert would make the SOAR isolate or delete a healthy pod | NetworkPolicy: only `app.kubernetes.io/name=falco` pods may reach :2801 | A POST from another namespace times out |
| Default UI login `admin:admin` | Random 24-character password in Secret `falcosidekick-ui-creds`. Local copy in `falco/secrets/ui-credentials.txt` (git-ignored) | `admin:admin` → 401 |
| UI / Redis exposed to the cluster | NetworkPolicies: UI accepts Sidekick only, Redis accepts the UI only. Services are ClusterIP (no NodePort) | UI unreachable from another namespace |

**Residual risk** (for the SOAR-compromise analysis): the forgery control
relies on a **pod label**. Anyone allowed to create pods in the `falco`
namespace can create a pod labelled `app.kubernetes.io/name=falco` and send
alerts. So RBAC on the `falco` namespace is part of the trust chain. In
production: mTLS between Falco and Sidekick (`certs`, `tlsserver.deploy`), and
alert authentication towards the SOAR.

## Using the Web UI

```bash
kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802
# open http://localhost:2802 ; login = content of falco/secrets/ui-credentials.txt
```
`kubectl port-forward` enters the pod's network namespace through the
kubelet, so the NetworkPolicies don't block it. Access is controlled by
Kubernetes RBAC (`pods/portforward`).

## Test results (`bash tests/alert-pipeline/run-test.sh`): 0 unexpected

| Check | Result |
|---|---|
| Falco, Sidekick, UI and Redis ready; Falco `http_output` → `http://falco-falcosidekick:2801` | PASS |
| A real Juice Shop alert (with a unique marker) reaches the UI | PASS, ~2 s |
| Sidekick `outputs_total{destination="webui",status="ok"}` increases; 0 errors | PASS |
| `admin:admin` rejected, generated credential accepted | PASS |
| Forged alert from another namespace blocked; UI unreachable | PASS |
| Falco clock skew within 5 s | PASS (+0.5 s) |
| Real Juice Shop alert → Sidekick webhook → **Shuffle execution FINISHED/SUCCESS** | PASS, about 12 s |

Troubleshooting notes from this step:
- The metric name is `falcosecurity_falcosidekick_outputs_total`, on :2801 `/metrics`.
- The UI search (`/api/v1/events/search?since=5m&filter=…`) is RediSearch:
  a `-` in the filter is a NOT operator, so test markers must be
  alphanumeric.

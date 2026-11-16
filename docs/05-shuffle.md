# 05 — Shuffle SOAR deployment

**Date:** 2026-11-10. **Shuffle v2.3.0** (latest stable; release candidates
2.3.1-rc* not used). Images pinned to `ghcr.io/shuffle/*:2.3.0`, plus
`opensearchproject/opensearch:3.2.0`.

Files: `soar/shuffle/docker-compose.yml`, `soar/shuffle/.env` (non-secret),
`soar/shuffle/shuffle.sh`. The official files are kept unmodified in
`soar/shuffle/upstream-v2.3.0/` (sha256 compose `b613e692…`,
.env `81d89ec8…`). Secrets are in `soar/shuffle/secrets/` (git-ignored).

```bash
bash soar/shuffle/shuffle.sh up        # start (generates secrets on first run)
bash soar/shuffle/shuffle.sh status
bash soar/shuffle/shuffle.sh down      # stop, keep data
```
UI: http://localhost:3001. The admin account is created **by a person** on
first visit, so there are no default credentials in the config.

## Why outside the cluster

The SOAR is the component that *acts* on the cluster. Running it outside the
monitored environment means a compromised workload can't easily tamper with
its own responder. Shuffle also expects a Docker host for its workers.

## Hardening compared with the upstream compose

| Upstream | Change | Why |
|---|---|---|
| `:latest` images | `2.3.0` | Reproducibility |
| Ports on `0.0.0.0` | `127.0.0.1` | The lab also runs a vulnerable app. Nothing should be reachable from the LAN |
| OpenSearch `9200` published, default password `StrongShufflePassword321!` (public) | Not published; random password | The SOAR database holds workflows, credentials and execution data |
| `SHUFFLE_ENCRYPTION_MODIFIER` empty | Random 40 characters | Otherwise app credentials stored in Shuffle aren't properly encrypted |
| `shuffle-security` service (`build: .`) | Removed | Optional add-on that needs the source tree |
| 3 GB heap | 1 GB | Memory budget (other stacks share the Docker VM) |
| Bind mounts in the project folder | Docker named volumes | OpenSearch is slow and hits permission issues on the Windows drive |
| `TZ=Europe/Amsterdam` | `UTC` | Evidence timelines from Falco, Kubernetes and the SOAR must line up |

Verified: `docker port` shows only `127.0.0.1:3001`, `127.0.0.1:3443` and
`127.0.0.1:5001`. OpenSearch has no host port.

## Connection to the cluster

The kind node resolves DNS through Docker Desktop's host resolver
(`192.168.65.254`), not Docker's embedded DNS, so pods can't resolve
container names. `shuffle-backend` is therefore also attached to the `kind`
network at a **fixed IP `172.24.255.10`** (`SHUFFLE_KIND_IP`). From the kind
node, `http://172.24.255.10:5001/api/v1/_ah/health` returns 200.

The Juice Shop egress policy now excludes `172.24.0.0/16`:

| From a Juice Shop pod | Result |
|---|---|
| Shuffle backend `172.24.255.10:5001` | **blocked** ✅ |
| API server (node `172.24.0.2:6443`, or Service `10.96.0.1:443`) | **still reachable** ⚠️ |

**Finding:** traffic from a pod to its *own node's* IP is delivered locally
by the node. It never takes the forwarding path where kindnet enforces
NetworkPolicy, and the NetworkPolicy spec leaves pod→node traffic undefined.
It can't be closed with a NetworkPolicy here. It remains mitigated by
`automountServiceAccountToken: false` and RBAC (anonymous requests are only
allowed on health/version endpoints).

## Apps: vendored, pinned, minimal

On first start, Shuffle clones its whole app library
(`github.com/shuffle/python-apps`, about 200 apps). On this network GitHub
ran at **10–34 KB/s**, so the clone never finished, and the backend reported
0 apps. Instead:

- `soar/shuffle/fetch-apps.sh` downloads **only `http` 1.4.0 and
  `shuffle-tools` 1.2.0** at commit `4a3d7209…` into `soar/shuffle/apps/`
  (SHA256SUMS recorded). They're mounted **read-only** as the hotload folder.
- `SHUFFLE_APP_DOWNLOAD_LOCATION=` (empty) turns off the full clone.
- `SHUFFLE_USE_GCHR_OVERRIDE_FOR_AUTODEPLOY=false` makes the app runtime
  images (`frikky/shuffle:http_1.4.0`, `…:shuffle-tools_1.2.0`) come from
  Docker Hub, which is fast here.

Security benefit: 2 apps instead of about 200 means far less third-party code
runs inside an environment that has Docker access.

## Orborus (execution runner)

| Problem observed | Fix |
|---|---|
| `SHUFFLE_SWARM_CONFIG=run` (upstream) → "This node is not a swarm manager" | Removed. Workers run as plain containers |
| Orborus blocked while pulling the unpinned `tenzir/tenzir:main` (pipeline engine), never checking in | `SHUFFLE_SKIP_PIPELINES=true`, `SHUFFLE_PIPELINE_ENABLED=false` (names found in the Orborus binary) |
| "Orborus UUID mismatch" after the restart | Transient: the previous instance's leader lock expired after about 30 s |

## Workflow "IR - Falco alert intake"

Provisioned from code: `python3 -I soar/shuffle/workflows/provision_intake.py`
(idempotent, and the trigger id stays stable so the URL doesn't change).
Export with the token redacted: `soar/shuffle/workflows/ir-falco-intake.json`.

```
[Webhook falco_alert_webhook] --(X-IR-Token required)--> [record_falco_alert: Shuffle Tools repeat_back_to_me($exec)]
```

The webhook API format was taken from the Shuffle UI's own code
(`POST /api/v1/hooks/new {name,type:"webhook",id,workflow,start,environment,auth,…}`).
The `auth` field (`auth_headers` in the trigger) makes Shuffle **reject any
request without that header**:

| Request | Result |
|---|---|
| No `X-IR-Token` | `401 Bad authentication headers` |
| Wrong token | `401` |
| Correct token | `200` + execution, `FINISHED` in about 12–25 s |

Secrets (git-ignored, `soar/shuffle/secrets/`): `api-key.txt` (created by the
admin in the UI), `webhook-token.txt` and `webhook-url.txt` (generated).
Note: `chmod 600` has no effect on `/mnt/d` (DrvFs ignores Linux modes). On a
single-user lab machine this is acceptable; in production, secrets belong in
a secret manager.

The admin's API key was **not** extracted automatically. Reading a live
credential out of the browser session was blocked by the agent's
permission controls. The admin copied it into the file. This is the right
separation: the person who owns the account handles its credentials.

## Startup notes

- The first backend log lines show `connection refused` /
  `OpenSearch Security not initialized`. That's a startup race: the backend
  retries until OpenSearch is initialised (≈ 60 s), then reports GREEN.
- Pulling from ghcr.io was very slow on this connection (≈ 30 min). Docker
  Hub pulls were fast. That was a slow network path, not a Docker failure.

## Risks to carry into the SOAR-compromise analysis

1. **`/var/run/docker.sock` is mounted into `backend` and `orborus`.** Control
   of Shuffle means root on the Docker host. That includes the kind node
   container, and so the **whole cluster**, plus every other container on the
   machine. It's required by Shuffle's design (it starts worker and app
   containers).
2. Incoming alerts are authenticated by a shared-secret header
   (`X-IR-Token`, checked by Shuffle itself, verified above) plus the network
   path (only Falco can submit to Sidekick). Anyone who reads the token
   (Helm release values, the Sidekick Secret, `soar/shuffle/secrets/`) can
   forge SOAR input.
3. The SOAR's Kubernetes credential (next steps) must be least-privilege and
   scoped to the Juice Shop namespaces. It must not be cluster-admin.

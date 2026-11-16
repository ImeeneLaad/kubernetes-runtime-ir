# Incident report `inc0f5bd1b0f51ef9a2c989`

_Generated 2026-11-10 17:42:58.345Z by response/incident_report.py — times are UTC._

## Summary

| | |
|---|---|
| Target | `juice-prod/juice-shop-776c95cb48-hfsnl` (environment **prod**) |
| Opening alert | Juice Shop - Exec into container (Warning) |
| Alerts received by the SOAR | 9 (rules: Exec into container, Outbound TCP connection, Process spawned by the application, Sensitive file read, Write outside application data directories) |
| Process / user | `node -e /* sim2026111017381623742 */ console.log("hello")` / `<NA>` |
| Outcome | **contained and eradicated** |
| Human approval | `shuffle-userinput user=<shuffle-admin> time=1794332360 incident=inc0f5bd1b0f51ef9a2c989` |
| Safeguard refusals | 0 |

## Key metrics

| Metric | Value |
|---|---|
| First alert → evidence complete | 33.0 s |
| First alert → contained (isolated) | 88.9 s |
| First alert → recovered (compromised pod eradicated, service healthy) | 100.5 s |

For PROD, the containment time includes the wait for the human decision.

## Timeline

| Time (UTC) | Phase | Event |
|---|---|---|
| 2026-11-10 17:38:23.707Z | detection | Falco: **Juice Shop - Exec into container** (Warning) |
| 2026-11-10 17:38:26.988Z | detection | Falco: **Juice Shop - Exec into container** (Warning) |
| 2026-11-10 17:38:27.117Z | detection | Falco: **Juice Shop - Process spawned by the application** (Critical) |
| 2026-11-10 17:38:30.530Z | detection | Falco: **Juice Shop - Exec into container** (Warning) |
| 2026-11-10 17:38:30.580Z | detection | Falco: **Juice Shop - Sensitive file read** (Error) |
| 2026-11-10 17:38:33.527Z | detection | Falco: **Juice Shop - Exec into container** (Warning) |
| 2026-11-10 17:38:33.591Z | detection | Falco: **Juice Shop - Outbound TCP connection** (Critical) |
| 2026-11-10 17:38:37.220Z | detection | Falco: **Juice Shop - Exec into container** (Warning) |
| 2026-11-10 17:38:37.287Z | detection | Falco: **Juice Shop - Write outside application data directories** (Error) |
| 2026-11-10 17:38:44.733Z | evidence | evidence snapshot **initial** started |
| 2026-11-10 17:38:56.689Z | evidence | evidence snapshot **initial** finished (21 files) |
| 2026-11-10 17:39:00.913Z | response | `collect` → **done** |
| 2026-11-10 17:39:52.623Z | response | `isolate` → **done** (quarantine-label, orphan, conntrack-flush(19) — approval: `shuffle-userinput user=<shuffle-admin> time=1794332360 incident=inc0f5bd1b0f51ef9a2c989`) |
| 2026-11-10 17:39:53.261Z | evidence | evidence snapshot **pre-eradicate** started |
| 2026-11-10 17:40:00.487Z | evidence | evidence snapshot **pre-eradicate** finished (21 files) |
| 2026-11-10 17:40:04.189Z | response | `eradicate` → **done** (approval: `shuffle-userinput user=<shuffle-admin> time=1794332360 incident=inc0f5bd1b0f51ef9a2c989`) |

Falco event times come from the sensor. Evidence and response times come from the collector/responder wall clock. Sensor clock skew is checked by `falco/check-clock.sh` before simulations (see docs/04).

## Evidence

### Snapshot `initial`

- Package: `evidence/inc0f5bd1b0f51ef9a2c989/juice-prod__juice-shop-776c95cb48-hfsnl.tar.gz`
- Archive SHA-256: `d0424608610403c4346152c40dcb9f960694d4cf68fc2d257cd42bfd81914eb2` (also recorded in the SOAR execution: `collect` result)
- Collected 2026-11-10T17:38:44.733Z → 2026-11-10T17:38:56.689Z by `collect-evidence 1.0` from node `k8s-ir-control-plane`, container `914acf243952`, 21 files

Verification at report time:

```
[PASS] archive hash matches d0424608610403c4...
[PASS] all 21 files match SHA256SUMS
       incident=inc0f5bd1b0f51ef9a2c989 target=juice-prod/juice-shop-776c95cb48-hfsnl collected 2026-11-10T17:38:44.733Z -> 2026-11-10T17:38:56.689Z
```

Files written outside the application directories (filesystem delta):

```
2026-11-10T17:38:37.5022647590 65532:65532 644 26 ./tmp/sim2026111017381623742.txt
```

Network sockets at collection time:

```
proto  local                                         remote                                        state        uid inode
tcp    10.244.0.59:41172                             1.1.1.1:443                                   TIME_WAIT      0 0
tcp6   :::3000                                       :::0                                          LISTEN       65532 2750997
```

### Snapshot `pre-eradicate`

- Package: `evidence/inc0f5bd1b0f51ef9a2c989/juice-prod__juice-shop-776c95cb48-hfsnl__pre-eradicate.tar.gz`
- Archive SHA-256: `70792dba8816e3713e392723c52f948f153b618ea3817c019fcdcbb34e5ca27f`
- Collected 2026-11-10T17:39:53.261Z → 2026-11-10T17:40:00.487Z by `collect-evidence 1.0` from node `k8s-ir-control-plane`, container `914acf243952`, 21 files

Verification at report time:

```
[PASS] archive hash matches 70792dba8816e371...
[PASS] all 21 files match SHA256SUMS
       incident=inc0f5bd1b0f51ef9a2c989 target=juice-prod/juice-shop-776c95cb48-hfsnl collected 2026-11-10T17:39:53.261Z -> 2026-11-10T17:40:00.487Z
```

Files written outside the application directories (filesystem delta):

```
2026-11-10T17:38:37.5022647590 65532:65532 644 26 ./tmp/sim2026111017381623742.txt
```

Network sockets at collection time:

```
proto  local                                         remote                                        state        uid inode
tcp6   :::3000                                       :::0                                          LISTEN       65532 2750997
```


## Response actions (audit trail)

| Time (UTC) | Action | Result | Operator | Details |
|---|---|---|---|---|
| 2026-11-10T17:39:00.913Z | collect | done | root@6fd3bc81a739 | sha256 d0424608610403c4… |
| 2026-11-10T17:39:52.623Z | isolate | done | root@6fd3bc81a739 | quarantine-label, orphan, conntrack-flush(19) |
| 2026-11-10T17:40:04.189Z | eradicate | done | root@6fd3bc81a739 | final snapshot sha256 70792dba8816e371… |

## Recovery check (now)

```
== prod (namespace juice-prod, http://127.0.0.1:3031)
  replicas available : 2/2
  ready endpoints    : 10.244.0.52 10.244.0.65 
  GET /              : HTTP 200
  app version        : {"version":"20.3.0"}
  [PASS] prod healthy (attempt 1)
```


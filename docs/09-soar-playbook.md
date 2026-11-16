# 09 — SOAR playbook (Shuffle) and the ir-responder service

**Date:** 2026-11-10. Files: `response/service/` (Dockerfile, server.py,
run.sh), `soar/shuffle/workflows/provision_playbook.py`,
`soar/shuffle/approve.py`, `soar/shuffle/show_executions.py`.
Export (secrets redacted): `soar/shuffle/workflows/ir-juice-shop-playbook.json`.
Tests: `tests/responder-api/run-test.sh`, `tests/playbook/run-test.sh`.

```bash
bash response/service/run.sh                                   # build + start ir-responder
python3 -I soar/shuffle/workflows/provision_playbook.py        # (re)create the playbook
python3 -I soar/shuffle/show_executions.py                     # what the SOAR did
python3 -I soar/shuffle/approve.py list                        # PROD decisions waiting
python3 -I soar/shuffle/approve.py decide <execution> approve|reject --approver "<name>"
```

## Architecture

```
Falco --> Sidekick --(X-IR-Token)--> Shuffle playbook --(X-Responder-Token)--> ir-responder --> Kubernetes API
                                    (decisions,             (Shuffle network       (RBAC + admission policy)
                                     human approval)         only, no host port)  --> kind node (docker exec:
                                                                                       evidence, conntrack)
```

- **Shuffle decides**: branching, dev vs prod, human approval.
  **The responder acts**: it holds the short-lived ServiceAccount token and
  re-checks every safeguard.
- `ir-responder` is a container built from our own Dockerfile: official
  `python:3.12.14-slim` + Docker CLI from `docker:29.8.1-cli` + the kind
  node's own `kubectl` (v1.34.0, exact cluster version). No package manager
  runs during the build: Alpine/apt mirrors were 80 KB/s here, and the first
  build attempt hung for 11 minutes. The project is mounted read-only, and
  only `evidence/` is writable.

## Playbook "IR - Juice Shop response"

```
webhook ─► triage ─[decision startswith "respond-"]─► collect ─┬─[respond-dev  & collect ok]─► dev_isolate ─► dev_eradicate ─► dev_verify
 (token)   (correlate +                               (evidence │
            atomic claim)                              FIRST)   └─[respond-prod & collect ok]─► prod_approval (User Input) ─► prod_respond
duplicate / out-of-scope: stops after triage (alert still recorded)                              (human: approve / reject)    (isolate + eradicate,
                                                                                                                                run by the responder)
```

| Node | Calls | Purpose |
|---|---|---|
| `triage` | `POST /v1/triage {alert: $exec}` | Validates tags (`juice_shop`, `ir_response`), namespace and pod. Derives **one incident id per pod** (`inc` + sha256(ns/pod)). **Atomically claims** it (`O_EXCL` file). Returns a single string `decision`: `respond-dev`, `respond-prod`, `duplicate` or `out-of-scope` (string comparisons only, no boolean ambiguity in Shuffle conditions) |
| `collect` | `POST /v1/action collect` | Evidence first. Its result, **including the archive SHA-256, is stored in Shuffle**: the out-of-band record required by Step 6 |
| `dev_*` | isolate → eradicate → verify | Automatic in dev, each branch gated by `outcome == ok` |
| `prod_approval` | Shuffle **User Input** | Pauses the execution and shows the incident, pod, first alert and **evidence hash** |
| `prod_respond` | `POST /v1/respond-approved` | Passes `user=$prod_approval.click_info.user time=…`: the **authenticated Shuffle user** who answered |

## Correlation

One incident produces about 9 alerts and so about 9 executions (Step 5).
Verified: 9 concurrent triage calls for one pod → **exactly 1 claim**, the
same incident id for all, and all 9 alerts in
`evidence/<incident>/alerts-received.jsonl`. The responder also serialises
work per pod (a lock per namespace/pod).

## Findings while building the playbook

1. **Shuffle resume race after a User Input.** On approval, Shuffle resumes
   the paused execution with a new worker and stops the old one a few
   seconds later. An action the old worker had just started (`prod_isolate`,
   about 14 s) completed on the cluster, but its result was sent to the dead
   worker (`Max retries exceeded … /api/v1/streams`). The execution then hung,
   and eradication never ran. **Fix:** after approval, one fast call
   (`/v1/respond-approved`). The responder records the approval and runs
   isolate → eradicate itself, in the background, under the pod lock.
   Progress goes to the audit trail as usual.
2. **User Input `type: subflow` is a notification channel**, not an "on
   approve" hook. It's started when the question is asked and receives the
   question plus the continue/abort links (verified with a probe workflow).
3. **The approval links carry the execution's `authorization` secret.**
   Whoever holds a link can answer, without logging in. `click_info.user`
   records who was logged in when answering. `approve.py` answers with the
   admin's API key. Risk carried to the SOAR-compromise analysis.
4. `$exec_id` is not a Shuffle variable ("Failed finding 'exec_id'"). The
   approval reference uses `$prod_approval.click_info.*` instead.

## Test results

### Responder API (`tests/responder-api/run-test.sh`): 18/18

No host port; wrong or missing token → 401; out-of-scope alerts (missing
tag, unprotected namespace, invalid pod name) refused; unknown action → 400;
correlation 9 → 1; actions through the API (isolate refused before collect,
then collect → isolate → eradicate); dev healthy; custody log names the
responder container.

### Playbook with real Falco alerts (`tests/playbook/run-test.sh`)

**22/22**, final run 2026-11-10:

| Scenario | Checks |
|---|---|
| **A. dev, automatic** | Playbook ran triage → collect → isolate → eradicate → verify(healthy); **exactly 1 execution responded, 10 duplicates stopped after triage** and skipped collection; **the evidence hash stored in Shuffle matches the archive**; package verifies; pod eradicated; **pre-eradication snapshot taken, verifies and contains the file dropped during the incident**; dev healthy |
| **B. prod, approved** | Playbook paused at `prod_approval`; evidence complete **before** the decision; pod untouched while waiting; after approval, isolate + eradicate done; **75/75 user requests OK**; audit trail names the **authenticated Shuffle user**; pod eradicated; final snapshot OK; prod healthy |
| **C. prod, rejected** | Pod **not** quarantined and still serving; no isolate/eradicate in the audit trail; evidence kept |

### Automation kill switch

`bash response/automation.sh pause "<reason>"` / `resume` / `status`. While
paused, triage records every alert but returns `decision: paused`, so the
playbook does nothing. It was added because a component test
(`tests/response`) and the live playbook acted on the **same pod at the same
time**: the playbook correctly responded to the test's simulated alerts, and
deleted the pod during the test's idempotency check. Tests that drive the
responder by hand now pause automation for their duration.

## Operating notes

- For the demo, the PROD decision is made **by a person**: in the Shuffle UI
  (the waiting execution, question `prod_approval`) or with `approve.py`.
  Automated tests answer as `automated-test-harness` so they can't be mistaken
  for a human decision.
- A rejected prod incident leaves the pod running and untouched. Its evidence
  is kept, and handling it further is a human decision.
- Responder token: 12 h. `bash response/service/run.sh` renews it and
  restarts the service.

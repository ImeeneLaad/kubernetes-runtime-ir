# 01 — CNI NetworkPolicy validation

**Date:** 2026-11-10. **Cluster:** kind v0.30.0, node `kindest/node:v1.34.0`,
CNI `kindest/kindnetd:v20250512-df8de77b`, WSL2 kernel 6.6.114.1.
**Reproduce:** `bash tests/netpol/run-test.sh` (Ubuntu, project root).

## Question

The whole isolation step depends on NetworkPolicies being *enforced*. The
Kubernetes API accepts NetworkPolicy objects whether or not the CNI implements
them, so a policy that is never enforced fails silently. We therefore test
before relying on them.

## What kindnet uses

This kindnet build embeds the `kube-network-policies` controller (log:
`Starting controller name="kube-network-policies"`). It sends the **first
packet of each new connection** to an NFQUEUE, where it is checked against the
policies. Packets of a flow that is already open are accepted through
conntrack.

The log also shows
`reading nfqueue stats: open /proc/net/netfilter/nfnetlink_queue: no such file`.
That only affects the statistics reader. The tests below show that
enforcement works.

## Results

| Test | Check | Result |
|---|---|---|
| 0 | Baseline: pod↔pod HTTP, DNS | allowed ✅ |
| 1 | Namespace default-deny ingress | ingress blocked, DNS still OK, reversible ✅ |
| 2 | Quarantine label (`security.ir/quarantine=true`) with ingress+egress deny | in, out and DNS blocked; neighbour unaffected; reversible ✅ |
| 3 | Connection opened **before** quarantine | **survives** ⚠️ |
| 3b | Same, plus `conntrack -D -s/-d <podIP>` on the node | **cut** ✅ |
| 4 | Quarantine + another policy allowing ingress to the pod | **ingress still allowed** ⚠️ (spec behaviour) |

Unexpected results: **0**. Logs: `tests/netpol/results/`.

## Decision

**kindnet is kept.** It enforces ingress and egress NetworkPolicies on this
setup, so installing Calico would add a component without being needed. This
was a deliberate choice to avoid unnecessary tools.

## Consequences for the incident-response design

1. **Quarantine alone does not stop an attacker who is already connected**
   (for example, an open reverse shell). Isolation must also do one of these:
   - flush the pod's conntrack entries on its node (proven in Test 3b), or
   - terminate the pod.

   Flushing conntrack needs node-level privileges (`docker exec` on kind; on a
   real cluster, a privileged node agent). That privilege is itself a risk,
   and the SOAR-compromise analysis must cover it.
2. **NetworkPolicies are additive allow-lists**: there is no deny rule and no
   priority. Any policy that allows traffic to the application must exclude
   quarantined pods:
   ```yaml
   podSelector:
     matchExpressions:
       - { key: security.ir/quarantine, operator: DoesNotExist }
   ```
   Otherwise the quarantine is silently overridden (Test 4). An explicit deny
   with priority would need Calico `GlobalNetworkPolicy` or the
   AdminNetworkPolicy API. Neither is required if this rule is followed.
3. Packets that the quarantine silently drops leave TCP peers hanging (beta's
   listener stayed stuck during development). This is expected and harmless,
   but worth knowing when you interpret evidence.

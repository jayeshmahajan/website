---
layout: blog
title: 'Kubernetes v1.35: Numeric Toleration Operators for SLA-Aware Scheduling'
date: XXXX-XX-XX
draft: true
slug: kubernetes-v1-35-numeric-toleration-operators-sla-aware-scheduling
author: >
  Jayesh Mahajan

---

Kubernetes v1.35 introduces **Extended Toleration Operators for Threshold-Based Placement** as an alpha feature, enabling Pods to express scheduling preferences using numeric comparisons on taint values.

Instead of requiring exact matches, workloads can now specify thresholds like "only schedule on nodes with `sla > 980`" or "accept any node with `risk < 50`". This is especially valuable for clusters mixing on-demand and spot/preemptible instances, where operators need fine-grained control over which workloads run on which reliability tiers.

Platform teams can define numeric taint values (such as `sla=999` for premium nodes, `sla=950` for spot instances) representing reliability or risk scores. Workloads declare their tolerance thresholds, creating a clear policy model: critical services might require `sla > 980`, while batch jobs accept `sla > 0`. These numeric values represent **policy-defined reliability tiers**, not measured uptime metrics, and are typically assigned at the node pool or instance class level.

This feature is **alpha in v1.35** and requires the `TaintTolerationComparisonOperators` feature gate to be enabled on both the API server and scheduler. It is disabled by default and recommended for testing in non-production environments.

## The challenge: Expressing risk tolerance with existing tools

Production clusters often run a mix of node types: expensive but reliable on-demand instances alongside cost-effective spot or preemptible nodes. Operators need to ensure critical workloads stay on high-reliability nodes while allowing less critical jobs to utilize cheaper capacity.

Current approaches rely on node labels with affinity rules or taints with tolerations. Node affinity is "attractive"—Pods are drawn to matching nodes, but a misconfigured selector can inadvertently place workloads on inappropriate nodes. Taints provide a safer "repulsive" model where nodes reject Pods unless explicitly tolerated, but the existing `Equal` and `Exists` operators only support binary matching. You can't express "schedule only if SLA is above this threshold" or "avoid nodes with risk above this level."

Extended Toleration Operators solve this by introducing numeric comparison operators (`Gt`, `Lt`) that work with integer taint values. You define a single numeric dimension (like `sla` or `risk`) across your node pools, and workloads declare their minimum or maximum thresholds. This creates a straightforward policy framework where each Pod explicitly states its risk tolerance.

## How it works: Numeric comparison operators

The feature adds four new operator types to `core/v1.Toleration` that perform numeric comparisons when the taint value is an integer:

* `Gt` – tolerates taints where the numeric value is **greater than** the toleration's `value`
* `Lt` – tolerates taints where the numeric value is **less than** the toleration's `value`

These operators complement the existing `Equal` and `Exists` operators. Comparisons are performed numerically (not as strings), so `sla=100` is correctly greater than `sla=99`. All standard taint effects (`NoSchedule`, `PreferNoSchedule`, `NoExecute`) work with these operators, including eviction timing via `tolerationSeconds` for `NoExecute` taints.

Enabling the `TaintTolerationComparisonOperators` feature gate on your API server and scheduler activates the feature. Once enabled, you can use numeric taint values and the new operators in your Pod tolerations.

## Interpreting SLA scores: `sla=999` vs `sla=980`

The `sla` values used in examples—such as `sla=999` or `sla=980`—are **conventions you define**, not metrics that Kubernetes calculates automatically. They typically encode a platform-level view of **expected availability or failure probability** for a node pool over time, similar to how cloud providers publish SLAs for instance classes or zones.

For example, a platform team might agree on the following scale:

* `sla=999`: on-demand nodes in highly redundant configurations; minimal preemption and maintenance risk; used for critical workloads

* `sla=980`: slightly less redundant or more frequently maintained nodes; used for most standard services

* `sla=950` / `sla=900`: spot or preemptible nodes with higher preemption risk but significantly lower cost; used for batch and best-effort workloads

Importantly, these values are generally assigned at the **pool level** rather than per individual node. Even if a specific node has never failed, it still carries the SLA of its pool (for example, `sla=950` for a spot pool), because the score is about **expected behavior and risk** rather than historical uptime for that machine.

## Basic setup: Tainting nodes with SLA scores

Assume your cluster has three node pools: high-SLA on-demand, medium-SLA standard, and low-SLA spot.

You can taint them with SLA scores like this:

**High-SLA on-demand nodes**

```bash
kubectl taint nodes on-demand-1 sla=999:NoSchedule
kubectl taint nodes on-demand-2 sla=999:NoSchedule
```

**Medium-SLA nodes**

```bash
kubectl taint nodes standard-1 sla=980:NoSchedule
kubectl taint nodes standard-2 sla=980:NoSchedule
```

**Low-SLA (spot/preemptible) nodes**

```bash
kubectl taint nodes spot-1 sla=950:NoSchedule
kubectl taint nodes spot-2 sla=900:NoSchedule
```

All of these nodes now repel Pods by default due to the `NoSchedule` effect. Pods must explicitly tolerate `sla` using the new numeric operators to be scheduled onto these nodes, which reinforces a "safety by default" posture.

## Example: Critical workloads on only the highest-SLA nodes

A critical API or control-plane–adjacent component should only land on the most reliable on-demand nodes, tagged as `sla=999`.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: critical-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: critical-service
  template:
    metadata:
      labels:
        app: critical-service
    spec:
      tolerations:
      - key: "sla"
        operator: "Gt"
        value: "980"
        effect: "NoSchedule"
      containers:
      - name: app
        image: node:20-alpine
        command: ["node", "-e", "require('http').createServer((req,res)=>res.end('OK')).listen(8080)"]
```

Here, `operator: "Gt"` with `value: "980"` means "tolerate nodes whose `sla` is greater than 980." With the scale above, this matches `sla=999` but not 980, 950, or 900.

This simple rule provides a strong guarantee: even if you later introduce new mid-tier pools (for example, `sla=990`), the workload remains constrained to nodes whose SLA is strictly greater than 980, without needing manifest updates.

## Example: Standard workloads that can use multiple pools

A standard backend service might be allowed on both `sla=999` and `sla=980` pools, but should stay off spot nodes.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: standard-service
spec:
  replicas: 5
  selector:
    matchLabels:
      app: standard-service
  template:
    metadata:
      labels:
        app: standard-service
    spec:
      tolerations:
      - key: "sla"
        operator: "Gt"
        value: "940"
        effect: "NoSchedule"
      containers:
      - name: app
        image: nginx:1.25-alpine
```

With `sla > 940`, this Pod can run on nodes with `sla=980` and `sla=999`, while avoiding pools at 950 and 900. As you add or adjust pools, you only need to maintain the SLA scale; tolerations continue to express **intent** in terms of thresholds.

## Example: Best-effort workloads that soak up cheap capacity

Batch jobs or best-effort workloads can be more tolerant of risk, and you may want them to use any node, including the cheapest spot pools.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: best-effort-job
spec:
  template:
    spec:
      tolerations:
      - key: "sla"
        operator: "Gt"
        value: "0"
        effect: "NoSchedule"
      restartPolicy: Never
      containers:
      - name: worker
        image: busybox:1.36
        command: ["sh", "-c", "echo Processing batch job && sleep 30"]
```

Assuming all SLA scores are positive integers, `sla > 0` effectively tolerates all SLA-tainted nodes. This lets the scheduler place this job onto any pool, which helps the cluster efficiently utilize unused capacity while keeping critical workloads constrained to higher scores.

## Example: Evicting workloads when SLA degrades

You can combine numeric operators with `NoExecute` and `tolerationSeconds` to **evict Pods when a node's SLA score drops below what they tolerate**, enabling controlled failover based on risk changes.

Assume you run some component (an operator or external controller) that periodically updates taints based on health, provider signals, or local metrics:

**SLA score for a node degrades from 999 to 940**

```bash
kubectl taint nodes on-demand-1 sla=940:NoExecute --overwrite
```

A latency-sensitive application might use:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: latency-sensitive
spec:
  replicas: 2
  selector:
    matchLabels:
      app: latency-sensitive
  template:
    metadata:
      labels:
        app: latency-sensitive
    spec:
      tolerations:
      - key: "sla"
        operator: "Gt"
        value: "950"
        effect: "NoExecute"
        tolerationSeconds: 300
      containers:
      - name: app
        image: nginx:1.25-alpine
```

While the node has `sla=999`, the Pod's toleration (`sla > 950`) matches, and the Pod runs there. When the taint is updated to `sla=940:NoExecute`, the toleration no longer matches (`940` is not greater than 950), so the `NoExecute` taint triggers eviction after 300 seconds, and the scheduler moves the Pod to a node that still satisfies `sla > 950`.

This pattern supports **time-bounded, risk-aware migration** rather than immediate eviction at the first sign of trouble, giving you space for graceful degradation or controlled failover.

## How this compares to node affinity

Numeric toleration operators are not a replacement for node labels and affinity; they complement each other:

- Use **node labels and affinity** for structural attributes like region, zone, architecture, or presence of hardware accelerators.

- Use **taints and numeric tolerations** for **safety and risk dimensions**, such as SLA scores, preemption likelihood, or internal "risk tiers."

Taints keep risky nodes off-limits unless workloads explicitly opt in, while `NoExecute` taints can actively evict Pods when a node's risk profile changes. Numeric operators make these policies more expressive and easier to maintain, since one key and a numeric scale describe the entire spectrum of reliability classes.

## Prerequisites and rollout considerations

The Extended Toleration Operators feature is **alpha in Kubernetes v1.35**, guarded by the `TaintTolerationComparisonOperators` feature gate. It is implemented in the existing `TaintToleration` scheduler plugin, so once enabled, it applies to standard scheduling decisions without additional configuration.

Suggested rollout steps:

- Start in a non-production or staging cluster.

- Define a simple SLA scale (for example, `sla=999` for on-demand, `sla=950` for spot) and apply taints to your node pools.

- Update a small number of workloads to use numeric tolerations and validate scheduling and eviction behavior.

- Expand the model over time to include more granular tiers or additional numeric dimensions as your team becomes comfortable with the semantics.

## Community and feedback

Extended Toleration Operators emerged from work in the Kubernetes scheduling community focused on cost optimization and risk-aware workload placement. The feature addresses real operational needs in clusters that mix different node reliability tiers.

We're particularly interested in feedback from teams operating clusters with mixed on-demand and spot/preemptible nodes, as their experiences will help validate the SLA scoring patterns and operator usage shown in this post. If you're experimenting with this feature or have questions, we encourage you to participate in [SIG Scheduling](https://github.com/kubernetes/community/tree/master/sig-scheduling) discussions or share your experiences on the [KEP-5471](https://github.com/kubernetes/enhancements/issues/5471) issue. Your use cases and feedback will guide the feature's evolution from alpha toward beta and GA.

## How can I learn more?

- [KEP-5471: Extended Toleration Operators for Threshold-Based Placement](https://github.com/kubernetes/enhancements/issues/5471)
- [Taints and Tolerations](/docs/concepts/scheduling-eviction/taint-and-toleration/)
- [Kubernetes v1.35 Sneak Peek](/blog/2025/11/26/kubernetes-v1-35-sneak-peek/)
- [Kubernetes v1.35 feature overviews from ecosystem blogs]

## Acknowledgments

Special thanks to Heba (@helayoty) for writing the KEP and implementing this feature. Her vision and technical expertise brought Extended Toleration Operators from concept to reality.

We also extend our gratitude to the community members who reviewed the KEP, provided constructive feedback, and collaborated throughout the development process:

- Tim Hockin (@thockin)
- Daniel Mendizabal (@damendin)
- Dims (@dims)
- Liggitt (@liggitt)
- Maseho (@maseho)
- Domtha (@domtha)
- Sanjeev Posahatta (@sanposahio)

Your collaborative spirit and technical excellence continue to strengthen the Kubernetes community and the SIG Scheduling group.

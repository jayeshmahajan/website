---
layout: blog
title: 'Best Practices for Kubernetes Resource Quotas and Limit Ranges in Multi-Team Environments'
date: XXXX-XX-XX
draft: true
slug: kubernetes-resource-quotas-limit-ranges-multi-team-best-practices
author: >
  Jayesh Mahajan

---

As Kubernetes adoption grows, many organizations operate shared clusters serving multiple teams and applications. Without proper resource governance, these environments face critical challenges: one team's resource-hungry workload can starve others (the "noisy neighbor" problem), costs spiral unpredictably, and cluster stability becomes fragile. This post explores battle-tested patterns for implementing Resource Quotas and Limit Ranges that scale across your organization.

## The problem: Resource contention without governance

Imagine a scenario: your data science team launches a large batch processing job, consuming all available CPU and memory. Meanwhile, your customer-facing web services start timing out. This is the noisy neighbor problem—and it's preventable.

Without resource boundaries, you also face:

- **Unpredictable costs**: No visibility into per-team resource consumption
- **Unfair resource allocation**: Early teams monopolize resources
- **Cluster instability**: Unconstrained pods can trigger node failures
- **Complex troubleshooting**: Hard to attribute resource exhaustion to specific teams

## Understanding Resource Quotas and Limit Ranges

Before implementing practices, let's clarify these two complementary Kubernetes features:

**Resource Quotas** limit the aggregate resource consumption within a namespace:

- Total CPU/memory across all pods
- Number of pods, services, or persistent volumes
- Storage limits

**Limit Ranges** enforce per-pod resource constraints:

- Minimum and maximum CPU/memory per container
- Default requests and limits for containers without explicit specifications
- Storage size constraints

Together, they create a two-level governance model: cluster-level fairness through quotas, and pod-level safety through limit ranges.

## Best Practice 1: Design namespace strategy around teams

Each team should have dedicated namespaces, not shared ones. This provides:

- **Isolation**: Teams can't accidentally interfere with each other
- **Accountability**: Clear mapping of quotas to organizational units
- **Flexibility**: Different quota policies for different teams

Example structure:

```
namespaces/
├── team-platform/
├── team-data-science/
├── team-payments/
├── team-analytics/
└── team-platform-services/
```

For organizations with environment tiers (dev, staging, prod), add another level:

```
team-payments-dev/
team-payments-staging/
team-payments-prod/
```

## Best Practice 2: Right-size quotas based on actual needs

Quotas should reflect each team's legitimate requirements, not arbitrary numbers. Follow this process:

### Step 1: Audit current usage

Monitor your cluster for 2-4 weeks. Calculate:

- Peak CPU usage per team
- Average memory footprint
- Peak memory requirement
- Pod count volatility

```bash
kubectl top pods --all-namespaces
```

### Step 2: Calculate with buffer

Apply a multiplier based on growth expectations:

- **Mature, stable workloads**: 1.2x (20% buffer)
- **Growing teams**: 1.5x (50% buffer)
- **New products/teams**: 2.0x (100% buffer)

### Step 3: Establish SLOs

Teams should understand: "You have a quota of 100 CPU cores. If you hit 85%, we'll review with you."

## Best Practice 3: Implement resource requests and limits for all containers

Resource quotas only work when pods declare requests and limits. Without them:

- The scheduler can't make intelligent placement decisions
- Quotas don't prevent the noisy neighbor problem

**Minimum requirement**: Set requests for all containers

- Requests enable fair resource allocation
- The scheduler uses them for placement decisions

**Better practice**: Set both requests and limits

- Limits prevent a container from hogging resources
- QoS guarantees improve with guaranteed class (requests == limits)

Example configuration:

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

## Best Practice 4: Use Limit Ranges with sensible defaults

Limit Ranges prevent problematic edge cases. Always set defaults:

```yaml
apiVersion: v1
kind: LimitRange
metadata:
  name: team-payments-limits
  namespace: team-payments
spec:
  limits:
  # Default requests for containers without explicit requests
  - default:
      cpu: 200m
      memory: 256Mi
    defaultRequest:
      cpu: 100m
      memory: 128Mi
    type: Container
  # Per-pod limits
  - max:
      cpu: 4
      memory: 8Gi
    min:
      cpu: 50m
      memory: 64Mi
    type: Pod
```

This prevents:

- Unbounded containers that consume cluster resources
- Impossible requests that scheduler can't satisfy
- Unexpected quota exhaustion

## Best Practice 5: Monitor and iterate

Implementation isn't a one-time activity. Establish monitoring:

```bash
# View current quota usage
kubectl describe resourcequota -n team-payments
```

Create alerts:

- When a namespace hits 80% of its quota
- When a pod exceeds its request (potential memory leak)
- When a pod is throttled (CPU requests too low)

Review quarterly:

- Is any team consistently hitting quotas?
- Do quotas match actual business requirements?
- Are there underutilized quotas you can reclaim?

## Best Practice 6: Communicate boundaries to teams

The best quota system fails without organizational alignment:

- **Publish quota budgets**: Each team should know its CPU, memory, and pod count limits
- **Document request sizes**: Provide team-specific guidance on appropriate resource requests
- **Create runbooks**: What do teams do when they hit quotas?
- **Establish review process**: How do teams request quota increases?

Example team communication:

```
Team Payments - Resource Budget
├── CPU: 50 cores
├── Memory: 100Gi
├── Pod count: 100
└── Review process: Submit 2-week notice via #k8s-ops
```

## Best Practice 7: Use Network Policies alongside resource controls

Resource quotas address compute, but also consider:

- **Network bandwidth**: Pod Disruption Budgets for stability
- **Storage**: Persistent Volume quotas
- **API rate limits**: Prevent stampeding through kube-apiserver

## Practical example: Configuring for a team

Here's a complete, production-ready example for the `team-payments` namespace:

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-payments
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: team-payments-quota
  namespace: team-payments
spec:
  hard:
    requests.cpu: "50"
    requests.memory: "100Gi"
    limits.cpu: "100"
    limits.memory: "200Gi"
    pods: "100"
    services: "20"
    persistentvolumeclaims: "10"
  scopeSelector:
    matchExpressions:
    - operator: In
      scopeName: PriorityClass
      values: ["default", "high-priority"]
---
apiVersion: v1
kind: LimitRange
metadata:
  name: team-payments-limits
  namespace: team-payments
spec:
  limits:
  - default:
      cpu: 500m
      memory: 512Mi
    defaultRequest:
      cpu: 200m
      memory: 256Mi
    max:
      cpu: 4
      memory: 8Gi
    min:
      cpu: 50m
      memory: 64Mi
    type: Container
  - max:
      cpu: 8
      memory: 16Gi
    min:
      cpu: 100m
      memory: 128Mi
    type: Pod
```

## Common pitfalls to avoid

- **Setting quotas too low**: Causes constant contention and developer frustration
- **Ignoring actual growth**: Fixed quotas don't scale with teams
- **Inconsistent Limit Ranges**: Different policies per team confuse users
- **Not documenting defaults**: Teams won't understand why their pods get modified
- **Not monitoring quota usage**: You can't improve what you don't measure

## Conclusion

Resource Quotas and Limit Ranges are force multipliers for multi-team Kubernetes environments. They provide guardrails without micromanagement, when implemented thoughtfully. The key is treating them as a living system: measure, monitor, communicate, and iterate.

Your teams will deploy faster when they trust the cluster's resource boundaries. Your cluster operators will sleep better knowing rogue workloads can't destabilize production. And your CFO will appreciate the visibility into per-team resource consumption.

Start with one team, refine the process, and scale to your entire organization.

## How can I learn more?

- [Resource Quotas](/docs/concepts/policy/resource-quotas/)
- [Limit Ranges](/docs/concepts/policy/limit-range/)
- [Managing Resources for Containers](/docs/concepts/configuration/manage-resources-containers/)
- [Configure Quality of Service for Pods](/docs/tasks/configure-pod-container/quality-service-pod/)

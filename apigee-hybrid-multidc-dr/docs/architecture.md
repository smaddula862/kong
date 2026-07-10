# Architecture — Apigee hybrid, multi-DC (East/West) with DR on OpenShift + ArgoCD

## Goal

Run Apigee hybrid runtime in two OpenShift data centers — **East** (`us-east-1`)
and **West** (`us-west-1`) — as a single Apigee organization, so that the loss
of an entire region does not lose API traffic or runtime state. All of it is
delivered by **GitOps** (ArgoCD / OpenShift GitOps) from this repository.

```
                         ┌──────────────────────────────┐
                         │   Apigee control plane (GCP)  │
                         │   org: my-apigee-project      │
                         └───────────────┬──────────────┘
                                         │ MART / Apigee Connect
                 ┌───────────────────────┴───────────────────────┐
                 │                                                 │
        ┌────────▼─────────┐                            ┌──────────▼────────┐
        │  OCP East (hub?) │                            │     OCP West      │
        │  ns: apigee      │                            │   ns: apigee      │
        │  DC: dc-east      │   Cassandra replication    │   DC: dc-west     │
        │  synchronizer=ACT │ <========================> │ synchronizer=STBY │
        │  ingress VIP (act)│   NetworkTopologyStrategy  │ ingress VIP (stby)│
        └────────┬─────────┘   {dc-east:3, dc-west:3}    └──────────┬────────┘
                 │                                                   │
                 └─────────────────► GSLB / weighted DNS ◄───────────┘
                             api.example.com  (single hostname)
                                         ▲
                                     API clients
```

## GitOps topology

- **Hub cluster** runs OpenShift GitOps (ArgoCD) in `openshift-gitops`.
- Each data center is registered as an ArgoCD **cluster** secret labeled
  `apigee.dc: east|west` and `apigee.role: primary|standby`
  (`bootstrap/argocd/cluster-secrets.example.yaml`).
- A single **app-of-apps** (`root-app.yaml`) pulls in:
  1. the `apigee-hybrid` **AppProject** (guardrails: allowed repos/dests),
  2. the **OpenShift prerequisites** ApplicationSet (namespaces, SCC, priority
     classes) — sync wave `-10`,
  3. the **Apigee hybrid** ApplicationSet — a matrix of `datacenter × chart`.

The matrix generator emits `2 DCs × 8 charts = 16` Applications named
`apigee-east-*` / `apigee-west-*`. ArgoCD **sync waves** enforce the required
install order (operator → datastore → telemetry/redis → ingress → org → env →
virtualhost).

## Why one Apigee org across two regions

Apigee hybrid's runtime state (KMS keys, KVMs, quota buckets, OAuth tokens,
deployed proxy bundles, developer/app data cache) lives in **Cassandra**. By
running a single Cassandra ring stretched across both regions
(`clusterName: apigee-cassandra`, two datacenters `dc-east`/`dc-west`) with
`NetworkTopologyStrategy {dc-east:3, dc-west:3}`, every region holds a full,
continuously-replicated copy. That is what makes the second region a hot
standby rather than a cold rebuild.

## Traffic model

- Both regions expose an ingress `LoadBalancer` (`api-east.example.com`,
  `api-west.example.com`).
- A **global DNS / GSLB** publishes the single client-facing hostname
  `api.example.com` and points it at the regional VIPs with weights:
  - Steady state: East weight high (active), West weight low/zero (standby) →
    **active/standby**. Set both weights equal for **active/active**.
- Failover = shift DNS/GSLB weight to West. Clients keep using the same
  hostname; no client-side change.

## Component / DR roles summary

| Component            | Scope        | Replicated cross-DC? | DR behavior                              |
|----------------------|--------------|----------------------|------------------------------------------|
| apigee-operator      | per-cluster  | n/a                  | Independent per region                   |
| apigee-datastore     | **stretched**| **yes (Cassandra)**  | Full copy in each region                 |
| apigee-telemetry     | per-cluster  | ships to GCP         | Independent                              |
| apigee-redis         | per-cluster  | no (ephemeral cache) | Rebuilt on failover                      |
| apigee-ingress-mgr   | per-cluster  | n/a                  | Regional VIP behind GSLB                 |
| apigee-org           | per-cluster  | via Cassandra        | MART/Connect active in both              |
| apigee-env           | per-cluster  | via Cassandra        | Synchronizer active=East, standby=West   |
| apigee-virtualhost   | per-cluster  | n/a                  | Same hostname/cert in both regions       |

See `dr-runbook.md` for the operational procedures (bring-up, add second
region, failover, failback) and `cassandra-multiregion.md` for the datastore
details.

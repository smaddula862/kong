# Apigee hybrid — Multi-DC (East/West) with DR, on OpenShift via ArgoCD

GitOps implementation that deploys **Apigee hybrid** runtime across two
OpenShift data centers — **East** (`us-east-1`) and **West** (`us-west-1`) — as
a single Apigee organization with cross-region **Cassandra replication** for
**disaster recovery**. Everything is declarative and driven by **ArgoCD /
Red Hat OpenShift GitOps**.

```
apigee-hybrid-multidc-dr/
├── README.md                     ← you are here
├── docs/
│   ├── architecture.md           ← topology, traffic model, component/DR roles
│   ├── cassandra-multiregion.md  ← the DR backbone: one ring, two DCs
│   ├── dr-runbook.md             ← bring-up, failover, failback, restore
│   └── openshift-prerequisites.md
├── bootstrap/argocd/
│   ├── root-app.yaml                    ← app-of-apps entrypoint
│   ├── appproject.yaml                  ← AppProject guardrails
│   ├── appset-openshift-prereqs.yaml    ← ns / SCC / priorityclasses per DC
│   ├── appset-apigee-hybrid.yaml        ← matrix: DC × chart, with sync waves
│   └── cluster-secrets.example.yaml     ← how East/West clusters are registered
├── openshift/                    ← prereqs synced into each DC (wave -10)
│   ├── namespaces/  (namespaces + priorityclasses)
│   └── scc/         (apigee-hybrid SCC + bindings)
├── clusters/
│   ├── common/<chart>/values.yaml   ← shared Helm values (identity)
│   ├── east/<chart>/values.yaml     ← East overrides (seed region, active)
│   └── west/<chart>/values.yaml     ← West overrides (joins ring, standby)
└── scripts/validate.sh           ← offline YAML / completeness check
```

## How it works (30-second version)

1. One **app-of-apps** (`bootstrap/argocd/root-app.yaml`) is applied to the hub
   ArgoCD.
2. It installs the **AppProject** + two **ApplicationSets**.
3. The prereqs ApplicationSet lays down namespaces, an OpenShift **SCC**, and
   priority classes in **both** clusters.
4. The Apigee ApplicationSet is a **matrix** of `2 data centers × 8 Apigee Helm
   charts = 16 Applications`. **Sync waves** enforce the required install order
   (operator → datastore → telemetry/redis → ingress → org → env → virtualhost).
5. Each Application is **multi-source**: the chart comes from Apigee's OCI
   registry; the values come from this repo (`common` + per-DC override).
6. **Cassandra** is stretched across both regions as one ring
   (`dc-east` + `dc-west`, RF 3 each) → every region holds a full copy of
   runtime state. That is the DR guarantee.
7. A single hostname `api.example.com` is fronted by **GSLB/weighted DNS** over
   the two regional ingress VIPs. Failover = shift the weight; clients don't
   change anything.

## Quick start

```bash
# 0. Prereqs: OpenShift GitOps operator on the hub; both DC clusters reachable.
#    Provision non-git secrets (Cassandra auth/TLS, GCP SA keys, TLS cert).
#    See docs/openshift-prerequisites.md.

# 1. Register the two data-center clusters with ArgoCD (labels apigee.dc / role)
#    Start from bootstrap/argocd/cluster-secrets.example.yaml (do NOT commit tokens).

# 2. Point the manifests at your environment: replace my-apigee-project,
#    api.example.com, storageClass, seed host, registry, etc. (see below).

# 3. Deploy everything:
oc apply -f apigee-hybrid-multidc-dr/bootstrap/argocd/root-app.yaml

# 4. Bring up East, verify the Cassandra ring, then let West join.
#    Follow docs/dr-runbook.md §1 and docs/cassandra-multiregion.md.

# offline sanity check of the manifests:
bash apigee-hybrid-multidc-dr/scripts/validate.sh
```

## What you must customize

These are placeholders used consistently across the tree:

| Placeholder                                   | Meaning                                  |
|-----------------------------------------------|------------------------------------------|
| `my-apigee-project`                           | GCP project / Apigee org name            |
| `api.example.com`, `api-east/west.example.com`| Public + regional hostnames              |
| `https://api.east/west.ocp.example.com:6443`  | OpenShift API server URLs                |
| `us-docker.pkg.dev/apigee-release/apigee-hybrid-helm-charts` | Chart registry (mirror if egress-restricted) |
| `1.14.1`                                       | Apigee hybrid chart version              |
| `ocs-storagecluster-ceph-rbd`                 | StorageClass                             |
| `cassandra-east-seed...`                      | West→East Cassandra seed host            |
| `claude/apigee-hybrid-multidc-dr-vqwa1u`      | git branch ArgoCD tracks                 |

## Disaster recovery at a glance

- **Steady state:** East active, West hot standby; Cassandra replicates both
  ways (RPO ≈ seconds).
- **East fails:** shift GSLB to West + promote West synchronizer → serving in
  minutes (RTO ≈ 5–15 min). West already has all data.
- **East returns:** repair/rebuild Cassandra, restore roles, shift traffic back.
- **Total loss / corruption:** restore from scheduled Cassandra backups.

Full procedures: [`docs/dr-runbook.md`](docs/dr-runbook.md).

> These manifests are a production-shaped **reference/scaffold**. Validate chart
> versions, registry paths and value keys against the exact Apigee hybrid
> release you deploy, and wire real secrets via Sealed/External Secrets before
> using in production.

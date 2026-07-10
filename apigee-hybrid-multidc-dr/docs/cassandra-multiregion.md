# Cassandra multi-region setup (the DR backbone)

Apigee hybrid stores all durable runtime state in Cassandra. Cross-region DR is
achieved by stretching **one** Cassandra cluster over both OpenShift clusters,
with each region as its own logical Cassandra datacenter.

| Region | Cassandra DC | Nodes (RF) | Role         | Seed                         |
|--------|--------------|-----------|--------------|------------------------------|
| East   | `dc-east`    | 3         | seed region  | self-seeds                   |
| West   | `dc-west`    | 3         | joins East   | `multiRegionSeedHost` → East |

Replication strategy after both regions are up:

```
NetworkTopologyStrategy: { dc-east: 3, dc-west: 3 }
```

Every keyspace write is acknowledged locally (LOCAL_QUORUM) and asynchronously
replicated to the peer DC. If a region is lost, the survivor already has a
complete, consistent-enough copy to serve traffic.

## Network prerequisites

The two regions' Cassandra pods must reach each other on the storage/gossip
ports across the inter-DC link (VPN / private interconnect / peered VPC):

| Port | Purpose                        |
|------|--------------------------------|
| 7001 | TLS internode (gossip/stream)  |
| 7199 | JMX (repair/rebuild tooling)   |
| 9042 | CQL native (client)            |

Internode TLS is **mandatory** here because gossip crosses regions — see the
`cassandra.ssl*` keys in `clusters/common/apigee-datastore/values.yaml`.

The West region reaches an East seed via
`cassandra.multiRegionSeedHost`
(`clusters/west/apigee-datastore/values.yaml`). Point it at a stable East seed
address reachable over the interconnect (a seed pod IP, or an East Cassandra
seed `Service` exposed privately).

## Bring-up order (must be sequential)

1. **East first.** ArgoCD syncs `apigee-east-apigee-datastore`; East self-seeds
   `dc-east`. Confirm ring is healthy:
   ```
   kubectl exec -n apigee apigee-cassandra-default-0 -- nodetool status
   # all dc-east nodes UN (Up/Normal)
   ```
2. **West second.** ArgoCD syncs `apigee-west-apigee-datastore`; West joins via
   `multiRegionSeedHost`. Nodes appear as `dc-west`, initially `UJ` (joining).
3. **Expand replication + rebuild.** Once West nodes are `UN`, expand the Apigee
   keyspaces to include `dc-west` and stream data into West:
   ```
   # run against a West node
   nodetool rebuild -- dc-east
   ```
   Apigee's datastore chart provides a job/hook for this; if running manually,
   follow Apigee's "expand hybrid to multiple regions" procedure for the exact
   keyspace list (kms, kvm, quota, cache, perses, ...).

> Ordering is why the West datastore Application must not sync before East is
> healthy. The ArgoCD sync waves order charts **within** a cluster; cross-cluster
> ordering (East ring healthy before West joins) is enforced operationally — do
> the initial East bring-up, verify `nodetool status`, then enable/sync West.

## Verifying replication

```
# From an East node — both DCs should be listed and Up/Normal:
nodetool status
# Datacenter: dc-east   ... UN x3
# Datacenter: dc-west   ... UN x3

# Confirm a keyspace replicates to both DCs:
cqlsh> DESCRIBE KEYSPACE kms;
#   ... WITH replication = {'class':'NetworkTopologyStrategy','dc-east':'3','dc-west':'3'}
```

## Backups

In addition to live replication, scheduled backups to per-region object storage
(`cassandra.backup` in common values) provide point-in-time recovery for the
"both regions corrupted / bad data written" case that replication cannot help
with. Restore procedure is in `dr-runbook.md`.

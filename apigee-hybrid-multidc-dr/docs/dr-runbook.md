# DR runbook — Apigee hybrid East/West

Roles in steady state: **East = active/primary**, **West = standby**. Cassandra
replicates both ways, so West is a *hot* standby.

Targets (tune to your SLA):
- **RTO** (time to serve from West after East loss): ~5–15 min (DNS/GSLB shift +
  synchronizer promotion).
- **RPO** (data loss): near-zero for Cassandra-backed state (async replication
  lag, typically seconds); Redis quota counters reset (acceptable by design).

---

## 1. Initial multi-region bring-up

1. Register both clusters as ArgoCD cluster secrets (labels `apigee.dc`,
   `apigee.role`) — `bootstrap/argocd/cluster-secrets.example.yaml`.
2. Provision the non-git secrets in **both** clusters (never in git): Cassandra
   auth, Cassandra internode TLS, Apigee GCP service-account keys/workload
   identity, `apigee-prod-tls`. Use Sealed Secrets / External Secrets.
3. Apply the app-of-apps:
   ```
   oc apply -f apigee-hybrid-multidc-dr/bootstrap/argocd/root-app.yaml
   ```
4. Let ArgoCD converge **East** (prereqs → operator → datastore → ...). Verify
   East Cassandra ring is healthy before West joins (see below).
5. Bring up **West**; it joins East's ring via `multiRegionSeedHost`. Expand
   keyspace replication and `nodetool rebuild dc-east` on West nodes
   (`cassandra-multiregion.md`).

Verify end-to-end:
```
# both DCs Up/Normal
oc -n apigee exec apigee-cassandra-default-0 -- nodetool status
# proxy responds from each regional VIP
curl -H 'Host: api.example.com' https://api-east.example.com/healthz
curl -H 'Host: api.example.com' https://api-west.example.com/healthz
```

---

## 2. Failover: East is down → serve from West

Trigger: East region/cluster unreachable or degraded.

1. **Shift traffic.** Update the global DNS/GSLB record `api.example.com` to
   send all weight to the **West** VIP (`api-west.example.com`). This alone
   restores client traffic — West already runs the full runtime.
2. **Promote West synchronizer to active** so control-plane changes keep
   syncing:
   ```
   # flip the standby -> active role for West and let ArgoCD apply it
   git commit: clusters/west/apigee-env/values.yaml  synchronizerRole: active
   # (and, if East is truly gone, East -> standby to avoid split-brain)
   ```
   ArgoCD self-heals West to the new desired state.
3. **Cassandra.** No action needed to *read/write* — West's `dc-west` replicas
   serve LOCAL_QUORUM on their own. Do **not** decommission `dc-east` yet; you
   want it back.
4. **Capacity.** West may need to scale runtime/ingress to carry 100% traffic —
   bump `replicaCountMax` in `clusters/west/*` and commit.

Announce: West is now primary.

---

## 3. Failback: East recovered → return to East-primary

1. **Rejoin East Cassandra.** Bring East cluster back; ArgoCD re-syncs the East
   datastore. If East nodes were down < `max_hint_window`, hints replay
   automatically. Otherwise run repair to reconcile:
   ```
   # on East nodes, pull any missed data from West
   nodetool rebuild -- dc-west     # only if East data was lost/wiped
   nodetool repair -pr             # otherwise, anti-entropy repair
   ```
   Confirm `nodetool status` shows all `dc-east` + `dc-west` nodes `UN`.
2. **Restore roles.** Commit East `synchronizerRole: active`, West
   `synchronizerRole: standby`.
3. **Shift traffic back** by re-weighting DNS/GSLB to East (do it gradually if
   you want to bake East first).
4. Scale West runtime back down to standby footprint.

---

## 4. Full region rebuild (East wiped entirely)

If East is rebuilt from scratch (new cluster, empty storage):

1. Re-register the East ArgoCD cluster secret; ArgoCD redeploys prereqs +
   charts.
2. East Cassandra comes up **empty** — treat it like the "second region" join:
   set East's datastore to seed from a **West** node
   (`multiRegionSeedHost` → West), then `nodetool rebuild dc-west` on East to
   re-hydrate a full copy from the survivor.
3. Once East is `UN` and rebuilt, revert the seed override and proceed with
   failback (section 3).

---

## 5. Both regions lost / data corruption — restore from backup

Replication cannot undo bad data written everywhere. Use the scheduled
Cassandra backups (`cassandra.backup`, per-region bucket):

1. Stand up one region's Cassandra.
2. Run the Apigee `apigee-cassandra-restore` job against the chosen backup
   snapshot (bucket + snapshot timestamp).
3. Verify keyspaces, then bring up the second region as a fresh join and
   rebuild from the restored region.

---

## Quick reference — where the knobs live

| Action                         | File(s) (committed → ArgoCD applies)                          |
|--------------------------------|--------------------------------------------------------------|
| Promote/demote synchronizer    | `clusters/<dc>/apigee-env/values.yaml` (`synchronizerRole`)  |
| West joins East ring           | `clusters/west/apigee-datastore/values.yaml` (`multiRegionSeedHost`) |
| Scale a region's runtime       | `clusters/<dc>/apigee-env/values.yaml` (`replicaCountMax`)   |
| Ingress LB / DNS weight hints  | `clusters/<dc>/apigee-ingress-manager/values.yaml`           |
| Backup schedule/bucket         | `clusters/common/apigee-datastore/values.yaml`               |

Traffic weighting itself lives in your GSLB/DNS provider, not in this repo —
reference it from your DNS-as-code pipeline.

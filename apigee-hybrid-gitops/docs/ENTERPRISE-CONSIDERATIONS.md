# Enterprise / restricted-environment design

This package assumes a locked-down OpenShift platform. Below is how each common
enterprise restriction is handled so that **everything ships through Git + Argo CD**.

## 1. No cluster-admin for app teams — scoped Argo CD AppProject

`bootstrap/argocd-appproject.yaml` defines an `apigee-hybrid` AppProject that:

- whitelists **only** this Git repo and the Apigee OCI Helm registry as sources;
- whitelists **only** the destination namespaces (`apigee`, `apigee-system`,
  `cert-manager`) plus the cluster scope needed for CRDs/SCCs;
- restricts which cluster-scoped resources may be created (CRDs, SCCs,
  ClusterRoles/Bindings) via `clusterResourceWhitelist`.

Argo CD runs with its own service account; humans never need cluster-admin.

## 2. Private image registry mirror (air-gapped / no public pulls)

Restricted clusters cannot pull from `gcr.io` / `us-docker.pkg.dev`. Mirror the
Apigee images into your internal registry and point Apigee at it with the **`hub`**
key in `overrides.yaml`:

```yaml
hub: "registry.internal.example.com/apigee"   # all component images resolve under here
imagePullSecrets:
  - name: apigee-registry-pull
```

The Helm **charts** themselves are also OCI artifacts; either allow Argo CD egress
to `us-docker.pkg.dev` for the chart pull, or mirror the charts into your registry
and change `repoURL` in each `apps/*.yaml`.

## 3. Egress allow-list (control-plane connectivity)

The runtime and synchronizer must reach the Apigee control plane even in a
restricted network. Allow-list at minimum:

```
*.googleapis.com:443
apigee.googleapis.com:443
apigeeconnect.googleapis.com:443
*.pkg.dev:443            # only if pulling charts/images directly
oauth2.googleapis.com:443
```

Add these to your egress firewall / `EgressNetworkPolicy` (OpenShift SDN) or
`AdminNetworkPolicy`. If a forward proxy is mandatory, set `HTTPS_PROXY` on the
Apigee components via `overrides.yaml` (`ao`, `mart`, `runtime`, `synchronizer`
`env`/proxy settings).

## 4. OpenShift SecurityContextConstraints (least privilege)

Apigee does **not** need `privileged` or global `anyuid`. `base/scc/` defines a
purpose-built `apigee-scc` and binds it **only** to the Apigee service accounts in
the `apigee`/`apigee-system` namespaces. It allows the specific `fsGroup`/`runAsUser`
ranges the Cassandra/telemetry images require and nothing else. This keeps the rest
of the cluster on the default `restricted-v2` SCC.

## 5. Secrets never in Git

SA JSON keys, Cassandra passwords, and TLS material are delivered by one of:

- **Sealed Secrets** — encrypted `SealedSecret` CRs *are* committed; the controller
  decrypts in-cluster.
- **External Secrets Operator** — `ExternalSecret` CRs reference Vault/GSM.
- **HashiCorp Vault Agent injector**.

`base/overrides/secrets/` contains templates for each; pick one for your platform.
Plain `Secret` manifests with real data must never be committed.

## 6. Change control / promotion

- The `main`/protected branch is the source of truth; changes land via reviewed PRs.
- Argo CD `syncPolicy.automated` is enabled with `prune` + `selfHeal` so drift is
  corrected, but `apps/*.yaml` also set `syncOptions: [ServerSideApply=true]` and,
  for the datastore, **no auto-prune of PVCs** to avoid data loss.
- Promote dev→test→prod by overlaying different `overrides.yaml` per environment
  (duplicate `base/overrides` into an overlay per cluster and point the root app at it).

## 7. Guardrails / dry-run

The Google guide requires `--dry-run=server` and Helm guardrails before applying.
The equivalent in Argo CD:

- `ServerSideApply=true` sync option (used on the operator/CRD app);
- Argo CD **diff preview** in the UI/PR gate acts as the dry-run;
- optionally run `helm template … | kubectl apply --dry-run=server` in CI on PRs.

# Install guide — official steps → GitOps artifacts

Every step of the Apigee hybrid v1.16 install guide, and the artifact in this repo
that performs it. Control-plane steps (Google Cloud) are done once per
[`PREREQUISITES.md`](PREREQUISITES.md); everything cluster-side is done by Argo CD.

Guide root: <https://docs.cloud.google.com/apigee/docs/hybrid/v1.16/install-before-begin>

---

## Part 1 — Project & Org setup (control plane; not GitOps)

| Step | Official page | Where |
|------|---------------|-------|
| Enable APIs | `precog-enableapi` | `PREREQUISITES.md` §2 |
| Create organization | `precog-provision` | `PREREQUISITES.md` §3 |
| Create environment group | `precog-add-environment` | `PREREQUISITES.md` §4 |

## Part 2 — Hybrid runtime setup

| Step | Official page | GitOps artifact |
|------|---------------|-----------------|
| Before you begin | `install-before-begin` | — (platform prep: OpenShift 4.x cluster, StorageClass, node sizing) |
| 1. Create a cluster | `install-create-cluster` | Out of band (provision OpenShift). StorageClass name → `overrides.yaml: cassandra.storage.storageClass` |
| 2. Download Helm charts | `install-download-charts` | Not needed as a manual step — Argo CD pulls charts from `oci://us-docker.pkg.dev/apigee-release/apigee-hybrid-helm-charts` v`1.16.1` (`bootstrap/repositories.yaml`) |
| 3. Create the apigee namespace | `install-create-namespace` | `apps/00-namespaces.yaml` → `base/namespaces/` |
| 4. Set up service accounts | `install-service-accounts` | `PREREQUISITES.md` §5 (creates keys) → delivered as Secrets via `base/overrides/secrets/` |
| 5. Service account authentication | `install-sa-authentication` | Secrets referenced from `overrides.yaml` (`*Secret` keys); Workload Identity Federation preferred (see ENTERPRISE §2/§5) |
| 6. Create TLS certificates | `install-create-tls-certificates` | `apigee-ingress-tls` Secret (`base/overrides/secrets/`), referenced by `virtualhosts[].sslSecret` |
| 7. Create the overrides | `install-create-overrides` | `base/overrides/overrides.yaml` |
| 8. Enable control-plane access | `install-enable-control-plane-access` | Egress allow-list (ENTERPRISE §3) + synchronizer SA (PREREQUISITES §7) |
| 9. Install cert-manager | `install-cert-manager` | `apps/10-cert-manager.yaml` (v1.17.2) |
| 10. Install the CRDs | `install-crds` | Handled by `apps/20-apigee-operator.yaml` with `ServerSideApply=true` (operator chart carries the CRDs) |
| 11. Install Apigee hybrid using Helm | `install-helm-charts` | `apps/20`…`apps/90` (operator → datastore → telemetry → redis → ingress-manager → org → env → virtualhost), ordered by sync-wave |

## Part 3 — Expose ingress & deploy a proxy

| Step | Official page | GitOps artifact |
|------|---------------|-----------------|
| 1. Expose Apigee ingress | `install-expose-apigee-ingress` | On OpenShift, front the `apigee-ingress` service with an OpenShift **Route** (passthrough TLS). Template below — add it to Git as another Application if you want it managed. |
| 2. Deploy an API proxy | `install-deploy-proxy` | Application layer, done via Apigee API/UI or an `ApiProxy` CI job — not part of the platform install. |

### OpenShift Route to expose the ingress (Part 3, Step 1)

```yaml
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: apigee-ingress
  namespace: apigee
spec:
  host: api.example.com                # == env-group hostname
  to:
    kind: Service
    name: apigee-ingress               # the ingress gateway service created by apigee-ingress-manager
  port:
    targetPort: https
  tls:
    termination: passthrough           # Apigee terminates TLS with the env-group cert
```
Commit this under `base/` and add a matching Application (e.g. `apps/95-openshift-route.yaml`)
if you want the Route reconciled by Argo CD too.

---

## Release-name reminders (must match Apigee conventions)

The org/env/virtualhost charts key resources off the release name:

- `apps/70-apigee-org.yaml` → `releaseName: <ORG_NAME>`
- `apps/80-apigee-env.yaml` → `releaseName: <ENV_NAME>` **and** `--set env=<ENV_NAME>`
- `apps/90-apigee-virtualhost.yaml` → `releaseName: <ENV_GROUP>` **and** `--set envgroup=<ENV_GROUP>`

For **multiple** environments or groups, duplicate the `80-`/`90-` Applications
(one per env / group) with distinct names and waves.

## Verifying the rollout

Argo CD shows each wave going Healthy in order. Equivalent CLI checks:

```bash
oc get pods -n apigee-system        # apigee-controller Running
oc get pods -n apigee               # datastore(3) telemetry redis ingress org env virtualhost
oc get apigeedatastore,apigeeorganization,apigeeenvironment -n apigee
argocd app list -p apigee-hybrid    # all Applications Synced/Healthy
```

The guide's mandated `--dry-run=server` guardrail is provided by Argo CD's diff
(review before sync) plus the `ServerSideApply=true` sync option; optionally gate
PRs with `helm template … | oc apply --dry-run=server`.

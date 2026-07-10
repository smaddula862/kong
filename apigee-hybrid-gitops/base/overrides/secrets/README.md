# Delivering secrets (GitOps-safe)

Apigee needs several secrets in the `apigee` (and `apigee-system`) namespace.
**None of them may be committed as plaintext.** Use one of the mechanisms below;
all of them keep the *encrypted or referencing* manifest in Git and let a
controller materialize the real `Secret` in-cluster.

## Secrets required

| Secret name | Type | Contents | Referenced by |
|-------------|------|----------|---------------|
| `apigee-registry-pull` | `kubernetes.io/dockerconfigjson` | pull creds for the internal mirror | `overrides.yaml: imagePullSecrets` |
| `apigee-cassandra-auth` | `Opaque` | `adminPassword`, `ddlPassword`, `dmlPassword`, `jmxUsername`, `jmxPassword` | `cassandra.auth.secret` |
| `apigee-ingress-tls` | `kubernetes.io/tls` | `tls.crt`, `tls.key` for the env-group host | `virtualhosts[].sslSecret` |
| `apigee-synchronizer-svc-account` | `Opaque` | `client_secret.json` (SA key) | `envs[].synchronizerSecret` |
| `apigee-udca-svc-account` | `Opaque` | SA key | `envs[].udcaSecret` |
| `apigee-runtime-svc-account` | `Opaque` | SA key | `envs[].runtimeSecret` |
| `apigee-mart-svc-account` | `Opaque` | SA key | `mart` / `connectAgent` |
| `apigee-watcher-svc-account` | `Opaque` | SA key | `watcher` |
| `apigee-metrics-svc-account` | `Opaque` | SA key | `metrics_sa` |
| `apigee-guardrails-svc-account` | `Opaque` | SA key (v1.16) | `guardrails` |

## Option A — Sealed Secrets (encrypted manifest committed)

```bash
# encrypt an SA key so the SealedSecret CR can be committed safely
kubectl create secret generic apigee-synchronizer-svc-account \
  --namespace apigee \
  --from-file=client_secret.json=./service-accounts/apigee-non-prod.json \
  --dry-run=client -o yaml \
| kubeseal --format yaml --controller-namespace kube-system \
> apigee-synchronizer-svc-account.sealedsecret.yaml
```
Commit the `*.sealedsecret.yaml` files into this directory and add an Argo CD
Application (or include them in the operator app's kustomize) to sync them.

## Option B — External Secrets Operator (reference committed)

Commit `ExternalSecret` CRs that pull from Vault / Google Secret Manager:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: apigee-synchronizer-svc-account
  namespace: apigee
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: apigee-synchronizer-svc-account
  data:
    - secretKey: client_secret.json
      remoteRef:
        key: apigee/sa/synchronizer
        property: client_secret.json
```

## Option C — Vault Agent injection

Annotate the Apigee pods (via `overrides.yaml` pod annotations) to have the
Vault sidecar render the key into a shared volume.

Whichever you choose, ensure the secrets exist **before** the wave that needs
them (registry-pull + guardrails before the operator; SA + TLS before org/env/
virtualhost). Add them at sync-wave `-9` if you manage them through Argo CD.

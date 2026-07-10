# Prerequisites — one-time control-plane (Google Cloud) setup

These steps correspond to **Part 1 (Project & Org setup)** and the
service-account / control-plane portions of **Part 2** of the official guide.
They act on **Google Cloud**, not on the cluster, so a Kubernetes GitOps
controller (Argo CD) cannot perform them. Run them once (ideally from a CI
pipeline or a scripted runbook so they are still reproducible), then feed the
*outputs* into the cluster via Git values and Secrets.

Reference: <https://docs.cloud.google.com/apigee/docs/hybrid/v1.16/install-before-begin>

---

## 0. Tooling / versions

| Tool | Version for hybrid v1.16 |
|------|--------------------------|
| `helm` | 3.14.2+ (Argo CD bundles a compatible Helm; only needed locally for `--dry-run` checks) |
| `kubectl` / `oc` | matching your OpenShift 4.x cluster |
| `apigeectl` | not used in the Helm flow (Helm replaces it) |
| cert-manager | 1.16.3+ or 1.17.2+ |
| Apigee Helm charts | **1.16.1** from `oci://us-docker.pkg.dev/apigee-release/apigee-hybrid-helm-charts` |

## 1. Environment variables used throughout

```bash
export PROJECT_ID="my-apigee-project"
export ANALYTICS_REGION="us-central1"          # nearest supported analytics region
export ORG_NAME="$PROJECT_ID"                  # hybrid org name == project id
export ENV_NAME="dev"
export ENV_GROUP="dev-group"
export ENV_GROUP_HOSTNAME="api.example.com"
export CLUSTER_NAME="ocp-apigee"
export CLUSTER_REGION="us-central1"
```

## 2. Enable APIs (Part 1, Step 1)

```bash
gcloud services enable \
  apigee.googleapis.com \
  apigeeconnect.googleapis.com \
  cloudresourcemanager.googleapis.com \
  --project "$PROJECT_ID"
```

## 3. Create the organization (Part 1, Step 2)

Provision the Apigee org against your project + analytics region and pass your
runtime type as `HYBRID`. Follow the "Create an organization" page — it walks
through `apigee.googleapis.com/v1/organizations` provisioning and the RuntimeType
selection. Record the resulting **org name** (goes into `overrides.yaml: org`).

## 4. Create the environment and environment group (Part 1, Step 3)

Create `$ENV_NAME`, create `$ENV_GROUP`, attach the hostname `$ENV_GROUP_HOSTNAME`,
and attach the environment to the group. These names flow into `overrides.yaml`
(`envs[].name`, `virtualhosts[].name`).

## 5. Google service accounts (Part 2, Step 4 — `install-service-accounts`)

Hybrid uses a set of Google service accounts. The `create-service-account` tool
shipped in the operator Helm chart (`apigee-operator/etc/tools/create-service-account`)
creates them and downloads JSON keys. **New in v1.16:** the `apigee-guardrails`
service account is required for the `apigee-operator` chart.

Non-prod (single combined SA) is allowed; production uses one SA per component:

| Service account | Google role |
|-----------------|-------------|
| `apigee-cassandra`    | `roles/storage.objectAdmin` (backup/restore) |
| `apigee-logger`       | `roles/logging.logWriter` |
| `apigee-mart`         | `roles/apigee.serviceAgent` |
| `apigee-metrics`      | `roles/monitoring.metricWriter` |
| `apigee-runtime`      | `roles/apigee.serviceAgent`* |
| `apigee-synchronizer` | `roles/apigee.synchronizerManager` |
| `apigee-udca`         | `roles/apigee.analyticsAgent` |
| `apigee-watcher`      | `roles/apigee.runtimeAgent` |
| `apigee-guardrails`   | (v1.16) used by the operator chart preflight |

```bash
# from the downloaded operator chart directory
./apigee-operator/etc/tools/create-service-account \
  --env non-prod \
  --dir ./service-accounts
```

> **Enterprise / restricted clusters:** prefer **Workload Identity Federation**
> over long-lived JSON keys where the platform supports it. On OpenShift without
> GKE Workload Identity, JSON keys are the common path — deliver them to the
> cluster only as Secrets through Sealed Secrets / Vault / External Secrets
> Operator (see `../base/overrides/secrets/`). **Never commit key material.**

## 6. TLS certificate for the ingress (Part 2, Step 6 — `install-create-tls-certificates`)

The environment group needs a serving cert/key for `$ENV_GROUP_HOSTNAME`. For a
real deployment use a CA-issued cert delivered as a Kubernetes TLS Secret; for
non-prod you may self-sign. This is referenced from `overrides.yaml`
(`virtualhosts[].sslSecret`). See `../base/overrides/secrets/README.md`.

## 7. Control-plane access / egress (Part 2, Step 8 — `install-enable-control-plane-access`)

The runtime must reach the Apigee control plane. In a restricted network you must
allow-list the Google endpoints (see `ENTERPRISE-CONSIDERATIONS.md` §Egress) and,
if using a synchronizer identity, grant the synchronizer SA on the control plane.

---

Once §2–§7 are complete you have: an **org**, an **env**, an **env group + host**,
**SA keys**, and a **TLS secret**. Everything after this is done by Argo CD from
this repo.

# Apigee hybrid v1.16 on OpenShift — GitOps with Argo CD

This directory is a **GitOps package** that installs and manages the **Apigee hybrid
v1.16 runtime plane** on **Red Hat OpenShift** using **Argo CD**. Every artifact the
official Google install guide creates imperatively with `helm` and `kubectl` is
expressed here declaratively, so the cluster state is fully driven from Git.

Source of truth for the procedure:
<https://docs.cloud.google.com/apigee/docs/hybrid/v1.16/install-before-begin>

> **What GitOps can and cannot do here.** Argo CD deploys everything that lives
> *inside* the cluster (namespaces, SCCs, cert-manager, the Apigee operator, CRDs
> and all eight Apigee Helm charts). The Google **control‑plane** setup — enabling
> APIs, creating the Apigee **organization** and **environment group**, and minting
> **Google service accounts** — happens once against Google Cloud and is *not*
> something a Kubernetes GitOps controller can perform. Those steps are captured as
> reproducible scripts/checklists in [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md)
> and their *outputs* (SA keys, org/env names) are fed into the cluster as Secrets
> and Helm values, never committed in clear text.

## Layout

```
apigee-hybrid-gitops/
├── bootstrap/
│   ├── argocd-appproject.yaml     # Restricted Argo CD AppProject (enterprise guardrails)
│   ├── repositories.yaml          # Repo/registry credential templates (OCI Helm + Git)
│   └── root-app.yaml              # App-of-apps root Application
├── apps/                          # One Argo CD Application per install step, ordered by sync-wave
│   ├── 00-namespaces.yaml
│   ├── 05-openshift-scc.yaml
│   ├── 10-cert-manager.yaml
│   ├── 20-apigee-operator.yaml    # operator chart == CRDs + controller (server-side apply)
│   ├── 30-apigee-datastore.yaml
│   ├── 40-apigee-telemetry.yaml
│   ├── 50-apigee-redis.yaml
│   ├── 60-apigee-ingress-manager.yaml
│   ├── 70-apigee-org.yaml
│   ├── 80-apigee-env.yaml
│   └── 90-apigee-virtualhost.yaml
├── base/
│   ├── namespaces/                # apigee + apigee-system namespaces
│   ├── scc/                       # OpenShift SecurityContextConstraints + bindings
│   └── overrides/
│       ├── overrides.yaml         # Apigee Helm values (the "overrides" file), placeholders
│       └── secrets/               # How to deliver SA keys & TLS (Sealed Secrets / Vault / ESO)
└── docs/
    ├── PREREQUISITES.md           # Control-plane (Google Cloud) one-time setup
    ├── INSTALL.md                 # Maps every official step -> the artifact that replaces it
    └── ENTERPRISE-CONSIDERATIONS.md
```

## How the install order is preserved

The Google guide is explicit that **component order matters**
(operator → datastore → telemetry → redis → ingress-manager → org → env → virtualhost).
Argo CD reproduces this with **sync waves**
(`argocd.argoproj.io/sync-wave`) on each Application, so the root app-of-apps rolls
the fleet out in exactly the documented sequence and blocks a wave until the previous
one is Healthy.

| Wave | Application            | Replaces this manual step |
|-----:|-----------------------|---------------------------|
| -10  | `namespaces`          | `kubectl create namespace apigee` |
|  -8  | `openshift-scc`       | OpenShift SCCs for datastore/telemetry |
|  -5  | `cert-manager`        | Step 9 — Install cert-manager |
|   0  | `apigee-operator`     | Step 10 (CRDs) + Step 11 operator chart |
|  10  | `apigee-datastore`    | Step 11 — `helm upgrade datastore …` |
|  20  | `apigee-telemetry`    | Step 11 — `helm upgrade telemetry …` |
|  30  | `apigee-redis`        | Step 11 — `helm upgrade redis …` |
|  40  | `apigee-ingress-manager` | Step 11 — `helm upgrade ingress-manager …` |
|  50  | `apigee-org`          | Step 11 — `helm upgrade $ORG apigee-org …` |
|  60  | `apigee-env`          | Step 11 — `helm upgrade $ENV apigee-env …` |
|  70  | `apigee-virtualhost`  | Step 11 — `helm upgrade $ENVGROUP apigee-virtualhost …` |

## Quick start (once prerequisites in `docs/PREREQUISITES.md` are done)

```bash
# 1. Register the OCI Helm registry + this Git repo with Argo CD (edit creds first)
oc apply -n argocd -f apigee-hybrid-gitops/bootstrap/repositories.yaml

# 2. Create the restricted AppProject
oc apply -n argocd -f apigee-hybrid-gitops/bootstrap/argocd-appproject.yaml

# 3. Deliver secrets (SA keys, TLS) via your enterprise mechanism — see base/overrides/secrets/

# 4. Deploy the root app-of-apps. Argo CD does the rest, in order.
oc apply -n argocd -f apigee-hybrid-gitops/bootstrap/root-app.yaml
```

Then edit [`base/overrides/overrides.yaml`](base/overrides/overrides.yaml) with your
org/env/cluster/registry values and commit — Argo CD reconciles automatically.

See [`docs/INSTALL.md`](docs/INSTALL.md) for the full step-by-step mapping and
[`docs/ENTERPRISE-CONSIDERATIONS.md`](docs/ENTERPRISE-CONSIDERATIONS.md) for the
restricted-environment design (private registry mirror, no cluster-admin for app
teams, egress allow-list, SCC scoping, secret handling).

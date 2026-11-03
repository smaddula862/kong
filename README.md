Deployment flow
1. Argo CD is initially configured to watch apigee-platform-argocd/bootstrap.
2. Bootstrap creates the root Application.
3. The root Application watches clusters/apigee-sbx-usw2.
4. That directory establishes the namespace, permissions, SCCs, project, and ten child Applications.
5. Each child Application reads charts and values from apigee-hybrid-infra.
6. Webhooks notify Argo CD after commits to either repository.
7. Automatic sync and self-healing apply the changes.
1. apigee-hybrid-infra
This repository contains the deployable Apigee assets and environment-specific values. It contains no Argo CD Applications.
.gitignore
[.gitignore](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-hybrid-infra/.gitignore)
Prevents sensitive or unwanted files from entering Git:
- macOS .DS_Store
- Private keys and PEM certificates
- Service-account JSON files
- OAuth client secrets
- Apigee credential JSON files
This is important because Argo CD reads the repository, but private credential material must be managed externally.
Region 1 configuration
[environments/sbx/region1-us-east-2/overrides.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-hybrid-infra/environments/sbx/region1-us-east-2/overrides.yaml)
Apigee Hybrid values for the sandbox Region 1 cluster.
It defines:
- Kubernetes namespace: apigee
- GCP project: apigeehybrid-506416
- GCP control-plane region: us-central1
- Kubernetes cluster: apigee-sbx
- Kubernetes cluster region: us-east-2
- Apigee organization, instance, environment, and environment group
- Data and runtime node selectors
- Three Cassandra replicas
- Cassandra datacenter dc-1
- gp3 storage with 100 GiB per Cassandra instance
- Daily Cassandra backups to GCP
- References to externally managed service-account Secrets
- Disabled Apigee logger
- Metrics service account
- Runtime and synchronizer Secret references
- Ingress gateway scaling from 2 to 10 replicas
- Virtual-host selection and TLS Secret
This file is not currently referenced by a Region 1 Argo CD Application. It is configuration prepared for a future Region 1 deployment.
Region 2 configuration
[environments/sbx/region2-us-west-2/overrides.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-hybrid-infra/environments/sbx/region2-us-west-2/overrides.yaml)
The active values file used by all Region 2 child Applications.
It defines:
- Kubernetes namespace: apigee
- Cluster: apigee-sbx-usw2
- Region: us-west-2
- Cassandra datacenter dc-2
- Three Cassandra replicas
- GCP Cassandra backup configuration
- Workload service-account Secret names
- Node selectors
- Component resource limits
- Four minimum ingress gateway replicas
- OpenShift Route configuration
- Route hostname: api-sbx.com
- TLS Secret and virtual-host selection
- Redis Envoy, runtime, synchronizer, watcher, MART, and scheduler CPU limits
certManager.manageApigeeCA: false means the platform is expected to supply the required certificate infrastructure rather than letting Apigee manage its own CA.
All child Applications use this file through Argo CD’s multi-source $values mechanism.
Cassandra Secret contract
[environments/sbx/shared/cassandra-backup-secret-contract.md](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-hybrid-infra/environments/sbx/shared/cassandra-backup-secret-contract.md)
Documents the externally managed Cassandra backup credential.
It specifies:
- Secret namespace: apigee
- Secret name: apigee-cassandra-svc-account
- Expected Google service-account email
- Required Secret keys:
  - client_secret.json
  - dbbackup_key.json
- Both keys must contain identical service-account JSON
- Credential data must never be committed
- The Apigee Cassandra backup process reads dbbackup_key.json
This contract is documentation only; Argo CD does not create this Secret.
Cassandra Secret validation utility
[environments/sbx/shared/validate-cassandra-backup-secret.sh](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-hybrid-infra/environments/sbx/shared/validate-cassandra-backup-secret.sh)
Optional operational utility—not part of deployment.
It uses oc, jq, and openssl to verify:
- The Secret exists.
- Both required keys exist.
- The two values contain identical bytes.
- The decoded JSON is a service-account credential.
- The service-account email matches the expected identity.
- The project ID matches the expected GCP project.
Argo CD does not execute this script.
2. apigee-platform-argocd
This repository owns every Argo CD object and all OpenShift platform prerequisites.
.gitignore
[.gitignore](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/.gitignore)
Uses the same credential protections as the infrastructure repository. It prevents keys, certificates, and service-account JSON from being committed.
Bootstrap
The bootstrap directory is the entry point configured during initial Argo CD onboarding.
Bootstrap README
[bootstrap/README.md](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/bootstrap/README.md)
Explains:
- The platform repository owns all Argo CD configuration.
- Argo CD’s initial Application should watch the bootstrap directory.
- The bootstrap layer creates the root Application.
- Future changes are driven by commits and webhooks.
- No deployment script is required.
- Pruning remains disabled.
Bootstrap AppProject
[bootstrap/apigee-bootstrap-project.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/bootstrap/apigee-bootstrap-project.yaml)
Creates the apigee-bootstrap Argo CD project used by the root Application.
It restricts the root to:
- The platform Git repository.
- The local Kubernetes cluster.
- The openshift-gitops and apigee namespaces.
It permits the root Application to manage:
- Namespace-scoped resources.
- Namespaces.
- CRDs.
- cert-manager ClusterIssuers.
- ClusterRoles and ClusterRoleBindings.
- Mutating and validating webhooks.
- OpenShift SecurityContextConstraints.
Root Application
[bootstrap/apigee-sbx-usw2-root.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/bootstrap/apigee-sbx-usw2-root.yaml)
Creates the root Argo CD Application.
It watches:
Repository: apigee-platform-argocd
Revision: main
Path: clusters/apigee-sbx-usw2
It automatically:
- Detects changes.
- Self-heals drift.
- Reconciles the platform configuration.
- Creates or updates the ten child Applications.
Pruning is disabled, so deleting a manifest from Git does not automatically delete the live resource.
Bootstrap Kustomization
[bootstrap/kustomization.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/bootstrap/kustomization.yaml)
Combines:
- apigee-bootstrap-project.yaml
- apigee-sbx-usw2-root.yaml
This is the path the initial Argo CD onboarding Application should use.
Cluster configuration
Main cluster Kustomization
[clusters/apigee-sbx-usw2/kustomization.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/kustomization.yaml)
This is the main composition file for the entire Region 2 deployment.
It includes:
- Namespace
- Apigee AppProject
- Cluster and namespace RBAC
- OpenShift SCC configuration
- All ten child Applications
It also applies dependency ordering:
- Wave -3: namespace
- Wave -2: AppProject
- Wave -1: RBAC and SCC prerequisites
- Waves 0–7: child Applications
A Kustomize patch adds automatic synchronization to every child Application:
automated:
  prune: false
  selfHeal: true
  allowEmpty: false
It also adds retry behavior:
- Up to 10 retries
- Initial delay of 10 seconds
- Exponential backoff
- Maximum delay of three minutes
Namespace
[clusters/apigee-sbx-usw2/namespace.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/namespace.yaml)
Creates the apigee namespace.
It:
- Assigns namespace management to OpenShift GitOps.
- Configures pod-security warnings and audits for privileged workloads.
- Declares privileged security as minimally sufficient for OpenShift.
- Is installed in sync wave -3 through the Kustomize patch.
Apigee AppProject
[clusters/apigee-sbx-usw2/projects/apigee-sbx-usw2.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/projects/apigee-sbx-usw2.yaml)
Creates the apigee-sbx-usw2 AppProject used by all ten child Applications.
It restricts them to:
- The infrastructure Git repository.
- The local Kubernetes cluster.
- The apigee namespace.
It permits:
- All namespace-scoped resources.
- Apigee CRDs.
- ClusterIssuers.
- ClusterRoles and ClusterRoleBindings.
- Admission webhooks.
- OpenShift SCC resources.
The Kustomization places it in sync wave -2.
RBAC and OpenShift security
Argo CD cluster-resource access
[rbac/argocd-apigee-cluster-resources.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/rbac/argocd-apigee-cluster-resources.yaml)
Creates a ClusterRole and ClusterRoleBinding for the OpenShift GitOps Application controller.
It grants the controller permission to manage:
- Namespaces
- ClusterRoles
- ClusterRoleBindings
- CRDs
- cert-manager ClusterIssuers
- Mutating webhooks
- Validating webhooks
- OpenShift SCCs
It grants read, create, update, and patch access, but not deletion.
Apigee custom-resource access
[rbac/apigee-custom-resources.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/rbac/apigee-custom-resources.yaml)
Creates a Role and RoleBinding in the apigee namespace.
It lets the Argo CD Application controller manage all resources in the:
apigee.cloud.google.com
API group.
Allowed operations include:
- Get
- List
- Watch
- Create
- Update
- Patch
Deletion is intentionally excluded.
Cassandra guardrail SCC access
[rbac/apigee-datastore-guardrail-scc.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/rbac/apigee-datastore-guardrail-scc.yaml)
Creates a Role and RoleBinding allowing:
apigee-cassandra-guardrails-sa
to use:
apigee-scc-apigee-apigee-datastore
Without this binding, the Cassandra guardrail workload might be rejected by OpenShift security admission.
Apigee SCC prerequisites
[rbac/apigee-operator-scc-prerequisites.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/rbac/apigee-operator-scc-prerequisites.yaml)
Defines three OpenShift SecurityContextConstraints.
General Apigee SCC
Used by normal Apigee workloads.
It establishes:
- Required UID and group ranges.
- Runtime-default seccomp.
- Non-privileged containers.
- No host networking or host paths.
- Access for service accounts in the apigee namespace.
Cassandra SCC
Used by the datastore.
It allows:
- Host networking.
- Host ports.
- IPC_LOCK.
- SYS_RESOURCE.
- Flexible user and filesystem group IDs.
It is assigned to the Cassandra service account.
Logger SCC
Used if the Apigee logger is enabled.
It allows:
- Privileged containers.
- Host-path volumes.
- spc_t SELinux type.
- Flexible user and group IDs.
The current environment disables the logger, but the SCC remains available.
Child Applications
Every child Application:
- Runs in openshift-gitops.
- Uses the apigee-sbx-usw2 AppProject.
- Deploys to the local cluster’s apigee namespace.
- Tracks the infrastructure repository’s main branch.
- Uses Region 2 overrides.
- Receives automatic sync, self-healing, and retry configuration from the parent Kustomization.
CRDs
[applications/apigee-sbx-usw2-crds.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-crds.yaml)
Sync wave 0.
Installs the Apigee CustomResourceDefinitions required by the operator and all Apigee custom resources.
It uses server-side apply because CRDs are large and often contain extensive schemas.
Operator
[applications/apigee-sbx-usw2-operator.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-operator.yaml)
Sync wave 1.
Deploys the Apigee operator. The operator watches Apigee custom resources and creates the underlying Kubernetes workloads.
It uses:
- The operator chart from the infrastructure repository.
- Region 2 overrides.
- Helm release name operator.
Datastore
[applications/apigee-sbx-usw2-datastore.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-datastore.yaml)
Sync wave 2.
Deploys the Apigee datastore configuration, primarily Cassandra.
It controls:
- Cassandra replicas.
- Storage.
- Datacenter and rack.
- Credentials.
- Host networking.
- Backup destination, identity, and schedule.
It uses Argo CD multi-source mode:
- One source supplies the chart.
- The $values source supplies the Region 2 values file.
Telemetry
[applications/apigee-sbx-usw2-telemetry.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-telemetry.yaml)
Sync wave 3.
Deploys Apigee telemetry and metrics components.
It contains ignoreDifferences rules for fields that the Apigee operator or Kubernetes defaults after deployment. These rules prevent false OutOfSync states for empty/default component fields and disabled logging options.
Redis
[applications/apigee-sbx-usw2-redis.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-redis.yaml)
Sync wave 3.
Deploys the Apigee Redis custom resource and Redis Envoy configuration.
Its difference rules ignore:
- Operator-generated empty/default fields.
- The default 75% autoscaling target represented in different Kubernetes API formats.
Ingress manager
[applications/apigee-sbx-usw2-ingress-manager.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-ingress-manager.yaml)
Sync wave 4.
Deploys the Apigee ingress and Istio management components.
It establishes the ingress control plane required before virtual hosts and external routes become usable.
Organization
[applications/apigee-sbx-usw2-org.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-org.yaml)
Sync wave 4.
Creates the Apigee organization custom resource and organization-level services such as:
- MART
- Connect Agent
- Watcher
- Organization encryption configuration
- Optional monetization-related configuration
Its difference rules suppress operator-generated defaults and empty fields.
Environment
[applications/apigee-sbx-usw2-env.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-env.yaml)
Sync wave 5.
Creates the sbx Apigee environment.
It supplies:
- Runtime identity.
- Synchronizer identity.
- Runtime resource settings.
- Environment-level encryption configuration.
Difference rules ignore fields defaulted or normalized by the Apigee operator.
Virtual host
[applications/apigee-sbx-usw2-virtualhost.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-virtualhost.yaml)
Sync wave 6.
Creates the sbx-group virtual host.
It connects:
- The Apigee environment group.
- The selected ingress gateway.
- The TLS Secret.
- Apigee route configuration.
The envgroup Helm parameter explicitly selects sbx-group.
OpenShift Route
[applications/apigee-sbx-usw2-route.yaml](/Users/sai/Documents/Codex/2026-11-02/re/outputs/apigee-hybrid-gitops-ready/apigee-platform-argocd/clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-route.yaml)
Sync wave 7, the final deployment stage.
Creates the external OpenShift Route that exposes the Apigee ingress gateway.
It uses the Region 2 values for:
- Route name
- External hostname
- Target ingress Service
- HTTPS target port
This is the final link between the external hostname and the internal Apigee ingress service.


----------------------
FILE: bootstrap/apigee-bootstrap-project.yaml

apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: apigee-bootstrap
  namespace: openshift-gitops
spec:
  description: Bootstraps the Apigee platform configuration
  sourceRepos:
    - git@github.com:smaddula862/apigee-platform-argocd.git
  destinations:
    - namespace: openshift-gitops
      server: https://kubernetes.default.svc
    - namespace: apigee
      server: https://kubernetes.default.svc
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
  clusterResourceWhitelist:
    - group: ""
      kind: Namespace
    - group: apiextensions.k8s.io
      kind: CustomResourceDefinition
    - group: cert-manager.io
      kind: ClusterIssuer
    - group: rbac.authorization.k8s.io
      kind: ClusterRole
    - group: rbac.authorization.k8s.io
      kind: ClusterRoleBinding
    - group: admissionregistration.k8s.io
      kind: MutatingWebhookConfiguration
    - group: admissionregistration.k8s.io
      kind: ValidatingWebhookConfiguration
    - group: security.openshift.io
      kind: SecurityContextConstraints



-__________________


FILE: bootstrap/apigee-sbx-usw2-root.yaml

apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-root
  namespace: openshift-gitops
  labels:
    app.kubernetes.io/name: apigee-sbx-usw2-root
    app.kubernetes.io/part-of: apigee-hybrid
spec:
  project: apigee-bootstrap
  source:
    repoURL: git@github.com:smaddula862/apigee-platform-argocd.git
    targetRevision: main
    path: clusters/apigee-sbx-usw2
  destination:
    server: https://kubernetes.default.svc
    namespace: openshift-gitops
  revisionHistoryLimit: 10
  syncPolicy:
    automated:
      prune: false
      selfHeal: true
      allowEmpty: false
    syncOptions:
      - CreateNamespace=false



-__________________


FILE: bootstrap/kustomization.yaml

apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - apigee-bootstrap-project.yaml
  - apigee-sbx-usw2-root.yaml



-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-crds.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-crds
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-crds
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/sync-wave: '0'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  source:
    path: charts/apigee-operator/etc/crds/default
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false
    - ServerSideApply=true




-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-datastore.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-datastore
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-datastore
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/compare-options: ServerSideDiff=true,IncludeMutationWebhook=true
    argocd.argoproj.io/sync-wave: '2'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  sources:
  - helm:
      ignoreMissingValueFiles: false
      releaseName: datastore
      valueFiles:
      - "$values/environments/sbx/region2-us-west-2/overrides.yaml"
    path: charts/apigee-datastore
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  - ref: values
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false




-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-env.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-env
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-env
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/compare-options: ServerSideDiff=true,IncludeMutationWebhook=true
    argocd.argoproj.io/sync-wave: '5'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  ignoreDifferences:
  - group: apigee.cloud.google.com
    jqPathExpressions:
    - ".spec.components | .. | .nodeAffinityRequired? | select(. == false)"
    - ".spec.components | .. | .properties? | select(. == {})"
    - ".spec.components | .. | .release? | select(. == {})"
    - ".spec.components | .. | .storage? | select(. == {})"
    - ".spec.components.synchronizer.containers[]?.readinessProbe.initialDelaySeconds
      | select(. == 0)"
    - .spec.dataEncryptionSecretProviderClass | select(. == "")
    jsonPointers:
    - "/metadata"
    - "/release"
    kind: ApigeeEnvironment
    name: apigeehybrid-50-sbx-ad29baa
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  sources:
  - helm:
      ignoreMissingValueFiles: false
      parameters:
      - name: env
        value: sbx
      releaseName: sbx-env
      valueFiles:
      - "$values/environments/sbx/region2-us-west-2/overrides.yaml"
    path: charts/apigee-env
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  - ref: values
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false




-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-ingress-manager.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-ingress-manager
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-ingress-manager
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/sync-wave: '4'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  sources:
  - helm:
      ignoreMissingValueFiles: false
      releaseName: ingress-manager
      valueFiles:
      - "$values/environments/sbx/region2-us-west-2/overrides.yaml"
    path: charts/apigee-ingress-manager
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  - ref: values
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false




-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-operator.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-operator
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-operator
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/sync-wave: '1'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  sources:
  - helm:
      ignoreMissingValueFiles: false
      releaseName: operator
      valueFiles:
      - "$values/environments/sbx/region2-us-west-2/overrides.yaml"
    path: charts/apigee-operator
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  - ref: values
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false




-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-org.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-org
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-org
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/compare-options: ServerSideDiff=true,IncludeMutationWebhook=true
    argocd.argoproj.io/sync-wave: '4'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  ignoreDifferences:
  - group: apigee.cloud.google.com
    jqPathExpressions:
    - ".spec.components | .. | .nodeAffinityRequired? | select(. == false)"
    - ".spec.components | .. | .properties? | select(. == {})"
    - ".spec.components | .. | .release? | select(. == {})"
    - ".spec.components | .. | .storage? | select(. == {})"
    - ".spec.apigeeMonetizationAddon | select(. == {})"
    - .spec.axHashingSaltSecretProviderClass | select(. == "")
    - .spec.dataEncryptionSecretProviderClass | select(. == "")
    jsonPointers:
    - "/metadata"
    - "/release"
    kind: ApigeeOrganization
    name: apigeehybrid-50-3819840
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  sources:
  - helm:
      ignoreMissingValueFiles: false
      releaseName: org
      valueFiles:
      - "$values/environments/sbx/region2-us-west-2/overrides.yaml"
    path: charts/apigee-org
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  - ref: values
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false




-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-redis.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-redis
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-redis
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/compare-options: ServerSideDiff=true,IncludeMutationWebhook=true
    argocd.argoproj.io/sync-wave: '3'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  ignoreDifferences:
  - group: apigee.cloud.google.com
    jqPathExpressions:
    - ".spec.components | .. | .nodeAffinityRequired? | select(. == false)"
    - ".spec.components | .. | .properties? | select(. == {})"
    - ".spec.components | .. | .release? | select(. == {})"
    - ".spec.components | .. | .storage? | select(. == {})"
    - ".spec.components.redisEnvoy.autoScaler.metrics[]?.resource.targetAverageUtilization
      | select(. == 75)"
    - .spec.components.redisEnvoy.autoScaler.metrics[]?.resource.target | select(.
      == {"averageUtilization":75,"type":"Utilization"})
    jsonPointers:
    - "/metadata"
    - "/release"
    kind: ApigeeRedis
    name: default
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  sources:
  - helm:
      ignoreMissingValueFiles: false
      releaseName: redis
      valueFiles:
      - "$values/environments/sbx/region2-us-west-2/overrides.yaml"
    path: charts/apigee-redis
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  - ref: values
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false




-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-route.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-route
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-openshift-route
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/compare-options: ServerSideDiff=true
    argocd.argoproj.io/sync-wave: '7'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  sources:
  - helm:
      ignoreMissingValueFiles: false
      releaseName: apigee-sbx-route
      valueFiles:
      - "$values/environments/sbx/region2-us-west-2/overrides.yaml"
    path: charts/apigee-openshift-route
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  - ref: values
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false




-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-telemetry.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-telemetry
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-telemetry
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/compare-options: ServerSideDiff=true,IncludeMutationWebhook=true
    argocd.argoproj.io/sync-wave: '3'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  ignoreDifferences:
  - group: apigee.cloud.google.com
    jqPathExpressions:
    - ".spec.components.collector | select(.nodeAffinityRequired == false) | .nodeAffinityRequired"
    - ".spec.components.collector | select(.properties == {}) | .properties"
    - ".spec.components.collector | select(.release == {}) | .release"
    - ".spec.components.collector | select(.storage == {}) | .storage"
    - ".spec.components.metricsAdapter | select(.nodeAffinityRequired == false) |
      .nodeAffinityRequired"
    - ".spec.components.metricsAdapter | select(.properties == {}) | .properties"
    - ".spec.components.metricsAdapter | select(.release == {}) | .release"
    - ".spec.components.metricsAdapter | select(.storage == {}) | .storage"
    - ".spec.components.metricsApp | select(.nodeAffinityRequired == false) | .nodeAffinityRequired"
    - ".spec.components.metricsApp | select(.properties == {}) | .properties"
    - ".spec.components.metricsApp | select(.release == {}) | .release"
    - ".spec.components.metricsApp | select(.storage == {}) | .storage"
    - ".spec.components.metricsProxy | select(.nodeAffinityRequired == false) | .nodeAffinityRequired"
    - ".spec.components.metricsProxy | select(.properties == {}) | .properties"
    - ".spec.components.metricsProxy | select(.release == {}) | .release"
    - ".spec.components.metricsProxy | select(.storage == {}) | .storage"
    - ".spec | select(.accessLogsExport.enabled == false) | .accessLogsExport.enabled"
    - ".spec | select(.containerLogsExport.enabled == false) | .containerLogsExport.enabled"
    - ".spec | select(.containerOSLogsExport == {}) | .containerOSLogsExport"
    - ".spec | select(.helmSecurityConfig == {}) | .helmSecurityConfig"
    - ".spec | select(.slmAccessLogsExport == {}) | .slmAccessLogsExport"
    jsonPointers:
    - "/metadata"
    - "/release"
    kind: ApigeeTelemetry
    name: apigee-telemetry
    namespace: apigee
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  sources:
  - helm:
      ignoreMissingValueFiles: false
      releaseName: telemetry
      valueFiles:
      - "$values/environments/sbx/region2-us-west-2/overrides.yaml"
    path: charts/apigee-telemetry
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  - ref: values
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false




-__________________


FILE: clusters/apigee-sbx-usw2/applications/apigee-sbx-usw2-virtualhost.yaml

---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: apigee-sbx-usw2-virtualhost
  namespace: openshift-gitops
  labels:
    apigee.cloud.google.com/environment: sbx
    apigee.cloud.google.com/region: us-west-2
    app.kubernetes.io/name: apigee-virtualhost
    app.kubernetes.io/part-of: apigee-hybrid
  annotations:
    argocd.argoproj.io/compare-options: ServerSideDiff=true,IncludeMutationWebhook=true
    argocd.argoproj.io/sync-wave: '6'
spec:
  destination:
    namespace: apigee
    server: https://kubernetes.default.svc
  project: apigee-sbx-usw2
  revisionHistoryLimit: 5
  sources:
  - helm:
      ignoreMissingValueFiles: false
      parameters:
      - name: envgroup
        value: sbx-group
      releaseName: sbx-group
      valueFiles:
      - "$values/environments/sbx/region2-us-west-2/overrides.yaml"
    path: charts/apigee-virtualhost
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  - ref: values
    repoURL: git@github.com:smaddula862/apigee-hybrid-infra.git
    targetRevision: main
  syncPolicy:
    syncOptions:
    - CreateNamespace=false




-__________________


FILE: clusters/apigee-sbx-usw2/kustomization.yaml

apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - namespace.yaml
  - projects/apigee-sbx-usw2.yaml
  - rbac/argocd-apigee-cluster-resources.yaml
  - rbac/apigee-custom-resources.yaml
  - rbac/apigee-operator-scc-prerequisites.yaml
  - rbac/apigee-datastore-guardrail-scc.yaml
  - applications/apigee-sbx-usw2-crds.yaml
  - applications/apigee-sbx-usw2-operator.yaml
  - applications/apigee-sbx-usw2-datastore.yaml
  - applications/apigee-sbx-usw2-telemetry.yaml
  - applications/apigee-sbx-usw2-redis.yaml
  - applications/apigee-sbx-usw2-ingress-manager.yaml
  - applications/apigee-sbx-usw2-org.yaml
  - applications/apigee-sbx-usw2-env.yaml
  - applications/apigee-sbx-usw2-virtualhost.yaml
  - applications/apigee-sbx-usw2-route.yaml

# The root Application installs prerequisites before creating the child
# Applications. Child Applications reconcile automatically and retry transient
# dependency failures without pruning live resources.
patches:
  - target:
      kind: Namespace
    patch: |-
      - op: add
        path: /metadata/annotations/argocd.argoproj.io~1sync-wave
        value: "-3"
  - target:
      kind: AppProject
    patch: |-
      - op: add
        path: /metadata/annotations
        value:
          argocd.argoproj.io/sync-wave: "-2"
  - target:
      kind: "Role|RoleBinding|ClusterRole|ClusterRoleBinding"
    patch: |-
      - op: add
        path: /metadata/annotations
        value:
          argocd.argoproj.io/sync-wave: "-1"
  - target:
      kind: SecurityContextConstraints
    patch: |-
      - op: add
        path: /metadata/annotations/argocd.argoproj.io~1sync-wave
        value: "-1"
  - target:
      kind: Application
    patch: |-
      - op: add
        path: /spec/syncPolicy/automated
        value:
          prune: false
          selfHeal: true
          allowEmpty: false
      - op: add
        path: /spec/syncPolicy/retry
        value:
          limit: 10
          backoff:
            duration: 10s
            factor: 2
            maxDuration: 3m



-__________________


FILE: clusters/apigee-sbx-usw2/namespace.yaml

apiVersion: v1
kind: Namespace
metadata:
  name: apigee
  labels:
    argocd.argoproj.io/managed-by: openshift-gitops
    pod-security.kubernetes.io/audit: privileged
    pod-security.kubernetes.io/audit-version: latest
    pod-security.kubernetes.io/warn: privileged
    pod-security.kubernetes.io/warn-version: latest
  annotations:
    security.openshift.io/MinimallySufficientPodSecurityStandard: privileged



-__________________


FILE: clusters/apigee-sbx-usw2/projects/apigee-sbx-usw2.yaml

apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: apigee-sbx-usw2
  namespace: openshift-gitops
  labels:
    app.kubernetes.io/part-of: apigee-hybrid
spec:
  description: Apigee Hybrid SBX Region 2 applications
  sourceRepos:
    - git@github.com:smaddula862/apigee-hybrid-infra.git
  destinations:
    - namespace: apigee
      server: https://kubernetes.default.svc
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
  clusterResourceWhitelist:
    - group: apiextensions.k8s.io
      kind: CustomResourceDefinition
    - group: cert-manager.io
      kind: ClusterIssuer
    - group: rbac.authorization.k8s.io
      kind: ClusterRole
    - group: rbac.authorization.k8s.io
      kind: ClusterRoleBinding
    - group: admissionregistration.k8s.io
      kind: MutatingWebhookConfiguration
    - group: admissionregistration.k8s.io
      kind: ValidatingWebhookConfiguration
    - group: security.openshift.io
      kind: SecurityContextConstraints



-__________________


FILE: clusters/apigee-sbx-usw2/rbac/apigee-custom-resources.yaml

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: apigee-gitops-custom-resource-manager
  namespace: apigee
  labels:
    app.kubernetes.io/part-of: apigee-hybrid
    app.kubernetes.io/managed-by: openshift-gitops
rules:
  - apiGroups:
      - apigee.cloud.google.com
    resources:
      - "*"
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: apigee-gitops-custom-resource-manager
  namespace: apigee
  labels:
    app.kubernetes.io/part-of: apigee-hybrid
    app.kubernetes.io/managed-by: openshift-gitops
subjects:
  - kind: ServiceAccount
    name: openshift-gitops-argocd-application-controller
    namespace: openshift-gitops
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: apigee-gitops-custom-resource-manager



-__________________


FILE: clusters/apigee-sbx-usw2/rbac/apigee-datastore-guardrail-scc.yaml

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: apigee-datastore-guardrail-scc-user
  namespace: apigee
  labels:
    app.kubernetes.io/part-of: apigee-hybrid
    app.kubernetes.io/managed-by: openshift-gitops
rules:
  - apiGroups:
      - security.openshift.io
    resources:
      - securitycontextconstraints
    resourceNames:
      - apigee-scc-apigee-apigee-datastore
    verbs:
      - use
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: apigee-datastore-guardrail-scc-user
  namespace: apigee
  labels:
    app.kubernetes.io/part-of: apigee-hybrid
    app.kubernetes.io/managed-by: openshift-gitops
subjects:
  - kind: ServiceAccount
    name: apigee-cassandra-guardrails-sa
    namespace: apigee
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: apigee-datastore-guardrail-scc-user



-__________________


FILE: clusters/apigee-sbx-usw2/rbac/apigee-operator-scc-prerequisites.yaml

---
# Source: apigee-operator/templates/apigee-operators.yaml
# If we are running in an openshift cluster, we should install the appropriate SecurityContextConstraints
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: apigee-scc-apigee
  annotations:
    argocd.argoproj.io/tracking-id: "apigee-sbx-usw2-operator:security.openshift.io/SecurityContextConstraints:apigee/apigee-scc-apigee"
priority: 9
allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
readOnlyRootFilesystem: false
runAsUser:
  type: MustRunAsRange
  uidRangeMin: 999
  uidRangeMax: 999
seccompProfiles:
  - runtime/default
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: MustRunAs
  ranges:
  - min: 998
    max: 998
fsGroup:
  type: MustRunAs
  ranges:
  - min: 998
    max: 998
groups:
- system:serviceaccounts:apigee
---
# Source: apigee-operator/templates/apigee-operators.yaml
# Cassandra specific scc as it needs other capabilities.
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: apigee-scc-apigee-apigee-datastore
  annotations:
    argocd.argoproj.io/tracking-id: "apigee-sbx-usw2-operator:security.openshift.io/SecurityContextConstraints:apigee/apigee-scc-apigee-apigee-datastore"
priority: 9
allowHostNetwork: true
allowHostPorts: true
allowHostDirVolumePlugin: false
allowHostIPC: false
allowHostPID: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: false
readOnlyRootFilesystem: false
allowedCapabilities:
- "IPC_LOCK"
- "SYS_RESOURCE"
runAsUser:
  type: RunAsAny
seccompProfiles:
  - runtime/default
seLinuxContext:
  type: MustRunAs
supplementalGroups:
  type: MustRunAs
  ranges:
  - min: 998
    max: 998
fsGroup:
  type: RunAsAny
users:
- system:serviceaccount:apigee:apigee-cassandra-default
---
# Source: apigee-operator/templates/apigee-operators.yaml
# logger specific scc as it needs other capabilities.
apiVersion: security.openshift.io/v1
kind: SecurityContextConstraints
metadata:
  name: apigee-scc-apigee-apigee-logger
  annotations:
    argocd.argoproj.io/tracking-id: "apigee-sbx-usw2-operator:security.openshift.io/SecurityContextConstraints:apigee/apigee-scc-apigee-apigee-logger"
priority: 9
allowHostIPC: false
allowHostNetwork: false
allowHostPID: false
allowHostPorts: false
allowPrivilegeEscalation: true
allowPrivilegedContainer: true
allowHostDirVolumePlugin: true
readOnlyRootFilesystem: false
runAsUser:
  type: RunAsAny
seccompProfiles:
  - runtime/default
seLinuxContext:
  type: MustRunAs
  seLinuxOptions:
    type: spc_t
fsGroup:
  type: RunAsAny
volumes:
- configMap
- csi
- downwardAPI
- emptyDir
- hostPath
- secret
users:
- system:serviceaccount:apigee:apigee-logger-apigee-telemetry



-__________________


FILE: clusters/apigee-sbx-usw2/rbac/argocd-apigee-cluster-resources.yaml

apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: openshift-gitops-apigee-cluster-resources
  labels:
    app.kubernetes.io/part-of: apigee-hybrid
rules:
  - apiGroups:
      - ""
    resources:
      - namespaces
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
  - apiGroups:
      - rbac.authorization.k8s.io
    resources:
      - clusterroles
      - clusterrolebindings
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
  - apiGroups:
      - apiextensions.k8s.io
    resources:
      - customresourcedefinitions
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
  - apiGroups:
      - cert-manager.io
    resources:
      - clusterissuers
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
  - apiGroups:
      - admissionregistration.k8s.io
    resources:
      - mutatingwebhookconfigurations
      - validatingwebhookconfigurations
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
  - apiGroups:
      - security.openshift.io
    resources:
      - securitycontextconstraints
    verbs:
      - get
      - list
      - watch
      - create
      - update
      - patch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: openshift-gitops-apigee-cluster-resources
  labels:
    app.kubernetes.io/part-of: apigee-hybrid
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: openshift-gitops-apigee-cluster-resources
subjects:
  - kind: ServiceAccount
    name: openshift-gitops-argocd-application-controller
    namespace: openshift-gitops



-__________________





















































































































































  

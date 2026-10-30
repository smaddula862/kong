Hi Team,

As part of our Apigee Hybrid 1.17 implementation using OpenShift GitOps (Argo CD), we have identified the following configuration patches and security prerequisites in our infrastructure repositories.

**1. Apigee CRD Kustomize Patches**

The Apigee operator repository contains 20 CRD patch files, of which 16 are enabled in the current CRD Kustomization:

- 7 conversion webhook patches
- 7 cert-manager CA-injection patches
- 1 Kubernetes list/map keys patch
- 1 nested metadata validation patch

These patches support Apigee CRD schema configuration, webhook conversion and certificate authority injection.

We require an approved mechanism for deploying and updating these cluster-scoped CRDs.

**2. Argo CD Cluster-Level Permissions**

Our GitOps repository defines a ClusterRole for the OpenShift GitOps application controller to manage:

- CustomResourceDefinitions
- ClusterIssuers
- MutatingWebhookConfigurations
- ValidatingWebhookConfigurations
- SecurityContextConstraints

The configured permissions include get, list, watch, create, update and patch.

Please review and approve these permissions or identify which resources must be provisioned by the OCP team.

**3. Apigee SCC Requirements**

The repository defines three SCCs:

- apigee-scc-apigee
- apigee-scc-apigee-apigee-datastore
- apigee-scc-apigee-apigee-logger

It also defines SCC-use permissions for the Cassandra guardrails service account.

We request review and approval of the SCC definitions and their corresponding service account assignments.

**4. Apigee Operator RBAC**

The Apigee operator and ingress controllers require their associated Kubernetes Roles, ClusterRoles and bindings.

Please confirm whether these resources can be deployed through Argo CD or must be provisioned as part of an OCP-managed bootstrap.

**5. Cluster-Level Read-Only Access**

We request cluster-wide read-only access for the Apigee platform team to inspect nodes, MachineSets, storage, networking, operators, CRDs, SCCs, RBAC and relevant cluster events.

**Business justification:** Apigee Hybrid operates within the Apigee namespace but depends on cluster-level infrastructure for Cassandra availability, runtime scheduling, persistent storage, ingress connectivity and component reconciliation.

Cluster-level read-only access is required to diagnose infrastructure-related incidents, validate cluster maintenance, support root-cause analysis and reduce incident resolution time.

This request does not include cluster-wide write access for individual engineers or access to sensitive credentials.

**6. Additional Requirements**

Please confirm:

- Namespace-level Argo CD permissions for standard Kubernetes workloads.
- Required ClusterRole and ClusterRoleBinding bootstrap.
- Certificate management and admission webhook prerequisites.
- Required StorageClasses, node labels, taints and network configuration.
- Appropriate production change controls and resource deletion permissions.

Our preferred approach is for the OCP team to approve and provision security-sensitive cluster prerequisites, while Argo CD manages authorized Apigee resources through GitOps.

Please review the attached RBAC, SCC and CRD manifests and confirm the approved implementation approach.

Thanks,
Apigee Platform Team

# OpenShift prerequisites

Applies to **both** the East and West OpenShift clusters. Most of this is
delivered by the `apigee-openshift-prereqs` ApplicationSet (sync wave `-10`);
this doc explains the why and the manual/out-of-band bits.

## Cluster requirements

- OpenShift **4.12+** (Pod Security Admission enforced).
- A default `StorageClass` backed by fast block storage (the values assume
  **OpenShift Data Foundation** `ocs-storagecluster-ceph-rbd`; change per your
  platform).
- A `LoadBalancer` Service implementation (cloud LB, MetalLB, or F5) for the
  Apigee ingress.
- Cluster-admin to install the SCC and OpenShift GitOps operator.
- Nodes labeled with `topology.kubernetes.io/region` = `us-east-1` / `us-west-1`
  for rack-aware Cassandra placement.

## OpenShift GitOps (ArgoCD)

Install the **Red Hat OpenShift GitOps** operator on the hub cluster. It
provides the `openshift-gitops` namespace and the ArgoCD instance the
`bootstrap/argocd` manifests target. ArgoCD 2.6+ is required (multi-source
Applications).

## SecurityContextConstraints

OpenShift's default `restricted-v2` SCC assigns a random UID and drops
capabilities. Apigee's Cassandra/Envoy/runtime images expect fixed UIDs and
`NET_BIND_SERVICE`. `openshift/scc/apigee-scc.yaml` defines a dedicated
`apigee-hybrid-scc` (much narrower than `privileged`) and binds it to all
service accounts in the `apigee` and `apigee-system` namespaces.

Verify after sync:
```
oc get scc apigee-hybrid-scc
oc adm policy who-can use scc apigee-hybrid-scc
```

## Pod Security Admission

The `apigee` / `apigee-system` namespaces are labeled
`pod-security.kubernetes.io/enforce: privileged`
(`openshift/namespaces/namespaces.yaml`) so PSA does not reject the runtime
pods. Tighten to `baseline` only after validating each image's requirements.

## Inter-DC networking

Cassandra gossip/streaming and the West→East seed connection cross regions.
Ensure the private interconnect (VPN / peering) allows TCP `7001`, `7199`,
`9042` between the two `apigee` namespaces. See `cassandra-multiregion.md`.

## Secrets (NOT in git)

Provision these in both clusters via Sealed Secrets / External Secrets before
the charts sync:

| Secret                          | Used by                     |
|---------------------------------|-----------------------------|
| `apigee-cassandra-auth`         | Cassandra auth              |
| Cassandra internode TLS keypair | Cassandra `ssl*` paths      |
| Apigee GCP SA keys / WI binding | telemetry, mart, synchronizer, udca, runtime |
| `apigee-prod-tls`               | apigee-virtualhost TLS      |

## GCP control-plane setup

The Apigee **org** and **environments** (`prod`) must already exist in the GCP
control plane, and the runtime service accounts must be created/entitled, before
`apigee-org` / `apigee-env` sync successfully. This is a one-time control-plane
provisioning step outside GitOps (use `apigeectl`/gcloud or Terraform).

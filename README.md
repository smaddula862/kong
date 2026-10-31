You can consolidate this to:
- One Google Workload Identity Pool/provider.
- Separate credential-configuration JSON per Google service account—required because each file has a different impersonation URL.
- One Vault KV secret containing all configurations.
- One Vault Kubernetes role.
- One OpenShift SecretProviderClass exposing all expected Apigee filenames.
This differs from Google’s documented least-privilege layout, which uses separate organization and environment Vault secrets/classes. The single-class approach works conceptually but gives every bound Apigee Kubernetes service account access to every WIF configuration.
1. Set variables
export PROJECT_ID="your-gcp-project-id"
export PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" \
  --format='value(projectNumber)')"

export POOL_ID="your-wif-pool"
export WORKLOAD_PROVIDER_ID="your-ocp-provider"

export APIGEE_NAMESPACE="apigee"
export APIGEE_ORG="your-apigee-org"
export APIGEE_ENV_LIST="dev,prod"

export VAULT_ADDR="https://vault.example.com"
export VAULT_KV_PATH="apigee/all-wif"
export CONFIG_DIR="$PWD/credential-configurations"

mkdir -p "$CONFIG_DIR"

export WIF_PROVIDER_RESOURCE="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${WORKLOAD_PROVIDER_ID}"
2. Generate the WIF credential configurations
A single credential file cannot represent several individually created Google service accounts: service_account_impersonation_url identifies exactly one service account. The loop below creates all required files against the same WIF provider.
for GSA_NAME in \
  apigee-cassandra \
  apigee-guardrails \
  apigee-mart \
  apigee-metrics \
  apigee-runtime \
  apigee-synchronizer \
  apigee-watcher
do
  gcloud iam workload-identity-pools create-cred-config \
    "$WIF_PROVIDER_RESOURCE" \
    --service-account="${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --credential-source-file="/var/run/service-account/token" \
    --credential-source-type="text" \
    --output-file="${CONFIG_DIR}/${GSA_NAME}-credential-configuration.json"
done
If Monetization is enabled:
gcloud iam workload-identity-pools create-cred-config \
  "$WIF_PROVIDER_RESOURCE" \
  --service-account="apigee-mint-task-scheduler@${PROJECT_ID}.iam.gserviceaccount.com" \
  --credential-source-file="/var/run/service-account/token" \
  --credential-source-type="text" \
  --output-file="${CONFIG_DIR}/apigee-mint-task-scheduler-credential-configuration.json"
Do not generate one for apigee-logger; the Apigee 1.16 instructions explicitly exclude it.
Validate the files:
for FILE in "$CONFIG_DIR"/*.json; do
  jq -e . "$FILE" >/dev/null || exit 1
done
3. Put every configuration in one Vault secret
Apigee expects these exact mounted filenames:
- cassandraBackup
- cassandraRestore
- connectAgent
- guardrails
- mart
- metrics
- runtime
- synchronizer
- watcher
- mint, when Monetization is enabled
The documentation generates no separate Connect Agent Google credential. Therefore, the consolidated example uses the MART credential for both mart and connectAgent.
vault kv put "$VAULT_KV_PATH" \
  cassandraBackup=@"${CONFIG_DIR}/apigee-cassandra-credential-configuration.json" \
  cassandraRestore=@"${CONFIG_DIR}/apigee-cassandra-credential-configuration.json" \
  connectAgent=@"${CONFIG_DIR}/apigee-mart-credential-configuration.json" \
  guardrails=@"${CONFIG_DIR}/apigee-guardrails-credential-configuration.json" \
  mart=@"${CONFIG_DIR}/apigee-mart-credential-configuration.json" \
  metrics=@"${CONFIG_DIR}/apigee-metrics-credential-configuration.json" \
  runtime=@"${CONFIG_DIR}/apigee-runtime-credential-configuration.json" \
  synchronizer=@"${CONFIG_DIR}/apigee-synchronizer-credential-configuration.json" \
  watcher=@"${CONFIG_DIR}/apigee-watcher-credential-configuration.json"
With Monetization:
vault kv patch "$VAULT_KV_PATH" \
  mint=@"${CONFIG_DIR}/apigee-mint-task-scheduler-credential-configuration.json"
Verify keys without printing their contents:
vault kv get -format=json "$VAULT_KV_PATH" |
  jq -r '.data.data | keys[]'
Expected output includes all the object names listed above.
4. Create one Vault policy
For a KV v2 engine mounted as secret, vault kv put apigee/all-wif normally maps to the API path secret/data/apigee/all-wif.
vault policy write apigee-all-wif-auth - <<'EOF'
path "secret/data/apigee/all-wif" {
  capabilities = ["read"]
}
EOF
If your KV engine is not mounted at secret/, change both this policy and the secretPath in the SecretProviderClass.
5. Get all Apigee OpenShift service accounts
It is safer to query the actual deployed service accounts than reproduce Apigee’s hashed names manually:
export APIGEE_KSA_NAMES="$(
  oc get serviceaccount -n "$APIGEE_NAMESPACE" \
    -o jsonpath='{range .items[*]}{.metadata.name}{","}{end}' |
  sed 's/,$//'
)"

printf '%s\n' "$APIGEE_KSA_NAMES"
If the namespace contains unrelated service accounts, filter the result:
export APIGEE_KSA_NAMES="$(
  oc get serviceaccount -n "$APIGEE_NAMESPACE" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' |
  grep '^apigee-' |
  paste -sd, -
)"
6. Create one Vault Kubernetes role
vault write auth/kubernetes/role/apigee-all-wif \
  bound_service_account_names="$APIGEE_KSA_NAMES" \
  bound_service_account_namespaces="$APIGEE_NAMESPACE" \
  policies="apigee-all-wif-auth" \
  audience="vault" \
  ttl="1m"
The audience must agree with the projected service-account token audience used by the Vault CSI provider. If your existing Vault Kubernetes auth setup does not enforce audience, omit that line.
7. Create the single SecretProviderClass
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: apigee-all-wif-spc
  namespace: apigee
spec:
  provider: vault
  parameters:
    roleName: apigee-all-wif
    vaultAddress: "https://vault.example.com"
    # Set this if Vault uses a private CA:
    # vaultCACertPath: "/vault/tls/ca.crt"
    objects: |
      - objectName: "cassandraBackup"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "cassandraBackup"
      - objectName: "cassandraRestore"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "cassandraRestore"
      - objectName: "connectAgent"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "connectAgent"
      - objectName: "guardrails"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "guardrails"
      - objectName: "mart"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "mart"
      - objectName: "metrics"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "metrics"
      - objectName: "runtime"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "runtime"
      - objectName: "synchronizer"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "synchronizer"
      - objectName: "watcher"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "watcher"
      # Keep only when Monetization is enabled:
      - objectName: "mint"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "mint"
Save as apigee-all-wif-spc.yaml, then apply it:
oc apply -f apigee-all-wif-spc.yaml

oc get secretproviderclass \
  apigee-all-wif-spc \
  -n "$APIGEE_NAMESPACE" \
  -o yaml
8. Reference the same class in Apigee overrides
Use the same SPC for organization-level and environment-level settings:
serviceAccountSecretProviderClass: apigee-all-wif-spc

envs:
  - name: dev
    serviceAccountSecretProviderClass: apigee-all-wif-spc
  - name: prod
    serviceAccountSecretProviderClass: apigee-all-wif-spc
Depending on the exact overrides schema you are using, the environment property may be represented under your existing envs entries; preserve the surrounding structure.
Google’s documented Apigee 1.16 procedure confirms that WIF credential files use /var/run/service-account/token, that the exact object names must be preserved, and that overrides refer to the Vault classes through the organization and environment serviceAccountSecretProviderClass settings. Apigee hybrid 1.16 WIF with Vault documentation


1:15 AM







what about loger







1:19 AM






apigee-logger is the exception: do not create a WIF credential configuration or Vault entry for it.
Apigee Hybrid 1.16 explicitly says:
Do not create a credential configuration file for the apigee-logger service account.

Logger does not need one of these objects in the SecretProviderClass. Therefore, do not add:
- objectName: "logger"
And do not generate:
apigee-logger-credential-configuration.json
However, the OpenShift Kubernetes service account apigee-logger-apigee-telemetry can remain in the Vault role’s bound_service_account_names. It is harmless but unnecessary for Vault access. For tighter least privilege, remove it from that list.
Your single Vault secret should contain:
cassandraBackup
cassandraRestore
connectAgent
guardrails
mart
metrics
runtime
synchronizer
watcher
mint              # only with Monetization
No logger key is required. This exception is stated in the Apigee Hybrid 1.16 WIF: Vault instructions.


1:19 AM







what is the purpose of logger







1:23 AM






Worked for 7s



apigee-logger collects operational logs from Apigee Hybrid workloads and sends them to Google Cloud Logging.
On OpenShift, the flow is:
Apigee pods
   ↓ stdout/stderr
OpenShift node log files
   ↓
apigee-logger DaemonSet / Fluent Bit
   ↓ using roles/logging.logWriter
Google Cloud Logging
Its purpose is troubleshooting and operational visibility—for example, diagnosing unhealthy runtime, MART, synchronizer, or Cassandra pods. The logger runs once on each eligible node as a DaemonSet. Google’s logging documentation
For OCP/non-GKE, logging is normally enabled with:
logger:
  enabled: true
The Google service account:
apigee-logger@PROJECT_ID.iam.gserviceaccount.com
is assigned:
roles/logging.logWriter
That permission lets the collector write logs into your Google Cloud project. It is only required when you use Apigee’s logger to export logs to Cloud Logging on a non-GKE cluster. Apigee service-account roles
The confusing part is that Apigee 1.16’s WIF/Vault procedure explicitly says not to create a WIF credential configuration for apigee-logger. Therefore:
- Keep the apigee-logger Google service account and its roles/logging.logWriter role if using Cloud Logging.
- Enable the logger on OCP.
- Do not put a logger object in your WIF SecretProviderClass.
- Do not create apigee-logger-credential-configuration.json under that documented WIF/Vault flow.
- If you send logs through an OpenShift-native collector to Loki, Splunk, Elasticsearch, or another destination instead, you may disable Apigee’s logger.


1:23 AM







what if i want to enble logger even though we push logs ocp observability







1:24 AM






Worked for 7s



Yes, you can enable apigee-logger while OpenShift Observability also collects the logs. They are independent collectors reading the same container output:
Apigee stdout/stderr
 ├─ OpenShift collector → Loki/your OCP destination
 └─ apigee-logger       → Google Cloud Logging
This produces two copies in different destinations, with additional CPU, memory, network traffic, and Cloud Logging ingestion cost.
For Apigee Hybrid 1.16 on OCP:
logger:
  enabled: true
  serviceAccountRef: apigee-logger-svc-account
Create the required Kubernetes secret from the apigee-logger Google service-account key:
oc -n apigee create secret generic apigee-logger-svc-account \
  --from-file="client_secret.json=${PROJECT_ID}-apigee-logger.json"
The Google service account needs:
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:apigee-logger@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"
Also ensure the API is enabled:
gcloud services enable logging.googleapis.com \
  --project="$PROJECT_ID"
Important: the documented WIF/Vault flow for Apigee 1.16 excludes logger. Therefore, keep the logger JSON-key secret separate from your consolidated WIF SecretProviderClass; do not add a logger object to that SPC.
Node scheduling on OCP
The logger is a DaemonSet. By default, it can require this node label:
oc label node <APIGEE_NODE_NAME> \
  apigee.cloud.google.com/apigee-logger-enabled=true
Check where it is running:
oc get daemonset,pods -n apigee -l app=apigee-logger -o wide
If you want logger on every eligible node, clear its selector:
logger:
  enabled: true
  serviceAccountRef: apigee-logger-svc-account
  nodeSelector:
    key: ""
    value: ""
Apigee 1.16.9 fixed a logger DaemonSet scheduling issue present in earlier 1.16 patches, so use the latest supported 1.16 patch if possible. Apigee logger configuration, Apigee logging architecture
If you do not need logs in Google Cloud Logging, leave logger.enabled: false; OpenShift Observability will still collect the Apigee containers’ stdout/stderr.


1:24 AM







our gcp team will not proivde any sa.json with us







1:25 AM






Worked for 6s



Then the supported choice for Apigee Hybrid 1.16 on OpenShift is:
logger:
  enabled: false
apigee-logger does not support Workload Identity Federation in Apigee Hybrid 1.16. Google documents this explicitly in the 1.16 overrides instructions and links it to known issue 341099433.
Therefore:
Requirement	Result
No Google service-account JSON keys	Good security policy
WIF for normal Apigee components	Supported
WIF for apigee-logger	Not supported in 1.16
Enable Apigee logger without a JSON key	Not supported
Collect logs with OpenShift Observability	Supported and recommended here


Do not add logger to your Vault secret or SecretProviderClass; doing so will not make the Apigee logger WIF-capable.
Your overrides should look like:
gcp:
  projectID: your-project-id
  region: us-central1
  federatedWorkloadIdentity:
    enabled: true
    audience: "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
    credentialSourceFile: "/var/run/service-account/token"

logger:
  enabled: false
OpenShift Observability can continue collecting the stdout/stderr logs from all Apigee pods. You can retain those logs in Loki or forward them through your organization’s supported logging pipeline.
If Google Cloud Logging is mandatory, the keyless design should be:
Apigee pods
    ↓ stdout/stderr
OpenShift logging collector
    ↓ keyless authentication managed outside apigee-logger
Google Cloud Logging
That would be a custom OpenShift logging integration, not the Apigee logger component. Your platform/GCP teams would need to configure the collector’s WIF identity and grant it roles/logging.logWriter.
So the clean decision is: use WIF for Apigee, disable apigee-logger, and use OpenShift Observability as the logging system.


1:25 AM







what about 1.17







1:27 AM






Worked for 5s



Apigee Hybrid 1.17 has the same limitation: apigee-logger still does not support Workload Identity Federation.
Google’s known issue 341099433 remains open. The reason is that the Fluent Bit implementation used by apigee-logger cannot use Apigee’s federated credential configuration. Apigee known issues
Therefore, on OpenShift with Apigee 1.17:
Authentication method	Logger supported?
Google service-account JSON key	Yes
JSON key stored in Kubernetes Secret	Yes
JSON key stored in Vault	Yes
WIF credential configuration stored in Vault	No
WIF credential configuration stored in Kubernetes Secret	No
OpenShift Observability collection	Yes


The 1.17 documentation still says:
Do not create a credential configuration file for the apigee-logger service account.

There is an important distinction in the 1.17 Vault documentation:
- The ordinary Vault with service-account keys example contains a logger key.
- The WIF with Vault procedure omits logger.
Because your GCP team will not issue JSON keys, use:
logger:
  enabled: false
Continue using WIF for the other Apigee components:
gcp:
  projectID: your-project-id
  region: us-central1
  federatedWorkloadIdentity:
    enabled: true
    audience: "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
    credentialSourceFile: "/var/run/service-account/token"

logger:
  enabled: false
Your supported architecture remains:
Apigee 1.17 pods
       ↓ stdout/stderr
OpenShift Observability collector
       ↓
Loki / Splunk / Elasticsearch / approved destination
If Cloud Logging is required, configure the OpenShift collector to forward there using a separately supported keyless identity mechanism. Do not enable apigee-logger without credentials—it would deploy a collector that cannot authenticate and would continually fail to export logs.
See the Apigee Hybrid 1.17 authentication instructions.You can consolidate this to:
- One Google Workload Identity Pool/provider.
- Separate credential-configuration JSON per Google service account—required because each file has a different impersonation URL.
- One Vault KV secret containing all configurations.
- One Vault Kubernetes role.
- One OpenShift SecretProviderClass exposing all expected Apigee filenames.
This differs from Google’s documented least-privilege layout, which uses separate organization and environment Vault secrets/classes. The single-class approach works conceptually but gives every bound Apigee Kubernetes service account access to every WIF configuration.
1. Set variables
export PROJECT_ID="your-gcp-project-id"
export PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" \
  --format='value(projectNumber)')"

export POOL_ID="your-wif-pool"
export WORKLOAD_PROVIDER_ID="your-ocp-provider"

export APIGEE_NAMESPACE="apigee"
export APIGEE_ORG="your-apigee-org"
export APIGEE_ENV_LIST="dev,prod"

export VAULT_ADDR="https://vault.example.com"
export VAULT_KV_PATH="apigee/all-wif"
export CONFIG_DIR="$PWD/credential-configurations"

mkdir -p "$CONFIG_DIR"

export WIF_PROVIDER_RESOURCE="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/providers/${WORKLOAD_PROVIDER_ID}"
2. Generate the WIF credential configurations
A single credential file cannot represent several individually created Google service accounts: service_account_impersonation_url identifies exactly one service account. The loop below creates all required files against the same WIF provider.
for GSA_NAME in \
  apigee-cassandra \
  apigee-guardrails \
  apigee-mart \
  apigee-metrics \
  apigee-runtime \
  apigee-synchronizer \
  apigee-watcher
do
  gcloud iam workload-identity-pools create-cred-config \
    "$WIF_PROVIDER_RESOURCE" \
    --service-account="${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
    --credential-source-file="/var/run/service-account/token" \
    --credential-source-type="text" \
    --output-file="${CONFIG_DIR}/${GSA_NAME}-credential-configuration.json"
done
If Monetization is enabled:
gcloud iam workload-identity-pools create-cred-config \
  "$WIF_PROVIDER_RESOURCE" \
  --service-account="apigee-mint-task-scheduler@${PROJECT_ID}.iam.gserviceaccount.com" \
  --credential-source-file="/var/run/service-account/token" \
  --credential-source-type="text" \
  --output-file="${CONFIG_DIR}/apigee-mint-task-scheduler-credential-configuration.json"
Do not generate one for apigee-logger; the Apigee 1.16 instructions explicitly exclude it.
Validate the files:
for FILE in "$CONFIG_DIR"/*.json; do
  jq -e . "$FILE" >/dev/null || exit 1
done
3. Put every configuration in one Vault secret
Apigee expects these exact mounted filenames:
- cassandraBackup
- cassandraRestore
- connectAgent
- guardrails
- mart
- metrics
- runtime
- synchronizer
- watcher
- mint, when Monetization is enabled
The documentation generates no separate Connect Agent Google credential. Therefore, the consolidated example uses the MART credential for both mart and connectAgent.
vault kv put "$VAULT_KV_PATH" \
  cassandraBackup=@"${CONFIG_DIR}/apigee-cassandra-credential-configuration.json" \
  cassandraRestore=@"${CONFIG_DIR}/apigee-cassandra-credential-configuration.json" \
  connectAgent=@"${CONFIG_DIR}/apigee-mart-credential-configuration.json" \
  guardrails=@"${CONFIG_DIR}/apigee-guardrails-credential-configuration.json" \
  mart=@"${CONFIG_DIR}/apigee-mart-credential-configuration.json" \
  metrics=@"${CONFIG_DIR}/apigee-metrics-credential-configuration.json" \
  runtime=@"${CONFIG_DIR}/apigee-runtime-credential-configuration.json" \
  synchronizer=@"${CONFIG_DIR}/apigee-synchronizer-credential-configuration.json" \
  watcher=@"${CONFIG_DIR}/apigee-watcher-credential-configuration.json"
With Monetization:
vault kv patch "$VAULT_KV_PATH" \
  mint=@"${CONFIG_DIR}/apigee-mint-task-scheduler-credential-configuration.json"
Verify keys without printing their contents:
vault kv get -format=json "$VAULT_KV_PATH" |
  jq -r '.data.data | keys[]'
Expected output includes all the object names listed above.
4. Create one Vault policy
For a KV v2 engine mounted as secret, vault kv put apigee/all-wif normally maps to the API path secret/data/apigee/all-wif.
vault policy write apigee-all-wif-auth - <<'EOF'
path "secret/data/apigee/all-wif" {
  capabilities = ["read"]
}
EOF
If your KV engine is not mounted at secret/, change both this policy and the secretPath in the SecretProviderClass.
5. Get all Apigee OpenShift service accounts
It is safer to query the actual deployed service accounts than reproduce Apigee’s hashed names manually:
export APIGEE_KSA_NAMES="$(
  oc get serviceaccount -n "$APIGEE_NAMESPACE" \
    -o jsonpath='{range .items[*]}{.metadata.name}{","}{end}' |
  sed 's/,$//'
)"

printf '%s\n' "$APIGEE_KSA_NAMES"
If the namespace contains unrelated service accounts, filter the result:
export APIGEE_KSA_NAMES="$(
  oc get serviceaccount -n "$APIGEE_NAMESPACE" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' |
  grep '^apigee-' |
  paste -sd, -
)"
6. Create one Vault Kubernetes role
vault write auth/kubernetes/role/apigee-all-wif \
  bound_service_account_names="$APIGEE_KSA_NAMES" \
  bound_service_account_namespaces="$APIGEE_NAMESPACE" \
  policies="apigee-all-wif-auth" \
  audience="vault" \
  ttl="1m"
The audience must agree with the projected service-account token audience used by the Vault CSI provider. If your existing Vault Kubernetes auth setup does not enforce audience, omit that line.
7. Create the single SecretProviderClass
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: apigee-all-wif-spc
  namespace: apigee
spec:
  provider: vault
  parameters:
    roleName: apigee-all-wif
    vaultAddress: "https://vault.example.com"
    # Set this if Vault uses a private CA:
    # vaultCACertPath: "/vault/tls/ca.crt"
    objects: |
      - objectName: "cassandraBackup"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "cassandraBackup"
      - objectName: "cassandraRestore"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "cassandraRestore"
      - objectName: "connectAgent"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "connectAgent"
      - objectName: "guardrails"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "guardrails"
      - objectName: "mart"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "mart"
      - objectName: "metrics"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "metrics"
      - objectName: "runtime"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "runtime"
      - objectName: "synchronizer"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "synchronizer"
      - objectName: "watcher"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "watcher"
      # Keep only when Monetization is enabled:
      - objectName: "mint"
        secretPath: "secret/data/apigee/all-wif"
        secretKey: "mint"
Save as apigee-all-wif-spc.yaml, then apply it:
oc apply -f apigee-all-wif-spc.yaml

oc get secretproviderclass \
  apigee-all-wif-spc \
  -n "$APIGEE_NAMESPACE" \
  -o yaml
8. Reference the same class in Apigee overrides
Use the same SPC for organization-level and environment-level settings:
serviceAccountSecretProviderClass: apigee-all-wif-spc

envs:
  - name: dev
    serviceAccountSecretProviderClass: apigee-all-wif-spc
  - name: prod
    serviceAccountSecretProviderClass: apigee-all-wif-spc
Depending on the exact overrides schema you are using, the environment property may be represented under your existing envs entries; preserve the surrounding structure.
Google’s documented Apigee 1.16 procedure confirms that WIF credential files use /var/run/service-account/token, that the exact object names must be preserved, and that overrides refer to the Vault classes through the organization and environment serviceAccountSecretProviderClass settings. Apigee hybrid 1.16 WIF with Vault documentation


1:15 AM







what about loger







1:19 AM






apigee-logger is the exception: do not create a WIF credential configuration or Vault entry for it.
Apigee Hybrid 1.16 explicitly says:
Do not create a credential configuration file for the apigee-logger service account.

Logger does not need one of these objects in the SecretProviderClass. Therefore, do not add:
- objectName: "logger"
And do not generate:
apigee-logger-credential-configuration.json
However, the OpenShift Kubernetes service account apigee-logger-apigee-telemetry can remain in the Vault role’s bound_service_account_names. It is harmless but unnecessary for Vault access. For tighter least privilege, remove it from that list.
Your single Vault secret should contain:
cassandraBackup
cassandraRestore
connectAgent
guardrails
mart
metrics
runtime
synchronizer
watcher
mint              # only with Monetization
No logger key is required. This exception is stated in the Apigee Hybrid 1.16 WIF: Vault instructions.


1:19 AM







what is the purpose of logger







1:23 AM






Worked for 7s



apigee-logger collects operational logs from Apigee Hybrid workloads and sends them to Google Cloud Logging.
On OpenShift, the flow is:
Apigee pods
   ↓ stdout/stderr
OpenShift node log files
   ↓
apigee-logger DaemonSet / Fluent Bit
   ↓ using roles/logging.logWriter
Google Cloud Logging
Its purpose is troubleshooting and operational visibility—for example, diagnosing unhealthy runtime, MART, synchronizer, or Cassandra pods. The logger runs once on each eligible node as a DaemonSet. Google’s logging documentation
For OCP/non-GKE, logging is normally enabled with:
logger:
  enabled: true
The Google service account:
apigee-logger@PROJECT_ID.iam.gserviceaccount.com
is assigned:
roles/logging.logWriter
That permission lets the collector write logs into your Google Cloud project. It is only required when you use Apigee’s logger to export logs to Cloud Logging on a non-GKE cluster. Apigee service-account roles
The confusing part is that Apigee 1.16’s WIF/Vault procedure explicitly says not to create a WIF credential configuration for apigee-logger. Therefore:
- Keep the apigee-logger Google service account and its roles/logging.logWriter role if using Cloud Logging.
- Enable the logger on OCP.
- Do not put a logger object in your WIF SecretProviderClass.
- Do not create apigee-logger-credential-configuration.json under that documented WIF/Vault flow.
- If you send logs through an OpenShift-native collector to Loki, Splunk, Elasticsearch, or another destination instead, you may disable Apigee’s logger.


1:23 AM







what if i want to enble logger even though we push logs ocp observability







1:24 AM






Worked for 7s



Yes, you can enable apigee-logger while OpenShift Observability also collects the logs. They are independent collectors reading the same container output:
Apigee stdout/stderr
 ├─ OpenShift collector → Loki/your OCP destination
 └─ apigee-logger       → Google Cloud Logging
This produces two copies in different destinations, with additional CPU, memory, network traffic, and Cloud Logging ingestion cost.
For Apigee Hybrid 1.16 on OCP:
logger:
  enabled: true
  serviceAccountRef: apigee-logger-svc-account
Create the required Kubernetes secret from the apigee-logger Google service-account key:
oc -n apigee create secret generic apigee-logger-svc-account \
  --from-file="client_secret.json=${PROJECT_ID}-apigee-logger.json"
The Google service account needs:
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:apigee-logger@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"
Also ensure the API is enabled:
gcloud services enable logging.googleapis.com \
  --project="$PROJECT_ID"
Important: the documented WIF/Vault flow for Apigee 1.16 excludes logger. Therefore, keep the logger JSON-key secret separate from your consolidated WIF SecretProviderClass; do not add a logger object to that SPC.
Node scheduling on OCP
The logger is a DaemonSet. By default, it can require this node label:
oc label node <APIGEE_NODE_NAME> \
  apigee.cloud.google.com/apigee-logger-enabled=true
Check where it is running:
oc get daemonset,pods -n apigee -l app=apigee-logger -o wide
If you want logger on every eligible node, clear its selector:
logger:
  enabled: true
  serviceAccountRef: apigee-logger-svc-account
  nodeSelector:
    key: ""
    value: ""
Apigee 1.16.9 fixed a logger DaemonSet scheduling issue present in earlier 1.16 patches, so use the latest supported 1.16 patch if possible. Apigee logger configuration, Apigee logging architecture
If you do not need logs in Google Cloud Logging, leave logger.enabled: false; OpenShift Observability will still collect the Apigee containers’ stdout/stderr.


1:24 AM







our gcp team will not proivde any sa.json with us







1:25 AM






Worked for 6s



Then the supported choice for Apigee Hybrid 1.16 on OpenShift is:
logger:
  enabled: false
apigee-logger does not support Workload Identity Federation in Apigee Hybrid 1.16. Google documents this explicitly in the 1.16 overrides instructions and links it to known issue 341099433.
Therefore:
Requirement	Result
No Google service-account JSON keys	Good security policy
WIF for normal Apigee components	Supported
WIF for apigee-logger	Not supported in 1.16
Enable Apigee logger without a JSON key	Not supported
Collect logs with OpenShift Observability	Supported and recommended here


Do not add logger to your Vault secret or SecretProviderClass; doing so will not make the Apigee logger WIF-capable.
Your overrides should look like:
gcp:
  projectID: your-project-id
  region: us-central1
  federatedWorkloadIdentity:
    enabled: true
    audience: "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
    credentialSourceFile: "/var/run/service-account/token"

logger:
  enabled: false
OpenShift Observability can continue collecting the stdout/stderr logs from all Apigee pods. You can retain those logs in Loki or forward them through your organization’s supported logging pipeline.
If Google Cloud Logging is mandatory, the keyless design should be:
Apigee pods
    ↓ stdout/stderr
OpenShift logging collector
    ↓ keyless authentication managed outside apigee-logger
Google Cloud Logging
That would be a custom OpenShift logging integration, not the Apigee logger component. Your platform/GCP teams would need to configure the collector’s WIF identity and grant it roles/logging.logWriter.
So the clean decision is: use WIF for Apigee, disable apigee-logger, and use OpenShift Observability as the logging system.


1:25 AM







what about 1.17







1:27 AM






Worked for 5s



Apigee Hybrid 1.17 has the same limitation: apigee-logger still does not support Workload Identity Federation.
Google’s known issue 341099433 remains open. The reason is that the Fluent Bit implementation used by apigee-logger cannot use Apigee’s federated credential configuration. Apigee known issues
Therefore, on OpenShift with Apigee 1.17:
Authentication method	Logger supported?
Google service-account JSON key	Yes
JSON key stored in Kubernetes Secret	Yes
JSON key stored in Vault	Yes
WIF credential configuration stored in Vault	No
WIF credential configuration stored in Kubernetes Secret	No
OpenShift Observability collection	Yes


The 1.17 documentation still says:
Do not create a credential configuration file for the apigee-logger service account.

There is an important distinction in the 1.17 Vault documentation:
- The ordinary Vault with service-account keys example contains a logger key.
- The WIF with Vault procedure omits logger.
Because your GCP team will not issue JSON keys, use:
logger:
  enabled: false
Continue using WIF for the other Apigee components:
gcp:
  projectID: your-project-id
  region: us-central1
  federatedWorkloadIdentity:
    enabled: true
    audience: "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
    credentialSourceFile: "/var/run/service-account/token"

logger:
  enabled: false
Your supported architecture remains:
Apigee 1.17 pods
       ↓ stdout/stderr
OpenShift Observability collector
       ↓
Loki / Splunk / Elasticsearch / approved destination
If Cloud Logging is required, configure the OpenShift collector to forward there using a separately supported keyless identity mechanism. Do not enable apigee-logger without credentials—it would deploy a collector that cannot authenticate and would continually fail to export logs.
See the Apigee Hybrid 1.17 authentication instructions.

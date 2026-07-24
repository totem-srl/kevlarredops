---
name: vuln-assessment-phase
tags: [vuln_assess]
description: Vulnerability assessment phase — scanning, CVE lookup, misconfig detection. Use when the current phase is VULN_ASSESS.
---

# Vulnerability Assessment Checklist

## Automated Vulnerability Scanning
```bash
# Nuclei — critical and high first
nuclei -u <target> -severity critical,high -o nuclei_crithigh.txt
nuclei -u <target> -t cves/ -o nuclei_cves.txt
nuclei -u <target> -t misconfiguration/ -o nuclei_misconfig.txt
nuclei -u <target> -t exposures/ -o nuclei_exposures.txt

# From list of URLs
nuclei -l urls.txt -severity critical,high -o nuclei_bulk.txt

# Nmap vuln scripts
nmap --script vuln -p <ports> <target> -oA vuln_scan
```

## CVE Lookup
For each identified service version:
```bash
searchsploit <service> <version>
searchsploit --nmap services.xml   # parse nmap output
```

## Default Credentials Check
Test common defaults for discovered services:
- Web admin panels: admin/admin, admin/password, root/root
- Databases: root/(empty), sa/(empty), postgres/postgres
- SSH: root/toor, admin/admin
- Network devices: admin/admin, cisco/cisco

```bash
# Hydra single credential test
hydra -l admin -p admin <target> <protocol>
```

## Web Vulnerability Assessment
```bash
# SQL injection discovery
sqlmap -u "http://<target>/page?id=1" --batch --level 3 --risk 2

# XSS scanning
dalfox url "http://<target>/page?q=test"

# SSL/TLS issues
sslscan <target>
testssl.sh <target>

# Security headers
curl -sI http://<target> | grep -iE "x-frame|x-content|strict-transport|content-security|x-xss"
```

## Misconfiguration Checks
- Anonymous FTP access: `ftp <target>` with anonymous/anonymous
- Open Redis: `redis-cli -h <target> INFO`
- MongoDB no auth: `mongosh --host <target> --eval "db.adminCommand('listDatabases')"`
- Elasticsearch open: `curl http://<target>:9200/_cat/indices`
- Docker API exposed: `curl http://<target>:2375/version`
- Kubernetes API: `curl -k https://<target>:6443/api`

## Severity Classification
- **Critical**: RCE, auth bypass, default creds on critical service, SQLi with data access
- **High**: File read/write, privilege escalation vector, SSRF to internal
- **Medium**: XSS (stored), information disclosure (sensitive), misconfig with limited impact
- **Low**: XSS (reflected), verbose errors, minor info disclosure
- **Info**: Open ports, version disclosure, missing headers

## Phase Completion Criteria
Move to EXPLOITATION when:
- Automated scans completed
- CVEs checked for all versioned services
- Default credentials tested
- Web vulns assessed
- All findings recorded with severity and evidence

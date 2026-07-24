---
name: playbook-infra
description: Infrastructure pentest playbook — PTES-based phase flow for internal networks, servers, and non-web services. Load at the START of an internal/infra engagement or multi-host network assessment. Triggers - internal network, subnet/CIDR scan, infra pentest, multi-host, pivoting, lateral movement across services.
---

# Infrastructure Pentest Playbook

Based on PTES (Penetration Testing Execution Standard).

## Scope Verification
Before starting:
- Confirm target IPs/CIDRs are authorized
- Identify excluded hosts/services
- Note time windows and rules of engagement
- Verify emergency contacts

## Phase Flow

### 1. Passive Reconnaissance
- WHOIS, DNS records, ASN mapping
- Subdomain enumeration (passive sources only)
- Certificate transparency logs
- Shodan/Censys for exposed services
- **Goal**: Map attack surface without touching targets

### 2. Active Enumeration
- Host discovery: `nmap -sn <cidr>`
- Port scan: `nmap -sS -p- --min-rate 5000 <targets>`
- Service detection: `nmap -sV -sC -p <ports> <targets>`
- OS detection: `nmap -O <targets>`
- UDP top ports: `nmap -sU --top-ports 50 <targets>`
- Protocol-specific enumeration (SMB, LDAP, SNMP, NFS, RPC)
- **Goal**: Complete inventory of hosts, ports, services, versions

### 3. Vulnerability Assessment
- Automated: `nuclei -severity critical,high` + `nmap --script vuln`
- CVE search for every versioned service: `searchsploit <service> <version>`
- Default credential checks on all login services
- SSL/TLS configuration: `sslscan`, `testssl.sh`
- Misconfiguration checks (open databases, exposed APIs, anonymous access)
- **Goal**: Prioritized vulnerability list with evidence

### 4. Exploitation
Priority order:
1. Known CVEs with public exploits (critical/high)
2. Default/weak credentials
3. Misconfigurations allowing access
4. Brute force attacks
5. Manual exploitation of custom services
- **Goal**: Gain initial access, document every attempt

### 5. Post-Exploitation
- Privilege escalation on every accessed host
- Credential harvesting (files, memory, databases)
- Lateral movement with found credentials
- Network pivoting to unreachable segments
- Data discovery (sensitive files, databases, secrets)
- **Goal**: Demonstrate maximum impact, document attack path

### 6. Reporting
- Executive summary with risk rating
- Technical findings by severity (CVSS scoring)
- Attack path narrative with evidence
- Remediation recommendations prioritized by risk
- Host summary table

## Tool Arsenal
**Scanning**: nmap, masscan, nuclei, nikto
**Enumeration**: enum4linux-ng, ldapsearch, snmpwalk, gobuster
**Exploitation**: metasploit, searchsploit, hydra, crackmapexec
**Post-exploit**: linpeas/winpeas, mimikatz, impacket suite
**Reporting**: custom report generator

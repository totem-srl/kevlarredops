---
name: playbook-infra
description: Infrastructure pentest playbook — PTES-based phase flow for internal networks, servers, and non-web services. Load at the START of an internal/infra engagement or multi-host network assessment. Triggers - internal network, subnet/CIDR scan, infra pentest, multi-host, pivoting, lateral movement across services.
tags: [recon, enumeration, vuln_assess, exploitation, post_exploit]
---

# Infrastructure Pentest Playbook

PTES-based flow. This is the ORDER; the deep technique lives in the `svc-*` skills — load the one matching each discovered service.

## 0. Scope gate FIRST
- `scope_check` every CIDR/host BEFORE any packet leaves. Excluded hosts noted and skipped.
- Note time windows, rules of engagement, emergency contacts.
- Scan noise is contract noise: rate-limit scans on production windows (`--min-rate` tuned down, T4 only where authorized).
- `state_update` every confirmed host/service as you go — state is the shared memory across agents and sessions.

## Phase Flow

### 1. Passive Recon
- WHOIS, DNS records, ASN mapping; subdomains (passive sources); CT logs; Shodan/Censys.
- **Goal**: attack surface mapped with zero target touch. Exit: inventory draft in `state_update`.

### 2. Active Enumeration
- Host discovery: `nmap -sn <cidr>` → port scan `nmap -sS -p- --min-rate 5000` → `nmap -sV -sC` on live ports → UDP top-50 `-sU`.
- Protocol-specific: SMB/LDAP/SNMP/NFS/RPC → load matching svc skill (smb, kerberos, adcs...).
- Parse everything through `nmap_parse`, never eyeball raw scans.
- **Goal**: complete host/service/version inventory. Exit: every open port classified or flagged unknown.

### 3. Vulnerability Assessment
- Automated pass: `nuclei -severity critical,high` → `nuclei_parse`; `nmap --script vuln` as secondary signal only.
- CVE search EVERY versioned service: `searchsploit <service> <version>`. Backported-patch distros (RHEL/Ubuntu LTS) make version→CVE mapping unreliable — verify exploitability, don't trust the banner.
- Default creds on all login services; SSL/TLS config via sslscan/testssl.sh (weak-algo findings are hardening notes, Medium cap unless exploitable).
- Misconfig sweep: open databases, exposed APIs, anonymous access.
- **Goal**: prioritized list, each entry `suspected` until proven. Exit: top-5 exploitation queue agreed.

### 4. Exploitation
Priority order:
1. Known CVEs with public exploits (critical/high) — vet PoC before running; destructive PoCs need operator unlock via `phase_control`
2. Default/weak credentials (`cred_spray`, lockout-aware, low thread count)
3. Misconfigurations allowing access
4. Manual exploitation of custom services
- Every success = shell/exec proof (see PROVE IMPACT) + immediate `state_update` (Access node + Credential if harvested).
- **Goal**: initial access documented with evidence chain. Exit: at least one proven foothold OR queue exhausted with negative results logged.

### 5. Post-Exploitation
- Local privesc every host (post-exploit phase skill checklists), credential harvesting (files/memory/databases), lateral movement reusing creds (`cred_spray` reuse checks), pivoting (`tunnel_manage`) to unreachable segments, data discovery.
- After ≥2 compromised nodes run `attack_path_suggest` — graph paths beat ad-hoc wandering.
- **Goal**: maximum demonstrated impact + full attack path narrative.

### 6. Reporting
- Executive summary by business risk; technical findings w/ CVSS + reproduction steps + evidence; attack-path narrative; remediation priority; host summary table.
- `report_gen` builds the deterministic skeleton from engagement state; you supply the narrative quality.

## PROVE IMPACT — infra edition
A finding graduates `suspected → confirmed` ONLY with concrete impact evidence:
- RCE/shell: verbatim `id && hostname` output from the TARGET.
- Data access: one real sensitive record/file quoted (redact half), not a directory listing.
- Auth bypass: successful authenticated action that should have been denied.
- Reachability alone (open port, version match, banner) caps severity at Low/Medium `suspected`.

## Tooling integration
- `scope_check` before every NEW subnet — pivot discoveries may cross the authorization boundary silently.
- `nmap_parse` / `nuclei_parse` / `gobuster_parse` / `cme_parse` / `sqlmap_parse` — always parse, never paste raw.
- `cred_spray` for any password testing (lockout-aware). `tunnel_manage` for pivots. `attack_path_suggest` at ≥2 nodes. `report_gen` at close.

## Pitfalls
- UDP scans lie: `open|filtered` ≠ closed — targeted probe (e.g. `nmap -sU -p161 -sV`) before writing off SNMP.
- Firewall rate-limiting masquerades as "host down" mid-scan — re-check silent drops with slow scan before concluding.
- Creds valid but "failed" often = protocol mismatch (NTLM vs Kerberos, LM hash truncation) — try `cme` protocol variants before discarding.
- Internal DNS may resolve differently than your resolver — use the domain's own DNS server for enum (`--dnsserver`).
- Scanning can crash legacy/embedded devices (printers, OT) — excluded-host list exists for a reason; when in doubt ask operator.
- NEVER destructive actions (shutdown, format, factory-reset PoCs) without explicit operator unlock.

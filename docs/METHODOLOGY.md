# PentestCode Methodology — How Penetration Testing Works

Reference map of the pentest discipline and how PentestCode implements each part.
Audience: contributors tuning agent behavior, prompts, skills, or tools.

## The discipline

A penetration test is a scoped, authorized attack simulation with one deliverable:
**proven, reproducible impact** ranked by business risk. Everything else is noise.
The kill criteria are simple — a finding counts only when:

1. Evidence exists (raw output, not inference).
2. Impact is demonstrated (data read, shell obtained, privilege gained).
3. Reproduction steps fit in a report a defender can follow.

Unproven findings are `suspected`, never reported as confirmed. This single rule
drives most of the product design (see [Evidence chain](#evidence-chain)).

## Phase lifecycle

Standard kill-chain used by the industry (PTES / OSSTMM lineage), mapped to
PentestCode phases (`PentestPhase` in `packages/core/src/engagement/schema.ts`):

| # | Phase | Goal | Exit condition | Skill |
|---|-------|------|----------------|-------|
| 1 | recon | Map external surface, org data, exposed assets | target inventory w/ scope_check pass | `phases/recon` |
| 2 | enumeration | Enumerate services, versions, shares, users, routes | per-host service matrix in state | `phases/enumeration` |
| 3 | vuln-assessment | Correlate versions/configs against known vulns; validate | vuln list w/ confidence + evidence | `phases/vuln-assessment` |
| 4 | exploitation | Gain initial access on weakest proven link | first shell/cred = foothold recorded | `phases/exploitation` |
| 5 | post-exploit | Escalate, pivot, persist (in-scope), exfil-proof | highest AccessLevel reached + path | `phases/post-exploit` |
| 6 | reporting | Findings → evidence-backed report | report generated via report_gen | `phases/reporting` |

Phase flow is not strictly linear — loops back to 2/3 from any phase are normal
(new host found during post-exploit). `phase_control` tool gates transitions;
`state_query` reads current position.

## Target domains

### Infrastructure (network)
Hosts/services over TCP/IP. Tools: nmap_parse, gobuster_parse, tunnel_manage.
Skills: `playbooks/infra`, `services/pivoting`, `services/web-server`.

### Directory / identity (AD)
Domains, Kerberos, LDAP, certificates, delegation. Highest-value modern target.
Tools: bloodhound_parse, cme_parse, cred_spray, jwt_analyze (for ADFS/OAuth).
Skills: `playbooks/ad`, `services/adcs`, `services/kerberos`, `services/smb`,
`services/cracking`, `services/relay`.

### Web application
HTTP apps, APIs, auth flows. OWASP Top 10 plus logic abuse.
Tools: nuclei_parse, sqlmap_parse, xss_detect, jwt_analyze.
Skills: `playbooks/webapp`, `web/*` (sqli ssrf ssti xxe lfi upload deserialization
auth-bypass api-testing).

### Cloud (AWS/GCP/Azure)
Identity-first: metadata endpoints, token theft, actAs/PassRole chains.
Skills: `playbooks/cloud`. Containers: `services/docker-k8s`.

### CI/CD & supply chain
Runner escape, secret leakage, pipeline injection. Skill: `services/cicd`.

## Core state model

All agents share one structured engagement state (`EngagementStore`,
`packages/core/src/engagement/store.ts`). Entities:

- **Host** — IP/DNS, OS guess, segments.
- **Service** — port/product/version/auth posture per host.
- **Vulnerability** — status `suspected → confirmed → exploited` or
  `false_positive`; carries EvidenceItem list; confidence derived from evidence.
- **Credential** — username/hash/plaintext/type, source, validity.
- **Access** — what level where (none/user/admin/SYSTEM/root/domain).
- **AttackStep** — ordered chain of actions with evidence at each step.
- **Relationship graph** — EXPLOITED_VIA, CREDENTIAL_FROM, ADMIN_OF, PIVOT_TO,
  enabling Dijkstra/Yen K-shortest **attack paths** (`attack-path-suggest` tool).
- **DomainState** — AD objects: users/groups/computers/trusts/delegation.
- **Objective / Scope / TaskTreeNode** — mission control: what we're doing,
  allowed targets, decomposition tree.

Rule: every meaningful action calls `state_update`. State survives sessions —
the engagement is durable, agents are disposable.

## Evidence chain

```
tool output (raw)  →  parsed artifact (nmap_parse etc.)  →  Vulnerability.evidence[]
                   →  deriveConfidence()                 →  suspected | confirmed
exploit succeeds   →  AttackStep w/ proof                →  exploited (reportable)
critic subagent    →  false_positive filter              →  removed before report
```

The critic agent challenges every confirmed finding pre-report. Report generation
(`report_gen`) refuses unproven claims — severity ordering, executive summary,
recommendations all read directly from EngagementStore.

## Worked example — one finding end to end

A compressed AD engagement showing every layer in motion. Scope:
`10.10.0.0/24`, objective `pentest`, mode `guided`.

```
1. SCOPE      scope_check("10.10.20.15")        → allowed; recorded in Scope
2. RECON      shell: nmap -sV -p- 10.10.20.15   → raw output
3. PARSE      nmap_parse                        → Service rows in state:
                                                 88/kerberos, 445/smb, 5985/winrm on DC01
              state_update                      → Host DC01 + 3 Services persisted
4. ENUM       identity subagent: bloodhound_parse over SharpHound zip
              → DomainState populated: users, groups, SPNs, delegation edges
              → svc-sql@CORP flagged: SPN present (roastable), adminCount=false
5. DECIDE     attack_path_suggest               → shortest path:
              svc-sql roast → crack → PTH → DA? no — but svc-sql RDP on SQL01
              → SQL01 has cred to DC01 backup operator (stored link)
6. EXPLOIT    shell: GetUserSPNs corp.local/svc-legacy:noPw1! -request
              → TGS hash → hashcat -m 13100 → plaintext recovered
7. PROVE      cme smb 10.10.20.15 -u svc-sql -p '<cracked>' --sam
              → Pwn3d! on SQL01, SAM dumped. AttackStep recorded with both outputs.
              Credential(svc-sql/plaintext) validity=valid source=kerberoast
8. ESCALATE   relay path or ADCS path per skills; each hop repeats 6–7.
              Final: Access(DA on corp.local) w/ evidence chain.
9. CRITIC     critic subagent re-reads evidence for step 6: was the SPN
              account actually used? yes (last_logon recent) → stands.
10. REPORT    report_gen                        → finding "Weak service
              account credential enables domain compromise", severity HIGH,
              reproduction = steps 2–7 verbatim, evidence linked.
```

What did NOT happen is equally instructive: no finding was claimed off the nmap
version banner alone (that would be `suspected` at best); the cracked hash alone
was not impact until an authenticated command executed (`PROVE IMPACT` rule);
every hop wrote state before moving on, so a session crash loses nothing.

## Multi-agent architecture

Coordinator (`pentest` lead) delegates to specialists rather than context-loading
every domain into one prompt:

| Agent | Domain | Prompt |
|-------|--------|--------|
| recon | external surface | session/prompt/recon.txt |
| scanner | vuln scanning | scanner.txt |
| enumerator | service depth | enumerator.txt |
| exploiter | initial access | exploiter.txt |
| identity | AD/Kerberos | identity.txt |
| infrastructure | SNMP/IPMI/db | infrastructure.txt |
| webapp | HTTP/API | webapp.txt |
| post-exploit | escalation/pivot | post-exploit.txt |
| exploit-dev | custom payloads | kernel-exploit.txt family |
| critic | FP challenge | critic.txt |
| reporter | deliverable | reporter.txt |

Pattern source: HPTSA planning+execution split (arXiv 2410.02246). Coordinator
holds strategy; subagents hold domain checklists; both read/write shared state.

## Skills system

Skills (`skills/` repo root, embedded at build time, layered
`bundled < packs < user` at runtime) are on-demand domain knowledge injected when
triggered. Four kinds:

- **Phase checklists** (6): exit-criteria-driven phase guides.
- **Playbooks** (4): cross-cutting campaign guides per environment class.
- **Service skills** (15): protocol-specific deep dives (smb ssh ftp dns database
  mail cicd docker-k8s web-server pivoting adcs kerberos cracking relay osint).
- **Web vuln skills** (14): per-vuln detect→decide→exploit→prove loops
  (sqli ssti ssrf xxe lfi-traversal upload-rce deserialization
  auth-bypass-idor api-testing command-injection xss).
- **Reverse & specialized skills** (35): malware analysis, binary/JS/.NET/mobile
  reversing, pwn chains, firmware, OT/ICS, SDR, forensics, threat intel,
  LLM security, supply chain — loaded when the engagement extends beyond
  network/web pentesting into RE and specialized domains.

Every skill follows house format: frontmatter triggers → When this fires →
Detect (tool-first) → Decide → Exploit → PROVE IMPACT → Tooling → Pitfalls.

Frontmatter constraint: `name`, `description`, and `tags` must each sit on a
single line (put trigger phrases inline in the description). A multiline
description continuation fails the YAML parse and the skill is silently skipped
at discovery — the only signal is a "failed to load skill" log line.

## Modes & human control

- **Modes** (`auto | free | guided`) × pause behaviors — how much autonomy the
  fleet has between operator checkpoints (`phase_control`, `/pause`).
- **Scope gate** — `scope_check` blocks out-of-bounds targets; breadth expansion
  requires explicit Yes.
- **Destructive payload guard** — DoS/data-destruction actions need operator
  unlock regardless of mode. Pentest proves impact; it does not break the client.

## Credential operations

Lifecycle: obtain (dump/spray/relay/crack) → validate (`cme_parse`) → reuse
(`cred_spray`, lockout-aware) → escalate (cracking/kerberos/adcs paths) → record.
Cracking constants and PTH-before-crack priority live in `services/cracking`.

## Reporting

Deliverable structure (deterministic builder, no LLM prose): executive summary,
objectives, scope, findings (severity-ranked, evidence-linked), attack path,
credentials, recommendations. Severity: critical > high > medium > low > info.
A finding without reproduction steps does not ship.

## Glossary

- **Foothold** — first authenticated execution inside target perimeter.
- **Lateral movement** — pivoting from one internal host to another using stolen
  credentials or trust relationships.
- **Privilege escalation** — local (user→admin/root) vs remote (user→DA/cloud-admin).
- **PTH** — Pass-the-Hash: authenticate with NT hash, no plaintext needed.
- **Kerberoast** — request service tickets, crack offline for service account passwords.
- **RBCD** — Resource-Based Constrained Delegation: write delegation permission
  onto a computer you control, impersonate anyone on it.
- **BOLA/IDOR** — accessing other tenants' objects by manipulating identifiers.
- **C2** — command-and-control channel; in-scope persistence mechanism.

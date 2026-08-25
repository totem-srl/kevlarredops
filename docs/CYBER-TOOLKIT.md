# Cyber Toolkit Reference

Tools and modules powering pentest / bug-bounty workflows. Everything here records
evidence into the engagement store and follows the finding lifecycle (see
[METHODOLOGY](./METHODOLOGY.md)).

## Core modules (`packages/core/src/cyber/`)

| Module | Purpose |
| --- | --- |
| `evidence` | Content-addressed (sha256) blob store + manifest per engagement |
| `observation` | Append-only event log folded into observations (vuln/risk/intel-fact/...) |
| `finding-lifecycle` | candidate → verified → reportable, replay or structured exemption |
| `vault` | Secrets store (~/.pentestcode/vault.json) + identity resolution for request auth |
| `boundary` | Scope decisions, strict-opsec mode, third-party intel blocklist |
| `methodology` | MITRE / PTES / WSTG frameworks, phase + technique lookup |
| `play` | Declarative playbooks (12 plays), requirement gating, execution contracts |
| `takeover` | Subdomain-takeover fingerprints (CNAME/body matching) |
| `defaultcreds` | Curated default credential pairs per product |
| `nvd-match` | CPE range evaluation, version comparison vs NVD data |
| `knowledge` | Vuln-intel cards from NVD records (severity, applicability, next actions) |

## Scanner (`packages/opencode/src/scanner/`)

`crawl` (links/forms/tech/openapi detection) · `dir-fuzzer` (soft-404 aware, paced) ·
`js-analyzer` (secrets/endpoints/SPA routes) · `port-scanner` (banner grab) ·
`service-prober` (active probes) · `pacer` (shared rate limiter).

## Tools

**Recon & surface**: `recon_pipeline`, `bounty_hunt`, `nmap_parse`, `gobuster_parse`,
`scope_check`, `phase_control`, `task_graph`

**Web appsec**: `appsec_probe` (SQLi/XSS/auth/IDOR/CORS candidates), `http_request`
(identity-aware, evidence-recorded), `xss_detect`, `jwt_analyze`, `crypto`

**Binary/reverse**: `file_triage` (magic sniff, strings, Shannon entropy),
`binary_triage` (checksec adapter)

**Infrastructure**: `net` (raw TCP/UDP/banner), `cred_spray`, `attack_path_suggest`,
`tunnel_manage`

**Cloud/IaC adapters**: `cloud_posture` (prowler), `container_surface` (trivy),
`iac_triage` (checkov)

**Intel**: `cve` (live NVD), `knowledge` (intel cards), `methodology`, `play`/`runbook`

**Lifecycle**: `evidence`, `observation`, `finding`, `remediate`, `report_gen`,
`vault`, `identity`, `opsec`, `pwn_bootstrap`, `state_query`/`state_update`

## Bug-bounty workflow

```
/pwn https://target.example     # bootstrap engagement + scope
/hunt https://target.example    # ranked sweep: takeover, headers, openapi,
                                # secrets in JS, bug-class grep, optional fuzz
```

Rate limits: `bounty_hunt` defaults to **5 req/s** (`max_rps`), compliant with
Intigriti-style program caps; the pacer threads through every probe.

Submission: `bounty_hunt export_json=<path>` writes a machine-readable report
(signals, surface, disclaimer). Promote verified findings via `finding promote`
with replay material or a justified exemption — automation output alone is never
submitted.

## Auth

The fork shares credentials with a sibling opencode install
(`~/.local/share/opencode/auth.json`, read-only fallback); fork-local logins via
`pentestcode providers login <provider>` take precedence. Model selection uses the
upstream models.dev catalog unchanged.

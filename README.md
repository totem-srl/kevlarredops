# KevlarRedOps

KevlarRedOps is the Totem-maintained derivative of [PentestCode](https://github.com/s0ld13rr/pentestcode),
which derives from [OpenCode](https://github.com/anomalyco/opencode). The CLI command remains `pentestcode`.
This repository's owner and security maintainer is [@naicud](https://github.com/naicud);
see [MAINTAINERS.md](MAINTAINERS.md) for responsibilities and [SECURITY.md](SECURITY.md) for private reporting.
Public adoption evidence is recorded separately in [docs/ADOPTION.md](docs/ADOPTION.md).

<p align="center">
  <strong>AI penetration testing agent in your terminal.</strong><br>
  Multi-agent architecture &bull; Engagement state tracking &bull; 20+ LLM providers
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
</p>

---

**KevlarRedOps is an autonomous pentesting agent for your terminal.** Point it at an authorized target and it runs the tools, reads the output, updates its picture of the network, and decides what to do next — the way an operator would. Its PentestCode/OpenCode lineage is distributed under the MIT license.

> **Beta** — expect rough edges. [File an issue](https://github.com/totem-srl/kevlarredops/issues) when something breaks. Use [private vulnerability reporting](https://github.com/totem-srl/kevlarredops/security/advisories/new) for security vulnerabilities.

Run engagements in an isolated environment with explicit target authorization. Shell tools check recognized targets against an active engagement, but command parsing does not contain network access. Read the [security model and validation guide](docs/SECURITY-MODEL.md) before running against real systems.

## What it does

One instruction in, a full attack chain out:

```
you: "pentest 10.10.10.5, goal is domain admin"
```

| Stage | What the agent does |
|-------|---------------------|
| **Scan** | `nmap -sS -p-` finds 7 open ports and parses the XML straight into engagement state |
| **Recognize** | Ports 88 + 389 → Domain Controller. Fans out three enumerators in parallel (SMB, LDAP, HTTP) |
| **Enumerate** | Null SMB session → writable share. LDAP → user list. Gobuster → web dirs |
| **Attack** | AS-REP roast → crackable hash → first valid credential |
| **Spray** | That credential sprayed across SMB, WinRM, LDAP and RDP on every known host |
| **Exploit** | WinRM foothold → post-exploit agent dumps SAM / LSA / DPAPI |
| **Result** | Domain admin hash in hand — every step recorded with its evidence chain |

It's methodical where people get lazy: it sprays every credential against every service on every host, and it doesn't forget to check things. Everything it learns lands in a structured state you can query mid-run with `/status`, `/vulns`, or `/creds`.

## Install

Install this repository from a checkout using Git and [Bun](https://bun.sh/):

```bash
git clone https://github.com/totem-srl/kevlarredops.git
cd kevlarredops
bash script/install.sh
```

The installer builds the CLI when needed and links it into `~/.local/bin`. Add that directory to your `PATH`.
Set `PENTESTCODE_DEST` to choose another installation directory or `PENTESTCODE_FORCE_BUILD=1` to rebuild.
The npm package `pentestcode-ai` and the installer in the upstream repository are separate upstream
distribution paths; they do not identify a KevlarRedOps release or establish adoption of this repository.

## Quick start

```bash
pentestcode auth login          # connect your LLM provider
pentestcode doctor              # local prerequisites; no scan or model call
pentestcode                     # interactive session
pentestcode --prompt "scan 10.10.10.0/24 and enumerate all services"   # one-shot
```

Works with 20+ providers through [ai-sdk](https://github.com/vercel/ai) — Anthropic, OpenAI, Google, Azure, AWS Bedrock, Ollama, and more.

Export a saved engagement without a model call:

```bash
pentestcode doctor --engagement lab --strict
pentestcode report lab --format html --output lab-report.html
pentestcode report lab --format json --fail-on-pending
pentestcode findings lab --json
pentestcode findings lab --action history --id lab-review-01
```

Reports separate verified findings from observations awaiting review, check stored evidence
against SHA-256, and redact recorded credential values. Findings carry ownership, impact,
reproduction steps and remediation. Reviewed retests can resolve or reopen a finding while
preserving the original proof and revision history. HTML is self-contained and printable;
Markdown and versioned JSON use the same snapshot. Read the [reporting guide](docs/REPORTING.md)
for promotion, compatibility, exit codes, and sharing limits. The [competitor analysis](docs/research/COMPETITORS-2026-10.md)
explains the product priorities against seven public references.

## How it works

Two things separate PentestCode from a pentester prompt pasted into a chat window: **a team of agents** and **a memory they share**.

### A team, not a monologue

The design follows the strategist-coordinator model from [HPTSA research](https://arxiv.org/abs/2410.02246) — a 4.3× improvement over a single agent:

```
                    ┌─────────────┐
                    │   pentest   │  strategist / coordinator
                    │   (lead)    │  plans, dispatches, tracks state
                    └──────┬──────┘
           ┌───────┬───────┼───────┬───────┐
           ▼       ▼       ▼       ▼       ▼
        ┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
        │recon ││scan- ││explo-││iden- ││post- │
        │      ││ner   ││iter  ││tity  ││explo │  ... + 7 more
        └──────┘└──────┘└──────┘└──────┘└──────┘
```

The lead agent (`pentest`) breaks the engagement into tasks and dispatches specialist subagents in parallel — each with its own system prompt, tool permissions, and domain knowledge. **13 agents in all:** recon, scanner, enumerator, exploiter, identity (AD/Kerberos), infrastructure (SNMP/IPMI/databases), webapp (OWASP Top 10), post-exploit, exploit-dev, critic (false-positive checker), reporter, plus hidden agents for context compression and session management.

### A memory they all share

When the scanner finds a port, the enumerator sees it instantly — because every agent reads from and writes to one structured **engagement state**:

- **Hosts & services** — IP, hostname, OS, ports, service versions, banners
- **Vulnerabilities** — severity, status (suspected / confirmed / exploited), evidence chain, confidence score
- **Credentials** — username, hash/password, type, domain, what they unlock
- **Access** — who holds shell/RDP/DB on which host, at what privilege level
- **Relationships** — an entity graph (EXPLOITED_VIA, CREDENTIAL_FROM, ADMIN_OF, PIVOT_TO, …)
- **AD domain model** — domain controllers, trusts, admins, password policy, GPOs
- **Network segments** — VLANs, reachable networks, pivot hosts
- **Attack paths** — cost-based Dijkstra + Yen's K-shortest routes through the relationship graph

State survives the session: close the terminal, come back tomorrow, and the agent resumes where it stopped. Alongside it, a human-readable `findings.md` logs every vulnerability, credential, and access gain with timestamps — `tail -f` it to watch the engagement unfold.

## Tools

18 built-in pentest tools beyond bash. Parser tools are mandatory: after running nmap the agent must pipe the output through `nmap_parse` rather than grep the XML by hand, so every finding reaches the engagement state.

| Tool | What it does |
|------|-------------|
| `nmap_parse` | Parse nmap XML → auto-populate hosts/services |
| `nuclei_parse` | Parse Nuclei JSON → create vulns with severity |
| `cme_parse` | Parse NetExec output → update creds/access/hosts |
| `gobuster_parse` | Parse dir brute output → classify findings |
| `bloodhound_parse` | Parse SharpHound JSON → populate AD model |
| `sqlmap_parse` | Parse sqlmap output → extract injection points |
| `xss_detect` | Analyze responses for reflected/stored XSS |
| `jwt_analyze` | Decode JWT, check alg:none/weak HMAC/expiry |
| `cred_spray` | Plan credential spray across all discovered services |
| `scope_check` | CIDR/wildcard scope validation |
| `attack_path_suggest` | Cost-based path finding through the relationship graph |
| `tunnel_manage` | Plan SSH/chisel/ligolo tunnels, track live sessions |
| `phase_control` | Phase management with quality gates |
| `finding` | Promote reviewed findings with authorized targets, stored evidence and replay or justified exemption |
| `report_gen` | Export evidence-backed Markdown/JSON/HTML snapshots with a separate verification queue |
| `state_update` | Record findings (30+ mutation types, batch mode) |
| `state_query` | Query engagement state (20+ query types) |

## Skills

74 curated knowledge packs, loaded on demand so they cost context only when relevant:

- **Phase checklists** (6) — what to do in each pentest phase
- **Service knowledge** (15) — SMB, SSH, FTP, DNS, databases, web servers, mail, Docker/K8s, CI/CD, Kerberos, ADCS, NTLM relay, cracking, pivoting, OSINT
- **Web vulnerability classes** (13) — SQLi, SSRF, SSTI, XXE, LFI/traversal, upload→RCE, deserialization, auth bypass/IDOR, API testing, command injection, XSS, race conditions, JS secrets
- **Playbooks** (4) — infrastructure, Active Directory, web application, cloud (AWS/GCP/Azure)
- **Reverse engineering & specialized** (38) — malware analysis, binary/JS/.NET/mobile reversing, Ghidra/IDA/radare2, pwn chains, firmware, OT/ICS, SDR, forensics, threat intel/hunting, LLM security, supply chain

The full operating model — kill-chain lifecycle, evidence chain, state graph, multi-agent topology — is documented in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

Skills are plain markdown. Add your own by dropping a `SKILL.md` into the skills directory — no code changes needed.

## Commands & modes

Drive a live session with slash commands:

| Command | What it does |
|---------|-------------|
| `/status` | Engagement dashboard — hosts, vulns, creds, phase |
| `/targets` | Host & service table |
| `/vulns` | Findings by severity |
| `/creds` | Discovered credentials |
| `/scope` | View/edit target scope |
| `/phase` | Phase management |
| `/mode` | Switch auto / free / guided |
| `/pause` | Pause on findings (never / always / checkpoint) |
| `/report` | Generate a pentest report |

And set how much rope the agent gets:

- **auto** — runs through the pentest phases autonomously, spawning subagents as needed
- **free** — no phase structure; responds to your requests directly. Recognized shell targets still obey the active engagement scope; specialized tools have separate limitations documented in the [security model](docs/SECURITY-MODEL.md).
- **guided** — step by step; proposes each action and waits for approval

Modes combine with pause behavior — `auto` + `pause always` gives you autonomous execution that stops at every finding for review.

## Use cases

One toolkit across offensive security:

- **Penetration testing** — full methodology from recon to reporting
- **CTF competitions** — flag tracking, objective management, multi-target coordination
- **Bug bounty** — web app testing, API security, recon automation
- **Vulnerability research** — systematic enumeration and validation
- **Infrastructure security** — network service auditing, default-credential checks

## Configuration

Config lives at `.pentestcode/pentestcode.jsonc`:

```jsonc
{
  "provider": {
    "anthropic": {
      "model": "claude-sonnet-4-20250514"
    }
  }
}
```

Providers: Anthropic, OpenAI, Google, Azure, AWS Bedrock, Ollama, Together, Groq, Fireworks, DeepSeek, Mistral, and more via [ai-sdk](https://github.com/vercel/ai).

## Contributing

Bug reports from real usage are the most valuable thing you can send. Run PentestCode on a CTF box, an HTB machine, or an authorized pentest, and when something goes wrong — it loops, misses an obvious path, chokes on tool output, or wastes tokens — open an issue with:

1. What you were testing (target type, not sensitive details)
2. What went wrong
3. The `findings.md` and/or relevant session output

Feature requests and PRs are welcome too. The codebase is TypeScript on the Effect library — see [CLAUDE.md](CLAUDE.md) for architecture.

For security vulnerabilities, follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  Derived from <a href="https://github.com/s0ld13rr/pentestcode">PentestCode</a> and <a href="https://github.com/anomalyco/opencode">OpenCode</a> &bull; Self-hosted &amp; open source
</p>

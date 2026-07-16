# PentestCode

<p align="center">
  <img src="https://github.com/s0ld13rr/pentestcode/raw/main/.github/logo.png" alt="PentestCode" width="480" />
</p>

<p align="center">
  <strong>AI penetration testing agent in your terminal.</strong><br>
  Multi-agent architecture &bull; Engagement state tracking &bull; 20+ LLM providers
</p>

<p align="center">
  <a href="https://github.com/s0ld13rr/pentestcode/releases/latest"><img src="https://img.shields.io/github/v/release/s0ld13rr/pentestcode?style=flat-square&color=red" alt="Release"></a>
  <a href="https://github.com/s0ld13rr/pentestcode/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <a href="https://github.com/s0ld13rr/pentestcode"><img src="https://img.shields.io/github/stars/s0ld13rr/pentestcode?style=flat-square" alt="Stars"></a>
</p>

---

PentestCode is an AI pentesting agent that runs tools, analyzes results, and makes decisions in your terminal. Hard fork of [OpenCode](https://github.com/anomalyco/opencode) (MIT), rebuilt for offensive security.

> **Beta** — works on real engagements and CTFs, but expect rough edges. [Open an issue](https://github.com/s0ld13rr/pentestcode/issues) if something breaks.

## What It Actually Does

You give it a target — it does the rest:

```
you: "pentest 10.10.10.5, goal is domain admin"
```

| Step | What happens |
|------|-------------|
| Scan | `nmap -sS -p-` → finds 7 open ports, auto-parses XML into engagement state |
| Recognize | Ports 88 + 389 → Domain Controller. Spawns 3 enumerators in parallel (SMB, LDAP, HTTP) |
| Enumerate | Null session on SMB → writable share. LDAP → user list. Gobuster → web dirs |
| Attack | AS-REP roast → crackable hash → valid credential |
| Spray | Credential sprayed across SMB, WinRM, LDAP, RDP on all known hosts |
| Exploit | WinRM access → spawns post-exploit agent → dumps SAM/LSA/DPAPI |
| Result | Domain admin hash. Every step recorded in state with evidence chain |

Every finding lands in `findings.md` (human-readable) and `state.json` (structured). Check progress anytime: `/status`, `/vulns`, `/creds`.

**Good at:** methodical enumeration, credential spraying, not forgetting to check things. It sprays every cred against every service on every host — something humans routinely skip.

**Bad at:** complex exploit chains, creative intuition, stealth. It doesn't replace a pentester — it's a force multiplier.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/s0ld13rr/pentestcode/main/install.sh | bash
```

Self-contained binary — no Bun, Node, or runtime needed. Works on Linux and macOS (x64/arm64).

<details>
<summary>Other options</summary>

**Pin version:**
```bash
PENTESTCODE_VERSION=0.1.7 curl -fsSL https://raw.githubusercontent.com/s0ld13rr/pentestcode/main/install.sh | bash
```

**Custom directory:**
```bash
PENTESTCODE_INSTALL=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/s0ld13rr/pentestcode/main/install.sh | bash
```

**From source:**
```bash
bun install
bun run build --single --skip-embed-web-ui
# binary at packages/opencode/dist/pentestcode-<os>-<arch>/bin/pentestcode
```

</details>

## Quick Start

```bash
# Authenticate with your LLM provider
pentestcode auth login

# Launch
pentestcode

# Or one-shot with a prompt
pentestcode --prompt "scan 10.10.10.0/24 and enumerate all services"
```

Supports 20+ providers: Anthropic, OpenAI, Google, Azure, Ollama, and more. 

## Architecture

Strategist-coordinator model based on [HPTSA research](https://arxiv.org/abs/2410.02246) (4.3x improvement over single-agent):

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

The coordinator (`pentest`) breaks work into tasks and spawns specialist subagents in parallel. Each subagent has its own system prompt, tool permissions, and domain knowledge. They share a single engagement state — when the scanner finds a port, the enumerator can see it immediately.

**13 agents total:** recon, scanner, enumerator, exploiter, identity (AD/Kerberos), infrastructure (SNMP/IPMI/databases), webapp (OWASP Top 10), post-exploit, exploit-dev, critic (false positive checker), reporter, plus hidden agents for context compression and session management.

## Engagement State

This is what makes PentestCode different from "put a pentester prompt in ChatGPT." Everything the agent discovers is recorded in a structured state:

- **Hosts & services** — IP, hostname, OS, ports, service versions, banners
- **Vulnerabilities** — severity, status (suspected/confirmed/exploited), evidence chain, confidence score
- **Credentials** — username, hash/password, type, domain, what they're valid for
- **Access** — who has shell/RDP/DB access on which host, privilege level
- **Relationships** — entity graph (EXPLOITED_VIA, CREDENTIAL_FROM, ADMIN_OF, PIVOT_TO, etc.)
- **AD domain model** — domain controllers, trusts, admins, password policy, GPOs
- **Network segments** — VLANs, reachable networks, pivot hosts
- **Attack path** — cost-based Dijkstra + Yen's K-shortest paths through the relationship graph

State persists across sessions. Close the terminal, come back tomorrow, the agent picks up where you left off.

The agent also keeps a `findings.md` — a human-readable log of every vulnerability, credential, and access gain with timestamps and evidence. You can `tail -f` it during a session to watch findings roll in.

## Tools

18 built-in pentest tools beyond bash:

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
| `attack_path_suggest` | Cost-based path finding through relationship graph |
| `tunnel_manage` | Plan SSH/chisel/ligolo tunnels, track live sessions |
| `phase_control` | Phase management with quality gates |
| `report_gen` | Generate markdown/JSON pentest reports |
| `state_update` | Record findings (30+ mutation types, batch mode) |
| `state_query` | Query engagement state (20+ query types) |

Parser tools are mandatory — after running nmap, the agent must pipe output through `nmap_parse` instead of manually grepping XML. This ensures every finding hits the engagement state.

## Skills

19 curated knowledge packs loaded on demand:

- **Phase checklists** (6) — what to do in each pentest phase
- **Service knowledge** (9) — SMB, SSH, FTP, DNS, databases, web servers, mail, Docker/K8s, CI/CD
- **Playbooks** (4) — infrastructure, Active Directory, web application, cloud

Skills are plain markdown files. Add your own by dropping a `SKILL.md` in the skills directory — no code changes needed.

## Slash Commands

| Command | What it does |
|---------|-------------|
| `/status` | Engagement dashboard — hosts, vulns, creds, phase |
| `/targets` | Host & service table |
| `/vulns` | Findings by severity |
| `/creds` | Discovered credentials |
| `/scope` | View/edit target scope |
| `/phase` | Phase management |
| `/mode` | Switch auto/free/guided |
| `/pause` | Pause on findings (never/always/checkpoint) |
| `/report` | Generate pentest report |

## Modes

- **auto** — agent runs through pentest phases autonomously, spawning subagents as needed
- **free** — no phase structure, agent responds to your requests directly (bypasses scope checks)
- **guided** — step-by-step, agent proposes actions and waits for approval

You can combine modes with pause behavior: `auto` + `pause always` = autonomous execution that stops at every finding for your review.

## Use Cases

PentestCode is designed to be universal across offensive security:

- **Penetration testing** — full methodology from recon to reporting
- **CTF competitions** — flag tracking, objective management, multi-target coordination
- **Bug bounty** — web app testing, API security, recon automation
- **Vulnerability research** — systematic enumeration and validation
- **Infrastructure security** — network service auditing, default credential checking

## Honest Limitations

- **Token-hungry.** A real engagement can burn $5-50 in API calls depending on scope and model. Large scans with verbose output make this worse.
- **Repeats work.** Despite wordlist tracking and state diffs, the agent sometimes re-runs tools it already ran. We're improving this.
- **No GUI.** Terminal only. No Burp Suite integration, no browser automation, no proxy interception.
- **Prompt-dependent.** The quality of results varies significantly between LLM providers. Claude Opus/Sonnet >> GPT-4o > local models for multi-agent coordination.
- **Not stealthy.** The agent doesn't think about OPSEC by default. Fine for authorized tests, not for red team stealth operations.
- **Alpha software.** APIs may change, engagement state format may change, things may break between versions.

## Configuration

Config at `.pentestcode/pentestcode.jsonc`:

```jsonc
{
  "provider": {
    "anthropic": {
      "model": "claude-sonnet-4-20250514"
    }
  }
}
```

Supports: Anthropic, OpenAI, Google, Azure, AWS Bedrock, Ollama, Together, Groq, Fireworks, DeepSeek, Mistral, and more via [ai-sdk](https://github.com/vercel/ai).

## Contributing

We want bug reports from real usage. If you run PentestCode on a CTF box, an HTB machine, or an authorized pentest and something goes wrong — the agent loops, misses an obvious path, crashes on tool output, or wastes tokens — open an issue with:

1. What you were testing (target type, not sensitive details)
2. What went wrong
3. The `findings.md` and/or relevant session output

Feature requests and PRs welcome. The codebase is TypeScript with Effect library — see [CLAUDE.md](CLAUDE.md) for architecture details.

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  Hard fork of <a href="https://github.com/anomalyco/opencode">OpenCode</a> &bull; Built for offensive security &bull; Self-hosted & open source
</p>

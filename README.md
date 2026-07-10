<p align="center">
  <img src="https://github.com/s0ld13rr/pentestcode/raw/main/.github/logo.png" alt="pentestcode" width="480" />
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

Hard fork of [OpenCode](https://github.com/anomalyco/opencode) (MIT). Stripped the code-editing focus, rebuilt for penetration testing.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/s0ld13rr/pentestcode/main/install.sh | bash
```

Self-contained binary — no Bun, Node, or runtime needed.

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
pentestcode                           # launch TUI
pentestcode -p "scan 10.10.10.0/24"   # one-shot prompt
pentestcode -s <session-id>           # resume session
```

On first launch, configure your LLM provider — Anthropic, OpenAI, Google, local Ollama, or any of 20+ providers via ai-sdk.

## Architecture

Strategist-coordinator model based on [HPTSA research](https://arxiv.org/abs/2410.02246) (4.3x improvement over single-agent):

```
                    ┌─────────────┐
                    │   pentest   │  strategist / coordinator
                    │   (lead)    │  plans, dispatches, tracks OODA loop
                    └──────┬──────┘
           ┌───────┬───────┼───────┬───────┐
           ▼       ▼       ▼       ▼       ▼
        ┌──────┐┌──────┐┌──────┐┌──────┐┌──────┐
        │recon ││scan- ││explo-││iden- ││post- │
        │      ││ner   ││iter  ││tity  ││explo │  ... + 7 more
        └──────┘└──────┘└──────┘└──────┘└──────┘
```

**13 specialist agents** — scanner, enumerator, exploiter, identity (AD/Kerberos), infrastructure, webapp, post-exploit, exploit-dev, critic, reporter, recon, and more. Each has domain-specific prompts, tool permissions, and knowledge.

## Features

**Engagement State** — persistent tracking of hosts, services, vulns, credentials, access levels, relationships, AD domain model. Shared across all agents in real-time.

**18 Pentest Tools** — nmap/nuclei/netexec/gobuster/bloodhound/sqlmap parsers, XSS detection, JWT analysis, credential spray planner, tunnel management, attack path derivation (Dijkstra + Yen's K-shortest), scope checker, phase control, report generator.

**19 Skills** — phase checklists (6), service knowledge packs (9), methodology playbooks (4). Loaded on demand as markdown — no code changes needed to add your own.

**Phased Methodology** — Recon → Enumeration → Vuln Assessment → Exploitation → Post-Exploitation → Reporting. Quality gates block premature phase transitions.

**Three Modes** — `auto` (phased autopilot), `free` (on-demand), `guided` (step-by-step approval).

**Intelligence Layer** — state diffs between turns, auto-critic for unvalidated findings, decision memory with failure tracking, inter-agent interrupt alerts, agent context carry across spawns, cost-based attack path derivation.

## Slash Commands

| Command | What it does |
|---------|-------------|
| `/status` | Engagement dashboard |
| `/targets` | Host & service table |
| `/vulns` | Findings by severity |
| `/creds` | Discovered credentials |
| `/scope` | View/edit scope |
| `/phase` | Phase management |
| `/mode` | Switch auto/free/guided |
| `/report` | Generate report |

## Universal

Works for penetration testing, bug bounty, vulnerability research, CTF, and infrastructure security. Not narrowly scoped to one use case.

## License

MIT — see [LICENSE](LICENSE).

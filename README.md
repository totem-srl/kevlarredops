# PentestCode

AI-powered penetration testing agent. Built on a hard fork of [OpenCode](https://github.com/anomalyco/opencode) (MIT license).

## What is PentestCode?

PentestCode is a terminal-based AI agent designed for penetration testing, bug bounty, CTF competitions, and security research. It uses a multi-agent architecture where a strategist-coordinator (the pentest agent) plans and dispatches specialist subagents for parallel assessment.

### Key Features

- **Multi-agent architecture** — 12 specialist agents (pentest orchestrator, recon, scanner, enumerator, exploiter, reporter, and more)
- **Engagement state management** — tracks hosts, services, vulnerabilities, credentials, and attack paths
- **Phased methodology** — Recon → Enumeration → Vulnerability Assessment → Exploitation → Post-Exploitation → Reporting
- **7 pentest tools** — state query/update, nmap parser, scope checker, phase control, report generator, task graph
- **19 skill files** — phase checklists, service knowledge packs, methodology playbooks
- **20+ LLM providers** — Anthropic, OpenAI, Google, local Ollama, and more via ai-sdk
- **Three operating modes** — auto (phased autopilot), free (on-demand), guided (step-by-step approval)

## Requirements

- [Bun](https://bun.sh) runtime
- An LLM API key (Anthropic, OpenAI, or any supported provider)

## Quick Start

```bash
# Install dependencies
bun install

# Run in dev mode
bun run dev
```

On first launch, configure your LLM provider in `.pentestcode/pentestcode.jsonc`.

## Slash Commands

| Command | Description |
|---------|-------------|
| `/status` | Engagement dashboard (hosts, vulns, creds) |
| `/targets` | Target table with services |
| `/vulns` | Vulnerability table by severity |
| `/creds` | Discovered credentials |
| `/scope` | View/modify engagement scope |
| `/phase` | Current phase, switch phases |
| `/mode` | Switch auto/free/guided mode |
| `/report` | Generate assessment report |

## Architecture

PentestCode uses a strategist-operator split (based on HPTSA research showing 4.3x improvement):

- **Pentest agent** (default) — Engagement Lead. Plans tasks, dispatches subagents, tracks progress via OODA loop.
- **Specialist subagents** — Scanner, Enumerator, Exploiter, Identity, Infrastructure, WebApp, Post-Exploit, Critic, Reporter — each with focused prompts and tool access.
- **Engagement state** — Global JSON store at `~/.pentestcode/engagements/` with hosts, services, vulns, credentials, attack paths.
- **Task graph** — DAG-based task planning with dependencies and difficulty scoring.

## License

MIT — see [LICENSE](LICENSE).

Hard fork of [OpenCode](https://github.com/anomalyco/opencode) by anomalyco (MIT license).

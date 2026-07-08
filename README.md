# PentestCode

AI-powered penetration testing agent. Hard fork of [OpenCode](https://github.com/anomalyco/opencode) (MIT).

## Install

**Linux / macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/s0ld13rr/pentestcode/main/install.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/s0ld13rr/pentestcode/main/install.ps1 | iex
```

**Options (env vars):**
```bash
PENTESTCODE_VERSION=1.17.15 curl -fsSL .../install.sh | bash   # pin version
PENTESTCODE_INSTALL=/usr/local/bin curl -fsSL .../install.sh | bash  # custom dir
```

The installer downloads a self-contained binary — no Bun, Node, or other runtime needed.

**From source:**
```bash
bun install
bun run build --single    # compiles for current platform
# binary at packages/opencode/dist/pentestcode-<os>-<arch>/bin/pentestcode
```

## Quick Start

```bash
pentestcode                           # launch TUI
pentestcode -p "scan 10.10.10.0/24"   # one-shot prompt
pentestcode -s <session-id>           # resume session
```

On first launch, configure your LLM provider — Anthropic, OpenAI, Google, local Ollama, or any of 20+ providers via ai-sdk.

## What It Does

Multi-agent AI pentester with a strategist-coordinator architecture (based on HPTSA research, 4.3x improvement over single-agent):

- **Pentest agent** — engagement lead. Plans, dispatches subagents, tracks progress via OODA loop.
- **12 specialist subagents** — scanner, enumerator, exploiter, identity (AD/Kerberos), infrastructure, webapp, post-exploit, exploit-dev, critic, reporter, recon.
- **Engagement state** — tracks hosts, services, vulns, credentials, access, attack paths, AD domain model.
- **11 pentest tools** — state query/update, nmap/nuclei/crackmapexec/gobuster/bloodhound parsers, credential spray planner, scope checker, phase control, report generator.
- **19 skill files** — phase checklists, service knowledge packs (SMB, SSH, databases, DNS, Docker, FTP, mail), methodology playbooks.
- **Phased methodology** — Recon → Enumeration → Vuln Assessment → Exploitation → Post-Exploitation → Reporting.
- **Three modes** — auto (phased autopilot), free (on-demand), guided (step-by-step approval).

## Slash Commands

| Command | Description |
|---------|-------------|
| `/status` | Engagement dashboard — hosts, vulns, creds, objectives |
| `/targets` | Target table with services |
| `/vulns` | Vulnerability table by severity |
| `/creds` | Discovered credentials |
| `/scope` | View/modify engagement scope |
| `/phase` | Current phase, switch phases |
| `/mode` | Switch auto/free/guided mode |
| `/report` | Generate assessment report |

## License

MIT — see [LICENSE](LICENSE).

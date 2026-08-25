---
name: rev-master-routing
tags: [reverse, routing]
description: Master router for all reverse-engineering, malware, CTF, and specialty security skills ported from reverse-skill. Load FIRST when a task involves binaries, APK/IPA, obfuscated JS, firmware, CTF, pwn, patch diffing, or any unknown artifact — it picks the right specialist skill instead of guessing tools.
---

# Reverse / Specialty Skill Router

Route BEFORE acting. Output chosen skill + one-line reason. No target ACT until authorization confirmed (see phases/recon scope discipline).

## Fast Ladder (first match wins)

| Hint | PRIMARY skill |
|------|---------------|
| DSL VM / custom opcode VM / risk-control JS VM | `dsl-vm-reverse` (skills/reverse/reverse-engineering/dsl-vm-reverse) |
| APK / smali / jadx / apktool | `apk-reverse` |
| IPA / iOS / Objection / MobSF | `mobile-reverse` |
| JS signing / frontend crypto / webpack / CDP hook | `js-reverse` |
| Browser extension RE | `browser-extension-reverse` |
| macOS / Mach-O | `macos-reverse` |
| Go / Rust stripped binary | `go-rust-reverse` |
| .NET / dnSpy / de4dot / ConfuserEx | `dotnet-reverse` |
| Malware sample / YARA / sandbox | `malware-analysis` |
| Protocol / Protobuf / PCAP protocol recovery | `protocol-reverse` |
| Ghidra / open-source decompiler | `ghidra-reverse` |
| IDA / deep disassembly | `ida-reverse` |
| radare2 / r2 CLI | `radare2` |
| Firmware / binwalk / IoT / EMBA | `firmware-pentest` |
| UART / JTAG / debug ports | `hardware-security` |
| OT / ICS / PLC / SCADA | `ot-ics` |
| pwn / ROP / heap-stack exploit | `pwn-chain` |
| N-day / vendor patch diff | `patch-diff-exploit` |
| EDR bypass / unhooking / syscalls | `edr-bypass-re` |
| SAML / OIDC / OAuth federation abuse | `identity-federation` |
| Forensics / memory dump / timeline | `digital-forensics` |
| OSINT / threat intel enrichment | `threat-intelligence` |
| Email / phishing analysis | `email-security` |
| Wi-Fi / WPA capture (authorized lab) | `wifi-wireless` |
| RF / SDR research | `radio-sdr` |
| Thick client / desktop app test | `thick-client` |
| Source audit / SAST / Semgrep | `code-audit` |
| Detection engineering / blue-team hunting | `threat-hunting` |
| SBOM / SCA / CI/CD supply chain | `supply-chain-security` |
| LLM app / prompt injection / agent abuse | `llm-security` |
| Binary diff / Bindiff / symbol migration | `binary-diff` |
| SRC / bug bounty workflow + payload library | `src-hunter` |
| CTF / AWD (single entry, do NOT expand sub-skills) | `ctf-sandbox` → sidecar `reverse-skill-reference/CTF-Sandbox-Orchestrator/` (GPLv3) |
| Generic RE / anti-debug / OLLVM / unknown binary fallback | `reverse-engineering` |

## Not ported (use local equivalents)

Upstream `windows-ad`, `api-security`, `database-security`, `cloud-k8s`, `attack-chain`, `pentest-tools`, `case-review` overlap with native skills (`playbooks/ad`, `web/*`, `services/*`, `playbooks/*`, `phases/*`) — prefer natives. Full upstream versions remain readable in `reverse-skill-reference/skills/`.

## Workflow Contract

1. Route first; name the PRIMARY skill and why.
2. Confirm scope/authorization before any active step against a target. Offline artifacts (binary, APK, PCAP) need no network scope.
3. Check tool availability (`which jadx apktool frida r2 ghidra binwalk...`); install missing via package manager only with user awareness — upstream bootstrap scripts live in `reverse-skill-reference/skills/scripts/` (Windows/PS-heavy).
4. Record evidence as you go: commands, outputs, timeline. Conclusions follow Evidence → Finding → Path (see `reverse-skill-reference/skills/ops/evidence-finding-path.md`).
5. No match on the ladder → fall back to `reverse-engineering`, then read `skills/reverse/routing.md` full matrix.

## Field Journal

Prior-case precedents (packed ELF, stripped Go malware, SSL-pin bypass, ROP x64, firmware XOR, IL2CPP...) live in `skills/reverse/field-journal/seed-*.md` — check for a precedent before reinventing an approach.

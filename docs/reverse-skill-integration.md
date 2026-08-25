# reverse-skill Integration

Provenance, scope, and usage of the skills ported from
[zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)
(MIT-licensed cybersecurity skill router pack) into this repo.

Integrated: 2026-08-25 · upstream main @ 122 commits (v1.0.1 era) · shallow clone.

## What was added

### 1. `skills/reverse/` — 35 native skills (discovered automatically)

`skills/**/SKILL.md` is auto-discovered by `packages/opencode/src/skill/index.ts`
(repo-local dev discovery via `skills.paths`; release binaries embed `skills/`
at build time — rebuild to bundle). No registry edit needed.

Ported modules (frontmatter `name:` unchanged from upstream, all unique vs our
32 pre-existing skills; `tags:` injected using our tag vocabulary; each file's
"ACTION REQUIRED" block replaced with an "Upstream Notes" pointer):

RE/binary: `apk-reverse`, `mobile-reverse`, `js-reverse`, `ida-reverse`,
`radare2`, `ghidra-reverse`, `dotnet-reverse`, `go-rust-reverse`,
`macos-reverse`, `browser-extension-reverse`, `protocol-reverse`,
`reverse-engineering` (+ nested `dsl-vm-reverse`), `binary-diff`,
`patch-diff-exploit`, `thick-client`

Offense/defense specialty: `malware-analysis`, `pwn-chain`, `firmware-pentest`,
`edr-bypass-re`, `digital-forensics`, `threat-hunting`, `threat-intelligence`,
`code-audit`, `llm-security`, `supply-chain-security`, `email-security`,
`identity-federation`, `src-hunter` (SRC/bug-bounty workflow + payload/WAF-bypass
library), `ctf-sandbox` (thin entry → GPLv3 sidecar), plus lab-gated
`hardware-security`, `radio-sdr`, `wifi-wireless`, `ot-ics`.

Entry point: **`skills/reverse/master-routing/SKILL.md`** (`rev-master-routing`) —
distilled English router mapping task hints → specialist skill, mirroring
upstream R0–R44 priority order.

Shared assets copied so upstream relative links (`../field-journal`,
`../ops`, `../references`, `../config/routing.json`) still resolve:
`field-journal/` (25 precedent/seed case notes), `ops/` (scope contract,
evidence chain, role map), `config/routing.json` (43-rule source of truth),
`references/`, `MASTER-ROUTING.md`, `routing.md`, `tool-index.md.template`.

Deliberately NOT ported as skills (duplicates native coverage): `windows-ad`,
`api-security`, `database-security`, `cloud-k8s`, `attack-chain`,
`pentest-tools` root, `case-review`, `docs-generator`, `diagram-generator`,
`browser-automation`. Their full text stays in the reference copy below.

### 2. `reverse-skill-reference/` — complete upstream snapshot

Full clone minus `.git`: `CTF-Sandbox-Orchestrator/` (**GPLv3**, not mixed into
our MIT skill tree — ctf-sandbox skill points here instead),
`burp-mcp-full/`, `kali/`, `docs/`, `examples/`, `reports/`, `scripts/`
(bootstrap/case-init/master-route PS1+sh), all READMEs/RULES.
Treat as read-only reference; do not import code from GPLv3 paths into MIT files.

## License

Imported SKILL.md + support dirs: MIT (upstream LICENSE at
`reverse-skill-reference/LICENSE`). CTF-Sandbox-Orchestrator: GPLv3 (reference
only). src-hunter subtree carries its own LICENSE file in-tree.

## Usage

- Ask for RE/pentest work on a binary/APK/JS/firmware target → agent loads
  `rev-master-routing` first, then the matched specialist skill.
- Tag scoping applies (`Skill.scopeByTags`): imported skills use tags like
  `[reverse, binary]`, `[exploitation, pwn]`, `[ctf]`.
- Upstream regression suite (173 routing cases) runs via
  `bash reverse-skill-reference/skills/scripts/test-routing.sh` if ever needed;
  we did not wire it into CI since routing.json is reference data here.

## Safety posture kept

- Scope-before-ACT discipline preserved ("Upstream Notes" in every ported file).
- No auto-executed bootstrap scripts were ported into active skills; tool
  installs stay explicit and user-visible.
- Dynamic-analysis skills (Frida, sandboxing, wireless) retain their
  authorized-device/lab-only language.

# CLAUDE.md

## What This Is

PentestCode — AI pentesting agent, hard fork of [OpenCode](https://github.com/anomalyco/opencode) (dev branch, MIT).
OpenCode — coding agent (183k stars). We stripped code-editing focus and rebuilt it for penetration testing.

**Stack**: TypeScript, Bun, Effect library, Turbo monorepo.
**TUI**: React/Ink (via @opentui). **LLM**: ai-sdk (20+ providers). **DB**: SQLite (drizzle-orm).

## Project Structure

```
opencode-fork/                    # Will be renamed to pentestcode
├── packages/
│   ├── core/src/                 # Domain logic, tools, sessions
│   │   ├── engagement/           # NEW: pentest state (schema, store, context)
│   │   ├── session/              # Session management (runner, compaction)
│   │   ├── tool/                 # Tool registry + built-in tools
│   │   ├── system-context/       # Context sources injected into prompts
│   │   ├── skill/                # Skill discovery + loading
│   │   └── agent.ts              # Agent schema, default ID = "pentest"
│   ├── opencode/src/             # Main application package
│   │   ├── agent/agent.ts        # Agent definitions (pentest/recon/scanner/...)
│   │   ├── session/prompt/*.txt  # System prompts per agent
│   │   ├── session/system.ts     # Prompt assembly (uses pentest.txt)
│   │   ├── session/prompt.ts     # Session runner loop
│   │   ├── tool/                 # Tool implementations (registry.ts is master)
│   │   ├── skill/                # Skill discovery paths
│   │   └── cli/                  # CLI commands (yargs)
│   ├── llm/                      # LLM client abstraction (ai-sdk)
│   ├── tui/                      # Terminal UI (React/Ink)
│   ├── server/                   # HTTP server + SSE events
│   ├── schema/                   # Shared type definitions
│   ├── protocol/                 # HTTP API contracts
│   ├── plugin/                   # Plugin system
│   └── client/                   # Generated SDK client
├── skills/
│   ├── phases/                   # Phase checklists (6 files)
│   ├── services/                 # Service knowledge packs (9 files)
│   └── playbooks/                # Methodology playbooks (4 files)
└── ...
```

## Multi-Agent Architecture

| Agent | Type | Description |
|-------|------|-------------|
| **pentest** | primary (default) | Strategist-coordinator. Plans, spawns subagents, can execute directly. |
| **recon** | primary | Reconnaissance (passive/active by user choice). |
| **scanner** | subagent | Port/vuln scanning. Spawned for parallel host scanning. |
| **enumerator** | subagent | Deep service enumeration (SMB/LDAP/web/etc). |
| **exploiter** | subagent | Exploitation of specific vulnerabilities. |
| **reporter** | subagent | Report generation from engagement state. No bash. |
| compaction | hidden | Context compression (inherited from OpenCode). |
| title | hidden | Session title generation. |
| summary | hidden | Session summary. |

Agents defined in: `packages/opencode/src/agent/agent.ts`
Prompts in: `packages/opencode/src/session/prompt/*.txt` and `packages/opencode/src/agent/prompt/*.txt`

## Key Files

- **Agent loop**: `packages/opencode/src/session/prompt.ts` → `runLoop()` (line ~1081)
- **LLM call**: `packages/core/src/session/runner/llm.ts`
- **Tool registry**: `packages/opencode/src/tool/registry.ts` (master registry)
- **Tool definitions (core)**: `packages/core/src/tool/builtins.ts`
- **System prompt assembly**: `packages/opencode/src/session/system.ts`
- **Agent definitions**: `packages/opencode/src/agent/agent.ts`
- **Engagement schema**: `packages/core/src/engagement/schema.ts` (Effect Schema, State/Host/Vuln/Cred types)
- **Engagement store**: `packages/core/src/engagement/store.ts` (global Ref + JSON persistence)
- **Engagement context (V2)**: `packages/core/src/engagement/context.ts` (SystemContext source, V2 only)
- **Pentest tools**: `packages/opencode/src/tool/state-query.ts`, `state-update.ts`, `nmap-parse.ts`, `scope-check.ts`, `phase-control.ts`, `report-gen.ts`
- **App runtime (V1)**: `packages/opencode/src/effect/app-runtime.ts` (LayerNode graph)
- **Location services (V2)**: `packages/core/src/location-services.ts` (V2 layer graph)
- **Config**: `.opencode/opencode.jsonc` (will rename to `.pentestcode/`)
- **Skills**: `skills/` directory, discovered via `**/SKILL.md` glob

## Commands

```bash
# Install dependencies
bun install

# Run (dev mode)
bun run dev

# Run TUI directly
bun run --cwd packages/opencode --conditions=browser src/index.ts

# Typecheck
bun turbo typecheck
```

## What Was Done (Phase 1-3)

### Phase 1: Fork & Strip
- Removed 12 packages: codemode, desktop, enterprise, storybook, docs, console, slack, stats, web, sdks, infra, artifacts
- Removed translated READMEs, SST config, Nix files
- Updated package.json: name→pentestcode, description→pentesting
- Removed edit/apply-patch/todowrite from core builtins
- Removed GitHub Copilot integration from core
- 178M → 109M

### Phase 2: Pentest Domain + Wiring
- **Agents rewritten**: build/plan/general/explore → pentest/recon/scanner/enumerator/exploiter/reporter
- **Default agent**: "pentest" everywhere (was "build")
- **Prompts created**: pentest.txt, recon.txt, scanner.txt, enumerator.txt, exploiter.txt, reporter.txt + mode switching prompts
- **system.ts**: Always uses pentest.txt (bypasses model-specific coding prompts)
- **Engagement state module**: schema.ts (Effect Schema models), store.ts (file persistence), context.ts (SystemContext source)
- **19 skill files**: 6 phases, 9 services, 4 playbooks
- **Global engagement store**: `~/.pentestcode/engagements/` — NOT per-directory (security work isn't tied to a cwd)
- **EngagementStore.node** registered in V1 app-runtime (`app-runtime.ts`) and V2 location-services (`location-services.ts`)
- **Engagement context injected** into V1 system prompt (`prompt.ts`) — compact JSON with phase, mode, hosts, vulns
- **Auto-load**: session start loads last engagement from `.last` file
- **Skills config**: `.opencode/opencode.jsonc` has `skills.paths: ["./skills"]`

### Phase 3: Pentest Tools (6 tools, 12 files)
- **state_query** — query engagement state (11 query types: summary, hosts, vulns, creds, scope, phase, flags, tasks, host, full, engagements)
- **state_update** — structured mutations (13 actions: add_host/vuln/credential/access, set_phase/mode, update_scope, add_flag/note/attack_step, create/load/reload_engagement)
- **nmap_parse** — parse nmap XML/greppable output via htmlparser2 SAX, auto-updates engagement state
- **scope_check** — CIDR containment, wildcard domain matching, excludes priority
- **phase_control** — status/next/set phase management
- **report_gen** — markdown/JSON reports with 6 sections (executive_summary, scope, findings, attack_path, credentials, recommendations)
- All tools registered in `packages/opencode/src/tool/registry.ts`
- Agent permissions configured per-agent in `packages/opencode/src/agent/agent.ts`

## What Was Done (Phase 3 cleanup + Phase 4 partial + Phase 5)

### Phase 3 Cleanup
- [x] Deleted stale test files: `code-mode.test.ts`, `code-mode-integration.test.ts`, `apply_patch.test.ts`, `lsp.test.ts`
- [x] Cleaned `parameters.test.ts` — removed apply_patch/lsp/todo imports, schemas, and describe blocks
- [x] Deleted orphaned snapshot file `__snapshots__/parameters.test.ts.snap`
- [x] Verified `@opencode-ai/codemode` dependency already removed
- [x] Deleted orphaned description `todowrite.txt`

### Phase 4: Code-Editing Remnant Removal (partial)
- [x] Removed `LspTool` from registry init and builtin array (kept `LSP.node` in deps — EditTool depends on LSP.Service)
- [x] Deleted `src/tool/lsp.ts` and `src/tool/lsp.txt` (tool file + description)
- [x] Cleaned CLI tool rendering (`cmd/run/tool.ts`) — removed ApplyPatchTool, LspTool, TodoWriteTool imports, types, render functions, TOOL_RULES entries (~300 lines)
- [x] Kept LSP/Format/Worktree service modules intact (deeply integrated, removal breaks types)

### Phase 5: Flow System
- [x] 8 slash commands: `/status`, `/targets`, `/vulns`, `/creds`, `/scope`, `/phase`, `/mode`, `/report`
  - Template files in `packages/opencode/src/command/template/pentest-*.txt`
  - Registered as built-in commands in `packages/opencode/src/command/index.ts`
- [x] Mode switching — mode directives injected into system prompt per engagement mode (auto/free/guided)
- [x] Phase auto-transition hints — `phaseTransitionHint()` in `prompt.ts` suggests next phase based on engagement state
- [x] TUI `/status` renamed to `/sysinfo` to avoid conflict with pentest `/status`

## What Remains (TODO)

### Phase 3 Remaining
- [ ] Add scope guard to bash tool (warn/block out-of-scope targets before execution)

### Phase 4 Remaining (deferred — not blocking)
- [ ] Remove or stub LSP service module (`packages/opencode/src/lsp/`) — needs EditTool refactor first
- [ ] Remove or stub Format integration (`packages/opencode/src/format/`)
- [ ] Remove git-specific logic (`packages/opencode/src/git.ts`) or repurpose
- [ ] Remove worktree support (`packages/opencode/src/worktree/`) — needs httpapi endpoint + test cleanup
- [ ] Clean up `packages/opencode/src/session/reminders.ts` — may still reference coding concepts

### Phase 5 Remaining
- [ ] /playbook, /export slash commands (not yet implemented)

### Phase 6: TUI & Branding
- [ ] Rebrand TUI (banner, logo, colors)
- [ ] Add engagement status bar (phase, hosts, vulns, creds)
- [ ] Add vulnerability/host/credential table rendering
- [ ] Rename config dir from `.opencode/` to `.pentestcode/`
- [ ] Rename all `@opencode-ai/*` package scopes to `@pentestcode/*` (or keep as fork)

### Phase 7: Build & Test
- [ ] Verify `bun install` succeeds
- [ ] Verify `bun run dev` launches TUI
- [ ] Test with real LLM provider (Anthropic/OpenAI)
- [ ] Test engagement state persistence
- [ ] Test skill loading from `skills/` directory
- [ ] End-to-end test on CTF target

## Design Decisions

- **Hard fork, no upstream tracking** — deep domain changes make merging impractical
- **Multi-agent strategist-operator split** — pentest agent coordinates, subagents execute (4.3x improvement per HPTSA research)
- **Pentesting Task Tree (PTT)** — hierarchical attack tree with difficulty scoring, strategic abandonment, credential propagation
- **Selective context injection** — don't dump full state each turn; assemble minimal relevant context
- **4-layer prompt system** — identity (always) → engagement state (dynamic) → phase skill (per-phase) → service knowledge (on-demand)
- **File-based engagement store** — single JSON at `~/.pentestcode/engagements/<name>/state.json`, not relational; simpler and portable
- **Global storage** — engagements at `~/.pentestcode/engagements/`, not per-directory. Security work isn't tied to cwd. Supports parallel activities (bounty + CTF + work pentest).
- **Universal tools** — tools work for pentesting, bug bounty, vuln research, CTF, infra security. Not narrowly scoped.
- **Skills as SKILL.md files** — no code changes needed, just add markdown files
- **edit tool kept** — useful for modifying exploit scripts, payloads, configs
- **recon agent has full tool access** — passive/active controlled by prompt and user choice, not permissions
- **Multi-session on same engagement** — two terminals can load the same engagement. Each has its own Ref. Last-write-wins on disk. `state_update reload_engagement` to pick up changes from other session.

## Architecture Notes (gotchas)

### Two Prompt Systems: V1 and V2
- **V1** (`packages/opencode/`) — active for interactive TUI sessions. Uses `prompt.ts` → `runLoop()`. Does NOT use `SystemContextRegistry`.
- **V2** (`packages/core/`) — durable runner path. Uses `SystemContextRegistry`, `LocationServiceMap`, etc.
- EngagementStore.node is `makeGlobalNode` (no deps) — works in both V1 and V2 graphs.
- EngagementContext.node is `makeLocationNode` (depends on SystemContextRegistry) — V2 only. V1 injects engagement context directly in `prompt.ts`.

### Effect Layer System
- `makeGlobalNode`: no scope dependencies, goes in `AppLayer` and any graph
- `makeLocationNode`: depends on Location.Service (scoped), only works in location-scoped graphs
- **Rule**: a global node CANNOT depend on a location-scoped node. Reverse is fine.
- `LayerNode.make` (used in V1 `app-runtime.ts`): can go in either graph

### Effect Schema (v4 beta)
- `Schema.Literal("a")` — single literal (1 arg only)
- `Schema.Literals(["a", "b", "c"])` — literal union (takes array)
- `Schema.optional(Schema.X)` — optional field (no `Schema.optionalWith`, no defaults in schema)
- `Schema.Record(Schema.String, ValueSchema)` — positional args, NOT `Schema.Record({ key, value })`
- No `Schema.withDefault` in this version. Handle defaults in application code (store.create, tool constructors).

### Tool Pattern (V1)
```typescript
export const MyTool = Tool.define("tool_id", Effect.gen(function* () {
  const store = yield* SomeService
  return {
    description: DESCRIPTION_FROM_TXT,
    parameters: Schema.Struct({ ... }),
    execute: (params, ctx) => Effect.gen(function* () {
      // ...
      return { title: "...", metadata: {}, output: "..." }
    }).pipe(Effect.orDie),
  }
}))
```

### Multi-Agent State Sharing
- All agents in same session share the same EngagementStore.Service Ref (cooperative fibers, no race conditions in single-thread Bun).
- Subagent spawned via `task` tool gets fresh prompt context but shares same Ref.
- State updates by subagent are immediately visible to parent agent.

import { Effect, Schema } from "effect"
import { EngagementStore } from "@opencode-ai/core/engagement/store"
import { EngagementSchema } from "@opencode-ai/core/engagement/schema"
import DESCRIPTION from "./state-query.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  query_type: Schema.Literals([
    "summary",
    "hosts",
    "vulns",
    "creds",
    "scope",
    "phase",
    "flags",
    "tasks",
    "host",
    "full",
    "engagements",
  ]).annotate({
    description:
      "Type of query: summary, hosts, vulns, creds, scope, phase, flags, tasks, host (single host), full (compact context), engagements (list all)",
  }),
  filter: Schema.optional(Schema.String).annotate({
    description: "Filter: IP for host query, severity for vulns, engagement name for details",
  }),
})

const NO_ENGAGEMENT = "No engagement loaded. Create one with state_update (action: create_engagement) or load an existing one (action: load_engagement)."

function formatHost(ip: string, host: EngagementSchema.Host): string {
  const lines: string[] = []
  lines.push(`[${ip}]${host.hostname ? ` (${host.hostname})` : ""}${host.os ? ` OS: ${host.os}` : ""}`)
  if (host.services.length > 0) {
    for (const svc of host.services) {
      const ver = svc.version ? ` ${svc.version}` : ""
      lines.push(`  ${svc.port}/${svc.protocol ?? "tcp"} ${svc.state ?? "open"} ${svc.service ?? ""}${ver}${svc.banner ? ` -- ${svc.banner}` : ""}`)
    }
  }
  if (host.vulns.length > 0) {
    lines.push(`  Vulns (${host.vulns.length}):`)
    for (const v of host.vulns) {
      lines.push(`    [${(v.severity ?? "medium").toUpperCase()}] ${v.title} (${v.status ?? "suspected"})${v.service_port ? ` port:${v.service_port}` : ""}`)
    }
  }
  if (host.access.length > 0) {
    lines.push(`  Access:`)
    for (const a of host.access) {
      lines.push(`    ${a.access_type} as ${a.username} (${a.level ?? "user"})${a.details ? ` -- ${a.details}` : ""}`)
    }
  }
  if (host.notes.length > 0) {
    lines.push(`  Notes: ${host.notes.join("; ")}`)
  }
  return lines.join("\n")
}

export const StateQueryTool = Tool.define(
  "state_query",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, _ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          // Handle engagements query separately -- doesn't require loaded state
          if (params.query_type === "engagements") {
            const engagements = yield* store.listEngagements()
            const current = yield* store.get()
            if (engagements.length === 0) {
              return {
                title: "Engagements",
                metadata: {},
                output: "No engagements found. Create one with state_update (action: create_engagement).",
              }
            }
            const lines = engagements.map((name) => {
              const marker = current && current.name === name ? " <-- LOADED" : ""
              return `  - ${name}${marker}`
            })
            return {
              title: "Engagements",
              metadata: { count: engagements.length },
              output: `Engagements (${engagements.length}):\n${lines.join("\n")}`,
            }
          }

          const state = yield* store.get()
          if (!state) {
            return { title: params.query_type, metadata: {}, output: NO_ENGAGEMENT }
          }

          switch (params.query_type) {
            case "summary": {
              const s = EngagementSchema.summary(state)
              const lines = [
                `Engagement: ${state.name} (${state.id})`,
                `Phase: ${s.current_phase} | Mode: ${s.mode}`,
                `Hosts: ${s.hosts_discovered} discovered, ${s.hosts_compromised} compromised`,
                `Vulnerabilities: ${s.vulnerabilities}`,
                `Credentials: ${s.credentials}`,
                `Flags: ${s.flags}`,
                `Attack steps: ${s.attack_steps}`,
                `Unchecked services: ${s.unchecked_services}`,
                `Scope: ${state.scope.targets.length} targets, ${state.scope.excludes.length} excludes`,
              ]
              return { title: "Summary", metadata: s, output: lines.join("\n") }
            }

            case "hosts": {
              const hosts = Object.entries(state.hosts)
              if (hosts.length === 0) {
                return { title: "Hosts", metadata: { count: 0 }, output: "No hosts discovered yet." }
              }
              const output = hosts.map(([ip, host]) => formatHost(ip, host)).join("\n\n")
              return { title: "Hosts", metadata: { count: hosts.length }, output: `Hosts (${hosts.length}):\n\n${output}` }
            }

            case "vulns": {
              const allVulns: { ip: string; vuln: EngagementSchema.Vulnerability }[] = []
              for (const [ip, host] of Object.entries(state.hosts)) {
                for (const vuln of host.vulns) {
                  allVulns.push({ ip, vuln })
                }
              }
              if (allVulns.length === 0) {
                return { title: "Vulnerabilities", metadata: { count: 0 }, output: "No vulnerabilities recorded yet." }
              }
              const filtered = params.filter
                ? allVulns.filter((v) => v.vuln.severity === params.filter)
                : allVulns
              // Sort by severity
              const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
              filtered.sort((a, b) => (order[a.vuln.severity ?? "medium"] ?? 5) - (order[b.vuln.severity ?? "medium"] ?? 5))
              const lines = filtered.map((v) => {
                const sev = v.vuln.severity ?? "medium"
                const port = v.vuln.service_port ? `:${v.vuln.service_port}` : ""
                const refs = (v.vuln.references ?? []).length > 0 ? ` refs:[${(v.vuln.references ?? []).join(",")}]` : ""
                return `[${sev.toUpperCase()}] ${v.ip}${port} -- ${v.vuln.title} (${v.vuln.status ?? "suspected"})${refs}${v.vuln.description ? `\n  ${v.vuln.description}` : ""}`
              })
              const label = params.filter ? `Vulnerabilities [${params.filter}]` : "Vulnerabilities"
              return {
                title: label,
                metadata: { count: filtered.length, total: allVulns.length },
                output: `${label} (${filtered.length}${params.filter ? ` of ${allVulns.length} total` : ""}):\n\n${lines.join("\n")}`,
              }
            }

            case "creds": {
              const creds = Object.values(state.credentials)
              if (creds.length === 0) {
                return { title: "Credentials", metadata: { count: 0 }, output: "No credentials captured yet." }
              }
              const lines = creds.map((c) => {
                const vf = c.valid_for ?? []
                const validFor = vf.length > 0 ? ` valid_for:[${vf.join(",")}]` : ""
                return `  [${c.id}] ${c.username ?? ""} (${c.cred_type ?? "password"}) source:${c.source || "unknown"}${validFor}`
              })
              return {
                title: "Credentials",
                metadata: { count: creds.length },
                output: `Credentials (${creds.length}):\n${lines.join("\n")}`,
              }
            }

            case "scope": {
              const lines = [
                `Targets (${state.scope.targets.length}):`,
                ...(state.scope.targets.length > 0 ? state.scope.targets.map((t) => `  - ${t}`) : ["  (none)"]),
                `Excludes (${state.scope.excludes.length}):`,
                ...(state.scope.excludes.length > 0 ? state.scope.excludes.map((e) => `  - ${e}`) : ["  (none)"]),
                ...(state.scope.notes ? [`Notes: ${state.scope.notes}`] : []),
              ]
              return { title: "Scope", metadata: {}, output: lines.join("\n") }
            }

            case "phase": {
              return {
                title: "Phase",
                metadata: { phase: state.current_phase, mode: state.mode },
                output: `Current phase: ${state.current_phase}\nMode: ${state.mode}`,
              }
            }

            case "flags": {
              if (state.flags.length === 0) {
                return { title: "Flags", metadata: { count: 0 }, output: "No flags captured yet." }
              }
              const lines = state.flags.map((f, i) => `  ${i + 1}. ${f}`)
              return {
                title: "Flags",
                metadata: { count: state.flags.length },
                output: `Flags (${state.flags.length}):\n${lines.join("\n")}`,
              }
            }

            case "tasks": {
              const pending = state.task_tree.filter((t) => t.status === "pending" || t.status === "in_progress")
              if (pending.length === 0) {
                return {
                  title: "Tasks",
                  metadata: { count: 0, total: state.task_tree.length },
                  output: state.task_tree.length === 0
                    ? "No tasks in the task tree."
                    : `All ${state.task_tree.length} tasks are done or abandoned.`,
                }
              }
              const lines = pending.map((t) => {
                const diff = (t.difficulty ?? 0) > 0 ? ` difficulty:${t.difficulty}` : ""
                return `  [${(t.status ?? "pending").toUpperCase()}] ${t.id}: ${t.description}${t.target ? ` target:${t.target}` : ""}${t.technique ? ` technique:${t.technique}` : ""}${diff}`
              })
              return {
                title: "Tasks",
                metadata: { count: pending.length, total: state.task_tree.length },
                output: `Active tasks (${pending.length} of ${state.task_tree.length}):\n${lines.join("\n")}`,
              }
            }

            case "host": {
              if (!params.filter) {
                return { title: "Host", metadata: {}, output: "Error: filter parameter required (set to the host IP address)." }
              }
              const host = state.hosts[params.filter]
              if (!host) {
                const available = Object.keys(state.hosts)
                return {
                  title: "Host",
                  metadata: {},
                  output: `Host ${params.filter} not found.${available.length > 0 ? ` Known hosts: ${available.join(", ")}` : ""}`,
                }
              }
              return { title: `Host ${params.filter}`, metadata: {}, output: formatHost(params.filter, host) }
            }

            case "full": {
              const compact = EngagementSchema.toCompactContext(state)
              return { title: "Full Context", metadata: {}, output: compact }
            }

            default: {
              return { title: "Error", metadata: {}, output: `Unknown query type: ${params.query_type}` }
            }
          }
        }).pipe(Effect.orDie),
    }
  }),
)

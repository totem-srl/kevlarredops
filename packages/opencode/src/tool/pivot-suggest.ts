import { Effect, Schema } from "effect"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { EngagementSchema } from "@pentestcode/core/engagement/schema"
import DESCRIPTION from "./pivot-suggest.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  from_host: Schema.optional(Schema.String).annotate({
    description: "Starting host IP (defaults to first compromised host)",
  }),
  to_host: Schema.optional(Schema.String).annotate({
    description: "Destination host IP (finds shortest path if specified)",
  }),
  objective: Schema.optional(Schema.String).annotate({
    description: 'What to reach: "domain controller", "10.10.10.0/24 subnet", etc.',
  }),
})

interface GraphNode {
  ip: string
  compromised: boolean
  serviceCount: number
  isDC: boolean
  hasAccess: boolean
  accessUsers: string[]
}

interface GraphEdge {
  from: string
  to: string
  relType: string
  metadata?: string
}

interface PivotSuggestion {
  path: string[]
  credentialNeeded: string
  tunnelType: string
  complexity: "low" | "medium" | "high"
  reason: string
}

function buildGraph(state: EngagementSchema.State): { nodes: Map<string, GraphNode>; edges: GraphEdge[] } {
  const nodes = new Map<string, GraphNode>()

  for (const [ip, host] of Object.entries(state.hosts)) {
    nodes.set(ip, {
      ip,
      compromised: host.access.length > 0,
      serviceCount: host.services.length,
      isDC: host.domain_info?.is_dc === true,
      hasAccess: host.access.length > 0,
      accessUsers: host.access.map((a) => a.username),
    })
  }

  const edges: GraphEdge[] = []
  const rels = state.relationships ?? []
  for (const rel of rels) {
    if (["REACHABLE_FROM", "PIVOT_TO", "LATERAL_MOVE", "AUTHENTICATES_TO", "ADMIN_OF"].includes(rel.rel_type)) {
      edges.push({
        from: rel.source_id,
        to: rel.target_id,
        relType: rel.rel_type,
        metadata: rel.metadata ?? undefined,
      })
    }
  }

  for (const [ip, host] of Object.entries(state.hosts)) {
    if (host.access.length > 0) {
      for (const [otherIp] of Object.entries(state.hosts)) {
        if (otherIp === ip) continue
        const hasEdge = edges.some(
          (e) => (e.from === ip && e.to === otherIp) || (e.from === otherIp && e.to === ip),
        )
        if (!hasEdge) {
          edges.push({ from: ip, to: otherIp, relType: "REACHABLE_FROM" })
        }
      }
    }
  }

  return { nodes, edges }
}

function bfs(
  edges: GraphEdge[],
  start: string,
  end: string,
): string[] | undefined {
  const adj = new Map<string, string[]>()
  for (const edge of edges) {
    if (!adj.has(edge.from)) adj.set(edge.from, [])
    adj.get(edge.from)!.push(edge.to)
  }

  const visited = new Set<string>()
  const queue: { node: string; path: string[] }[] = [{ node: start, path: [start] }]
  visited.add(start)

  while (queue.length > 0) {
    const current = queue.shift()!
    if (current.node === end) return current.path

    const neighbors = adj.get(current.node) ?? []
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        visited.add(neighbor)
        queue.push({ node: neighbor, path: [...current.path, neighbor] })
      }
    }
  }

  return undefined
}

function estimateComplexity(
  state: EngagementSchema.State,
  fromIp: string,
  toIp: string,
): "low" | "medium" | "high" {
  const fromHost = state.hosts[fromIp]
  const toHost = state.hosts[toIp]
  if (!fromHost || !toHost) return "high"

  if (fromHost.access.length > 0) {
    const hasCredsForTarget = fromHost.access.some((a) => {
      return Object.values(state.credentials).some(
        (c) => c.username === a.username && c.value,
      )
    })
    if (hasCredsForTarget) return "low"
  }

  const hasSSH = toHost.services.some((s) => s.service === "ssh" || s.port === 22)
  const hasRDP = toHost.services.some((s) => s.service === "rdp" || s.service === "ms-wbt-server" || s.port === 3389)
  const hasSMB = toHost.services.some((s) => s.service === "microsoft-ds" || s.service === "smb" || s.port === 445)

  if (hasSSH || hasRDP || hasSMB) return "medium"
  return "high"
}

function suggestTunnelType(state: EngagementSchema.State, hostIp: string): string {
  const host = state.hosts[hostIp]
  if (!host) return "chisel"
  const hasSSH = host.services.some((s) => s.service === "ssh" || s.port === 22)
  if (hasSSH) return "ssh_dynamic"
  return "chisel"
}

function findCredsDescription(state: EngagementSchema.State, hostIp: string): string {
  const host = state.hosts[hostIp]
  if (!host) return "no credentials available"
  for (const access of host.access) {
    const cred = Object.values(state.credentials).find(
      (c) => c.username === access.username && c.value,
    )
    if (cred) return `${cred.username} (${cred.cred_type ?? "password"})`
  }
  return "no credentials — enumerate/exploit first"
}

function scoreHost(node: GraphNode): number {
  let score = 0
  if (node.isDC) score += 100
  score += node.serviceCount * 5
  if (!node.compromised) score += 10
  return score
}

export const PivotSuggestTool = Tool.define(
  "pivot_suggest",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) {
            return { title: "Error", metadata: {}, output: "No engagement loaded." }
          }

          const { nodes, edges } = buildGraph(state)
          const compromised = [...nodes.values()].filter((n) => n.compromised)

          if (compromised.length === 0) {
            return {
              title: "No pivot sources",
              metadata: {},
              output: "No compromised hosts to pivot from. Gain initial access first.",
            }
          }

          const fromIp = params.from_host ?? compromised[0]!.ip
          const fromNode = nodes.get(fromIp)
          if (!fromNode || !fromNode.compromised) {
            return {
              title: "Error",
              metadata: {},
              output: `Host ${fromIp} is not compromised or not in engagement. Cannot pivot from it.`,
            }
          }

          if (params.to_host) {
            const path = bfs(edges, fromIp, params.to_host)
            if (!path) {
              return {
                title: "No path found",
                metadata: { from: fromIp, to: params.to_host },
                output: `No path found from ${fromIp} to ${params.to_host}. The target may be in an unreachable network segment. Consider:\n1. Enumerate more services on intermediate hosts\n2. Add network segments with state_update\n3. Check if additional pivot hosts are needed`,
              }
            }

            const lines: string[] = [`Pivot path: ${fromIp} -> ${params.to_host} (${path.length - 1} hops)`]
            lines.push("")

            for (let i = 0; i < path.length - 1; i++) {
              const hop = path[i]!
              const next = path[i + 1]!
              const complexity = estimateComplexity(state, hop, next)
              const tunnel = suggestTunnelType(state, hop)
              const creds = findCredsDescription(state, hop)
              lines.push(`  Hop ${i + 1}: ${hop} -> ${next}`)
              lines.push(`    Credentials: ${creds}`)
              lines.push(`    Tunnel: ${tunnel}`)
              lines.push(`    Complexity: ${complexity}`)
              lines.push("")
            }

            lines.push("Execute with tunnel_manage for each hop.")

            return {
              title: `Path: ${path.length - 1} hops`,
              metadata: { from: fromIp, to: params.to_host, hops: path.length - 1 },
              output: lines.join("\n"),
            }
          }

          // No specific target — suggest unexplored/high-value hosts
          const suggestions: PivotSuggestion[] = []
          const unexplored = [...nodes.values()]
            .filter((n) => !n.compromised)
            .sort((a, b) => scoreHost(b) - scoreHost(a))

          for (const target of unexplored.slice(0, 10)) {
            const path = bfs(edges, fromIp, target.ip)
            if (!path) continue

            suggestions.push({
              path,
              credentialNeeded: findCredsDescription(state, fromIp),
              tunnelType: suggestTunnelType(state, fromIp),
              complexity: estimateComplexity(state, fromIp, target.ip),
              reason: target.isDC
                ? "DOMAIN CONTROLLER — highest priority"
                : target.serviceCount > 5
                  ? `${target.serviceCount} services — likely important server`
                  : "unexplored host",
            })
          }

          // Check network segments for unreachable targets
          const segments = state.network_segments ?? []
          const reachableSegments = segments.filter((seg) =>
            seg.reachable_from?.some((r) => compromised.some((c) => c.ip === r)),
          )
          const unreachableSegments = segments.filter(
            (seg) => !seg.reachable_from?.some((r) => compromised.some((c) => c.ip === r)),
          )

          if (suggestions.length === 0 && unreachableSegments.length === 0) {
            return {
              title: "No pivot targets",
              metadata: {},
              output: "All discovered hosts are either compromised or unreachable from current positions. Enumerate more hosts or add network segments.",
            }
          }

          const lines: string[] = [`Pivot suggestions from ${fromIp} (${suggestions.length} targets):`]
          lines.push("")

          for (let i = 0; i < suggestions.length; i++) {
            const s = suggestions[i]!
            const target = s.path[s.path.length - 1]!
            lines.push(`${i + 1}. ${target} [${s.complexity.toUpperCase()}] — ${s.reason}`)
            lines.push(`   Path: ${s.path.join(" -> ")}`)
            lines.push(`   Tunnel: ${s.tunnelType} | Creds: ${s.credentialNeeded}`)
            lines.push("")
          }

          if (reachableSegments.length > 0) {
            lines.push("Reachable network segments:")
            for (const seg of reachableSegments) {
              lines.push(`  ${seg.cidr}${seg.name ? ` (${seg.name})` : ""}${seg.pivot_host ? ` via ${seg.pivot_host}` : ""}`)
            }
            lines.push("")
          }

          if (unreachableSegments.length > 0) {
            lines.push("Unreachable segments (need additional pivots):")
            for (const seg of unreachableSegments) {
              lines.push(`  ${seg.cidr}${seg.name ? ` (${seg.name})` : ""}`)
            }
          }

          return {
            title: `${suggestions.length} pivot targets`,
            metadata: { from: fromIp, suggestions: suggestions.length },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

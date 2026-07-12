export * as EngagementStore from "./store"

import { Context, Effect, Layer, Ref, Schema } from "effect"
import { makeGlobalNode } from "../effect/app-node"
import { EngagementSchema } from "./schema"
import { TaskGraph } from "./task-graph"
import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"

const ENGAGEMENTS_DIR = path.join(os.homedir(), ".pentestcode", "engagements")
const LAST_FILE = ".last"
const CHANGELOG_FILE = "changelog.json"
const DECISIONS_FILE = "decisions.json"
const AGENT_CONTEXTS_FILE = "agent-contexts.json"
const WORDLISTS_FILE = "wordlists.json"
const FINDINGS_FILE = "findings.md"

function mergeServices(
  existing: readonly EngagementSchema.Service[],
  incoming: readonly EngagementSchema.Service[],
): EngagementSchema.Service[] {
  const byPort = new Map<string, EngagementSchema.Service>()
  for (const svc of existing) {
    byPort.set(`${svc.port}/${svc.protocol ?? "tcp"}`, svc)
  }
  for (const svc of incoming) {
    const key = `${svc.port}/${svc.protocol ?? "tcp"}`
    const prev = byPort.get(key)
    byPort.set(key, prev ? { ...prev, ...svc } : svc)
  }
  return [...byPort.values()]
}

export interface Interface {
  readonly get: () => Effect.Effect<EngagementSchema.State | undefined>
  readonly save: (state: EngagementSchema.State) => Effect.Effect<void>
  readonly create: (name: string) => Effect.Effect<EngagementSchema.State>
  readonly load: (name: string) => Effect.Effect<EngagementSchema.State | undefined>
  readonly lastEngagement: () => Effect.Effect<string | undefined>
  readonly listEngagements: () => Effect.Effect<string[]>
  readonly addHost: (ip: string, data?: Partial<EngagementSchema.Host>) => Effect.Effect<EngagementSchema.Host>
  readonly deleteHost: (ip: string) => Effect.Effect<boolean>
  readonly addVuln: (hostIp: string, vuln: EngagementSchema.Vulnerability) => Effect.Effect<void>
  readonly updateVuln: (hostIp: string, vulnId: string, patch: Partial<{ -readonly [K in keyof EngagementSchema.Vulnerability]: EngagementSchema.Vulnerability[K] }>) => Effect.Effect<boolean>
  readonly deleteVuln: (hostIp: string, vulnId: string) => Effect.Effect<boolean>
  readonly addCredential: (id: string, cred: Omit<EngagementSchema.Credential, "id">) => Effect.Effect<void>
  readonly deleteCredential: (id: string) => Effect.Effect<boolean>
  readonly addAccess: (hostIp: string, access: EngagementSchema.Access) => Effect.Effect<void>
  readonly setPhase: (phase: EngagementSchema.PentestPhase) => Effect.Effect<void>
  readonly setMode: (mode: EngagementSchema.PentestMode) => Effect.Effect<void>
  readonly updateScope: (scope: Partial<EngagementSchema.Scope>) => Effect.Effect<void>
  readonly getTaskGraph: () => Effect.Effect<TaskGraph.TaskNodes>
  readonly setTaskGraph: (tasks: TaskGraph.TaskNodes) => Effect.Effect<void>
  readonly setDomain: (domain: EngagementSchema.DomainState) => Effect.Effect<void>
  readonly updateDomain: (patch: Record<string, unknown>) => Effect.Effect<void>
  readonly addObjective: (objective: EngagementSchema.Objective) => Effect.Effect<void>
  readonly updateObjective: (id: string, patch: Record<string, unknown>) => Effect.Effect<void>
  readonly completeObjective: (id: string, evidence?: string) => Effect.Effect<void>
  readonly getChangelog: (since?: string, limit?: number) => Effect.Effect<EngagementSchema.ChangelogEntry[]>
  readonly getChangelogSince: (since: string) => Effect.Effect<EngagementSchema.ChangelogEntry[]>
  readonly markInjected: () => Effect.Effect<string>
  readonly getLastInjectedTimestamp: () => Effect.Effect<string | undefined>
  readonly addRelationship: (rel: EngagementSchema.Relationship) => Effect.Effect<boolean>
  readonly getRelationships: (filter?: { entity_id?: string; rel_type?: string }) => Effect.Effect<readonly EngagementSchema.Relationship[]>
  readonly deleteRelationship: (source_id: string, rel_type: string, target_id: string) => Effect.Effect<boolean>
  // Decision Memory
  readonly addDecision: (decision: EngagementSchema.Decision) => Effect.Effect<void>
  readonly updateDecisionOutcome: (id: string, outcome: string, notes?: string) => Effect.Effect<boolean>
  readonly getDecisions: (limit?: number) => Effect.Effect<EngagementSchema.Decision[]>
  // Alert Queue
  readonly addAlert: (alert: EngagementSchema.Alert) => Effect.Effect<void>
  readonly acknowledgeAlert: (id: string) => Effect.Effect<boolean>
  readonly getActiveAlerts: () => Effect.Effect<EngagementSchema.Alert[]>
  // Live Sessions
  readonly addLiveSession: (session: EngagementSchema.LiveSession) => Effect.Effect<void>
  readonly updateLiveSession: (id: string, patch: Record<string, unknown>) => Effect.Effect<boolean>
  readonly removeLiveSession: (id: string) => Effect.Effect<boolean>
  // Network Segments
  readonly addNetworkSegment: (segment: EngagementSchema.NetworkSegment) => Effect.Effect<void>
  readonly updateNetworkSegment: (id: string, patch: Record<string, unknown>) => Effect.Effect<boolean>
  readonly removeNetworkSegment: (id: string) => Effect.Effect<boolean>
  // Agent Context Carry
  readonly addAgentContext: (summary: EngagementSchema.AgentContextSummary) => Effect.Effect<void>
  readonly getAgentContexts: (agentType: string, limit?: number) => Effect.Effect<EngagementSchema.AgentContextSummary[]>
  // Interrupt Alerts
  readonly drainInterruptAlerts: () => Effect.Effect<EngagementSchema.Alert[]>
  readonly hasInterruptAlerts: () => Effect.Effect<boolean>
  // Wordlist Usage Tracking
  readonly addWordlistUsage: (usage: EngagementSchema.WordlistUsage) => Effect.Effect<boolean>
  readonly getWordlistUsages: (filter?: { host_ip?: string; port?: number; tool_type?: string }) => Effect.Effect<readonly EngagementSchema.WordlistUsage[]>
  // Pause Behavior
  readonly setPauseBehavior: (behavior: EngagementSchema.PauseBehavior) => Effect.Effect<void>
}

export class Service extends Context.Service<Service, Interface>()("@pentestcode/EngagementStore") {}

function stateFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, "state.json")
}

function changelogFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, CHANGELOG_FILE)
}

function decisionsFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, DECISIONS_FILE)
}

function agentContextsFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, AGENT_CONTEXTS_FILE)
}

function wordlistsFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, WORDLISTS_FILE)
}

function findingsFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, FINDINGS_FILE)
}

function lastFilePath(): string {
  return path.join(ENGAGEMENTS_DIR, LAST_FILE)
}

const encode = Schema.encodeSync(EngagementSchema.State)
const decode = Schema.decodeUnknownSync(EngagementSchema.State)

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const stateRef = yield* Ref.make<EngagementSchema.State | undefined>(undefined)
    const changelogRef = yield* Ref.make<EngagementSchema.ChangelogEntry[]>([])
    const decisionsRef = yield* Ref.make<EngagementSchema.Decision[]>([])
    const agentContextsRef = yield* Ref.make<Record<string, EngagementSchema.AgentContextSummary[]>>({})
    const interruptQueueRef = yield* Ref.make<EngagementSchema.Alert[]>([])
    const wordlistsRef = yield* Ref.make<EngagementSchema.WordlistUsage[]>([])
    const lastInjectedRef = yield* Ref.make<string | undefined>(undefined)

    const logChange = (action: string, entityType: string, entityId: string | undefined, summary: string) =>
      Effect.gen(function* () {
        const entry: EngagementSchema.ChangelogEntry = {
          timestamp: new Date().toISOString(),
          action,
          entity_type: entityType,
          entity_id: entityId,
          summary,
        }
        const current = yield* Ref.get(changelogRef)
        const updated = [...current, entry]
        const trimmed = updated.length > EngagementSchema.CHANGELOG_MAX_ENTRIES
          ? updated.slice(updated.length - EngagementSchema.CHANGELOG_MAX_ENTRIES)
          : updated
        yield* Ref.set(changelogRef, trimmed)
      })

    const persistChangelogEntries = (name: string, entries: EngagementSchema.ChangelogEntry[]) => {
      try {
        const filePath = changelogFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        fs.writeFileSync(filePath, JSON.stringify(entries, undefined, 2), { encoding: "utf-8", mode: 0o600 })
      } catch {
        // changelog persistence is best-effort
      }
    }

    const loadChangelog = (name: string): EngagementSchema.ChangelogEntry[] => {
      try {
        const filePath = changelogFilePath(name)
        if (!fs.existsSync(filePath)) return []
        const raw = fs.readFileSync(filePath, "utf-8")
        return JSON.parse(raw) as EngagementSchema.ChangelogEntry[]
      } catch {
        return []
      }
    }

    const persistDecisions = (name: string, entries: EngagementSchema.Decision[]) => {
      try {
        const filePath = decisionsFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        fs.writeFileSync(filePath, JSON.stringify(entries, undefined, 2), { encoding: "utf-8", mode: 0o600 })
      } catch {
        // decisions persistence is best-effort
      }
    }

    const loadDecisions = (name: string): EngagementSchema.Decision[] => {
      try {
        const filePath = decisionsFilePath(name)
        if (!fs.existsSync(filePath)) return []
        const raw = fs.readFileSync(filePath, "utf-8")
        return JSON.parse(raw) as EngagementSchema.Decision[]
      } catch {
        return []
      }
    }

    const persistAgentContexts = (name: string, contexts: Record<string, EngagementSchema.AgentContextSummary[]>) => {
      try {
        const filePath = agentContextsFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        fs.writeFileSync(filePath, JSON.stringify(contexts, undefined, 2), { encoding: "utf-8", mode: 0o600 })
      } catch {
        // agent contexts persistence is best-effort
      }
    }

    const loadAgentContexts = (name: string): Record<string, EngagementSchema.AgentContextSummary[]> => {
      try {
        const filePath = agentContextsFilePath(name)
        if (!fs.existsSync(filePath)) return {}
        const raw = fs.readFileSync(filePath, "utf-8")
        return JSON.parse(raw) as Record<string, EngagementSchema.AgentContextSummary[]>
      } catch {
        return {}
      }
    }

    const persistWordlists = (name: string, entries: readonly EngagementSchema.WordlistUsage[]) => {
      try {
        const filePath = wordlistsFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        fs.writeFileSync(filePath, JSON.stringify(entries, undefined, 2), { encoding: "utf-8", mode: 0o600 })
      } catch {
        // wordlist persistence is best-effort
      }
    }

    const loadWordlists = (name: string): EngagementSchema.WordlistUsage[] => {
      try {
        const filePath = wordlistsFilePath(name)
        if (!fs.existsSync(filePath)) return []
        const raw = fs.readFileSync(filePath, "utf-8")
        return JSON.parse(raw) as EngagementSchema.WordlistUsage[]
      } catch {
        return []
      }
    }

    const appendFinding = (name: string, entry: string) => {
      try {
        const filePath = findingsFilePath(name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        if (!fs.existsSync(filePath)) {
          const header = `# Findings Journal\n\n*Auto-generated during engagement "${name}"*\n\n---\n\n`
          fs.writeFileSync(filePath, header, { encoding: "utf-8", mode: 0o600 })
        }
        fs.appendFileSync(filePath, entry + "\n\n", { encoding: "utf-8" })
      } catch {
        // findings journal is best-effort
      }
    }

    const persist = (state: EngagementSchema.State) =>
      Effect.sync(() => {
        const filePath = stateFilePath(state.name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
        const json = encode(state)
        fs.writeFileSync(filePath, JSON.stringify(json, undefined, 2), { encoding: "utf-8", mode: 0o600 })
        const lastPath = lastFilePath()
        fs.mkdirSync(path.dirname(lastPath), { recursive: true, mode: 0o700 })
        fs.writeFileSync(lastPath, state.name, { encoding: "utf-8", mode: 0o600 })
      })

    const readFromDisk = (name: string) =>
      Effect.sync(() => {
        const filePath = stateFilePath(name)
        if (!fs.existsSync(filePath)) return undefined
        const raw = fs.readFileSync(filePath, "utf-8")
        return decode(JSON.parse(raw))
      })

    return Service.of({
      get: () => Ref.get(stateRef),

      listEngagements: () =>
        Effect.sync(() => {
          if (!fs.existsSync(ENGAGEMENTS_DIR)) return []
          return fs.readdirSync(ENGAGEMENTS_DIR).filter((entry) => {
            if (entry === LAST_FILE) return false
            const stat = fs.statSync(path.join(ENGAGEMENTS_DIR, entry))
            return stat.isDirectory()
          })
        }),

      save: Effect.fn("EngagementStore.save")(function* (state) {
        const updated = { ...state, updated_at: new Date().toISOString() }
        yield* Ref.set(stateRef, updated)
        yield* persist(updated)
        const entries = yield* Ref.get(changelogRef)
        persistChangelogEntries(updated.name, entries)
        const decisions = yield* Ref.get(decisionsRef)
        if (decisions.length > 0) persistDecisions(updated.name, decisions)
        const contexts = yield* Ref.get(agentContextsRef)
        if (Object.keys(contexts).length > 0) persistAgentContexts(updated.name, contexts)
        const wordlists = yield* Ref.get(wordlistsRef)
        if (wordlists.length > 0) persistWordlists(updated.name, wordlists)
      }),

      create: Effect.fn("EngagementStore.create")(function* (name) {
        const state: EngagementSchema.State = {
          id: EngagementSchema.ID.make(crypto.randomUUID().slice(0, 8)),
          name,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          scope: { targets: [], excludes: [], notes: "" },
          hosts: {},
          credentials: {},
          flags: [],
          attack_path: [],
          task_tree: [],
          current_phase: "recon",
          mode: "auto",
          notes: [],
        }
        yield* Ref.set(stateRef, state)
        yield* Ref.set(changelogRef, [])
        yield* Ref.set(decisionsRef, [])
        yield* Ref.set(agentContextsRef, {})
        yield* Ref.set(interruptQueueRef, [])
        yield* Ref.set(wordlistsRef, [])
        yield* persist(state)
        yield* logChange("create_engagement", "engagement", state.id, `Created engagement "${name}"`)
        return state
      }),

      load: Effect.fn("EngagementStore.load")(function* (name) {
        const state = yield* readFromDisk(name)
        if (state) {
          yield* Ref.set(stateRef, state)
          yield* Ref.set(changelogRef, loadChangelog(name))
          yield* Ref.set(decisionsRef, loadDecisions(name))
          yield* Ref.set(agentContextsRef, loadAgentContexts(name))
          yield* Ref.set(interruptQueueRef, [])
          yield* Ref.set(wordlistsRef, loadWordlists(name))
        }
        return state
      }),

      lastEngagement: () =>
        Effect.sync(() => {
          const p = lastFilePath()
          if (!fs.existsSync(p)) return undefined
          return fs.readFileSync(p, "utf-8").trim() || undefined
        }),

      addHost: Effect.fn("EngagementStore.addHost")(function* (ip, data) {
        const current = yield* Ref.get(stateRef)
        if (!current) return { ip, services: [], vulns: [], access: [], notes: [], ...data } as EngagementSchema.Host
        const existing = current.hosts[ip]
        let host: EngagementSchema.Host
        if (existing) {
          const mergedServices = mergeServices(existing.services, data?.services ?? [])
          host = {
            ...existing,
            ...data,
            services: mergedServices,
            vulns: existing.vulns,
            access: existing.access,
            notes: existing.notes,
          }
        } else {
          host = { ip, services: [], vulns: [], access: [], notes: [], ...data } as EngagementSchema.Host
          yield* logChange("add_host", "host", ip, `Host ${ip}${data?.hostname ? ` (${data.hostname})` : ""} added, ${host.services.length} services`)
        }
        const updated = { ...current, hosts: { ...current.hosts, [ip]: host } }
        yield* Ref.set(stateRef, updated)
        return host
      }),

      deleteHost: Effect.fn("EngagementStore.deleteHost")(function* (ip) {
        const current = yield* Ref.get(stateRef)
        if (!current || !current.hosts[ip]) return false
        const { [ip]: _, ...remainingHosts } = current.hosts
        yield* Ref.set(stateRef, { ...current, hosts: remainingHosts })
        yield* logChange("delete_host", "host", ip, `Host ${ip} deleted`)
        return true
      }),

      addVuln: Effect.fn("EngagementStore.addVuln")(function* (hostIp, vuln) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const host = current.hosts[hostIp]
        if (!host) return
        const isDupe = host.vulns.some(
          (v) => v.title === vuln.title && v.service_port === vuln.service_port,
        )
        if (isDupe) {
          const updatedVulns = host.vulns.map((v) =>
            v.title === vuln.title && v.service_port === vuln.service_port ? { ...v, ...vuln } : v,
          )
          yield* Ref.set(stateRef, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, vulns: updatedVulns } } })
        } else {
          yield* Ref.set(stateRef, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, vulns: [...host.vulns, vuln] } } })
          yield* logChange("add_vuln", "vuln", vuln.id, `[${(vuln.severity ?? "medium").toUpperCase()}] ${vuln.title} on ${hostIp}${vuln.confidence !== undefined ? ` conf:${vuln.confidence}` : ""}`)
          const sevIcon: Record<string, string> = { critical: "!!!", high: "!!", medium: "!", low: ".", info: "i" }
          const findingLines = [
            `## ${sevIcon[vuln.severity ?? "medium"] ?? "!"} [${(vuln.severity ?? "medium").toUpperCase()}] ${vuln.title}`,
            `**Time**: ${new Date().toISOString()}`,
            `**Host**: ${hostIp}${vuln.service_port ? `:${vuln.service_port}` : ""}`,
            `**Status**: ${vuln.status ?? "suspected"}${vuln.confidence !== undefined ? ` (confidence: ${(vuln.confidence * 100).toFixed(0)}%)` : ""}`,
            ...(vuln.description ? [`**Description**: ${vuln.description}`] : []),
            ...(vuln.evidence ? [`**Evidence**: \`${vuln.evidence}\``] : []),
            ...(vuln.evidence_items?.length ? [
              `**Evidence Chain**:`,
              ...vuln.evidence_items.map((e) =>
                `- \`${e.tool}\`${e.source_agent ? ` (${e.source_agent})` : ""}: ${e.command ?? "(no command)"}${e.verification_status ? ` [${e.verification_status}]` : ""}`
              ),
            ] : []),
            `---`,
          ]
          appendFinding(current.name, findingLines.join("\n"))
        }
      }),

      updateVuln: Effect.fn("EngagementStore.updateVuln")(function* (hostIp, vulnId, patch) {
        const current = yield* Ref.get(stateRef)
        if (!current) return false
        const host = current.hosts[hostIp]
        if (!host) return false
        const idx = host.vulns.findIndex((v) => v.id === vulnId)
        if (idx === -1) return false
        const updatedVulns = [...host.vulns]
        updatedVulns[idx] = { ...updatedVulns[idx]!, ...patch }
        yield* Ref.set(stateRef, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, vulns: updatedVulns } } })
        yield* logChange("update_vuln", "vuln", vulnId, `Vuln ${vulnId} on ${hostIp} updated: ${Object.keys(patch).join(", ")}`)
        return true
      }),

      deleteVuln: Effect.fn("EngagementStore.deleteVuln")(function* (hostIp, vulnId) {
        const current = yield* Ref.get(stateRef)
        if (!current) return false
        const host = current.hosts[hostIp]
        if (!host) return false
        const before = host.vulns.length
        const filtered = host.vulns.filter((v) => v.id !== vulnId)
        if (filtered.length === before) return false
        yield* Ref.set(stateRef, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, vulns: filtered } } })
        yield* logChange("delete_vuln", "vuln", vulnId, `Vuln ${vulnId} deleted from ${hostIp}`)
        return true
      }),

      addCredential: Effect.fn("EngagementStore.addCredential")(function* (id, cred) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const isNew = !current.credentials[id]
        yield* Ref.set(stateRef, {
          ...current,
          credentials: { ...current.credentials, [id]: { ...cred, id } },
        })
        if (isNew) {
          yield* logChange("add_credential", "credential", id, `Credential ${cred.username ?? id} (${cred.cred_type ?? "password"})${cred.confidence !== undefined ? ` conf:${cred.confidence}` : ""}`)
          const findingLines = [
            `## Credential Found: ${cred.username ?? id}`,
            `**Time**: ${new Date().toISOString()}`,
            `**Type**: ${cred.cred_type ?? "password"}`,
            `**Source**: ${cred.source ?? "unknown"}`,
            ...(cred.valid_for?.length ? [`**Valid For**: ${cred.valid_for.join(", ")}`] : []),
            ...(cred.confidence !== undefined ? [`**Confidence**: ${(cred.confidence * 100).toFixed(0)}%`] : []),
            ...(cred.domain ? [`**Domain**: ${cred.domain}`] : []),
            `---`,
          ]
          appendFinding(current.name, findingLines.join("\n"))
        }
      }),

      deleteCredential: Effect.fn("EngagementStore.deleteCredential")(function* (id) {
        const current = yield* Ref.get(stateRef)
        if (!current || !current.credentials[id]) return false
        const { [id]: _, ...remaining } = current.credentials
        yield* Ref.set(stateRef, { ...current, credentials: remaining })
        yield* logChange("delete_credential", "credential", id, `Credential ${id} deleted`)
        return true
      }),

      addAccess: Effect.fn("EngagementStore.addAccess")(function* (hostIp, access) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const host = current.hosts[hostIp]
        if (!host) return
        const isDupe = host.access.some(
          (a) => a.access_type === access.access_type && a.username === access.username,
        )
        if (isDupe) {
          const updatedAccess = host.access.map((a) =>
            a.access_type === access.access_type && a.username === access.username ? { ...a, ...access } : a,
          )
          yield* Ref.set(stateRef, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, access: updatedAccess } } })
        } else {
          yield* Ref.set(stateRef, { ...current, hosts: { ...current.hosts, [hostIp]: { ...host, access: [...host.access, access] } } })
          yield* logChange("add_access", "access", hostIp, `${access.access_type} as ${access.username} (${access.level ?? "user"}) on ${hostIp}${access.confidence !== undefined ? ` conf:${access.confidence}` : ""}`)
          const findingLines = [
            `## Access Gained: ${hostIp}`,
            `**Time**: ${new Date().toISOString()}`,
            `**Type**: ${access.access_type}`,
            `**User**: ${access.username}`,
            `**Level**: ${access.level ?? "user"}`,
            ...(access.details ? [`**Details**: ${access.details}`] : []),
            ...(access.credential_id ? [`**Credential**: ${access.credential_id}`] : []),
            `---`,
          ]
          appendFinding(current.name, findingLines.join("\n"))
        }
      }),

      setPhase: Effect.fn("EngagementStore.setPhase")(function* (phase) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const oldPhase = current.current_phase
        yield* Ref.set(stateRef, { ...current, current_phase: phase })
        yield* logChange("set_phase", "phase", phase, `Phase: ${oldPhase} -> ${phase}`)
      }),

      setMode: Effect.fn("EngagementStore.setMode")(function* (mode) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        yield* Ref.set(stateRef, { ...current, mode })
        yield* logChange("set_mode", "mode", mode, `Mode: ${mode}`)
      }),

      updateScope: Effect.fn("EngagementStore.updateScope")(function* (scope) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        yield* Ref.set(stateRef, { ...current, scope: { ...current.scope, ...scope } })
      }),

      getTaskGraph: Effect.fn("EngagementStore.getTaskGraph")(function* () {
        const current = yield* Ref.get(stateRef)
        if (!current?.task_graph) return {} as TaskGraph.TaskNodes
        return current.task_graph as unknown as TaskGraph.TaskNodes
      }),

      setTaskGraph: Effect.fn("EngagementStore.setTaskGraph")(function* (tasks) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        yield* Ref.set(stateRef, { ...current, task_graph: tasks as unknown as Record<string, unknown> })
      }),

      setDomain: Effect.fn("EngagementStore.setDomain")(function* (domain) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        yield* Ref.set(stateRef, { ...current, domain })
      }),

      updateDomain: Effect.fn("EngagementStore.updateDomain")(function* (patch) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const existing = current.domain ?? { domain_name: "" } as EngagementSchema.DomainState
        yield* Ref.set(stateRef, { ...current, domain: { ...existing, ...patch } as EngagementSchema.DomainState })
      }),

      addObjective: Effect.fn("EngagementStore.addObjective")(function* (objective) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const objectives = current.objectives ?? {}
        yield* Ref.set(stateRef, { ...current, objectives: { ...objectives, [objective.id]: objective } })
      }),

      updateObjective: Effect.fn("EngagementStore.updateObjective")(function* (id, patch) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const objectives = current.objectives ?? {}
        const existing = objectives[id]
        if (!existing) return
        yield* Ref.set(stateRef, { ...current, objectives: { ...objectives, [id]: { ...existing, ...patch } } })
      }),

      completeObjective: Effect.fn("EngagementStore.completeObjective")(function* (id, evidence) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const objectives = current.objectives ?? {}
        const existing = objectives[id]
        if (!existing) return
        yield* Ref.set(stateRef, {
          ...current,
          objectives: {
            ...objectives,
            [id]: { ...existing, status: "completed" as const, ...(evidence !== undefined ? { evidence } : {}) },
          },
        })
        yield* logChange("complete_objective", "objective", id, `Objective "${existing.title}" completed`)
      }),

      getChangelog: Effect.fn("EngagementStore.getChangelog")(function* (since, limit) {
        let entries = yield* Ref.get(changelogRef)
        if (since) {
          entries = entries.filter((e) => e.timestamp > since)
        }
        if (limit && limit > 0) {
          entries = entries.slice(-limit)
        }
        return entries
      }),

      getChangelogSince: Effect.fn("EngagementStore.getChangelogSince")(function* (since) {
        const entries = yield* Ref.get(changelogRef)
        return entries.filter((e) => e.timestamp > since)
      }),

      markInjected: Effect.fn("EngagementStore.markInjected")(function* () {
        const ts = new Date().toISOString()
        yield* Ref.set(lastInjectedRef, ts)
        return ts
      }),

      getLastInjectedTimestamp: () => Ref.get(lastInjectedRef),

      addRelationship: Effect.fn("EngagementStore.addRelationship")(function* (rel) {
        const current = yield* Ref.get(stateRef)
        if (!current) return false
        const existing = current.relationships ?? []
        const isDupe = existing.some(
          (r) => r.source_id === rel.source_id && r.rel_type === rel.rel_type && r.target_id === rel.target_id,
        )
        if (isDupe) return false
        yield* Ref.set(stateRef, { ...current, relationships: [...existing, rel] })
        yield* logChange("add_relationship", "relationship", `${rel.source_id}->${rel.target_id}`, `${rel.source_type}:${rel.source_id} --[${rel.rel_type}]--> ${rel.target_type}:${rel.target_id}`)
        return true
      }),

      getRelationships: Effect.fn("EngagementStore.getRelationships")(function* (filter) {
        const current = yield* Ref.get(stateRef)
        if (!current) return []
        let rels = current.relationships ?? []
        if (filter?.entity_id) {
          const id = filter.entity_id
          rels = rels.filter((r) => r.source_id === id || r.target_id === id)
        }
        if (filter?.rel_type) {
          const rt = filter.rel_type
          rels = rels.filter((r) => r.rel_type === rt)
        }
        return rels
      }),

      deleteRelationship: Effect.fn("EngagementStore.deleteRelationship")(function* (sourceId, relType, targetId) {
        const current = yield* Ref.get(stateRef)
        if (!current) return false
        const existing = current.relationships ?? []
        const filtered = existing.filter(
          (r) => !(r.source_id === sourceId && r.rel_type === relType && r.target_id === targetId),
        )
        if (filtered.length === existing.length) return false
        yield* Ref.set(stateRef, { ...current, relationships: filtered })
        yield* logChange("delete_relationship", "relationship", `${sourceId}->${targetId}`, `Deleted ${relType} edge`)
        return true
      }),

      // --- Decision Memory ---
      addDecision: Effect.fn("EngagementStore.addDecision")(function* (decision) {
        const current = yield* Ref.get(decisionsRef)
        const updated = [...current, decision]
        const trimmed = updated.length > EngagementSchema.DECISIONS_MAX_ENTRIES
          ? updated.slice(updated.length - EngagementSchema.DECISIONS_MAX_ENTRIES)
          : updated
        yield* Ref.set(decisionsRef, trimmed)
        yield* logChange("add_decision", "decision", decision.id, `[${decision.phase}] ${decision.decision}`)
      }),

      updateDecisionOutcome: Effect.fn("EngagementStore.updateDecisionOutcome")(function* (id, outcome, notes) {
        const current = yield* Ref.get(decisionsRef)
        const idx = current.findIndex((d) => d.id === id)
        if (idx === -1) return false
        const updated = [...current]
        updated[idx] = { ...updated[idx]!, outcome: outcome as EngagementSchema.DecisionOutcome, ...(notes ? { outcome_notes: notes } : {}) }
        yield* Ref.set(decisionsRef, updated)
        yield* logChange("update_decision", "decision", id, `Outcome: ${outcome}${notes ? ` — ${notes}` : ""}`)
        return true
      }),

      getDecisions: Effect.fn("EngagementStore.getDecisions")(function* (limit) {
        const entries = yield* Ref.get(decisionsRef)
        return limit ? entries.slice(-limit) : entries
      }),

      // --- Alert Queue ---
      addAlert: Effect.fn("EngagementStore.addAlert")(function* (alert) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const existing = current.alerts ?? []
        // Expire old alerts first
        const now = Date.now()
        const active = existing.filter((a) => {
          if (a.acknowledged) return false
          const ttl = (a.ttl_minutes ?? EngagementSchema.ALERTS_DEFAULT_TTL_MINUTES) * 60 * 1000
          return now - new Date(a.timestamp).getTime() < ttl
        })
        const capped = active.length >= EngagementSchema.ALERTS_MAX_ACTIVE
          ? [...active.slice(1), alert]
          : [...active, alert]
        yield* Ref.set(stateRef, { ...current, alerts: capped })
        if (alert.priority === "interrupt") {
          const queue = yield* Ref.get(interruptQueueRef)
          yield* Ref.set(interruptQueueRef, [...queue, alert])
        }
        yield* logChange("add_alert", "alert", alert.id, `[${alert.severity.toUpperCase()}]${alert.priority === "interrupt" ? " [INTERRUPT]" : ""} ${alert.title}${alert.source_agent ? ` from:${alert.source_agent}` : ""}`)
      }),

      acknowledgeAlert: Effect.fn("EngagementStore.acknowledgeAlert")(function* (id) {
        const current = yield* Ref.get(stateRef)
        if (!current) return false
        const existing = current.alerts ?? []
        const idx = existing.findIndex((a) => a.id === id)
        if (idx === -1) return false
        const updated = [...existing]
        updated[idx] = { ...updated[idx]!, acknowledged: true }
        yield* Ref.set(stateRef, { ...current, alerts: updated })
        return true
      }),

      getActiveAlerts: Effect.fn("EngagementStore.getActiveAlerts")(function* () {
        const current = yield* Ref.get(stateRef)
        if (!current) return []
        return EngagementSchema.activeAlerts(current)
      }),

      // --- Live Sessions ---
      addLiveSession: Effect.fn("EngagementStore.addLiveSession")(function* (session) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const existing = current.live_sessions ?? []
        const isDupe = existing.some((s) => s.id === session.id)
        if (isDupe) {
          const updated = existing.map((s) => s.id === session.id ? { ...s, ...session } : s)
          yield* Ref.set(stateRef, { ...current, live_sessions: updated })
        } else {
          yield* Ref.set(stateRef, { ...current, live_sessions: [...existing, session] })
          yield* logChange("add_session", "live_session", session.id, `${session.session_type} on ${session.host_ip}${session.port ? `:${session.port}` : ""} as ${session.username ?? "?"}`)
        }
      }),

      updateLiveSession: Effect.fn("EngagementStore.updateLiveSession")(function* (id, patch) {
        const current = yield* Ref.get(stateRef)
        if (!current) return false
        const existing = current.live_sessions ?? []
        const idx = existing.findIndex((s) => s.id === id)
        if (idx === -1) return false
        const updated = [...existing]
        updated[idx] = { ...updated[idx]!, ...patch } as EngagementSchema.LiveSession
        yield* Ref.set(stateRef, { ...current, live_sessions: updated })
        return true
      }),

      removeLiveSession: Effect.fn("EngagementStore.removeLiveSession")(function* (id) {
        const current = yield* Ref.get(stateRef)
        if (!current) return false
        const existing = current.live_sessions ?? []
        const filtered = existing.filter((s) => s.id !== id)
        if (filtered.length === existing.length) return false
        yield* Ref.set(stateRef, { ...current, live_sessions: filtered })
        yield* logChange("remove_session", "live_session", id, `Session ${id} removed`)
        return true
      }),

      // --- Network Segments ---
      addNetworkSegment: Effect.fn("EngagementStore.addNetworkSegment")(function* (segment) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const existing = current.network_segments ?? []
        const isDupe = existing.some((s) => s.id === segment.id)
        if (isDupe) {
          const updated = existing.map((s) => s.id === segment.id ? { ...s, ...segment } : s)
          yield* Ref.set(stateRef, { ...current, network_segments: updated })
        } else {
          yield* Ref.set(stateRef, { ...current, network_segments: [...existing, segment] })
          yield* logChange("add_segment", "network_segment", segment.id, `${segment.cidr}${segment.vlan !== undefined ? ` VLAN:${segment.vlan}` : ""}${segment.pivot_host ? ` via ${segment.pivot_host}` : ""}`)
        }
      }),

      updateNetworkSegment: Effect.fn("EngagementStore.updateNetworkSegment")(function* (id, patch) {
        const current = yield* Ref.get(stateRef)
        if (!current) return false
        const existing = current.network_segments ?? []
        const idx = existing.findIndex((s) => s.id === id)
        if (idx === -1) return false
        const updated = [...existing]
        updated[idx] = { ...updated[idx]!, ...patch } as EngagementSchema.NetworkSegment
        yield* Ref.set(stateRef, { ...current, network_segments: updated })
        return true
      }),

      removeNetworkSegment: Effect.fn("EngagementStore.removeNetworkSegment")(function* (id) {
        const current = yield* Ref.get(stateRef)
        if (!current) return false
        const existing = current.network_segments ?? []
        const filtered = existing.filter((s) => s.id !== id)
        if (filtered.length === existing.length) return false
        yield* Ref.set(stateRef, { ...current, network_segments: filtered })
        yield* logChange("remove_segment", "network_segment", id, `Segment ${id} removed`)
        return true
      }),

      // --- Agent Context Carry ---
      addAgentContext: Effect.fn("EngagementStore.addAgentContext")(function* (summary) {
        const all = yield* Ref.get(agentContextsRef)
        const existing = all[summary.agent_type] ?? []
        const updated = [...existing, summary]
        const trimmed = updated.length > EngagementSchema.AGENT_CONTEXT_MAX_PER_TYPE
          ? updated.slice(updated.length - EngagementSchema.AGENT_CONTEXT_MAX_PER_TYPE)
          : updated
        const newAll = { ...all, [summary.agent_type]: trimmed }
        yield* Ref.set(agentContextsRef, newAll)
        const state = yield* Ref.get(stateRef)
        if (state) persistAgentContexts(state.name, newAll)
      }),

      getAgentContexts: Effect.fn("EngagementStore.getAgentContexts")(function* (agentType, limit) {
        const all = yield* Ref.get(agentContextsRef)
        const entries = all[agentType] ?? []
        return limit ? entries.slice(-limit) : entries
      }),

      // --- Interrupt Alerts ---
      drainInterruptAlerts: Effect.fn("EngagementStore.drainInterruptAlerts")(function* () {
        const alerts = yield* Ref.get(interruptQueueRef)
        if (alerts.length > 0) {
          yield* Ref.set(interruptQueueRef, [])
        }
        return alerts
      }),

      hasInterruptAlerts: Effect.fn("EngagementStore.hasInterruptAlerts")(function* () {
        const alerts = yield* Ref.get(interruptQueueRef)
        return alerts.length > 0
      }),

      // --- Wordlist Usage Tracking ---
      addWordlistUsage: Effect.fn("EngagementStore.addWordlistUsage")(function* (usage) {
        const current = yield* Ref.get(wordlistsRef)
        const isDupe = current.some(
          (w) => w.host_ip === usage.host_ip && w.port === usage.port && w.tool_type === usage.tool_type && w.wordlist_path === usage.wordlist_path,
        )
        if (isDupe) return false
        const updated = [...current, usage]
        const trimmed = updated.length > EngagementSchema.WORDLISTS_MAX_ENTRIES
          ? updated.slice(updated.length - EngagementSchema.WORDLISTS_MAX_ENTRIES)
          : updated
        yield* Ref.set(wordlistsRef, trimmed)
        yield* logChange("record_wordlist", "wordlist", `${usage.host_ip}:${usage.port}`, `${usage.tool_type}: ${usage.wordlist_path}`)
        return true
      }),

      getWordlistUsages: Effect.fn("EngagementStore.getWordlistUsages")(function* (filter) {
        let entries: readonly EngagementSchema.WordlistUsage[] = yield* Ref.get(wordlistsRef)
        if (filter?.host_ip) {
          const ip = filter.host_ip
          entries = entries.filter((w) => w.host_ip === ip)
        }
        if (filter?.port !== undefined) {
          const p = filter.port
          entries = entries.filter((w) => w.port === p)
        }
        if (filter?.tool_type) {
          const tt = filter.tool_type
          entries = entries.filter((w) => w.tool_type === tt)
        }
        return entries
      }),

      // --- Pause Behavior ---
      setPauseBehavior: Effect.fn("EngagementStore.setPauseBehavior")(function* (behavior) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        yield* Ref.set(stateRef, { ...current, pause_on_finding: behavior })
        yield* logChange("set_pause", "pause", behavior, `Pause on finding: ${behavior}`)
      }),
    })
  }),
)

export const node = makeGlobalNode({
  service: Service,
  layer,
  deps: [],
})

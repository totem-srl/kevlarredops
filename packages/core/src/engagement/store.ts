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
}

export class Service extends Context.Service<Service, Interface>()("@pentestcode/EngagementStore") {}

function stateFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, "state.json")
}

function changelogFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, CHANGELOG_FILE)
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
        yield* persist(state)
        yield* logChange("create_engagement", "engagement", state.id, `Created engagement "${name}"`)
        return state
      }),

      load: Effect.fn("EngagementStore.load")(function* (name) {
        const state = yield* readFromDisk(name)
        if (state) {
          yield* Ref.set(stateRef, state)
          yield* Ref.set(changelogRef, loadChangelog(name))
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
    })
  }),
)

export const node = makeGlobalNode({
  service: Service,
  layer,
  deps: [],
})

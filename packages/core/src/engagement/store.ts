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

export interface Interface {
  readonly get: () => Effect.Effect<EngagementSchema.State | undefined>
  readonly save: (state: EngagementSchema.State) => Effect.Effect<void>
  readonly create: (name: string) => Effect.Effect<EngagementSchema.State>
  readonly load: (name: string) => Effect.Effect<EngagementSchema.State | undefined>
  readonly lastEngagement: () => Effect.Effect<string | undefined>
  readonly listEngagements: () => Effect.Effect<string[]>
  readonly addHost: (ip: string, data?: Partial<EngagementSchema.Host>) => Effect.Effect<EngagementSchema.Host>
  readonly addVuln: (hostIp: string, vuln: EngagementSchema.Vulnerability) => Effect.Effect<void>
  readonly addCredential: (id: string, cred: Omit<EngagementSchema.Credential, "id">) => Effect.Effect<void>
  readonly addAccess: (hostIp: string, access: EngagementSchema.Access) => Effect.Effect<void>
  readonly setPhase: (phase: EngagementSchema.PentestPhase) => Effect.Effect<void>
  readonly setMode: (mode: EngagementSchema.PentestMode) => Effect.Effect<void>
  readonly updateScope: (scope: Partial<EngagementSchema.Scope>) => Effect.Effect<void>
  readonly getTaskGraph: () => Effect.Effect<TaskGraph.TaskNodes>
  readonly setTaskGraph: (tasks: TaskGraph.TaskNodes) => Effect.Effect<void>
}

export class Service extends Context.Service<Service, Interface>()("@pentestcode/EngagementStore") {}

function stateFilePath(name: string): string {
  return path.join(ENGAGEMENTS_DIR, name, "state.json")
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

    const persist = (state: EngagementSchema.State) =>
      Effect.sync(() => {
        const filePath = stateFilePath(state.name)
        const dir = path.dirname(filePath)
        fs.mkdirSync(dir, { recursive: true })
        const json = encode(state)
        fs.writeFileSync(filePath, JSON.stringify(json, undefined, 2), "utf-8")
        const lastPath = lastFilePath()
        fs.mkdirSync(path.dirname(lastPath), { recursive: true })
        fs.writeFileSync(lastPath, state.name, "utf-8")
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
        yield* persist(state)
        return state
      }),

      load: Effect.fn("EngagementStore.load")(function* (name) {
        const state = yield* readFromDisk(name)
        if (state) yield* Ref.set(stateRef, state)
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
        const host: EngagementSchema.Host = existing
          ? { ...existing, ...data }
          : ({ ip, services: [], vulns: [], access: [], notes: [], ...data } as EngagementSchema.Host)
        const updated = { ...current, hosts: { ...current.hosts, [ip]: host } }
        yield* Ref.set(stateRef, updated)
        return host
      }),

      addVuln: Effect.fn("EngagementStore.addVuln")(function* (hostIp, vuln) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const host = current.hosts[hostIp]
        if (!host) return
        const updatedHost = { ...host, vulns: [...host.vulns, vuln] }
        yield* Ref.set(stateRef, { ...current, hosts: { ...current.hosts, [hostIp]: updatedHost } })
      }),

      addCredential: Effect.fn("EngagementStore.addCredential")(function* (id, cred) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        yield* Ref.set(stateRef, {
          ...current,
          credentials: { ...current.credentials, [id]: { ...cred, id } },
        })
      }),

      addAccess: Effect.fn("EngagementStore.addAccess")(function* (hostIp, access) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        const host = current.hosts[hostIp]
        if (!host) return
        const updatedHost = { ...host, access: [...host.access, access] }
        yield* Ref.set(stateRef, { ...current, hosts: { ...current.hosts, [hostIp]: updatedHost } })
      }),

      setPhase: Effect.fn("EngagementStore.setPhase")(function* (phase) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        yield* Ref.set(stateRef, { ...current, current_phase: phase })
      }),

      setMode: Effect.fn("EngagementStore.setMode")(function* (mode) {
        const current = yield* Ref.get(stateRef)
        if (!current) return
        yield* Ref.set(stateRef, { ...current, mode })
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
    })
  }),
)

export const node = makeGlobalNode({
  service: Service,
  layer,
  deps: [],
})

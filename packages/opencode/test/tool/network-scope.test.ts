import { describe, expect } from "bun:test"
import { Effect, Layer, Ref } from "effect"
import http from "node:http"
import net from "node:net"
import dgram from "node:dgram"
import { once } from "node:events"
import { EngagementSchema } from "@pentestcode/core/engagement/schema"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { Agent } from "@/agent/agent"
import { SessionID, MessageID } from "@/session/schema"
import { HttpRequestTool } from "@/tool/http-request"
import { NetTool } from "@/tool/net"
import { Tool } from "@/tool/tool"
import { Truncate } from "@/tool/truncate"
import { testEffect } from "../lib/effect"

const it = testEffect(
  Layer.mergeAll(
    Layer.mock(Agent.Service, {
      get: (name) => Effect.succeed({ name, mode: "primary", permission: [], options: {} }),
    }),
    Layer.mock(Truncate.Service, {
      output: (content) => Effect.succeed({ content, truncated: false }),
    }),
  ),
)

const ctx: Tool.Context = {
  sessionID: SessionID.make("ses_network_scope"),
  messageID: MessageID.make("msg_network_scope"),
  agent: "pentest",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  ask: () => Effect.void,
}

function engagement(scope: EngagementSchema.State["scope"], mode: "auto" | "free"): EngagementSchema.State {
  return {
    id: EngagementSchema.ID.make("network-scope-test"),
    name: "network-scope-test",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    scope,
    mode,
    hosts: {},
    credentials: {},
    flags: [],
    attack_path: [],
    task_tree: [],
    notes: [],
    current_phase: "recon",
    network_segments: [],
  }
}

const cases = [
  { name: "out of scope", targets: ["198.51.100.1"], excludes: [], mode: "auto", blocked: true },
  { name: "free mode outside scope", targets: ["198.51.100.1"], excludes: [], mode: "free", blocked: true },
  { name: "empty scope", targets: [], excludes: [], mode: "auto", blocked: true },
  { name: "empty scope in free mode", targets: [], excludes: [], mode: "free", blocked: true },
  {
    name: "excluded loopback in free mode",
    targets: ["127.0.0.0/8"],
    excludes: ["127.0.0.1"],
    mode: "free",
    blocked: true,
  },
  { name: "explicitly allowed in free mode", targets: ["127.0.0.1"], excludes: [], mode: "free", blocked: false },
] satisfies { name: string; targets: string[]; excludes: string[]; mode: "auto" | "free"; blocked: boolean }[]

// These are real loopback servers, not patched fetch/socket implementations.
const httpLab = Effect.acquireRelease(
  Effect.promise(async () => {
    let requests = 0
    const server = http.createServer((_request, response) => {
      requests++
      response.end("owned HTTP lab")
    })
    server.listen(0, "127.0.0.1")
    await once(server, "listening")
    const address = server.address()
    if (!address || typeof address === "string") throw new Error("Expected a loopback TCP address")
    return { server, port: address.port, requests: () => requests }
  }),
  (lab) =>
    Effect.promise(
      () =>
        new Promise<void>((resolve) => {
          lab.server.close(() => resolve())
          lab.server.closeAllConnections()
        }),
    ),
)

describe("HTTP engagement scope at request dispatch", () => {
  for (const item of cases) {
    it.live(item.name, () =>
      Effect.gen(function* () {
        const lab = yield* httpLab
        const state = engagement({ targets: item.targets, excludes: item.excludes, notes: "" }, item.mode)
        const info = yield* HttpRequestTool.pipe(
          Effect.provide(
            Layer.mock(EngagementStore.Service, {
              get: () => Effect.succeed(state),
            }),
          ),
        )
        const tool = yield* info.init()
        const result = yield* tool.execute({ url: `http://127.0.0.1:${lab.port}/`, timeout_s: 1 }, ctx)
        expect(lab.requests()).toBe(item.blocked ? 0 : 1)
        if (item.blocked) expect(result.metadata.blocked).toBe(true)
        else {
          expect(result.metadata.status).toBe(200)
          const evidence = yield* Effect.promise(() => Evidence.get(state.name, `GET http://127.0.0.1:${lab.port}/`))
          const home = process.env.OPENCODE_TEST_HOME
          if (!home) throw new Error("The test preload must isolate user data")
          expect(evidence?.path.startsWith(home)).toBe(true)
        }
      }),
    )
  }

  it.live("scope is read again after command approval", () =>
    Effect.gen(function* () {
      const lab = yield* httpLab
      const state = yield* Ref.make<EngagementSchema.State | undefined>(
        engagement(
          {
            targets: ["127.0.0.1"],
            excludes: [],
            notes: "",
          },
          "auto",
        ),
      )
      const info = yield* HttpRequestTool.pipe(
        Effect.provide(
          Layer.mock(EngagementStore.Service, {
            get: () => Ref.get(state),
          }),
        ),
      )
      const tool = yield* info.init()
      const result = yield* tool.execute(
        { url: `http://127.0.0.1:${lab.port}/`, timeout_s: 1 },
        {
          ...ctx,
          ask: () => Ref.set(state, engagement({ targets: [], excludes: [], notes: "" }, "auto")),
        },
      )
      expect(result.metadata.blocked).toBe(true)
      expect(lab.requests()).toBe(0)
    }),
  )

  it.live("an engagement activated during approval is enforced", () =>
    Effect.gen(function* () {
      const lab = yield* httpLab
      const state = yield* Ref.make<EngagementSchema.State | undefined>(undefined)
      const info = yield* HttpRequestTool.pipe(
        Effect.provide(
          Layer.mock(EngagementStore.Service, {
            get: () => Ref.get(state),
          }),
        ),
      )
      const tool = yield* info.init()
      const result = yield* tool.execute(
        { url: `http://127.0.0.1:${lab.port}/`, timeout_s: 1 },
        {
          ...ctx,
          ask: () => Ref.set(state, engagement({ targets: [], excludes: [], notes: "" }, "free")),
        },
      )
      expect(result.metadata.blocked).toBe(true)
      expect(lab.requests()).toBe(0)
    }),
  )

  it.live("no active engagement preserves normal HTTP permission flow", () =>
    Effect.gen(function* () {
      const lab = yield* httpLab
      const approved = yield* Ref.make(false)
      const info = yield* HttpRequestTool.pipe(
        Effect.provide(
          Layer.mock(EngagementStore.Service, {
            get: () => Effect.succeed(undefined),
          }),
        ),
      )
      const tool = yield* info.init()
      const result = yield* tool.execute(
        { url: `http://127.0.0.1:${lab.port}/`, timeout_s: 1 },
        {
          ...ctx,
          ask: () => Ref.set(approved, true),
        },
      )
      expect(yield* Ref.get(approved)).toBe(true)
      expect(result.metadata.status).toBe(200)
      expect(lab.requests()).toBe(1)
    }),
  )

  it.live("redirect responses do not dispatch another request", () =>
    Effect.gen(function* () {
      const source = yield* httpLab
      const destination = yield* httpLab
      source.server.removeAllListeners("request")
      source.server.on("request", (_request, response) => {
        response.writeHead(302, { location: `http://127.0.0.1:${destination.port}/` })
        response.end()
      })
      const info = yield* HttpRequestTool.pipe(
        Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(undefined) })),
      )
      const tool = yield* info.init()
      const result = yield* tool.execute({ url: `http://127.0.0.1:${source.port}/`, timeout_s: 1 }, ctx)
      expect(result.metadata.status).toBe(302)
      expect(destination.requests()).toBe(0)
    }),
  )
})

const tcpLab = Effect.acquireRelease(
  Effect.promise(async () => {
    let connections = 0
    const server = net.createServer((socket) => {
      connections++
      socket.resume()
      socket.end("owned TCP lab")
    })
    server.listen(0, "127.0.0.1")
    await once(server, "listening")
    const address = server.address()
    if (!address || typeof address === "string") throw new Error("Expected a loopback TCP address")
    return { server, port: address.port, received: () => connections }
  }),
  (lab) => Effect.promise(() => new Promise<void>((resolve) => lab.server.close(() => resolve()))),
)

const udpLab = Effect.acquireRelease(
  Effect.promise(async () => {
    let messages = 0
    const server = dgram.createSocket("udp4")
    server.on("message", (_message, remote) => {
      messages++
      server.send("owned UDP lab", remote.port, remote.address)
    })
    server.bind(0, "127.0.0.1")
    await once(server, "listening")
    return { server, port: server.address().port, received: () => messages }
  }),
  (lab) => Effect.promise(() => new Promise<void>((resolve) => lab.server.close(() => resolve()))),
)

describe("raw network engagement scope at socket dispatch", () => {
  for (const op of ["tcp_send", "banner_grab", "udp_send"] as const) {
    for (const item of [
      ...cases,
      { name: "no active engagement", targets: [], excludes: [], mode: "auto", blocked: false },
    ] as const) {
      it.live(`${op}: ${item.name}`, () =>
        Effect.gen(function* () {
          const lab = yield* op === "udp_send" ? udpLab : tcpLab
          const state =
            item.name === "no active engagement"
              ? undefined
              : engagement(
                  {
                    targets: [...item.targets],
                    excludes: [...item.excludes],
                    notes: "",
                  },
                  item.mode,
                )
          const info = yield* NetTool.pipe(
            Effect.provide(
              Layer.mock(EngagementStore.Service, {
                get: () => Effect.succeed(state),
              }),
            ),
          )
          const tool = yield* info.init()
          const result = yield* tool.execute(
            { op, host: "127.0.0.1", port: lab.port, payload: "hello", timeout_ms: 1000 },
            ctx,
          )
          expect(lab.received()).toBe(item.blocked ? 0 : 1)
          if (item.blocked) expect(result.metadata.out_of_scope).toBe(true)
          else {
            expect(result.metadata.error).toBeUndefined()
            expect(result.output).toContain(op === "udp_send" ? "owned UDP lab" : "owned TCP lab")
          }
        }),
      )
    }
  }
})

import { describe, expect } from "bun:test"
import { Effect, Layer, Ref } from "effect"
import { EngagementSchema } from "@pentestcode/core/engagement/schema"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { Agent } from "@/agent/agent"
import { SessionID, MessageID } from "@/session/schema"
import { AppsecProbeTool } from "@/tool/appsec-probe"
import { BountyHuntTool, discoverOpenApi } from "@/tool/bounty-hunt"
import { ReconPipelineTool } from "@/tool/recon-pipeline"
import { Tool } from "@/tool/tool"
import { Truncate } from "@/tool/truncate"
import { analyzeJs } from "@/scanner/js-analyzer"
import { dirFuzz } from "@/scanner/dir-fuzzer"
import { ScopedRequest } from "@/scanner/scoped-request"
import { EffectBridge } from "@/effect/bridge"
import { testEffect } from "../lib/effect"

const it = testEffect(
  Layer.mergeAll(
    Layer.mock(Agent.Service, {
      get: (name) => Effect.succeed({ name, mode: "primary", permission: [], options: {} }),
    }),
    Layer.mock(Truncate.Service, { output: (content) => Effect.succeed({ content, truncated: false }) }),
  ),
)

const ctx: Tool.Context = {
  sessionID: SessionID.make("ses_scanner_scope"),
  messageID: MessageID.make("msg_scanner_scope"),
  agent: "pentest",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  ask: () => Effect.void,
}

function engagement(
  targets: string[],
  excludes: string[] = [],
  mode: "auto" | "free" = "auto",
): EngagementSchema.State {
  return {
    id: EngagementSchema.ID.make("scanner-scope-test"),
    name: "scanner-scope-test",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    scope: { targets, excludes, notes: "" },
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

const lab = (respond: (request: Request) => Response | Promise<Response>, host = "127.0.0.1") =>
  Effect.acquireRelease(
    Effect.sync(() => {
      const requests: string[] = []
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch(request) {
          requests.push(new URL(request.url).pathname)
          return respond(request)
        },
      })
      return { url: `http://${host}:${server.port}/`, requests, server }
    }),
    (value) => Effect.promise(() => value.server.stop(true)),
  )

const run = Effect.fn("ScannerScopeTest.run")(function* (
  name: "appsec" | "bounty" | "recon",
  target: string,
  context = ctx,
) {
  if (name === "appsec") {
    const info = yield* AppsecProbeTool
    const tool = yield* info.init()
    return yield* tool.execute({ target, checks: [], timeout_ms: 500 }, context)
  }
  if (name === "bounty") {
    const info = yield* BountyHuntTool
    const tool = yield* info.init()
    return yield* tool.execute({ target, max_rps: 20, timeout_ms: 1000 }, context)
  }
  const info = yield* ReconPipelineTool
  const tool = yield* info.init()
  return yield* tool.execute({ target, action: "run" }, context)
})

describe("scanner entry scope", () => {
  for (const name of ["appsec", "bounty", "recon"] as const) {
    for (const item of [
      { label: "free mode", targets: ["198.51.100.1"], excludes: [], mode: "free" },
      { label: "empty scope", targets: [], excludes: [], mode: "auto" },
      { label: "empty free scope", targets: [], excludes: [], mode: "free" },
      {
        label: "excluded in free mode",
        targets: ["127.0.0.1", "lab.invalid"],
        excludes: ["127.0.0.1", "lab.invalid"],
        mode: "free",
      },
    ] satisfies { label: string; targets: string[]; excludes: string[]; mode: "auto" | "free" }[]) {
      it.live(`${name}: ${item.label}`, () =>
        Effect.gen(function* () {
          const server = yield* lab(() => new Response("owned lab"))
          const result = yield* run(name, name === "recon" ? "lab.invalid" : server.url, {
            ...ctx,
            // A bypass must fail before it can launch a scanner or query DNS.
            ask: () => Effect.die(new Error("Out-of-scope operations must be denied before approval")),
          }).pipe(
            Effect.provide(
              Layer.mock(EngagementStore.Service, {
                get: () => Effect.succeed(engagement(item.targets, item.excludes, item.mode)),
              }),
            ),
          )
          expect(result.metadata.blocked).toBe(true)
          expect(server.requests).toHaveLength(0)
        }),
      )
    }
  }
})

describe("scoped scanner requests", () => {
  it.live("AppSec can send an explicitly authorized probe in free mode", () =>
    Effect.gen(function* () {
      const server = yield* lab((request) =>
        new URL(request.url).pathname === "/login"
          ? Response.json({ result: "owned lab" })
          : new Response('<form action="/login" method="POST"><input name="email"><input name="password"></form>'),
      )
      const info = yield* AppsecProbeTool.pipe(
        Effect.provide(
          Layer.mock(EngagementStore.Service, {
            get: () => Effect.succeed(engagement(["127.0.0.1"], [], "free")),
          }),
        ),
      )
      const tool = yield* info.init()
      const result = yield* tool.execute({ target: server.url, checks: ["broken_auth_jwt"], timeout_ms: 500 }, ctx)
      expect(server.requests).toEqual(["/", "/login"])
      expect(result.metadata.checks_run).toEqual(["broken_auth_jwt"])
    }),
  )

  it.live("Bounty can analyze an authorized loopback site in free mode", () =>
    Effect.gen(function* () {
      const server = yield* lab((request) =>
        new URL(request.url).pathname === "/openapi.json"
          ? Response.json({ openapi: "3.0.0", paths: {} })
          : new Response("owned lab"),
      )
      const result = yield* run("bounty", server.url).pipe(
        Effect.provide(
          Layer.mock(EngagementStore.Service, {
            get: () => Effect.succeed(engagement(["127.0.0.1"], [], "free")),
          }),
        ),
      )
      expect(server.requests).toEqual(["/", "/", "/openapi.json"])
      expect(result.output).toContain("openapi 3.0.0")
    }),
  )

  it.live("Recon planning remains available without scope authorization", () =>
    Effect.gen(function* () {
      const info = yield* ReconPipelineTool.pipe(
        Effect.provide(
          Layer.mock(EngagementStore.Service, {
            get: () => Effect.succeed(engagement([])),
          }),
        ),
      )
      const tool = yield* info.init()
      const result = yield* tool.execute(
        { target: "lab.invalid", action: "plan" },
        {
          ...ctx,
          ask: () => Effect.die(new Error("Planning must not request execution permission")),
        },
      )
      expect(result.title).toContain("plan")
      expect(result.metadata.blocked).toBeUndefined()
    }),
  )

  for (const name of ["appsec", "bounty", "recon"] as const) {
    it.live(`${name}: scope changes after approval`, () =>
      Effect.gen(function* () {
        const server = yield* lab(() => new Response("owned lab"))
        const state = yield* Ref.make(engagement(["127.0.0.1", "lab.invalid"]))
        const result = yield* run(name, name === "recon" ? "lab.invalid" : server.url, {
          ...ctx,
          ask: () => Ref.set(state, engagement([], [], "free")),
        }).pipe(Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Ref.get(state) })))
        expect(result.metadata.blocked).toBe(true)
        expect(server.requests).toHaveLength(0)
      }),
    )
  }

  it.live("scoped request rereads state and refuses automatic redirects", () =>
    Effect.gen(function* () {
      const destination = yield* lab(() => new Response("destination"), "localhost")
      const source = yield* lab(() => new Response("", { status: 302, headers: { location: destination.url } }))
      const state = yield* Ref.make(engagement(["127.0.0.1"]))
      const guard = yield* ScopedRequest.make.pipe(
        Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Ref.get(state) })),
      )
      const response = yield* Effect.promise(() => guard.request(source.url, { redirect: "follow" }))
      yield* Effect.promise(() => response.text())
      expect(response.status).toBe(302)
      expect(destination.requests).toHaveLength(0)
      yield* Ref.set(state, engagement([], [], "free"))
      const denied = yield* Effect.tryPromise(() => guard.request(source.url)).pipe(Effect.exit)
      expect(denied._tag).toBe("Failure")
      expect(source.requests).toHaveLength(1)
    }),
  )

  it.live("JS analysis does not follow a script redirect", () =>
    Effect.gen(function* () {
      const destination = yield* lab(() => new Response("foreign script"), "localhost")
      const source = yield* lab((request) =>
        new URL(request.url).pathname === "/asset.js"
          ? new Response("", { status: 302, headers: { location: destination.url } })
          : new Response('<script src="/asset.js"></script>'),
      )
      yield* Effect.promise(() => analyzeJs({ url: source.url, timeoutMs: 1000 }))
      expect(source.requests).toContain("/asset.js")
      expect(destination.requests).toHaveLength(0)
    }),
  )

  it.live("OpenAPI discovery does not follow redirects", () =>
    Effect.gen(function* () {
      const destination = yield* lab(() => Response.json({ openapi: "3.0.0", paths: {} }), "localhost")
      const source = yield* lab(() => new Response("", { status: 302, headers: { location: destination.url } }))
      const result = yield* Effect.promise(() => discoverOpenApi(new URL(source.url), 1000))
      expect(result).toBeUndefined()
      expect(destination.requests).toHaveLength(0)
    }),
  )

  it.live("AppSec rejects an out-of-scope form action", () =>
    Effect.gen(function* () {
      const destination = yield* lab(() => new Response("foreign form"), "localhost")
      const source = yield* lab(
        () =>
          new Response(
            `<form action="${destination.url}login" method="POST"><input name="email"><input name="password"></form>`,
          ),
      )
      const info = yield* AppsecProbeTool.pipe(
        Effect.provide(
          Layer.mock(EngagementStore.Service, {
            get: () => Effect.succeed(engagement(["127.0.0.1"], [], "free")),
          }),
        ),
      )
      const tool = yield* info.init()
      const result = yield* tool.execute({ target: source.url, checks: ["broken_auth_jwt"], timeout_ms: 500 }, ctx)
      expect(source.requests).toHaveLength(1)
      expect(destination.requests).toHaveLength(0)
      expect(result.metadata.checks_run).toEqual([])
      expect(result.output).toContain("outside engagement scope")
    }),
  )

  it.live("AppSec applies scope changed by a page response", () =>
    Effect.gen(function* () {
      const state = yield* Ref.make(engagement(["127.0.0.1"]))
      const bridge = yield* EffectBridge.make()
      const server = yield* lab(async () => {
        await bridge.promise(Ref.set(state, engagement([], [], "free")))
        return new Response('<form action="/login" method="POST"><input name="email"><input name="password"></form>')
      })
      const info = yield* AppsecProbeTool.pipe(
        Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Ref.get(state) })),
      )
      const tool = yield* info.init()
      const result = yield* tool.execute({ target: server.url, checks: ["broken_auth_jwt"], timeout_ms: 500 }, ctx)
      expect(server.requests).toHaveLength(1)
      expect(result.metadata.checks_run).toEqual([])
    }),
  )

  it.live("JS and fuzz helpers use the supplied scope boundary", () =>
    Effect.gen(function* () {
      const server = yield* lab(() => new Response("owned lab"))
      const guard = yield* ScopedRequest.make.pipe(
        Effect.provide(
          Layer.mock(EngagementStore.Service, {
            get: () => Effect.succeed(engagement([], [], "free")),
          }),
        ),
      )
      yield* Effect.promise(() => analyzeJs({ url: server.url, request: guard.request }))
      yield* Effect.promise(() => dirFuzz({ baseUrl: server.url, wordlist: ["owned"], request: guard.request }))
      yield* Effect.promise(() => discoverOpenApi(new URL(server.url), 1000, undefined, guard.request))
      expect(server.requests).toHaveLength(0)
    }),
  )
})

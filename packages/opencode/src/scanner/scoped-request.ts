import { Effect } from "effect"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { ScopeMatcher } from "@pentestcode/core/engagement/scope-matcher"
import { EffectBridge } from "@/effect/bridge"

export type Request = (url: string, options?: RequestInit) => Promise<Response>

// Capture services once, but read authorization again for each network operation.
export const make = Effect.gen(function* () {
  const store = yield* EngagementStore.Service
  const bridge = yield* EffectBridge.make()
  const check = Effect.fn("ScopedRequest.check")(function* (target: string) {
    const state = yield* store.get()
    return state ? ScopeMatcher.checkScope(target, state.scope) : { inScope: true as const }
  })
  const request: Request = (url, options) =>
    bridge.promise(
      Effect.gen(function* () {
        const result = yield* check(url)
        if (!result.inScope) {
          return yield* Effect.fail(
            new Error(`Blocked: ${url} is outside engagement scope (${result.reason ?? "no match"}).`),
          )
        }
        return yield* Effect.tryPromise(() => fetch(url, { ...options, redirect: "manual" }))
      }),
    )
  return { check, request }
})

export * as ScopedRequest from "./scoped-request"

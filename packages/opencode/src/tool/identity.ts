import { Effect, Schema } from "effect"
import { Vault } from "@pentestcode/core/cyber/vault"
import DESCRIPTION from "./identity.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals(["add", "use", "clear", "status", "list"]).annotate({
    description: "add stores an identity; use activates it; clear deactivates; status/list are read-only",
  }),
  key: Schema.optional(Schema.String.annotate({ description: "identity name" })),
  value: Schema.optional(
    Schema.String.annotate({
      description:
        'identity material when action = add. Accepts "Authorization: Bearer x", "Cookie: k=v", header lines, or raw tokens',
    }),
  ),
})

function summarize(resolved: ReturnType<typeof Vault.resolveIdentityValue>) {
  return {
    key: resolved.key,
    mode: resolved.mode,
    header_keys: resolved.headers ? Object.keys(resolved.headers) : [],
    has_cookies: Boolean(resolved.cookies),
  }
}

export const IdentityTool = Tool.define(
  "identity",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          action: "add" | "use" | "clear" | "status" | "list"
          key?: string
          value?: string
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          if (params.action === "add") {
            if (!params.key || !params.value) {
              return { title: "identity add", metadata: { action: "add" }, output: "Provide key and value when action = add." }
            }
            yield* Effect.promise(() => Vault.setSecret(params.key!, params.value!))
            const resolved = Vault.resolveIdentityValue(params.key!, params.value!)
            return {
              title: `identity · ${params.key}`,
              metadata: { action: "add", ...summarize(resolved) },
              output: `Stored identity "${params.key}" (${resolved.mode}). Use action=use to activate.`,
            }
          }

          if (params.action === "use") {
            if (!params.key) {
              return { title: "identity use", metadata: { action: "use" }, output: "Provide key when action = use." }
            }
            const state = yield* Effect.promise(() => Vault.useIdentity(params.key!))
            return {
              title: `identity · ${state.active_identity ?? params.key}`,
              metadata: { action: "use", active_identity: state.active_identity ?? null },
              output: state.active_identity
                ? `Identity "${state.active_identity}" is now active for outbound requests.`
                : `No secret "${params.key}" in vault.`,
            }
          }

          if (params.action === "clear") {
            yield* Effect.promise(() => Vault.useIdentity(undefined))
            return {
              title: "identity cleared",
              metadata: { action: "clear" },
              output: "Active identity cleared. Requests will be anonymous.",
            }
          }

          if (params.action === "status") {
            const active = yield* Effect.promise(() => Vault.activeIdentity())
            if (!active) {
              return {
                title: "identity status",
                metadata: { action: "status", active: false },
                output: "No active identity.",
              }
            }
            const resolved = Vault.resolveIdentityValue(active.key, active.value)
            return {
              title: `identity · ${active.key}`,
              metadata: { action: "status", active: true, ...summarize(resolved) },
              output: `Active identity "${active.key}" (${resolved.mode})${resolved.headers ? `, headers: ${Object.keys(resolved.headers).join(", ")}` : ""}${resolved.cookies ? ", cookies present" : ""}.`,
            }
          }

          const listing = yield* Effect.promise(() => Vault.listSecrets())
          return {
            title: `identities · ${listing.keys.length}`,
            metadata: { action: "list", count: listing.keys.length, active_identity: listing.active_identity ?? null },
            output:
              listing.keys.length === 0
                ? "Vault empty."
                : listing.keys.map((key) => `- ${key}${key === listing.active_identity ? " · ACTIVE" : ""}`).join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

import { Effect, Schema } from "effect"
import { Vault } from "@pentestcode/core/cyber/vault"
import DESCRIPTION from "./vault.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals(["set", "delete", "list", "get", "use_identity", "status"]).annotate({
    description: "vault operation",
  }),
  key: Schema.optional(Schema.String.annotate({ description: "secret/identity key name" })),
  value: Schema.optional(Schema.String.annotate({ description: "secret value when action = set" })),
})

function mask(value: string): string {
  if (value.length <= 6) return "***"
  return `${value.slice(0, 3)}…${value.slice(-2)} (len ${value.length})`
}

export const VaultTool = Tool.define(
  "vault",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          action: "set" | "delete" | "list" | "get" | "use_identity" | "status"
          key?: string
          value?: string
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          if (params.action === "set") {
            if (!params.key || params.value === undefined) {
              return { title: "vault set", metadata: { action: "set" }, output: "Provide key and value when action = set." }
            }
            yield* Effect.promise(() => Vault.setSecret(params.key!, params.value!))
            return {
              title: `vault · ${params.key}`,
              metadata: { action: "set", key: params.key },
              output: `Stored secret "${params.key}".`,
            }
          }

          if (params.action === "delete") {
            if (!params.key) {
              return { title: "vault delete", metadata: { action: "delete" }, output: "Provide key when action = delete." }
            }
            const state = yield* Effect.promise(() => Vault.deleteSecret(params.key!))
            return {
              title: `vault · ${params.key}`,
              metadata: { action: "delete", key: params.key, remaining: state.secrets ? Object.keys(state.secrets).length : 0 },
              output: `Deleted "${params.key}" (if present).`,
            }
          }

          if (params.action === "list") {
            const listing = yield* Effect.promise(() => Vault.listSecrets())
            const rows = listing.keys.map((key) => `- ${key}${key === listing.active_identity ? " · ACTIVE IDENTITY" : ""}`)
            return {
              title: `vault · ${listing.keys.length}`,
              metadata: { action: "list", count: listing.keys.length, active_identity: listing.active_identity },
              output: rows.length === 0 ? "Vault empty." : rows.join("\n"),
            }
          }

          if (params.action === "get") {
            if (!params.key) {
              return { title: "vault get", metadata: { action: "get" }, output: "Provide key when action = get." }
            }
            const value = yield* Effect.promise(() => Vault.getSecretValue(params.key!))
            if (value === undefined) {
              return { title: `vault · ${params.key}`, metadata: { action: "get", found: false }, output: `No secret "${params.key}".` }
            }
            return {
              title: `vault · ${params.key}`,
              metadata: { action: "get", found: true },
              output: `${params.key} = ${value}`,
            }
          }

          if (params.action === "use_identity") {
            const state = yield* Effect.promise(() => Vault.useIdentity(params.key))
            return {
              title: `vault identity · ${state.active_identity ?? "cleared"}`,
              metadata: { action: "use_identity", active_identity: state.active_identity ?? null },
              output: state.active_identity
                ? `Active identity is now "${state.active_identity}". http-request will merge its headers/cookies.`
                : "Active identity cleared.",
            }
          }

          const identity = yield* Effect.promise(() => Vault.activeIdentity())
          if (!identity) {
            return {
              title: "vault status",
              metadata: { action: "status", active: false },
              output: "No active identity. Use use_identity with a stored key.",
            }
          }
          const resolved = Vault.resolveIdentityValue(identity.key, identity.value)
          return {
            title: `vault status · ${identity.key}`,
            metadata: { action: "status", active: true, mode: resolved.mode },
            output: [
              `active identity: ${identity.key}`,
              `mode: ${resolved.mode}`,
              resolved.headers ? `header keys: ${Object.keys(resolved.headers).join(", ")}` : undefined,
              resolved.cookies ? `cookies: present (${Object.keys(resolved.cookies).length})` : undefined,
              `raw value: ${mask(identity.value)}`,
            ]
              .filter(Boolean)
              .join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

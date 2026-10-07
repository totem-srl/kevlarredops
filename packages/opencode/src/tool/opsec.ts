import { Effect, Schema } from "effect"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { OPSEC_BLOCKLIST } from "@pentestcode/core/cyber/boundary"
import DESCRIPTION from "./opsec.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals(["status", "set"]).annotate({ description: "status shows the current level; set changes it" }),
  level: Schema.optional(Schema.Literals(["normal", "strict"]).annotate({ description: "required when action = set" })),
})

function engagementDir(name: string) {
  return path.join(process.env.OPENCODE_TEST_HOME ?? os.homedir(), ".pentestcode", "engagements", name)
}

function formatStatus(name: string | undefined, level: "normal" | "strict") {
  if (!name) return `Opsec level: ${level}\n(no active engagement; level applies per engagement)`
  const lines = [`Active engagement: ${name}`, `Opsec: ${level}`, ""]
  if (level === "strict") {
    lines.push("Blocked 3rd-party intel hosts (when strict):")
    for (const host of OPSEC_BLOCKLIST) lines.push(`- ${host}`)
    lines.push("", "Strict mode: unmatched boundary decisions default to DENY (localhost excluded).")
  }
  return lines.join("\n")
}

export const OpsecTool = Tool.define(
  "opsec",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          action: "status" | "set"
          level?: "normal" | "strict"
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          const file = state ? path.join(engagementDir(state.name), "opsec.json") : undefined

          if (params.action === "set") {
            if (!params.level) {
              return { title: "opsec set", metadata: { action: "set" }, output: "Provide level (normal|strict) when action = set." }
            }
            if (file && state) {
              yield* Effect.promise(() =>
                fs
                  .writeFile(file, JSON.stringify({ level: params.level }, null, 2), { mode: 0o600 })
                  .catch(() => undefined),
              )
            }
            return {
              title: `opsec · ${params.level}`,
              metadata: { action: "set", level: params.level, persisted: Boolean(state) },
              output: formatStatus(state?.name, params.level),
            }
          }

          let level: "normal" | "strict" = "normal"
          if (file) {
            const raw = yield* Effect.promise(() => fs.readFile(file, "utf8").catch(() => undefined))
            if (raw) {
              try {
                const parsed = JSON.parse(raw) as { level?: string }
                if (parsed.level === "strict" || parsed.level === "normal") level = parsed.level
              } catch {
                // fall through to default
              }
            }
          }
          return {
            title: "opsec status",
            metadata: { action: "status", level },
            output: formatStatus(state?.name, level),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

export const readLevel = async (engagementName?: string): Promise<"normal" | "strict"> => {
  if (!engagementName) return "normal"
  try {
    const raw = await fs.readFile(path.join(engagementDir(engagementName), "opsec.json"), "utf8")
    const parsed = JSON.parse(raw) as { level?: string }
    return parsed.level === "strict" ? "strict" : "normal"
  } catch {
    return "normal"
  }
}

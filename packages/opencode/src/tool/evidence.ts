import { Effect, Schema } from "effect"
import fs from "node:fs/promises"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import DESCRIPTION from "./evidence.txt"
import * as Tool from "./tool"

const MAX_PREVIEW = 20_000

export const Parameters = Schema.Struct({
  action: Schema.Literals(["list", "search", "get", "add_text", "add_file"]).annotate({
    description: "list/search/get are read-only; add_text and add_file store immutable artifacts",
  }),
  label: Schema.optional(Schema.String.annotate({ description: "human label for added evidence" })),
  text: Schema.optional(Schema.String.annotate({ description: "text body when action = add_text" })),
  path: Schema.optional(Schema.String.annotate({ description: "file path to import when action = add_file" })),
  mime: Schema.optional(Schema.String.annotate({ description: "mime type override" })),
  query: Schema.optional(Schema.String.annotate({ description: "search string for action = search" })),
  ref: Schema.optional(Schema.String.annotate({ description: "sha256 (or prefix/label) for action = get" })),
  max_bytes: Schema.optional(Schema.Number.annotate({ description: "max preview bytes for action = get (default 4000, max 20000)" })),
})

function textLike(entry: { mime: string; ext: string }) {
  return (
    entry.mime.startsWith("text/") ||
    entry.mime.includes("json") ||
    ["txt", "md", "json", "html", "har", "replay"].includes(entry.ext)
  )
}

export const EvidenceTool = Tool.define(
  "evidence",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          action: "list" | "search" | "get" | "add_text" | "add_file"
          label?: string
          text?: string
          path?: string
          mime?: string
          query?: string
          ref?: string
          max_bytes?: number
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) {
            return {
              title: `evidence ${params.action}`,
              metadata: { active: false },
              output: "no_active_engagement -- load or create an engagement first.",
            }
          }

          if (params.action === "list") {
            const entries = yield* Effect.promise(() => Evidence.list(state.name))
            return {
              title: `evidence · ${entries.length}`,
              metadata: { action: "list", count: entries.length },
              output:
                entries.length === 0
                  ? "No evidence stored."
                  : entries
                      .map((entry) => `${entry.sha256} · ${entry.ext} · ${entry.size}B${entry.label ? ` · ${entry.label}` : ""}${entry.source ? ` · ${entry.source}` : ""}`)
                      .join("\n"),
            }
          }

          if (params.action === "search") {
            const query = (params.query ?? "").toLowerCase()
            const entries = yield* Effect.promise(() => Evidence.list(state.name))
            const rows: Array<{ sha256: string; ext: string; label: string; source: string; matched_fields: string[] }> = []
            for (const entry of entries) {
              const fields: Array<[string, string]> = [
                ["sha256", entry.sha256],
                ["ext", entry.ext],
                ["label", entry.label],
                ["source", entry.source],
              ]
              if (textLike(entry)) {
                const item = yield* Effect.promise(() => Evidence.get(state.name, entry.sha256))
                if (item) {
                  const raw = yield* Effect.promise(() => fs.readFile(item.path).catch(() => Buffer.alloc(0)))
                  fields.push(["preview", raw.toString("utf8").slice(0, 8000)])
                }
              }
              const matched = fields.filter(([, value]) => value.toLowerCase().includes(query)).map(([name]) => name)
              if (query && matched.length === 0) continue
              rows.push({ sha256: entry.sha256, ext: entry.ext, label: entry.label, source: entry.source, matched_fields: matched })
            }
            return {
              title: `evidence search · ${rows.length}`,
              metadata: { action: "search", count: rows.length },
              output: JSON.stringify(rows.slice(0, 50), null, 2),
            }
          }

          if (params.action === "get") {
            if (!params.ref) {
              return {
                title: "evidence get",
                metadata: { action: "get" },
                output: "Provide ref when action = get.",
              }
            }
            const item = yield* Effect.promise(() => Evidence.get(state.name, params.ref!))
            if (!item) {
              return {
                title: `evidence · ${params.ref}`,
                metadata: { action: "get", found: false },
                output: "No matching evidence artifact.",
              }
            }
            const maxBytes = Math.min(params.max_bytes ?? 4000, MAX_PREVIEW)
            let preview = `[binary preview omitted]`
            let truncated = true
            if (textLike(item.entry)) {
              const raw = yield* Effect.promise(() => fs.readFile(item.path).catch(() => Buffer.alloc(0)))
              truncated = raw.length > maxBytes
              preview = raw.toString("utf8").slice(0, maxBytes)
            }
            return {
              title: `evidence · ${item.entry.sha256}`,
              metadata: { action: "get", found: true, truncated },
              output: JSON.stringify({ entry: item.entry, preview, truncated }, null, 2),
            }
          }

          if (params.action === "add_text") {
            if (!params.text) {
              return { title: "evidence add_text", metadata: { action: "add_text" }, output: "Provide text when action = add_text." }
            }
            const entry = yield* Effect.promise(() =>
              Evidence.put({ engagementName: state.name, content: params.text!, mime: params.mime ?? "text/plain", label: params.label, source: "evidence tool" }),
            )
            return {
              title: `evidence · ${entry.sha256}`,
              metadata: { action: "add_text", sha256: entry.sha256 },
              output: `Stored text evidence ${entry.sha256}.${entry.ext}`,
            }
          }

          if (!params.path) {
            return { title: "evidence add_file", metadata: { action: "add_file" }, output: "Provide path when action = add_file." }
          }
          const content = yield* Effect.promise(() => fs.readFile(params.path!).catch(() => undefined))
          if (!content) {
            return { title: "evidence add_file", metadata: { action: "add_file", found: false }, output: `Could not read ${params.path}.` }
          }
          const entry = yield* Effect.promise(() =>
            Evidence.put({ engagementName: state.name, content, mime: params.mime, label: params.label, source: params.path }),
          )
          return {
            title: `evidence · ${entry.sha256}`,
            metadata: { action: "add_file", sha256: entry.sha256 },
            output: `Stored file evidence ${entry.sha256}.${entry.ext}`,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

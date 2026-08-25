import { Effect, Schema } from "effect"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { Observation } from "@pentestcode/core/cyber/observation"
import DESCRIPTION from "./observation.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals(["list", "add", "update", "remove", "link_evidence"]).annotate({
    description: "observation lifecycle operation",
  }),
  subtype: Schema.optional(
    Schema.Literals(["vuln", "code-smell", "intel-fact", "flag", "ioc", "control-gap", "risk"]).annotate({
      description: "observation kind when action = add",
    }),
  ),
  title: Schema.optional(Schema.String.annotate({ description: "short title when action = add or update" })),
  severity: Schema.optional(
    Schema.Literals(["info", "low", "medium", "high", "critical"]).annotate({ description: "severity" }),
  ),
  confidence: Schema.optional(Schema.String.annotate({ description: "free-form confidence note, e.g. high/medium/low" })),
  status: Schema.optional(
    Schema.Literals(["open", "triaged", "confirmed", "resolved", "false-positive"]).annotate({
      description: "lifecycle status when action = update",
    }),
  ),
  note: Schema.optional(Schema.String.annotate({ description: "detail note" })),
  tags: Schema.optional(Schema.String.annotate({ description: "comma-separated tags" })),
  id: Schema.optional(Schema.String.annotate({ description: "observation id for update/remove/link_evidence" })),
  evidence_ref: Schema.optional(Schema.String.annotate({ description: "evidence sha256 when action = link_evidence" })),
})

function parseTags(input?: string): string[] | undefined {
  if (!input) return undefined
  const tags = input
    .split(",")
    .map((tag) => tag.trim())
    .filter(Boolean)
  return tags.length > 0 ? tags : undefined
}

export const ObservationTool = Tool.define(
  "observation",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          action: "list" | "add" | "update" | "remove" | "link_evidence"
          subtype?: "vuln" | "code-smell" | "intel-fact" | "flag" | "ioc" | "control-gap" | "risk"
          title?: string
          severity?: "info" | "low" | "medium" | "high" | "critical"
          confidence?: string
          status?: "open" | "triaged" | "confirmed" | "resolved" | "false-positive"
          note?: string
          tags?: string
          id?: string
          evidence_ref?: string
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) {
            return {
              title: `observation ${params.action}`,
              metadata: { active: false },
              output: "no_active_engagement -- load or create an engagement first.",
            }
          }

          if (params.action === "list") {
            const all = yield* Effect.promise(() => Observation.list(state.name))
            const counts = Observation.severityCounts(all)
            return {
              title: `observations · ${all.length}`,
              metadata: { action: "list", count: all.length, counts },
              output:
                all.length === 0
                  ? "No observations recorded."
                  : [
                      all
                        .map(
                          (o) =>
                            `${o.id} · ${o.subtype} · ${o.severity ?? "none"} · ${o.status} · ${o.title}${o.evidence.length > 0 ? ` · evidence:${o.evidence.join(",")}` : ""}`,
                        )
                        .join("\n"),
                      "",
                      `severity counts: ${JSON.stringify(counts)}`,
                    ].join("\n"),
            }
          }

          if (params.action === "add") {
            if (!params.subtype || !params.title) {
              return {
                title: "observation add",
                metadata: { action: "add" },
                output: "Provide subtype and title when action = add.",
              }
            }
            const created = yield* Effect.promise(() =>
              Observation.add({
                engagementName: state.name,
                subtype: params.subtype!,
                title: params.title!,
                severity: params.severity,
                confidence: params.confidence,
                note: params.note,
                tags: parseTags(params.tags),
              }),
            )
            return {
              title: `observation · ${created.title}`,
              metadata: { action: "add", id: created.id },
              output: `Recorded ${created.subtype} observation ${created.id}: ${created.title}`,
            }
          }

          if (!params.id) {
            return {
              title: `observation ${params.action}`,
              metadata: { action: params.action },
              output: `Provide id when action = ${params.action}.`,
            }
          }

          if (params.action === "update") {
            const ok = yield* Effect.promise(() =>
              Observation.update(state.name, params.id!, {
                title: params.title,
                severity: params.severity,
                confidence: params.confidence,
                status: params.status,
                note: params.note,
                tags: parseTags(params.tags),
                subtype: params.subtype,
              }),
            )
            return {
              title: `observation · ${params.id}`,
              metadata: { action: "update", updated: ok },
              output: ok ? `Updated observation ${params.id}.` : `Observation ${params.id} not found.`,
            }
          }

          if (params.action === "remove") {
            const ok = yield* Effect.promise(() => Observation.remove(state.name, params.id!))
            return {
              title: `observation · ${params.id}`,
              metadata: { action: "remove", removed: ok },
              output: ok ? `Removed observation ${params.id}.` : `Observation ${params.id} not found.`,
            }
          }

          if (!params.evidence_ref) {
            return { title: "observation link_evidence", metadata: { action: "link_evidence" }, output: "Provide evidence_ref." }
          }
          const ok = yield* Effect.promise(() => Observation.linkEvidence(state.name, params.id!, params.evidence_ref!))
          return {
            title: `observation · ${params.id}`,
            metadata: { action: "link_evidence", linked: ok },
            output: ok ? `Linked evidence to ${params.id}.` : `Observation ${params.id} not found.`,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

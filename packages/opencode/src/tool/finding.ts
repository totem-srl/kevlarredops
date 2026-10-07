import { Effect, Schema } from "effect"
import { FindingReview } from "@pentestcode/core/cyber/finding-review"
import { FindingStore } from "@pentestcode/core/cyber/finding-store"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { EngagementReport } from "@pentestcode/core/engagement/report"
import DESCRIPTION from "./finding.txt"
import { Tool } from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.optional(Schema.Literals(["list", "status", "promote", "reject", "update", "retest"])),
  key: Schema.optional(Schema.String),
  title: Schema.optional(Schema.String),
  summary: Schema.optional(Schema.String),
  severity: Schema.optional(Schema.Literals(["info", "low", "medium", "high", "critical"])),
  target: Schema.optional(
    Schema.String.annotate({ description: "Affected target authorized by the current engagement scope" }),
  ),
  owner: Schema.optional(Schema.String),
  reviewer: Schema.optional(
    Schema.String.annotate({
      description: "Operator-provided reviewer label; required with note for update and retest",
    }),
  ),
  impact: Schema.optional(Schema.String),
  remediation: Schema.optional(Schema.String),
  reproduction_steps: Schema.optional(Schema.Array(Schema.String)),
  evidence: Schema.optional(Schema.Array(Schema.String)),
  replay: Schema.optional(
    Schema.String.annotate({
      description: "Recorded command and result, including retest timestamp; stored privately as evidence",
    }),
  ),
  replay_exemption_category: Schema.optional(
    Schema.Literals([
      "destructive_target",
      "operator_controlled_state",
      "external_dependency",
      "time_bound_access",
      "legacy_unspecified",
    ]),
  ),
  replay_exemption_rationale: Schema.optional(Schema.String),
  note: Schema.optional(Schema.String),
  outcome: Schema.optional(Schema.Literals(["resolved", "still_vulnerable", "inconclusive"])),
})

export const FindingTool = Tool.define(
  "finding",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, _ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) return { title: "finding", metadata: {}, output: "No active engagement. Initialize one first." }
          const action = params.action ?? "list"
          if (action === "list") {
            const report = yield* Effect.promise(() => EngagementReport.build(state, ["findings"]))
            return {
              title: `finding · list · ${report.engagement.name}`,
              metadata: {
                reportable: report.summary.reportable_findings,
                resolved: report.summary.resolved_findings,
                unverified: report.summary.awaiting_verification,
              },
              output: EngagementReport.renderMarkdown(report),
            }
          }
          if (!params.key)
            return { title: `finding · ${action}`, metadata: {}, output: `Provide key for action = ${action}.` }
          if (action === "status") {
            const records = yield* Effect.promise(() => FindingStore.load(state.name))
            const history = records.filter((record) => record.id === params.key)
            return {
              title: "finding · status",
              metadata: { revisions: history.length },
              output: history.length
                ? JSON.stringify(EngagementReport.redact(state, history), null, 2)
                : "No finding with this ID is recorded.",
            }
          }
          const result = yield* FindingReview.change(state, { ...params, action, key: params.key })
          if ("error" in result)
            return {
              title: `finding · ${action} · review required`,
              metadata: { promoted: false },
              output: result.error,
            }
          const record = result.record
          return {
            title: `finding · ${action} · ${record.status}`,
            metadata: { id: record.id, status: record.status, reportable: result.reportable },
            output: JSON.stringify(EngagementReport.redact(state, record), null, 2),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

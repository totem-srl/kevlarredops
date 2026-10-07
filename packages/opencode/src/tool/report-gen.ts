import path from "node:path"
import { createHash } from "node:crypto"
import { Effect, Schema } from "effect"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { EngagementReport } from "@pentestcode/core/engagement/report"
import DESCRIPTION from "./report-gen.txt"
import { Tool } from "./tool"

export const Parameters = Schema.Struct({
  format: Schema.optional(Schema.Literals(["markdown", "json", "html"])).annotate({
    description: "Output format; default markdown. HTML is offline and printable.",
  }),
  sections: Schema.optional(Schema.Array(Schema.Literals(EngagementReport.SECTIONS))).annotate({
    description: "Sections to include; default all. Applies to every format.",
  }),
  output_path: Schema.optional(Schema.String).annotate({
    description: "File path to write a private report. Omit to return inline.",
  }),
})

export const ReportGenTool = Tool.define(
  "report_gen",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state)
            return { title: "report", metadata: {}, output: "No engagement loaded. Start or load an engagement first." }
          const sections = [...new Set(params.sections ?? EngagementReport.SECTIONS)]
          if (!sections.length) return { title: "report", metadata: {}, output: "Choose at least one report section." }
          const format = params.format ?? "markdown"
          const data = yield* Effect.promise(() => EngagementReport.build(state, sections))
          const output = EngagementReport.render(data, format)
          const sha256 = createHash("sha256").update(output).digest("hex")
          const metadata = {
            format,
            sections,
            reportable: data.summary.reportable_findings,
            awaiting_verification: data.summary.awaiting_verification,
            redacted: true,
            snapshot_at: data.engagement.snapshot_at,
            sha256,
          }
          if (!params.output_path) return { title: `report (${format})`, metadata, output }
          const destination = path.resolve(params.output_path)
          yield* ctx.ask({
            permission: "edit",
            patterns: [destination],
            always: ["*"],
            metadata: { path: destination, format, sha256 },
          })
          yield* Effect.promise(() => EngagementReport.write(destination, output))
          return {
            title: `report -> ${destination}`,
            metadata: { ...metadata, output_path: destination },
            output: `${format.toUpperCase()} report written to ${destination} (${Buffer.byteLength(output)} bytes).\nReportable: ${metadata.reportable}; awaiting verification: ${metadata.awaiting_verification}.\nSHA-256: ${sha256}\nOperator review required before sharing.`,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

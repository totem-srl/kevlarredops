import { Effect, Schema } from "effect"
import { Methodology } from "@pentestcode/core/cyber/methodology"
import DESCRIPTION from "./methodology.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  framework: Schema.optional(
    Schema.Literals(["mitre", "ptes", "wstg"]).annotate({ description: "framework id (see list when omitted)" }),
  ),
  phase: Schema.optional(Schema.String.annotate({ description: "phase id within the framework" })),
  query: Schema.optional(Schema.String.annotate({ description: "search string; takes precedence over framework/phase" })),
})

export const MethodologyTool = Tool.define(
  "methodology",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          framework?: "mitre" | "ptes" | "wstg"
          phase?: string
          query?: string
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          if (params.query) {
            const hits = Methodology.search(params.query)
            if (hits.length === 0) return { title: `methodology · "${params.query}"`, metadata: { count: 0 }, output: "No matches." }
            return {
              title: `methodology · ${hits.length} matches`,
              metadata: { count: hits.length },
              output: hits
                .slice(0, 40)
                .map((hit) => `${hit.framework}/${hit.phase} · ${hit.technique}${hit.description ? ` — ${hit.description}` : ""}`)
                .join("\n"),
            }
          }

          if (!params.framework) {
            const frameworks = Methodology.listFrameworks()
            return {
              title: `methodology · ${frameworks.length} frameworks`,
              metadata: { frameworks: frameworks.map((f) => f.id) },
              output: frameworks
                .map((f) => `${f.id} · ${f.name} · ${f.phases.length} phases`)
                .join("\n"),
            }
          }

          if (!params.phase) {
            const framework = Methodology.getFramework(params.framework)
            if (!framework) {
              return {
                title: "methodology",
                metadata: { found: false },
                output: `Unknown framework "${params.framework}". Known: ${Methodology.frameworkIds().join(", ")}`,
              }
            }
            return {
              title: `methodology · ${framework.id}`,
              metadata: { framework: framework.id, phases: framework.phases.length },
              output: [
                `${framework.name} (v${framework.version})`,
                ...framework.phases.map((p) => `- ${p.id} · ${p.name} (${p.techniques.length} techniques)`),
              ].join("\n"),
            }
          }

          const found = Methodology.findPhase(params.framework, params.phase)
          if (!found) {
            return {
              title: `methodology · ${params.framework}/${params.phase}`,
              metadata: { found: false },
              output: `Phase "${params.phase}" not found in ${params.framework}.`,
            }
          }
          return {
            title: `methodology · ${params.framework}/${found.id}`,
            metadata: { framework: params.framework, phase: found.id, techniques: found.techniques.length },
            output: [
              `${found.name} — ${found.description ?? ""}`,
              "",
              ...found.techniques.map((t) => `- ${t.id} · ${t.name}${t.description ? ` — ${t.description}` : ""}`),
            ].join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

import { Effect, Schema } from "effect"
import {
  KnowledgeIntents,
  KnowledgeActions,
  buildVulnIntelCard,
  formatVulnIntelCard,
} from "@pentestcode/core/cyber/knowledge"
import { queryNvd } from "./cve"
import DESCRIPTION from "./knowledge.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals(["vuln_intel", "capabilities"]).annotate({
    description: "vuln_intel fetches a CVE intel card; capabilities lists broker support",
  }),
  cve_id: Schema.optional(Schema.String.annotate({ description: "CVE id, required for vuln_intel (e.g. CVE-2021-44228)" })),
  component_name: Schema.optional(
    Schema.String.annotate({ description: "Optional product name to evaluate applicability against (e.g. nginx)" }),
  ),
  component_version: Schema.optional(
    Schema.String.annotate({ description: "Optional version for the component (e.g. 1.18.0)" }),
  ),
})

export const KnowledgeTool = Tool.define(
  "knowledge",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          if (params.action === "capabilities") {
            const output = [
              "Knowledge broker capabilities:",
              "",
              `intents: ${KnowledgeIntents.join(", ")}`,
              `actions: ${KnowledgeActions.join(", ")}`,
              "modes: live (public NVD over network), offline (local records only), opsec_strict",
              "",
              "Live lookups currently cover vuln_intel via the public NVD API. KEV/EPSS enrichment is not wired.",
            ]
            return {
              title: "knowledge · capabilities",
              metadata: { action: "capabilities" },
              output: output.join("\n"),
            }
          }

          if (!params.cve_id) {
            return {
              title: "knowledge · vuln_intel",
              metadata: {},
              output: "Provide cve_id for action = vuln_intel (e.g. CVE-2021-44228).",
            }
          }

          const result = yield* Effect.promise(() => queryNvd(params.cve_id!, 1))
          if (result.error) {
            return {
              title: `knowledge · ${params.cve_id} · degraded`,
              metadata: { ok: false, error: result.error },
              output: `NVD lookup failed: ${result.error}`,
            }
          }
          if (result.records.length === 0) {
            return {
              title: `knowledge · ${params.cve_id}`,
              metadata: { ok: false },
              output: `No NVD record found for ${params.cve_id}.`,
            }
          }

          const card = buildVulnIntelCard({
            record: result.records[0] as never,
            component:
              params.component_name !== undefined
                ? {
                    name: params.component_name,
                    version: params.component_version,
                  }
                : undefined,
          })
          return {
            title: `knowledge · ${card.cve}`,
            metadata: { action: "vuln_intel", cve: card.cve },
            output: formatVulnIntelCard(card),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

import { Effect, Schema } from "effect"
import { buildVulnIntelCard, type VulnIntelCard } from "@pentestcode/core/cyber/knowledge"
import DESCRIPTION from "./cve.txt"
import * as Tool from "./tool"

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

export const Parameters = Schema.Struct({
  query: Schema.String.annotate({
    description: "CVE id (e.g. CVE-2021-44228) or keyword expression (e.g. 'apache log4j')",
  }),
  severity: Schema.optional(
    Schema.Literals(["low", "medium", "high", "critical", "advisory"]).annotate({
      description: "Only return records at this severity level",
    }),
  ),
  limit: Schema.optional(Schema.Number.annotate({ description: "Max cards to return (1-50, default 10)" })),
})

type NvdResponse = {
  totalResults?: number
  vulnerabilities?: { cve?: unknown }[]
}

function compactCard(card: VulnIntelCard) {
  return {
    cve: card.cve,
    level: card.severity.level,
    cvss_v3: card.severity.cvss_v3,
    summary: card.summary ? `${card.summary.slice(0, 240)}${card.summary.length > 240 ? "..." : ""}` : undefined,
    affected_criteria_count: card.affected.length,
    reference_count: card.references.length,
  }
}

export function matchesSeverity(card: VulnIntelCard, severity: string | undefined): boolean {
  if (!severity) return true
  if (severity === "advisory") return card.severity.cvss_v3 === undefined && !card.severity.level
  return card.severity.level?.toLowerCase() === severity
}

export async function queryNvd(query: string, limit: number): Promise<{ records: unknown[]; error?: string }> {
  const isCveId = /^CVE-\d{4}-\d{4,}$/i.test(query.trim())
  const url = isCveId
    ? `${NVD_URL}?cveId=${encodeURIComponent(query.trim())}`
    : `${NVD_URL}?keywordExpression=${encodeURIComponent(query.trim())}&resultsPerPage=${limit}`
  try {
    const response = await fetch(url, {
      headers: { "User-Agent": "pentestcode-cve/1.0", Accept: "application/json" },
      signal: AbortSignal.timeout(30_000),
    })
    if (!response.ok) return { records: [], error: `NVD returned ${response.status}` }
    const data = (await response.json()) as NvdResponse
    return { records: (data.vulnerabilities ?? []).map((v) => v.cve ?? v) }
  } catch (error) {
    return { records: [], error: error instanceof Error ? error.message : String(error) }
  }
}

export const CveTool = Tool.define(
  "cve",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          yield* ctx.ask({
            permission: "cve",
            patterns: [params.query],
            always: ["*"],
            metadata: { query: params.query },
          })

          const limit = Math.min(Math.max(Math.trunc(params.limit ?? 10), 1), 50)
          const result = yield* Effect.promise(() => queryNvd(params.query, limit))
          const errors: string[] = []
          if (result.error) errors.push(result.error)

          const cards = result.records.map((record) => buildVulnIntelCard({ record: record as never }))
          const filtered = cards.filter((card) => matchesSeverity(card, params.severity))
          filtered.sort((a, b) => (b.severity.cvss_v3 ?? -1) - (a.severity.cvss_v3 ?? -1))

          const summary = [
            `query "${params.query}" matched ${result.records.length} NVD record(s); returning ${filtered.length} card(s)`,
            ...(errors.length > 0 ? [`degraded: ${errors.join("; ")}`] : []),
          ].join("\n")

          return {
            title: `cve · ${params.query}`,
            metadata: {
              matched: result.records.length,
              returned: filtered.length,
              degraded: errors.length > 0,
            },
            output: JSON.stringify(
              {
                operator_summary: summary,
                request: { query: params.query, severity: params.severity, limit },
                cards_compact: filtered.map(compactCard),
                degraded: errors.length > 0,
                errors,
              },
              null,
              2,
            ),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

import type { NvdApplicability } from "./nvd-match"
import { collectNvdRanges, evaluateNvdApplicability } from "./nvd-match"

export const KnowledgeIntents = [
  "vuln_intel",
  "methodology",
  "tradecraft",
  "exploit_signal",
  "tool_docs",
  "field_research",
] as const
export type KnowledgeIntent = (typeof KnowledgeIntents)[number]

export const KnowledgeActions = [
  "lookup",
  "match_component",
  "enrich_observed",
  "enrich_dependency",
  "prioritize",
  "safe_next_actions",
] as const
export type KnowledgeAction = (typeof KnowledgeActions)[number]

export type KnowledgeMode = "live" | "offline" | "opsec_strict"

export type VulnIntelCard = {
  cve: string
  summary?: string
  affected: string[]
  severity: {
    cvss_v3?: number
    cvss_v4?: number
    level?: string
  }
  exploitation: {
    kev?: boolean
    epss?: number
    public_exploit_signal?: string
  }
  applicability?: NvdApplicability
  references: string[]
  safe_next_actions: string[]
  stale_after?: string
}

export type ResearchCard = {
  topic: string
  source_pack: string
  sources: { title: string; url: string }[]
  claims: string[]
  recommended_next_actions: string[]
  unsafe_or_out_of_scope_actions: string[]
}

type CveContainer = {
  id?: string
  descriptions?: { lang: string; value: string }[]
  metrics?: Record<string, { cvssData?: { baseScore?: number; baseSeverity?: string } }[]>
}

export type NvdCveLike = {
  id?: string
  descriptions?: { lang: string; value: string }[]
  cve?: CveContainer
  configurations?: unknown[]
  metrics?: Record<string, { cvssData?: { baseScore?: number; baseSeverity?: string } }[]>
  references?: { url: string; source?: string; tags?: string[] }[]
}

function containerOf(record: NvdCveLike): CveContainer {
  return record.cve ?? record
}

function extractDescriptions(record: NvdCveLike): string | undefined {
  return containerOf(record).descriptions?.find((d) => d.lang === "en")?.value
}

function extractScore(record: NvdCveLike): { v3?: number; level?: string } {
  const metrics = containerOf(record).metrics
  if (!metrics) return {}
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] as const) {
    const list: { cvssData?: { baseScore?: number; baseSeverity?: string } }[] | undefined = metrics[key]
    const entry = list?.[0]?.cvssData
    if (entry?.baseScore !== undefined) return { v3: entry.baseScore, level: entry.baseSeverity }
  }
  return {}
}

// Builds a vuln-intel card from a raw NVD record plus an optional component to match against.
// Pure/local: no network. Live enrichment (KEV/EPSS/websearch) happens at the tool layer.
export function buildVulnIntelCard(input: {
  record: NvdCveLike
  component?: { name: string; version?: string; aliases?: string[]; cpe_candidates?: string[] }
}): VulnIntelCard {
  const record = input.record
  const id = record.cve?.id ?? record.id ?? "CVE-UNKNOWN"
  const summary = extractDescriptions(record)
  const score = extractScore(record)
  const ranges = collectNvdRanges((record.configurations ?? []) as never)

  const card: VulnIntelCard = {
    cve: id,
    summary,
    affected: ranges.map((r) => r.criteria),
    severity: { cvss_v3: score.v3, level: score.level },
    exploitation: {},
    references: (record.references ?? []).map((r) => r.url).filter(Boolean),
    safe_next_actions: [
      "verify the deployed version against the affected range before acting",
      "check vendor advisories and patches referenced above",
      "record evidence for any verification performed",
    ],
  }

  if (input.component && ranges.length > 0) {
    card.applicability = evaluateNvdApplicability({
      component: input.component,
      ranges,
      summary,
    })
    if (card.applicability.state === "applicable") {
      card.safe_next_actions.unshift(
        `component ${input.component.name}${input.component.version ? `@${input.component.version}` : ""} matches an affected range — plan remediation`,
      )
    }
  }

  return card
}

export function formatVulnIntelCard(card: VulnIntelCard): string {
  const lines: string[] = []
  lines.push(`# ${card.cve}`)
  if (card.summary) lines.push(card.summary)
  lines.push("")
  const sev: string[] = []
  if (card.severity.cvss_v3 !== undefined) sev.push(`CVSSv3 ${card.severity.cvss_v3}`)
  if (card.severity.level) sev.push(card.severity.level)
  if (sev.length > 0) lines.push(`Severity: ${sev.join(" · ")}`)
  if (card.exploitation.kev !== undefined) lines.push(`KEV: ${card.exploitation.kev ? "yes" : "no"}`)
  if (card.applicability) {
    lines.push(`Applicability: ${card.applicability.state} (confidence: ${card.applicability.confidence})`)
    lines.push(`Reason: ${card.applicability.reason}`)
    if (card.applicability.affected_range) lines.push(`Affected range: ${card.applicability.affected_range}`)
    for (const pre of card.applicability.preconditions) lines.push(`Precondition: ${pre}`)
  }
  if (card.affected.length > 0) {
    lines.push("")
    lines.push("Affected CPE criteria:")
    for (const c of card.affected.slice(0, 20)) lines.push(`- ${c}`)
    if (card.affected.length > 20) lines.push(`- ... and ${card.affected.length - 20} more`)
  }
  if (card.references.length > 0) {
    lines.push("")
    lines.push("References:")
    for (const ref of card.references.slice(0, 10)) lines.push(`- ${ref}`)
  }
  lines.push("")
  lines.push("Safe next actions:")
  for (const action of card.safe_next_actions) lines.push(`- ${action}`)
  return lines.join("\n")
}

export * as Knowledge from "./knowledge"

import { Schema } from "effect"

export type FindingStatus = "candidate" | "verified" | "rejected" | "stale"

export type ReplayExemptionCategory =
  | "destructive_target"
  | "operator_controlled_state"
  | "external_dependency"
  | "time_bound_access"
  | "legacy_unspecified"

export type ReplayExemption = {
  category: ReplayExemptionCategory
  rationale: string
}

export type ReplayState = { present: true } | ({ present: false } & { exemption?: ReplayExemption })

export type FindingRecord = {
  id: string
  title: string
  status: FindingStatus
  severity?: string
  target?: string
  detail?: string
  evidence_refs: string[]
  replay: ReplayState
  superseded_by?: string
  at: string
}

export const RecordSchema = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  status: Schema.Literals(["candidate", "verified", "rejected", "stale"]),
  severity: Schema.optional(Schema.String),
  target: Schema.optional(Schema.String),
  detail: Schema.optional(Schema.String),
  evidence_refs: Schema.mutable(Schema.Array(Schema.String)),
  replay: Schema.Union([
    Schema.Struct({ present: Schema.Literal(true) }),
    Schema.Struct({
      present: Schema.Literal(false),
      exemption: Schema.optional(
        Schema.Struct({
          category: Schema.Literals([
            "destructive_target",
            "operator_controlled_state",
            "external_dependency",
            "time_bound_access",
            "legacy_unspecified",
          ]),
          rationale: Schema.String,
        }),
      ),
    }),
  ]),
  superseded_by: Schema.optional(Schema.String),
  at: Schema.String,
})

export const REPLAY_EXEMPTION_CATEGORIES: ReplayExemptionCategory[] = [
  "destructive_target",
  "operator_controlled_state",
  "external_dependency",
  "time_bound_access",
  "legacy_unspecified",
]

// A finding is reportable only when it is verified, backed by evidence,
// and either has replay material or a structured, reasoned replay exemption.
export function isReportableFinding(finding: FindingRecord): boolean {
  if (finding.superseded_by) return false
  if (finding.status !== "verified") return false
  if (!finding.target?.trim()) return false
  if (finding.evidence_refs.length === 0) return false
  if (finding.replay.present) return true
  return finding.replay.exemption !== undefined && finding.replay.exemption.rationale.trim().length > 0
}

export function bucketFindings(findings: FindingRecord[]): {
  reportable: FindingRecord[]
  unverified: FindingRecord[]
  noEvidence: FindingRecord[]
  noReplay: FindingRecord[]
  rejected: FindingRecord[]
  stale: FindingRecord[]
  superseded: FindingRecord[]
} {
  const buckets = {
    reportable: [] as FindingRecord[],
    unverified: [] as FindingRecord[],
    noEvidence: [] as FindingRecord[],
    noReplay: [] as FindingRecord[],
    rejected: [] as FindingRecord[],
    stale: [] as FindingRecord[],
    superseded: [] as FindingRecord[],
  }
  for (const finding of findings) {
    if (finding.superseded_by) {
      buckets.superseded.push(finding)
      continue
    }
    if (isReportableFinding(finding)) {
      buckets.reportable.push(finding)
      continue
    }
    if (finding.status === "rejected") {
      buckets.rejected.push(finding)
      continue
    }
    if (finding.status === "stale") {
      buckets.stale.push(finding)
      continue
    }
    if (finding.status !== "verified") {
      buckets.unverified.push(finding)
      continue
    }
    if (finding.evidence_refs.length === 0) {
      buckets.noEvidence.push(finding)
      continue
    }
    buckets.noReplay.push(finding)
  }
  return buckets
}

// Dedupes records: when the same candidate id reappears as a later record,
// the latest wins. Records superseded by another keep only a tombstone.
export function normalizeFindingRecords(records: FindingRecord[]): FindingRecord[] {
  const byId = new Map<string, FindingRecord>()
  for (const record of records) {
    byId.set(record.id, record)
  }
  const normalized = [...byId.values()]
  const liveIds = new Set(normalized.filter((r) => !r.superseded_by).map((r) => r.id))
  return normalized.filter((r) => {
    if (!r.superseded_by) return true
    // drop tombstones whose superseder never materialized
    return liveIds.has(r.superseded_by)
  })
}

export function formatBucketSummary(records: FindingRecord[]): string {
  const buckets = bucketFindings(normalizeFindingRecords(records))
  const lines: string[] = []
  lines.push(`reportable: ${buckets.reportable.length}`)
  lines.push(`unverified candidates: ${buckets.unverified.length}`)
  lines.push(`verified without evidence: ${buckets.noEvidence.length}`)
  lines.push(`verified without replay/exemption: ${buckets.noReplay.length}`)
  lines.push(`rejected: ${buckets.rejected.length}`)
  lines.push(`stale: ${buckets.stale.length}`)
  lines.push(`superseded: ${buckets.superseded.length}`)
  if (buckets.noReplay.length > 0) {
    lines.push("")
    lines.push(
      "Verified findings missing replay need replay material or a structured ReplayExemption before they are reportable:",
    )
    for (const f of buckets.noReplay) lines.push(`- ${f.id}: ${f.title}`)
  }
  return lines.join("\n")
}

export * as FindingLifecycle from "./finding-lifecycle"

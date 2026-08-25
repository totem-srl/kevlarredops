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
  if (finding.status !== "verified") return false
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
} {
  const buckets = {
    reportable: [] as FindingRecord[],
    unverified: [] as FindingRecord[],
    noEvidence: [] as FindingRecord[],
    noReplay: [] as FindingRecord[],
    rejected: [] as FindingRecord[],
    stale: [] as FindingRecord[],
  }
  for (const finding of findings) {
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
  const liveIds = new Set(
    normalized.filter((r) => !r.superseded_by).map((r) => r.id),
  )
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
  if (buckets.noReplay.length > 0) {
    lines.push("")
    lines.push("Verified findings missing replay need replay material or a structured ReplayExemption before they are reportable:")
    for (const f of buckets.noReplay) lines.push(`- ${f.id}: ${f.title}`)
  }
  return lines.join("\n")
}

export * as FindingLifecycle from "./finding-lifecycle"

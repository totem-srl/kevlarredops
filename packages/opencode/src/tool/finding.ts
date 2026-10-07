import { Effect, Schema } from "effect"
import {
  FindingLifecycle,
  type FindingRecord,
  type FindingStatus,
  type ReplayExemptionCategory,
} from "@pentestcode/core/cyber/finding-lifecycle"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { FindingStore } from "@pentestcode/core/cyber/finding-store"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { EngagementReport } from "@pentestcode/core/engagement/report"
import { ScopeMatcher } from "@pentestcode/core/engagement/scope-matcher"
import DESCRIPTION from "./finding.txt"
import { Tool } from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.optional(
    Schema.Literals(["list", "status", "promote", "reject"]).annotate({ description: "default list" }),
  ),
  key: Schema.optional(Schema.String.annotate({ description: "Finding id (required for status/promote/reject)" })),
  title: Schema.optional(Schema.String.annotate({ description: "Title when promoting a new finding id" })),
  summary: Schema.optional(Schema.String.annotate({ description: "Detail text stored on the finding" })),
  severity: Schema.optional(
    Schema.Literals(["info", "low", "medium", "high", "critical"]).annotate({ description: "Severity for promote" }),
  ),
  target: Schema.optional(
    Schema.String.annotate({
      description: "Affected target/host/URL authorized by the current scope; required for a new promotion",
    }),
  ),
  evidence: Schema.optional(
    Schema.Array(Schema.String).annotate({
      description: "Evidence refs (sha256, prefix, or label) supporting the finding",
    }),
  ),
  replay: Schema.optional(
    Schema.String.annotate({
      description: "Replay material (command + output) proving the finding reproduces; stored as an evidence artifact",
    }),
  ),
  replay_exemption_category: Schema.optional(
    Schema.Literals([
      "destructive_target",
      "operator_controlled_state",
      "external_dependency",
      "time_bound_access",
      "legacy_unspecified",
    ]).annotate({ description: "Exemption category when replay is impossible; requires replay_exemption_rationale" }),
  ),
  replay_exemption_rationale: Schema.optional(
    Schema.String.annotate({ description: "Why replay is impossible; requires replay_exemption_category" }),
  ),
  note: Schema.optional(Schema.String.annotate({ description: "Note recorded on reject/status updates" })),
})

function formatRecord(f: FindingRecord): string {
  const lines = [
    `${f.id} · ${f.status}${f.severity ? ` · ${f.severity}` : ""}`,
    f.title,
    ...(f.detail ? ["", f.detail] : []),
  ]
  lines.push("", `evidence refs: ${f.evidence_refs.length > 0 ? f.evidence_refs.join(", ") : "(none)"}`)
  if (f.replay.present) lines.push("replay: present")
  else if (f.replay.exemption)
    lines.push(`replay: exempt (${f.replay.exemption.category}) — ${f.replay.exemption.rationale}`)
  else lines.push("replay: missing")
  return lines.join("\n")
}

function formatListBucket(
  label: string,
  findings: { id: string; title: string; severity?: string; reasons?: string[] }[],
): string[] {
  const lines = ["", `${label} (${findings.length}):`]
  if (findings.length === 0) lines.push("  (none)")
  for (const f of findings) {
    lines.push(`  - ${f.id}: ${f.title}${f.severity ? ` [${f.severity}]` : ""}`)
    if (f.reasons?.length) lines.push(`    ${f.reasons.join("; ")}`)
  }
  return lines
}

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
          if (!state) {
            return {
              title: "finding",
              metadata: {},
              output: "No active engagement. Initialize one first (phase control or pwn bootstrap).",
            }
          }

          return yield* FindingStore.withLock(state.name)(
            Effect.gen(function* () {
              const action = params.action ?? "list"
              const records = yield* Effect.promise(() => FindingStore.load(state.name))

              if (action === "list") {
                const current = yield* store.get()
                if (!current || current.name !== state.name) {
                  return {
                    title: "finding · list",
                    metadata: {},
                    output: "Active engagement changed. Run finding list again.",
                  }
                }
                const report = yield* Effect.promise(() => EngagementReport.build(current, ["findings"]))
                const audited = report.sections.findings!
                const buckets = FindingLifecycle.bucketFindings(FindingLifecycle.normalizeFindingRecords(records))
                const lines = [`Findings for ${report.engagement.name}:`]
                lines.push(...formatListBucket("Reportable", audited.verified))
                lines.push(...formatListBucket("Awaiting verification", audited.verification_queue))
                lines.push(...formatListBucket("Excluded lifecycle records", audited.excluded))
                lines.push("", `Excluded records and false-positive observations: ${report.summary.excluded_findings}`)
                return {
                  title: `finding · list · ${state.name}`,
                  metadata: {
                    total: records.length,
                    reportable: report.summary.reportable_findings,
                    unverified: report.summary.awaiting_verification,
                    rejected: buckets.rejected.length,
                    stale: buckets.stale.length,
                  },
                  output: lines.join("\n"),
                }
              }

              if (!params.key) {
                return { title: `finding · ${action}`, metadata: {}, output: `Provide key for action = ${action}.` }
              }

              if (action === "status") {
                const record = [...records].reverse().find((r) => r.id === params.key)
                if (!record) {
                  return { title: `finding · status`, metadata: {}, output: `No finding "${params.key}" recorded.` }
                }
                return {
                  title: `finding · status · ${record.id}`,
                  metadata: { id: record.id, status: record.status },
                  output: formatRecord(record),
                }
              }

              if (action === "reject") {
                const existing = [...records].reverse().find((r) => r.id === params.key)
                if (!existing) {
                  return { title: `finding · reject`, metadata: {}, output: `No finding "${params.key}" recorded.` }
                }
                const rejected: FindingRecord = {
                  ...existing,
                  status: "rejected",
                  at: new Date().toISOString(),
                }
                if (params.note)
                  rejected.detail = `${existing.detail ? `${existing.detail}\n` : ""}reject note: ${params.note}`
                records.push(rejected)
                yield* Effect.promise(() => FindingStore.save(state.name, records))
                return {
                  title: `finding · rejected · ${rejected.id}`,
                  metadata: { id: rejected.id, status: "rejected" },
                  output: formatRecord(rejected),
                }
              }

              // promote
              if (params.replay !== undefined && params.replay_exemption_category !== undefined) {
                return {
                  title: "finding · promote · invalid input",
                  metadata: {},
                  output: "Provide either replay material OR a replay exemption — not both.",
                }
              }
              const hasCategory = params.replay_exemption_category !== undefined
              const hasRationale =
                params.replay_exemption_rationale !== undefined && params.replay_exemption_rationale.trim().length > 0
              if (hasCategory !== hasRationale) {
                return {
                  title: "finding · promote · invalid input",
                  metadata: {},
                  output: "Replay exemption needs BOTH category and rationale.",
                }
              }

              if (params.replay !== undefined && !params.replay.trim()) {
                return {
                  title: "finding · promote · invalid replay",
                  metadata: {},
                  output: "Replay material cannot be empty.",
                }
              }

              const prior = [...records].reverse().find((r) => r.id === params.key)
              const target = params.target ?? prior?.target
              const current = yield* store.get()
              if (
                !target?.trim() ||
                !current ||
                current.name !== state.name ||
                !ScopeMatcher.checkScope(target, current.scope).inScope
              ) {
                return {
                  title: "finding · promote · invalid target",
                  metadata: { promoted: false },
                  output: "Promotion requires an affected target authorized by the current engagement scope.",
                }
              }
              const provided = [...new Set([...(params.evidence ?? []), ...(prior?.evidence_refs ?? [])])]
              const resolved = yield* Effect.promise(async () => {
                try {
                  const entries = await Promise.all(provided.map((ref) => Evidence.get(state.name, ref)))
                  const missing = provided.filter((_ref, index) => !entries[index])
                  if (missing.length)
                    return { error: "Evidence references must resolve to stored artifacts in this engagement." }
                  return { refs: entries.flatMap((entry) => (entry ? [entry.entry.sha256] : [])) }
                } catch (error) {
                  return { error: error instanceof Error ? error.message : "Evidence verification failed." }
                }
              })
              if (resolved.error) {
                return {
                  title: "finding · promote · invalid evidence",
                  metadata: { promoted: false },
                  output: resolved.error,
                }
              }

              let replayRefs: string[] = []
              if (params.replay !== undefined) {
                const entry = yield* Effect.promise(() =>
                  Evidence.put({
                    engagementName: state.name,
                    content: params.replay!,
                    mime: "text/plain",
                    label: `${params.key} replay`,
                    source: "finding_replay",
                  }),
                )
                replayRefs = [entry.sha256]
              }

              const evidenceRefs = [...new Set([...(resolved.refs ?? []), ...replayRefs])]
              if (evidenceRefs.length === 0) {
                return {
                  title: "finding · promote · no evidence",
                  metadata: {},
                  output:
                    "Promotion requires at least one evidence ref. Attach evidence via params.evidence or capture it with the evidence tool first.",
                }
              }

              const replayState =
                params.replay !== undefined
                  ? ({ present: true } as const)
                  : hasCategory && hasRationale
                    ? ({
                        present: false,
                        exemption: {
                          category: params.replay_exemption_category as ReplayExemptionCategory,
                          rationale: params.replay_exemption_rationale!.trim(),
                        },
                      } as const)
                    : (prior?.replay ?? ({ present: false } as const))

              const status: FindingStatus = "verified"
              const record: FindingRecord = {
                id: params.key!,
                title: params.title ?? prior?.title ?? params.key!,
                status,
                severity: params.severity ?? prior?.severity,
                target,
                detail: params.summary ?? prior?.detail,
                evidence_refs: evidenceRefs,
                replay: replayState,
                at: new Date().toISOString(),
              }
              if (prior && prior.status === "candidate") {
                prior.superseded_by = params.key!
              }
              records.push(record)
              yield* Effect.promise(() => FindingStore.save(state.name, records))

              const reportable = FindingLifecycle.isReportableFinding(record)
              const oracle = reportable
                ? "reportable"
                : "not yet reportable — needs verified status, evidence, and replay or exemption"
              return {
                title: `finding · promoted · ${record.id}`,
                metadata: { id: record.id, status: record.status, reportable },
                output: [
                  formatRecord(record),
                  "",
                  `oracle: ${oracle}`,
                  `evidence: ${record.evidence_refs.join(", ")}`,
                ].join("\n"),
              }
            }),
          )
        }).pipe(Effect.orDie),
    }
  }),
)

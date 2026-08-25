import { Effect, Schema } from "effect"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import {
  FindingLifecycle,
  type FindingRecord,
  type FindingStatus,
  type ReplayExemptionCategory,
} from "@pentestcode/core/cyber/finding-lifecycle"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import DESCRIPTION from "./finding.txt"
import * as Tool from "./tool"

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
  target: Schema.optional(Schema.String.annotate({ description: "Affected target/host/URL" })),
  evidence: Schema.optional(
    Schema.Array(Schema.String).annotate({ description: "Evidence refs (sha256, prefix, or label) supporting the finding" }),
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

function engagementDir(name: string): string {
  return path.join(os.homedir(), ".pentestcode", "engagements", name)
}

async function loadRecords(name: string): Promise<FindingRecord[]> {
  try {
    const raw = await fs.readFile(path.join(engagementDir(name), "findings-lifecycle.json"), "utf8")
    return JSON.parse(raw) as FindingRecord[]
  } catch {
    return []
  }
}

async function saveRecords(name: string, records: FindingRecord[]): Promise<void> {
  await fs.mkdir(engagementDir(name), { recursive: true })
  await fs.writeFile(
    path.join(engagementDir(name), "findings-lifecycle.json"),
    JSON.stringify(records, null, 2),
    { mode: 0o600 },
  )
}

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

function formatListBucket(label: string, findings: FindingRecord[]): string[] {
  const lines = ["", `${label} (${findings.length}):`]
  if (findings.length === 0) lines.push("  (none)")
  for (const f of findings) {
    lines.push(`  - ${f.id}: ${f.title}${f.severity ? ` [${f.severity}]` : ""}`)
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
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) {
            return {
              title: "finding",
              metadata: {},
              output: "No active engagement. Initialize one first (phase control or pwn bootstrap).",
            }
          }

          const action = params.action ?? "list"
          const records = yield* Effect.promise(() => loadRecords(state.name))

          if (action === "list") {
            const buckets = FindingLifecycle.bucketFindings(FindingLifecycle.normalizeFindingRecords(records))
            const lines = [`Findings for ${state.name}:`]
            lines.push(...formatListBucket("Reportable", buckets.reportable))
            lines.push(...formatListBucket("Suspected / unverified", buckets.unverified))
            lines.push(...formatListBucket("Verified without evidence", buckets.noEvidence))
            lines.push(...formatListBucket("Verified without replay/exemption", buckets.noReplay))
            lines.push(...formatListBucket("Rejected", buckets.rejected))
            lines.push(...formatListBucket("Stale", buckets.stale))
            return {
              title: `finding · list · ${state.name}`,
              metadata: {
                total: records.length,
                reportable: buckets.reportable.length,
                unverified: buckets.unverified.length,
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
            if (params.note) rejected.detail = `${existing.detail ? `${existing.detail}\n` : ""}reject note: ${params.note}`
            records.push(rejected)
            yield* Effect.promise(() => saveRecords(state.name, records))
            return {
              title: `finding · rejected · ${rejected.id}`,
              metadata: { id: rejected.id, status: "rejected" },
              output: formatRecord(rejected),
            }
          }

          // promote
          if ((params.replay !== undefined && params.replay_exemption_category !== undefined)) {
            return {
              title: "finding · promote · invalid input",
              metadata: {},
              output: "Provide either replay material OR a replay exemption — not both.",
            }
          }
          const hasCategory = params.replay_exemption_category !== undefined
          const hasRationale = params.replay_exemption_rationale !== undefined && params.replay_exemption_rationale.trim().length > 0
          if (hasCategory !== hasRationale) {
            return {
              title: "finding · promote · invalid input",
              metadata: {},
              output: "Replay exemption needs BOTH category and rationale.",
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

          const prior = [...records].reverse().find((r) => r.id === params.key)
          const evidenceRefs = [...new Set([...(params.evidence ?? []), ...(prior?.evidence_refs ?? []), ...replayRefs])]
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
                : ({ present: false } as const)

          const status: FindingStatus = "verified"
          const record: FindingRecord = {
            id: params.key!,
            title: params.title ?? prior?.title ?? params.key!,
            status,
            severity: params.severity ?? prior?.severity,
            target: params.target ?? prior?.target,
            detail: params.summary ?? prior?.detail,
            evidence_refs: evidenceRefs,
            replay: replayState,
            at: new Date().toISOString(),
          }
          if (prior && prior.status === "candidate") {
            prior.superseded_by = params.key!
          }
          records.push(record)
          yield* Effect.promise(() => saveRecords(state.name, records))

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
        }).pipe(Effect.orDie),
    }
  }),
)

import { Effect, Schema } from "effect"
import { Evidence } from "./evidence"
import { FindingLifecycle } from "./finding-lifecycle"
import { FindingStore } from "./finding-store"
import { EngagementSchema } from "../engagement/schema"
import { ScopeMatcher } from "../engagement/scope-matcher"

export type Input = {
  action: "promote" | "reject" | "update" | "retest"
  key: string
  title?: string
  summary?: string
  severity?: "info" | "low" | "medium" | "high" | "critical"
  target?: string
  owner?: string
  reviewer?: string
  impact?: string
  remediation?: string
  reproduction_steps?: readonly string[]
  note?: string
  evidence?: readonly string[]
  replay?: string
  replay_exemption_category?: FindingLifecycle.ReplayExemptionCategory
  replay_exemption_rationale?: string
  outcome?: FindingLifecycle.Retest["outcome"]
}

export class InvalidInput extends Schema.TaggedErrorClass<InvalidInput>()("FindingReviewInvalidInput", {
  message: Schema.String,
}) {}
type Result = { record: FindingLifecycle.FindingRecord; reportable: boolean } | { error: string }

export const change = (state: EngagementSchema.State, input: Input): Effect.Effect<Result> =>
  FindingStore.withLock(state.name)(
    Effect.promise(async (): Promise<Result> => {
      try {
        if (!input.key.trim()) throw new InvalidInput({ message: "Provide a finding ID." })
        const records = await FindingStore.load(state.name)
        const prior = [...records].reverse().find((record) => record.id === input.key)
        if (input.action !== "promote" && !prior)
          throw new InvalidInput({ message: "No finding with this ID is recorded." })
        if (prior?.target && input.target && prior.target !== input.target)
          throw new InvalidInput({ message: "A finding ID cannot be reused for a different target." })
        const details = {
          owner: input.owner ?? prior?.owner,
          reviewer: input.reviewer ?? prior?.reviewer,
          impact: input.impact ?? prior?.impact,
          remediation: input.remediation ?? prior?.remediation,
          reproduction_steps: input.reproduction_steps ? [...input.reproduction_steps] : prior?.reproduction_steps,
          review_note: input.note ?? prior?.review_note,
        }
        const record = await (async (): Promise<FindingLifecycle.FindingRecord> => {
          if (input.action === "reject")
            return { ...prior!, ...details, status: "rejected", at: new Date().toISOString() }
          if (input.action === "update") {
            requireReview(input)
            if (
              [input.owner, input.impact, input.remediation, input.reproduction_steps].every(
                (value) => value === undefined,
              )
            ) {
              throw new InvalidInput({
                message: "Provide an owner, impact, remediation or reproduction steps to update.",
              })
            }
            return { ...prior!, ...details, at: new Date().toISOString() }
          }
          if (input.action === "retest") {
            requireReview(input)
            if (!input.outcome || !["resolved", "still_vulnerable", "inconclusive"].includes(input.outcome))
              throw new InvalidInput({ message: "Choose resolved, still_vulnerable or inconclusive." })
            if (
              prior!.superseded_by ||
              (prior!.status !== "verified" && prior!.status !== "resolved" && prior!.status !== "candidate")
            ) {
              throw new InvalidInput({
                message:
                  "Retest an active or previously resolved finding; rejected and superseded findings require a new review.",
              })
            }
            await resolveEvidence(state.name, references(records, input.key))
            const proof = await prepareProof(state, input, prior!.target)
            if (!proof.replay.present && !proof.replay.exemption)
              throw new InvalidInput({ message: "Retest requires replay material or a reasoned exemption." })
            const old = new Set(references(records, input.key))
            if (
              !proof.entries.some((entry) => !old.has(entry.sha256) && Date.parse(entry.at) >= Date.parse(prior!.at))
            ) {
              throw new InvalidInput({
                message:
                  "Retest requires distinct evidence captured after the previous revision. Include the retest timestamp and result in the proof; original evidence cannot prove a correction.",
              })
            }
            const at = new Date().toISOString()
            const retest: FindingLifecycle.Retest = {
              outcome: input.outcome,
              reviewer: input.reviewer!.trim(),
              note: input.note!.trim(),
              evidence_refs: proof.refs,
              replay: proof.replay,
              at,
            }
            return {
              ...prior!,
              ...details,
              status:
                input.outcome === "resolved"
                  ? "resolved"
                  : input.outcome === "still_vulnerable"
                    ? "verified"
                    : "candidate",
              evidence_refs: proof.refs,
              replay: proof.replay,
              retests: [...(prior!.retests ?? []), retest],
              at,
            }
          }
          if (prior?.status === "resolved")
            throw new InvalidInput({ message: "Use retest with still_vulnerable to reopen a resolved finding." })
          if (prior?.superseded_by) throw new InvalidInput({ message: "Use the superseding finding ID." })
          const target = input.target ?? prior?.target
          const proof = await prepareProof(state, input, target, prior)
          return {
            ...prior,
            id: input.key,
            title: input.title ?? prior?.title ?? input.key,
            status: "verified",
            severity: input.severity ?? prior?.severity,
            target,
            detail: input.summary ?? prior?.detail,
            ...details,
            evidence_refs: proof.refs,
            replay: proof.replay,
            at: new Date().toISOString(),
          }
        })()
        records.push(record)
        await FindingStore.save(state.name, records)
        const reportable =
          FindingLifecycle.isReportableFinding(record) &&
          Boolean(record.target && ScopeMatcher.checkScope(record.target, state.scope).inScope) &&
          (await resolveEvidence(state.name, references(records, record.id)).then(
            () => true,
            () => false,
          ))
        return { record, reportable }
      } catch (error) {
        if (error instanceof InvalidInput) return { error: error.message }
        throw error
      }
    }).pipe(Effect.uninterruptible),
  )

function requireReview(input: Input) {
  if (!input.reviewer?.trim() || !input.note?.trim())
    throw new InvalidInput({
      message: "Review requires a reviewer label and a nonempty note; no verified identity is inferred.",
    })
}

function references(records: readonly FindingLifecycle.FindingRecord[], id: string) {
  return records
    .filter((record) => record.id === id)
    .flatMap((record) => [...record.evidence_refs, ...(record.retests ?? []).flatMap((retest) => retest.evidence_refs)])
}

async function prepareProof(
  state: EngagementSchema.State,
  input: Input,
  target?: string,
  prior?: FindingLifecycle.FindingRecord,
) {
  if (!target?.trim() || !ScopeMatcher.checkScope(target, state.scope).inScope) {
    throw new InvalidInput({
      message: "Promotion or retest requires an affected target authorized by the current engagement scope.",
    })
  }
  if (input.replay !== undefined && input.replay_exemption_category !== undefined)
    throw new InvalidInput({ message: "Provide replay material or a replay exemption, not both." })
  if (input.replay !== undefined && !input.replay.trim())
    throw new InvalidInput({ message: "Replay material cannot be empty." })
  if (input.replay && Buffer.byteLength(input.replay) > 10 * 1024 * 1024)
    throw new InvalidInput({ message: "Replay material exceeds 10 MiB." })
  const hasCategory = input.replay_exemption_category !== undefined
  const hasRationale = Boolean(input.replay_exemption_rationale?.trim())
  if (hasCategory !== hasRationale)
    throw new InvalidInput({ message: "Replay exemption needs both category and rationale." })
  const refs = [...new Set([...(input.evidence ?? []), ...(prior?.evidence_refs ?? [])])]
  const entries = await resolveEvidence(state.name, refs)
  if (input.replay !== undefined)
    entries.push(
      await Evidence.put({
        engagementName: state.name,
        content: input.replay,
        mime: "text/plain",
        label: `${input.key} ${input.action === "retest" ? "retest" : "replay"}`,
        source: input.action === "retest" ? "finding_retest" : "finding_replay",
      }),
    )
  if (!entries.length)
    throw new InvalidInput({ message: "Promotion or retest requires at least one stored evidence artifact." })
  const replay: FindingLifecycle.ReplayState =
    input.replay !== undefined
      ? { present: true }
      : hasCategory
        ? {
            present: false,
            exemption: {
              category: input.replay_exemption_category!,
              rationale: input.replay_exemption_rationale!.trim(),
            },
          }
        : (prior?.replay ?? { present: false })
  return { entries, refs: [...new Set(entries.map((entry) => entry.sha256))], replay }
}

async function resolveEvidence(name: string, refs: readonly string[]) {
  const entries: Evidence.Entry[] = []
  for (const ref of new Set(refs)) {
    try {
      const stored = await Evidence.get(name, ref)
      if (!stored)
        throw new InvalidInput({ message: "Evidence references must resolve to stored artifacts in this engagement." })
      entries.push(stored.entry)
    } catch (error) {
      if (error instanceof InvalidInput) throw error
      throw new InvalidInput({ message: error instanceof Error ? error.message : "Evidence verification failed." })
    }
  }
  return entries
}

export * as FindingReview from "./finding-review"

import { expect } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { Deferred, Effect, Fiber } from "effect"
import { Evidence } from "../src/cyber/evidence"
import { FindingReview } from "../src/cyber/finding-review"
import { FindingStore } from "../src/cyber/finding-store"
import { EngagementSchema } from "../src/engagement/schema"
import { EngagementReport } from "../src/engagement/report"
import { it } from "./lib/effect"

const secret = "review-secret-owned-XYZ"
const fixture = Effect.acquireRelease(
  Effect.sync((): EngagementSchema.State => {
    if (!process.env.OPENCODE_TEST_HOME) throw new Error("The test preload must isolate user data")
    return {
      id: EngagementSchema.ID.make("review"),
      name: `review-${crypto.randomUUID()}`,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      current_phase: "reporting",
      mode: "guided",
      scope: { targets: ["127.0.0.1"], excludes: [] },
      hosts: {},
      credentials: { lab: { id: "lab", value: secret } },
      flags: [],
      attack_path: [],
      task_tree: [],
      notes: [],
    }
  }),
  (state) => Effect.promise(() => fs.rm(FindingStore.directory(state.name), { recursive: true, force: true })),
)

function review(state: EngagementSchema.State, input: FindingReview.Input) {
  return FindingReview.change(state, input).pipe(
    Effect.map((result) => {
      if ("error" in result) throw new Error(result.error)
      return result.record
    }),
  )
}

const initial: FindingReview.Input = {
  action: "promote",
  key: "owned",
  title: "Owned lab finding",
  target: "127.0.0.1",
  severity: "high",
  replay: "2026-10-07: initial command and vulnerable result",
}
const reviewer = { reviewer: "operator", note: "Reviewed in owned lab" }

it.live("review, resolution, reopening and inconclusive retests preserve original evidence and history", () =>
  Effect.gen(function* () {
    const state = yield* fixture
    const original = yield* review(state, initial)
    const artifact = yield* Effect.promise(() => Evidence.get(state.name, original.evidence_refs[0]!))
    expect((yield* Effect.promise(() => fs.stat(artifact!.path))).mode & 0o777).toBe(0o600)
    expect((yield* Effect.promise(() => fs.stat(path.dirname(artifact!.path)))).mode & 0o777).toBe(0o700)
    yield* review(state, {
      action: "update",
      key: "owned",
      ...reviewer,
      owner: "platform-team",
      impact: `Exposure of ${secret}`,
      remediation: "Remove the public debug endpoint",
      reproduction_steps: ["Request the owned debug endpoint", "Check the returned configuration"],
    })
    const resolved = yield* review(state, {
      action: "retest",
      key: "owned",
      ...reviewer,
      outcome: "resolved",
      replay: "2026-10-07: retest command returns 404 after correction",
    })
    expect(resolved.status).toBe("resolved")
    expect(resolved.retests).toHaveLength(1)
    const report = yield* Effect.promise(() => EngagementReport.build(state))
    expect(report.summary.reportable_findings).toBe(0)
    expect(report.summary.resolved_findings).toBe(1)
    expect(report.summary.awaiting_verification).toBe(0)
    expect(report.sections.recommendations).toEqual([])
    expect(report.sections.findings?.resolved[0]?.history).toHaveLength(3)
    expect(report.evidence_manifest.map((entry) => entry.sha256)).toContain(original.evidence_refs[0]!)
    for (const format of ["markdown", "html", "json"] as const) {
      const output = EngagementReport.render(report, format)
      expect(output).toContain("platform-team")
      expect(output).toContain("Remove the public debug endpoint")
      expect(output).toContain("Check the returned configuration")
      expect(output).toContain("resolved")
      expect(output).not.toContain(secret)
    }
    const reopened = yield* review(state, {
      action: "retest",
      key: "owned",
      ...reviewer,
      outcome: "still_vulnerable",
      replay: "2026-10-08: regression command returns configuration again",
    })
    expect(reopened.status).toBe("verified")
    const active = yield* Effect.promise(() => EngagementReport.build(state))
    expect(active.summary.reportable_findings).toBe(1)
    expect(active.summary.resolved_findings).toBe(0)
    expect(active.sections.recommendations?.[0]?.action).toBe("Remove the public debug endpoint")
    yield* review(state, {
      action: "retest",
      key: "owned",
      ...reviewer,
      outcome: "inconclusive",
      replay: "2026-10-09: owned endpoint unavailable, no conclusion",
    })
    const pending = yield* Effect.promise(() => EngagementReport.build(state))
    expect(pending.summary.awaiting_verification).toBe(1)
    expect(pending.summary.reportable_findings).toBe(0)
    expect(pending.sections.recommendations).toEqual([])
    const ledger = yield* Effect.promise(() => FindingStore.load(state.name))
    expect(ledger).toHaveLength(5)
    expect(ledger[0]?.evidence_refs).toEqual(original.evidence_refs)
    expect(ledger.at(-1)?.retests?.map((retest) => retest.outcome)).toEqual([
      "resolved",
      "still_vulnerable",
      "inconclusive",
    ])
  }),
)

it.live("review rejects reused, old, missing, out-of-scope and unreviewed retest evidence", () =>
  Effect.gen(function* () {
    const state = yield* fixture
    const old = yield* Effect.promise(() =>
      Evidence.put({ engagementName: state.name, content: "older capture", label: "old" }),
    )
    const original = yield* review(state, initial)
    // Make chronology independent of timer granularity in this boundary test.
    const records = yield* Effect.promise(() => FindingStore.load(state.name))
    records[0]!.at = new Date(Date.parse(old.at) + 1000).toISOString()
    yield* Effect.promise(() => FindingStore.save(state.name, records))
    for (const input of [
      { evidence: original.evidence_refs },
      { evidence: [old.sha256] },
      { evidence: ["missing"] },
      { replay: "new proof", reviewer: " " },
      { replay: "new proof", note: " " },
      { replay: "new proof", target: "198.51.100.1" },
      { replay: " " },
    ]) {
      const result = yield* FindingReview.change(state, {
        action: "retest",
        key: "owned",
        ...reviewer,
        outcome: "resolved",
        replay_exemption_category: "operator_controlled_state",
        replay_exemption_rationale: "Owned lab",
        ...input,
        ...(input.replay !== undefined
          ? { replay_exemption_category: undefined, replay_exemption_rationale: undefined }
          : {}),
      })
      expect("error" in result).toBe(true)
    }
    expect(yield* Effect.promise(() => FindingStore.load(state.name))).toHaveLength(1)
    const removed = { ...state, scope: { targets: [], excludes: [] } }
    expect(
      "error" in
        (yield* FindingReview.change(removed, {
          action: "retest",
          key: "owned",
          ...reviewer,
          outcome: "resolved",
          replay: "new proof with new scope",
        })),
    ).toBe(true)
  }),
)

it.live("corrupted original proof prevents a resolved finding from passing the report audit", () =>
  Effect.gen(function* () {
    const state = yield* fixture
    const original = yield* review(state, initial)
    yield* review(state, {
      action: "retest",
      key: "owned",
      ...reviewer,
      outcome: "resolved",
      replay: "fresh correction result",
    })
    const stored = yield* Effect.promise(() => Evidence.get(state.name, original.evidence_refs[0]!))
    yield* Effect.promise(() => fs.writeFile(stored!.path, "tampered"))
    const report = yield* Effect.promise(() => EngagementReport.build(state))
    expect(report.summary.resolved_findings).toBe(0)
    expect(report.summary.awaiting_verification).toBe(1)
    expect(report.sections.findings?.verification_queue[0]?.reasons.join(" ")).toContain("integrity")
    const update = yield* FindingReview.change(state, {
      action: "update",
      key: "owned",
      ...reviewer,
      owner: "platform",
    })
    expect("record" in update && update.reportable).toBe(false)
    const invalid = yield* FindingReview.change(state, {
      action: "retest",
      key: "owned",
      ...reviewer,
      outcome: "resolved",
      replay: "another fresh correction result",
    })
    expect("error" in invalid).toBe(true)
  }),
)

it.live("a bare resolved status and mismatched latest retest cannot establish resolution", () =>
  Effect.gen(function* () {
    const state = yield* fixture
    const original = yield* review(state, initial)
    yield* Effect.promise(() => FindingStore.save(state.name, [{ ...original, status: "resolved" }]))
    expect((yield* Effect.promise(() => EngagementReport.build(state))).summary.resolved_findings).toBe(0)
    yield* Effect.promise(() => FindingStore.save(state.name, [original]))
    const resolved = yield* review(state, {
      action: "retest",
      key: "owned",
      ...reviewer,
      outcome: "resolved",
      replay: "new resolved proof",
    })
    yield* Effect.promise(() => FindingStore.save(state.name, [{ ...resolved, evidence_refs: original.evidence_refs }]))
    expect((yield* Effect.promise(() => EngagementReport.build(state))).summary.resolved_findings).toBe(0)
  }),
)

it.live("resolved and rejected findings require explicit lifecycle actions", () =>
  Effect.gen(function* () {
    const state = yield* fixture
    yield* review(state, initial)
    yield* review(state, {
      action: "retest",
      key: "owned",
      ...reviewer,
      outcome: "resolved",
      replay: "new correction result",
    })
    expect("error" in (yield* FindingReview.change(state, { ...initial, replay: "silent reopen" }))).toBe(true)
    yield* review(state, { action: "reject", key: "owned", ...reviewer })
    expect(
      "error" in
        (yield* FindingReview.change(state, {
          action: "retest",
          key: "owned",
          ...reviewer,
          outcome: "resolved",
          replay: "invalid rejected retest",
        })),
    ).toBe(true)
    expect("error" in (yield* FindingReview.change(state, { action: "update", key: "owned", owner: "team" }))).toBe(
      true,
    )
  }),
)

it.live("file locks release after failure and interruption and preserve another owner's lock", () =>
  Effect.gen(function* () {
    const state = yield* fixture
    const file = path.join(FindingStore.directory(state.name), "findings.lock")
    const failed = yield* FindingStore.withLock(state.name)(Effect.die(new Error("owned failure"))).pipe(Effect.exit)
    expect(failed._tag).toBe("Failure")
    expect(yield* Effect.promise(() => fs.exists(file))).toBe(false)
    const ready = yield* Deferred.make<void>()
    const fiber = yield* FindingStore.withLock(state.name)(
      Deferred.succeed(ready, undefined).pipe(Effect.andThen(Effect.never)),
    ).pipe(Effect.forkChild)
    yield* Deferred.await(ready)
    expect((yield* Effect.promise(() => fs.stat(file))).mode & 0o777).toBe(0o600)
    yield* Fiber.interrupt(fiber)
    expect(yield* Effect.promise(() => fs.exists(file))).toBe(false)
    const compromised = yield* FindingStore.withLock(state.name)(
      Effect.promise(() =>
        fs.writeFile(file, JSON.stringify({ token: "another-owner", pid: 1, created_at: new Date().toISOString() })),
      ),
    ).pipe(Effect.exit)
    expect(compromised._tag).toBe("Failure")
    expect(yield* Effect.promise(() => fs.readFile(file, "utf8"))).toContain("another-owner")
  }),
)

it.live("missing or empty lock metadata cannot masquerade as a successful commit", () =>
  Effect.gen(function* () {
    const state = yield* fixture
    const file = path.join(FindingStore.directory(state.name), "findings.lock")
    const missing = yield* FindingStore.withLock(state.name)(Effect.promise(() => fs.rm(file))).pipe(Effect.exit)
    expect(missing._tag).toBe("Failure")
    const empty = yield* FindingStore.withLock(state.name)(Effect.promise(() => fs.writeFile(file, ""))).pipe(
      Effect.exit,
    )
    expect(empty._tag).toBe("Failure")
    expect(yield* Effect.promise(() => fs.exists(file))).toBe(true)
  }),
)

it.live("legacy evidence labels and new review fields are redacted and escaped in exported retest history", () =>
  Effect.gen(function* () {
    const state = yield* fixture
    const original = yield* review(state, initial)
    const label = `capture-${secret}`
    yield* Effect.promise(() => Evidence.put({ engagementName: state.name, content: "legacy labeled proof", label }))
    const at = new Date().toISOString()
    yield* Effect.promise(() =>
      FindingStore.save(state.name, [
        original,
        {
          ...original,
          status: "resolved",
          evidence_refs: [label],
          owner: "<svg onload=alert(1)>",
          impact: `Impact ${secret}`,
          remediation: "<script>fixture</script>",
          reproduction_steps: ["<img src=x onerror=alert(1)>"],
          retests: [
            {
              outcome: "resolved",
              reviewer: secret,
              note: `Reviewed ${secret}`,
              evidence_refs: [label],
              replay: { present: true },
              at,
            },
          ],
          at,
        },
      ]),
    )
    const report = yield* Effect.promise(() => EngagementReport.build(state))
    expect(report.summary.resolved_findings).toBe(1)
    for (const format of ["markdown", "html", "json"] as const)
      expect(EngagementReport.render(report, format)).not.toContain(secret)
    const html = EngagementReport.renderHtml(report)
    expect(html).not.toContain("<svg")
    expect(html).not.toContain("<script>")
    expect(html).not.toContain("<img")
    expect(html).toContain("&lt;script&gt;fixture&lt;/script&gt;")
  }),
)

it.live("a second real process cannot write while another process owns the finding lock", () =>
  Effect.gen(function* () {
    const state = yield* fixture
    const module = path.resolve(import.meta.dir, "../src/cyber/finding-store.ts")
    const touched = path.join(FindingStore.directory(state.name), "should-not-exist")
    const code = `import {Effect} from "effect"; import {FindingStore} from ${JSON.stringify(module)}; import fs from "node:fs/promises"; await Effect.runPromise(FindingStore.withLock(${JSON.stringify(state.name)})(Effect.promise(()=>fs.writeFile(${JSON.stringify(touched)},"unsafe")))).catch(error=>{console.error(error.message);process.exitCode=2})`
    yield* FindingStore.withLock(state.name)(
      Effect.gen(function* () {
        const child = yield* Effect.acquireRelease(
          Effect.sync(() =>
            Bun.spawn([process.execPath, "--eval", code], { stdout: "pipe", stderr: "pipe", env: process.env }),
          ),
          (child) =>
            Effect.sync(() => {
              if (child.exitCode === null) child.kill()
            }),
        )
        const result = yield* Effect.promise(async () => ({
          code: await child.exited,
          stderr: await new Response(child.stderr).text(),
        }))
        expect(result.code).toBe(2)
        expect(result.stderr).toContain("Finding ledger is busy")
        expect(yield* Effect.promise(() => fs.exists(touched))).toBe(false)
      }),
    )
    yield* review(state, initial)
    expect(yield* Effect.promise(() => FindingStore.load(state.name))).toHaveLength(1)
  }),
)

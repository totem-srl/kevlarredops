import { expect } from "bun:test"
import { Effect, Layer } from "effect"
import fs from "node:fs/promises"
import path from "node:path"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { FindingStore } from "@pentestcode/core/cyber/finding-store"
import { EngagementSchema } from "@pentestcode/core/engagement/schema"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { EngagementReport } from "@pentestcode/core/engagement/report"
import { Agent } from "@/agent/agent"
import { FindingTool } from "@/tool/finding"
import { ReportGenTool } from "@/tool/report-gen"
import { Tool } from "@/tool/tool"
import { Truncate } from "@/tool/truncate"
import { MessageID, SessionID } from "@/session/schema"
import { testEffect } from "../lib/effect"

const it = testEffect(
  Layer.mergeAll(
    Layer.mock(Agent.Service, {
      get: (name) => Effect.succeed({ name, mode: "primary", permission: [], options: {} }),
    }),
    Layer.mock(Truncate.Service, { output: (content) => Effect.succeed({ content, truncated: false }) }),
  ),
)
const secret = "owned-lab-secret-XYZ"
const ctx: Tool.Context = {
  sessionID: SessionID.make("ses_reports"),
  messageID: MessageID.make("msg_reports"),
  agent: "pentest",
  abort: AbortSignal.any([]),
  messages: [],
  metadata: () => Effect.void,
  ask: () => Effect.void,
}

function state(): EngagementSchema.State {
  return {
    id: EngagementSchema.ID.make("reports"),
    name: `reports-${crypto.randomUUID()}`,
    created_at: "2026-10-07T00:00:00Z",
    updated_at: "2026-10-07T01:00:00Z",
    current_phase: "reporting",
    mode: "guided",
    scope: { targets: ["127.0.0.1"], excludes: [], notes: "Owned lab" },
    hosts: {
      "127.0.0.1": {
        ip: "127.0.0.1",
        services: [],
        vulns: [
          {
            id: "candidate",
            title: "Scanner claim",
            severity: "critical",
            status: "suspected",
            description: `Observed ${secret}`,
          },
          { id: "dismissed", title: "Rejected scanner claim", severity: "high", status: "false_positive" },
        ],
        access: [],
        notes: [],
      },
    },
    credentials: { lab: { id: "lab", username: "operator", value: secret, source: "Owned lab" } },
    flags: [],
    attack_path: [],
    task_tree: [],
    notes: [],
  }
}

const fixture = Effect.acquireRelease(Effect.sync(state), (value) =>
  Effect.promise(() => fs.rm(FindingStore.directory(value.name), { recursive: true, force: true })),
)

for (const format of ["markdown", "json"] as const) {
  it.live(`${format} exports redact known credentials and keep claims in the verification queue`, () =>
    Effect.gen(function* () {
      const input = yield* fixture
      const info = yield* ReportGenTool.pipe(
        Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
      )
      const tool = yield* info.init()
      const result = yield* tool.execute({ format }, ctx)
      expect(result.output).not.toContain(secret)
      expect(result.metadata.reportable).toBe(0)
      expect(result.output).toContain("Scanner claim")
      expect(result.output).not.toContain("remediate immediately")
    }),
  )
}

it.live("reports include a finding promoted through the real evidence ledger", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const layer = Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })
    const findingInfo = yield* FindingTool.pipe(Effect.provide(layer))
    const finding = yield* findingInfo.init()
    const promoted = yield* finding.execute(
      {
        action: "promote",
        key: "verified-lab",
        title: "Verified owned lab",
        target: "127.0.0.1",
        replay: "owned command\nowned output",
      },
      ctx,
    )
    expect(promoted.metadata.reportable).toBe(true)
    const reportInfo = yield* ReportGenTool.pipe(Effect.provide(layer))
    const report = yield* reportInfo.init()
    const result = yield* report.execute({ format: "json" }, ctx)
    expect(result.output).toContain("Verified owned lab")
    expect(result.metadata.reportable).toBe(1)
  }),
)

it.live("finding promotion resolves and canonicalizes real evidence references", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const entry = yield* Effect.promise(() =>
      Evidence.put({ engagementName: input.name, content: "owned evidence", label: "proof" }),
    )
    const info = yield* FindingTool.pipe(
      Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
    )
    const tool = yield* info.init()
    const result = yield* tool.execute(
      {
        action: "promote",
        key: "owned",
        target: "127.0.0.1",
        evidence: ["proof"],
        replay_exemption_category: "operator_controlled_state",
        replay_exemption_rationale: "Operator-owned fixture resets after capture.",
      },
      ctx,
    )
    expect(result.metadata.reportable).toBe(true)
    const records = yield* Effect.promise(() => FindingStore.load(input.name))
    expect(records[0]?.evidence_refs).toEqual([entry.sha256])
    const report = yield* Effect.promise(() => EngagementReport.build(input))
    expect(report.summary.reportable_findings).toBe(1)
    expect(report.sections.findings?.verified[0]?.replay.exemption?.rationale).toContain("fixture resets")
  }),
)

it.live("unknown evidence cannot be promoted into a reportable finding", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const info = yield* FindingTool.pipe(
      Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
    )
    const tool = yield* info.init()
    const result = yield* tool.execute(
      {
        action: "promote",
        key: "invented",
        target: "127.0.0.1",
        evidence: ["missing"],
        replay_exemption_category: "external_dependency",
        replay_exemption_rationale: "Fixture",
      },
      ctx,
    )
    expect(result.metadata.reportable).not.toBe(true)
    expect(yield* Effect.promise(() => FindingStore.load(input.name))).toEqual([])
  }),
)

it.live("corrupt finding ledgers fail visibly instead of generating an empty successful report", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const dir = FindingStore.directory(input.name)
    yield* Effect.promise(async () => {
      await fs.mkdir(dir, { recursive: true })
      await fs.writeFile(path.join(dir, "findings-lifecycle.json"), "{broken")
    })
    const info = yield* ReportGenTool.pipe(
      Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
    )
    const tool = yield* info.init()
    const result = yield* Effect.exit(tool.execute({}, ctx))
    expect(result._tag).toBe("Failure")
  }),
)

it.live("HTML escapes active content and uses an offline content policy", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const unsafe = {
      ...input,
      hosts: {
        "127.0.0.1": {
          ...input.hosts["127.0.0.1"]!,
          vulns: [
            {
              ...input.hosts["127.0.0.1"]!.vulns[0]!,
              title: '<script src="https://example.invalid/a">unsafe</script>',
              description: `<img src="https://example.invalid/tracker"> ${secret}`,
            },
          ],
        },
      },
    }
    const data = yield* Effect.promise(() => EngagementReport.build(unsafe))
    const output = EngagementReport.render(data, "html")
    expect(output).toContain("Content-Security-Policy")
    expect(output).toContain("default-src 'none'")
    expect(output).toContain("&lt;script")
    expect(output).not.toContain("<script")
    expect(output).not.toContain("<img")
    expect(output).not.toContain(secret)
  }),
)

it.live("section selection, deterministic snapshots and secret removal apply across formats", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const data = yield* Effect.promise(() => EngagementReport.build(input, ["scope"]))
    const again = yield* Effect.promise(() => EngagementReport.build(input, ["scope"]))
    expect(data).toEqual(again)
    expect(Object.keys(data.sections)).toEqual(["scope"])
    expect(data.evidence_manifest).toEqual([])
    for (const format of ["markdown", "json", "html"] as const) {
      const output = EngagementReport.render(data, format)
      expect(output).not.toContain(secret)
      expect(output).not.toContain("Scanner claim")
      expect(output).not.toContain("operator")
    }
  }),
)

it.live("altered evidence and newly excluded scope move findings into review", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const proof = yield* Effect.promise(() =>
      Evidence.put({ engagementName: input.name, content: "owned", label: "proof" }),
    )
    yield* Effect.promise(() =>
      FindingStore.save(input.name, [
        {
          id: "validated",
          title: "Owned proof",
          target: "127.0.0.1",
          status: "verified",
          evidence_refs: [proof.sha256],
          replay: { present: true },
          at: input.updated_at,
        },
      ]),
    )
    const good = yield* Effect.promise(() => EngagementReport.build(input))
    expect(good.summary.reportable_findings).toBe(1)
    const excluded = yield* Effect.promise(() =>
      EngagementReport.build({ ...input, scope: { ...input.scope, excludes: ["127.0.0.1"] } }),
    )
    expect(excluded.summary.reportable_findings).toBe(0)
    expect(
      excluded.sections.findings?.verification_queue.some((finding) =>
        finding.reasons.some((reason) => reason.includes("authorized scope")),
      ),
    ).toBe(true)
    const stored = yield* Effect.promise(() => Evidence.get(input.name, proof.sha256))
    yield* Effect.promise(() => fs.writeFile(stored!.path, "other"))
    const changed = yield* Effect.promise(() => EngagementReport.build(input))
    expect(changed.summary.reportable_findings).toBe(0)
    expect(
      changed.sections.findings?.verification_queue.some((finding) =>
        finding.reasons.some((reason) => reason.includes("integrity")),
      ),
    ).toBe(true)
    const info = yield* FindingTool.pipe(
      Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
    )
    const tool = yield* info.init()
    const listed = yield* tool.execute({ action: "list" }, ctx)
    expect(listed.metadata.reportable).toBe(0)
    expect(listed.output).toContain("integrity")
  }),
)

it.live("rejected, stale and superseded findings do not become remediation claims", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const proof = yield* Effect.promise(() => Evidence.put({ engagementName: input.name, content: "owned" }))
    yield* Effect.promise(() =>
      FindingStore.save(input.name, [
        ...(["rejected", "stale"] as const).map((status) => ({
          id: status,
          title: status,
          target: "127.0.0.1",
          status,
          evidence_refs: [proof.sha256],
          replay: { present: true } as const,
          at: input.updated_at,
        })),
        {
          id: "old",
          title: "old",
          target: "127.0.0.1",
          status: "verified",
          evidence_refs: [proof.sha256],
          replay: { present: true },
          superseded_by: "new",
          at: input.updated_at,
        },
        {
          id: "new",
          title: "new",
          target: "127.0.0.1",
          status: "candidate",
          evidence_refs: [],
          replay: { present: false },
          at: input.updated_at,
        },
      ]),
    )
    const data = yield* Effect.promise(() => EngagementReport.build(input))
    expect(data.summary.reportable_findings).toBe(0)
    expect(data.sections.findings?.excluded).toHaveLength(3)
    expect(data.sections.recommendations).toEqual([])
  }),
)

it.live("repeated promotion preserves replay and concurrent findings do not overwrite one another", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const info = yield* FindingTool.pipe(
      Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
    )
    const tool = yield* info.init()
    yield* Effect.all(
      Array.from({ length: 8 }, (_, index) =>
        tool.execute(
          { action: "promote", key: `finding-${index}`, target: "127.0.0.1", replay: `owned proof ${index}` },
          ctx,
        ),
      ),
      { concurrency: 8 },
    )
    expect(yield* Effect.promise(() => FindingStore.load(input.name))).toHaveLength(8)
    const repeated = yield* tool.execute({ action: "promote", key: "finding-0", summary: "Updated review detail" }, ctx)
    expect(repeated.metadata.reportable).toBe(true)
    const data = yield* Effect.promise(() => EngagementReport.build(input))
    expect(data.summary.reportable_findings).toBe(8)
  }),
)

it.live("missing targets, out-of-scope targets and empty replay cannot be promoted", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const info = yield* FindingTool.pipe(
      Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
    )
    const tool = yield* info.init()
    for (const params of [
      { key: "missing", replay: "owned" },
      { key: "outside", target: "198.51.100.1", replay: "owned" },
      { key: "empty", target: "127.0.0.1", replay: "  " },
    ]) {
      const result = yield* tool.execute({ action: "promote", ...params }, ctx)
      expect(result.metadata.reportable).not.toBe(true)
    }
    expect(yield* Effect.promise(() => FindingStore.load(input.name))).toEqual([])
  }),
)

it.live("file export requests permission, preserves denied destinations and writes private receipts", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const info = yield* ReportGenTool.pipe(
      Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
    )
    const tool = yield* info.init()
    const file = path.join(FindingStore.directory(input.name), "report.html")
    yield* Effect.promise(async () => {
      await fs.mkdir(path.dirname(file), { recursive: true })
      await fs.writeFile(file, "existing")
    })
    const denied = yield* Effect.exit(
      tool.execute(
        { format: "html", output_path: file },
        { ...ctx, ask: () => Effect.die(new Error("Denied by fixture")) },
      ),
    )
    expect(denied._tag).toBe("Failure")
    expect(yield* Effect.promise(() => fs.readFile(file, "utf8"))).toBe("existing")
    let permission = ""
    const result = yield* tool.execute(
      { format: "html", output_path: file },
      {
        ...ctx,
        ask: (request) =>
          Effect.sync(() => {
            permission = request.patterns[0]!
          }),
      },
    )
    expect(permission).toBe(file)
    expect(result.metadata.sha256).toHaveLength(64)
    expect((yield* Effect.promise(() => fs.stat(file))).mode & 0o777).toBe(0o600)
    expect(yield* Effect.promise(() => fs.readFile(file, "utf8"))).toContain("<!doctype html>")
  }),
)

function cli(args: string[]) {
  return Effect.acquireRelease(
    Effect.sync(() =>
      Bun.spawn([process.execPath, "src/index.ts", ...args], {
        stdout: "pipe",
        stderr: "pipe",
        env: {
          ...process.env,
          OPENCODE_AUTH_CONTENT: JSON.stringify({ lab: { type: "api", key: secret } }),
          OPENCODE_DISABLE_MODELS_FETCH: "true",
        },
      }),
    ),
    (child) =>
      Effect.sync(() => {
        if (child.exitCode === null) child.kill()
      }),
  ).pipe(
    Effect.flatMap((child) =>
      Effect.promise(async () => {
        const [stdout, stderr, code] = await Promise.all([
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
          child.exited,
        ])
        return { stdout, stderr, code }
      }),
    ),
  )
}

it.live("real CLI exports without a model and returns a distinct pending-review exit code", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const dir = FindingStore.directory(input.name)
    yield* Effect.promise(async () => {
      await fs.mkdir(dir, { recursive: true })
      await fs.writeFile(path.join(dir, "state.json"), JSON.stringify(input))
    })
    const result = yield* cli(["report", input.name, "--format", "json", "--fail-on-pending"])
    expect(result.code).toBe(2)
    expect(result.stdout).toContain('"format_version": 1')
    expect(result.stdout).not.toContain(secret)
    expect(result.stderr).toContain("await verification")
  }),
)

it.live("real CLI writes a private HTML report with a digest receipt", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const dir = FindingStore.directory(input.name)
    yield* Effect.promise(async () => {
      await fs.mkdir(dir, { recursive: true })
      await fs.writeFile(path.join(dir, "state.json"), JSON.stringify(input))
    })
    const file = path.join(dir, "report.html")
    const saved = yield* cli(["report", input.name, "--format", "html", "--output", file])
    expect(saved.code).toBe(0)
    expect(saved.stdout).toContain("SHA-256:")
    expect(yield* Effect.promise(() => fs.readFile(file, "utf8"))).toContain("Assessment overview")
  }),
)

it.live("malformed CLI report input fails without exposing sensitive state", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const dir = FindingStore.directory(input.name)
    yield* Effect.promise(() => fs.mkdir(dir, { recursive: true }))
    yield* Effect.promise(() =>
      fs.writeFile(path.join(dir, "state.json"), JSON.stringify({ ...input, current_phase: secret })),
    )
    const malformed = yield* cli(["report", input.name])
    expect(malformed.code).not.toBe(0)
    expect(malformed.stdout + malformed.stderr).not.toContain(secret)
    expect(malformed.stdout + malformed.stderr).toContain("Saved engagement is malformed")
  }),
)

it.live("doctor checks saved evidence locally, hides credentials and reports untested boundaries", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const dir = FindingStore.directory(input.name)
    yield* Effect.promise(async () => {
      await fs.mkdir(dir, { recursive: true })
      await fs.writeFile(path.join(dir, "state.json"), JSON.stringify(input))
    })
    const healthy = yield* cli(["doctor", "--engagement", input.name, "--json", "--strict"])
    expect(healthy.code).toBe(0)
    expect(healthy.stdout).not.toContain(secret)
    expect(healthy.stdout).toContain('"local_checks_only": true')
    expect(healthy.stdout).toContain('"not_run"')
  }),
)

it.live("doctor fails strict local checks when saved evidence has changed", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const dir = FindingStore.directory(input.name)
    yield* Effect.promise(async () => {
      await fs.mkdir(dir, { recursive: true })
      await fs.writeFile(path.join(dir, "state.json"), JSON.stringify(input))
    })
    const proof = yield* Effect.promise(() => Evidence.put({ engagementName: input.name, content: "owned" }))
    const stored = yield* Effect.promise(() => Evidence.get(input.name, proof.sha256))
    yield* Effect.promise(() => fs.writeFile(stored!.path, "other"))
    const invalid = yield* cli(["doctor", "--engagement", input.name, "--json", "--strict"])
    expect(invalid.code).toBe(2)
    expect(invalid.stdout).toContain("fails integrity checks")
  }),
)

it.live("the agent finding tool records remediation, retests and redacted revision history", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const info = yield* FindingTool.pipe(
      Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
    )
    const tool = yield* info.init()
    yield* tool.execute(
      {
        action: "promote",
        key: "reviewed",
        title: "Owned finding",
        target: "127.0.0.1",
        replay: "original proof",
        impact: `Impact ${secret}`,
      },
      ctx,
    )
    const updated = yield* tool.execute(
      {
        action: "update",
        key: "reviewed",
        owner: "platform",
        remediation: "Disable debug exposure",
        reviewer: "operator",
        note: "Assigned remediation",
      },
      ctx,
    )
    expect(updated.metadata.reportable).toBe(true)
    expect(updated.output).not.toContain(secret)
    const resolved = yield* tool.execute(
      {
        action: "retest",
        key: "reviewed",
        outcome: "resolved",
        reviewer: "operator",
        note: "Corrected owned endpoint",
        replay: "new proof: endpoint returns 404",
      },
      ctx,
    )
    expect(resolved.metadata.status).toBe("resolved")
    expect(resolved.metadata.reportable).toBe(false)
    const list = yield* tool.execute({ action: "list" }, ctx)
    expect(list.metadata.resolved).toBe(1)
    expect(list.output).toContain("Disable debug exposure")
    const reportInfo = yield* ReportGenTool.pipe(
      Effect.provide(Layer.mock(EngagementStore.Service, { get: () => Effect.succeed(input) })),
    )
    const reportTool = yield* reportInfo.init()
    const report = yield* reportTool.execute({ format: "json" }, ctx)
    expect(report.metadata.resolved).toBe(1)
    expect(report.metadata.reportable).toBe(0)
    const history = yield* tool.execute({ action: "status", key: "reviewed" }, ctx)
    expect(history.metadata.revisions).toBe(3)
    expect(history.output).not.toContain(secret)
    expect(history.output).toContain("Assigned remediation")
  }),
)

it.live("real CLI promotes, assigns, resolves and exports history without a model", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const dir = FindingStore.directory(input.name)
    const proof = path.join(dir, "proof.txt")
    yield* Effect.promise(async () => {
      await fs.mkdir(dir, { recursive: true })
      await fs.writeFile(path.join(dir, "state.json"), JSON.stringify(input))
      await fs.writeFile(proof, "2026-10-07 original owned command and result")
    })
    const common = ["findings", input.name, "--id", "cli-owned", "--reviewer", "operator", "--note", "Owned lab review"]
    const promoted = yield* cli([
      ...common,
      "--action",
      "promote",
      "--target",
      "127.0.0.1",
      "--proof",
      proof,
      "--severity",
      "high",
    ])
    expect(promoted.code).toBe(0)
    expect(promoted.stdout).toContain('"reportable": true')
    const original = (yield* Effect.promise(() => FindingStore.load(input.name)))[0]!
    const assigned = yield* cli([
      ...common,
      "--action",
      "update",
      "--owner",
      "platform-team",
      "--impact",
      `Exposure ${secret}`,
      "--remediation",
      "Remove debug route",
      "--reproduction",
      "Request owned endpoint",
      "Check response",
    ])
    expect(assigned.code).toBe(0)
    yield* Effect.promise(() => fs.writeFile(proof, "2026-10-08 retest owned command returns 404 after correction"))
    const resolved = yield* cli([...common, "--action", "retest", "--outcome", "resolved", "--proof", proof])
    expect(resolved.code).toBe(0)
    expect(resolved.stdout).toContain('"status": "resolved"')
    const report = yield* cli(["findings", input.name, "--json"])
    expect(report.code).toBe(0)
    expect(report.stdout).toContain('"resolved_findings": 1')
    expect(report.stdout).toContain("Remove debug route")
    expect(report.stdout).not.toContain(secret)
    const history = yield* cli(["findings", input.name, "--action", "history", "--id", "cli-owned"])
    expect(history.code).toBe(0)
    expect(history.stdout).toContain(original.evidence_refs[0]!)
    expect(history.stdout).toContain('"status": "verified"')
    expect(history.stdout).toContain('"status": "resolved"')
    expect(history.stdout).not.toContain(secret)
  }),
)

it.live("real CLI refuses a mutation without a review and leaves the ledger unchanged", () =>
  Effect.gen(function* () {
    const input = yield* fixture
    const dir = FindingStore.directory(input.name)
    yield* Effect.promise(async () => {
      await fs.mkdir(dir, { recursive: true })
      await fs.writeFile(path.join(dir, "state.json"), JSON.stringify(input))
    })
    const invalid = yield* cli([
      "findings",
      input.name,
      "--action",
      "promote",
      "--id",
      "invalid",
      "--target",
      "127.0.0.1",
    ])
    expect(invalid.code).not.toBe(0)
    expect(invalid.stderr).toContain("Provide --reviewer and --note")
    expect(yield* Effect.promise(() => FindingStore.load(input.name))).toEqual([])
  }),
)

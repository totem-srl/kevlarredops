import { cmd } from "./cmd"

export const FindingsCommand = cmd({
  command: "findings <engagement>",
  describe: "review findings, assign remediation and record evidence-backed retests without a model call",
  builder: (yargs) =>
    yargs
      .positional("engagement", { type: "string", demandOption: true })
      .option("action", {
        type: "string",
        choices: ["list", "history", "promote", "update", "reject", "retest"] as const,
        default: "list" as const,
      })
      .option("id", { type: "string", describe: "Stable finding ID" })
      .option("title", { type: "string" })
      .option("summary", { type: "string" })
      .option("target", { type: "string", describe: "Authorized affected target for a new finding" })
      .option("severity", { type: "string", choices: ["info", "low", "medium", "high", "critical"] as const })
      .option("owner", { type: "string", describe: "Person or team responsible for remediation" })
      .option("reviewer", { type: "string", describe: "Operator-provided label; required for mutations" })
      .option("note", { type: "string", describe: "Review rationale; required for mutations" })
      .option("impact", { type: "string" })
      .option("remediation", { type: "string" })
      .option("reproduction", { type: "array", string: true, describe: "Ordered reproduction steps" })
      .option("evidence", { type: "array", string: true, describe: "Stored evidence SHA-256 or unambiguous labels" })
      .option("proof", {
        type: "string",
        describe: "UTF-8 file containing recorded command and result; include retest timestamp",
      })
      .option("replay-exemption-category", {
        type: "string",
        choices: [
          "destructive_target",
          "operator_controlled_state",
          "external_dependency",
          "time_bound_access",
          "legacy_unspecified",
        ] as const,
      })
      .option("replay-exemption-rationale", {
        type: "string",
        describe: "Reason replay is impossible; requires exemption category",
      })
      .option("outcome", { type: "string", choices: ["resolved", "still_vulnerable", "inconclusive"] as const })
      .option("json", { type: "boolean", default: false, describe: "Print redacted structured findings" }),
  async handler(args) {
    const { readFile, stat } = await import("node:fs/promises")
    const { join } = await import("node:path")
    const { Effect, Schema } = await import("effect")
    const { EngagementSchema } = await import("@pentestcode/core/engagement/schema")
    const { EngagementReport } = await import("@pentestcode/core/engagement/report")
    const { FindingStore } = await import("@pentestcode/core/cyber/finding-store")
    const { FindingReview } = await import("@pentestcode/core/cyber/finding-review")
    const state = await readFile(join(FindingStore.directory(args.engagement), "state.json"), "utf8").then((source) => {
      try {
        return Schema.decodeUnknownSync(EngagementSchema.State)(JSON.parse(source))
      } catch {
        throw new Error("Saved engagement is malformed; sensitive state is not displayed")
      }
    })
    if (state.name !== args.engagement) throw new Error("Engagement file name does not match its stored identity")
    if (args.action === "list") {
      const report = await EngagementReport.build(state, ["findings"])
      console.log(args.json ? JSON.stringify(report, null, 2) : EngagementReport.renderMarkdown(report))
      return
    }
    if (!args.id?.trim()) throw new Error("Provide --id for this action")
    if (args.action === "history") {
      const history = (await FindingStore.load(state.name)).filter((record) => record.id === args.id)
      if (!history.length) throw new Error("No finding with this ID is recorded")
      console.log(JSON.stringify(EngagementReport.redact(state, { finding_id: args.id, revisions: history }), null, 2))
      return
    }
    if (!args.reviewer?.trim() || !args.note?.trim())
      throw new Error("Provide --reviewer and --note for every mutation; labels do not imply verified identity")
    if (args.proof && args.action !== "promote" && args.action !== "retest")
      throw new Error("Use --proof with promote or retest")
    const replay = args.proof
      ? await (async () => {
          if ((await stat(args.proof!)).size > 10 * 1024 * 1024) throw new Error("Proof exceeds 10 MiB")
          const content = await readFile(args.proof!, "utf8")
          if (Buffer.byteLength(content) > 10 * 1024 * 1024) throw new Error("Proof exceeds 10 MiB")
          return content
        })()
      : undefined
    const result = await Effect.runPromise(
      FindingReview.change(state, {
        action: args.action,
        key: args.id,
        title: args.title,
        summary: args.summary,
        target: args.target,
        severity: args.severity,
        owner: args.owner,
        reviewer: args.reviewer,
        note: args.note,
        impact: args.impact,
        remediation: args.remediation,
        reproduction_steps: args.reproduction,
        evidence: args.evidence,
        replay,
        outcome: args.outcome,
        replay_exemption_category: args.replayExemptionCategory,
        replay_exemption_rationale: args.replayExemptionRationale,
      }),
    )
    if ("error" in result) throw new Error(result.error)
    console.log(
      JSON.stringify(
        EngagementReport.redact(state, {
          finding_id: result.record.id,
          status: result.record.status,
          reportable: result.reportable,
          evidence_refs: result.record.evidence_refs,
        }),
        null,
        2,
      ),
    )
  },
})

import { cmd } from "./cmd"

export const ReportCommand = cmd({
  command: "report <engagement>",
  describe: "export an evidence-backed engagement report without a model call",
  builder: (yargs) =>
    yargs
      .positional("engagement", { type: "string", demandOption: true, describe: "Saved engagement name" })
      .option("format", {
        type: "string",
        choices: ["markdown", "json", "html"] as const,
        default: "markdown" as const,
      })
      .option("section", {
        type: "array",
        string: true,
        choices: [
          "executive_summary",
          "objectives",
          "scope",
          "findings",
          "attack_path",
          "credentials",
          "recommendations",
        ] as const,
        describe: "Sections to include; default all",
      })
      .option("output", { type: "string", describe: "Write a private file instead of stdout" })
      .option("fail-on-pending", {
        type: "boolean",
        default: false,
        describe: "Exit 2 when observations still await verification; the report is still exported",
      }),
  async handler(args) {
    const { readFile } = await import("node:fs/promises")
    const { join } = await import("node:path")
    const { Schema } = await import("effect")
    const { EngagementSchema } = await import("@pentestcode/core/engagement/schema")
    const { EngagementReport } = await import("@pentestcode/core/engagement/report")
    const { FindingStore } = await import("@pentestcode/core/cyber/finding-store")
    const file = join(FindingStore.directory(args.engagement), "state.json")
    const state = await readFile(file, "utf8").then((source) => {
      try {
        return Schema.decodeUnknownSync(EngagementSchema.State)(JSON.parse(source))
      } catch {
        throw new Error("Saved engagement is malformed; sensitive state is not displayed")
      }
    })
    if (state.name !== args.engagement) throw new Error("Engagement file name does not match its stored identity")
    if (args.section && !args.section.length) throw new Error("Choose at least one report section")
    const data = await EngagementReport.build(state, args.section)
    const output = EngagementReport.render(data, args.format)
    if (args.output) {
      const receipt = await EngagementReport.write(args.output, output)
      console.log(`Report: ${receipt.path}\nSHA-256: ${receipt.sha256}`)
    } else console.log(output)
    if (args.failOnPending && data.summary.awaiting_verification > 0) {
      process.stderr.write(
        `${data.summary.awaiting_verification} finding(s) await verification. Operator review required.\n`,
      )
      process.exitCode = 2
    }
  },
})

import { Effect, Schema } from "effect"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import DESCRIPTION from "./cloud-posture.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  quick: Schema.optional(Schema.Boolean.annotate({ description: "Run a fast subset of checks (default true)" })),
  profile: Schema.optional(Schema.String.annotate({ description: "AWS profile to use" })),
  region: Schema.optional(Schema.String.annotate({ description: "AWS region to scan" })),
})

type ProwlerFinding = {
  Severity?: string
  Status?: string
  CheckTitle?: string
  Title?: string
  Service?: string
}

function collectJsonFiles(dir: string): Promise<string[]> {
  return fs.readdir(dir).then((names) => names.filter((n) => n.endsWith(".json")).map((n) => path.join(dir, n)))
}

async function loadFindings(dir: string): Promise<ProwlerFinding[]> {
  const files = await collectJsonFiles(dir)
  const out: ProwlerFinding[] = []
  for (const file of files) {
    try {
      const parsed = JSON.parse(await fs.readFile(file, "utf8")) as unknown
      if (Array.isArray(parsed)) out.push(...(parsed as ProwlerFinding[]))
    } catch {
      // skip unparseable output files
    }
  }
  return out
}

export const CloudPostureTool = Tool.define(
  "cloud_posture",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          if (!Bun.which("prowler")) {
            return {
              title: "cloud_posture · unavailable",
              metadata: { available: false },
              output:
                'Required adapter "prowler" is not installed or not on PATH. Install prowler (pip install prowler-cloud) and configure AWS credentials.',
            }
          }

          yield* ctx.ask({
            permission: "cloud_posture",
            patterns: [params.profile ?? "default"],
            always: [],
            metadata: { region: params.region },
          })

          const outDir = path.join(os.tmpdir(), `pentestcode-prowler-${Date.now()}`)
          yield* Effect.promise(() => fs.mkdir(outDir, { recursive: true }))

          const argv = ["prowler", "aws", "--output-mode", "json", "--output-directory", outDir]
          if (params.quick !== false) argv.push("--quick")
          if (params.profile) argv.push("--profile", params.profile)
          if (params.region) argv.push("--region", params.region)

          const proc = Bun.spawnSync(argv, { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" })
          const stderr = proc.stderr.toString().trim()
          if (proc.exitCode !== 0) {
            return {
              title: "cloud_posture · adapter failed",
              metadata: { available: true, exit_code: proc.exitCode },
              output: `prowler exited ${proc.exitCode}: ${stderr.slice(0, 2000) || "(no stderr)"}`,
            }
          }

          const findings = yield* Effect.promise(() => loadFindings(outDir))
          const failures = findings.filter((f) => f.Status === "FAIL")
          const bySeverity = new Map<string, number>()
          const byService = new Map<string, number>()
          for (const failure of failures) {
            const sev = failure.Severity ?? "unknown"
            bySeverity.set(sev, (bySeverity.get(sev) ?? 0) + 1)
            const svc = failure.Service ?? "unknown"
            byService.set(svc, (byService.get(svc) ?? 0) + 1)
          }
          const top = failures.slice(0, 20).map((f) => ({
            severity: f.Severity ?? "unknown",
            service: f.Service,
            title: f.CheckTitle ?? f.Title ?? "(untitled)",
          }))

          const state = yield* store.get()
          let evidenceSha: string | undefined
          if (state) {
            evidenceSha = (
              yield* Effect.promise(() =>
                Evidence.put({
                  engagementName: state.name,
                  content: JSON.stringify({ command: argv.join(" "), total: findings.length, failures: top }, null, 2),
                  mime: "application/json",
                  label: `cloud posture ${params.profile ?? "default"}`,
                  source: "cloud_posture",
                }).catch(() => undefined),
              )
            )?.sha256
          }

          const lines = [
            `Prowler scan complete: ${findings.length} finding records, ${failures.length} FAIL.`,
            "",
            "By severity:",
            ...[...bySeverity.entries()].sort().map(([sev, count]) => `- ${sev}: ${count}`),
            "",
            "By service:",
            ...[...byService.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([svc, count]) => `- ${svc}: ${count}`),
            "",
            "Top failures:",
            ...(top.length > 0 ? top.map((f) => `- [${f.severity}] ${f.service ?? "?"} · ${f.title}`) : ["(none)"]),
          ]
          return {
            title: `cloud_posture · ${failures.length} failure(s)`,
            metadata: {
              available: true,
              adapter: "prowler",
              total_records: findings.length,
              failures: failures.length,
              by_severity: Object.fromEntries(bySeverity),
              evidence_sha: evidenceSha,
            },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

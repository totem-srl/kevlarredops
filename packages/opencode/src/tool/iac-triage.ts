import { Effect, Schema } from "effect"
import path from "node:path"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import DESCRIPTION from "./iac-triage.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Directory or file with IaC to scan" }),
  framework: Schema.optional(
    Schema.String.annotate({ description: "Restrict to one framework, e.g. terraform (default: all)" }),
  ),
})

type CheckovFailedCheck = {
  check_id?: string
  check_name?: string
  resource?: string
  severity?: string
}

type CheckovOutput = {
  summary?: { passed?: number; failed?: number; skipped?: number }
  results?: { failed_checks?: CheckovFailedCheck[] }
}

function summarize(output: CheckovOutput) {
  const summary = output.summary ?? {}
  const failed = output.results?.failed_checks ?? []
  const top = failed.slice(0, 20).map((check) => ({
    id: check.check_id ?? "?",
    name: check.check_name ?? "(untitled)",
    resource: check.resource ?? "?",
    severity: check.severity ?? "unknown",
  }))
  return {
    passed: summary.passed ?? 0,
    failed: summary.failed ?? failed.length,
    skipped: summary.skipped ?? 0,
    top,
  }
}

export const IacTriageTool = Tool.define(
  "iac_triage",
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
          if (!Bun.which("checkov")) {
            return {
              title: "iac_triage · unavailable",
              metadata: { available: false },
              output: 'Required adapter "checkov" is not installed or not on PATH. Install checkov (pip install checkov) and retry.',
            }
          }

          const abs = path.isAbsolute(params.target) ? params.target : path.join(process.cwd(), params.target)

          yield* ctx.ask({
            permission: "iac_triage",
            patterns: [abs],
            always: [],
            metadata: {},
          })

          const argv = ["checkov"]
          argv.push("-d", abs)
          if (params.framework) argv.push("--framework", params.framework)
          else argv.push("--framework", "all")
          argv.push("-o", "json", "--quiet")

          const proc = Bun.spawnSync(argv, { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" })
          const stdout = proc.stdout.toString().trim()
          // checkov exits 1 when failed checks exist — that is a successful scan
          if (proc.exitCode !== 0 && proc.exitCode !== 1) {
            return {
              title: "iac_triage · adapter failed",
              metadata: { available: true, exit_code: proc.exitCode },
              output: `checkov exited ${proc.exitCode}: ${proc.stderr.toString().slice(0, 2000) || "(no stderr)"}`,
            }
          }

          let summary: ReturnType<typeof summarize>
          try {
            const parsed = JSON.parse(stdout) as CheckovOutput | CheckovOutput[]
            const first = Array.isArray(parsed) ? (parsed[0] as CheckovOutput | undefined) : parsed
            if (!first) throw new Error("empty output")
            summary = summarize(first)
          } catch {
            return {
              title: "iac_triage · parse failed",
              metadata: {},
              output: `Could not parse checkov JSON. Raw output start:\n${stdout.slice(0, 2000)}`,
            }
          }

          const state = yield* store.get()
          let evidenceSha: string | undefined
          if (state) {
            evidenceSha = (
              yield* Effect.promise(() =>
                Evidence.put({
                  engagementName: state.name,
                  content: stdout.slice(0, 500_000),
                  mime: "application/json",
                  label: `iac triage ${params.target}`,
                  source: "iac_triage",
                }).catch(() => undefined),
              )
            )?.sha256
          }

          const lines = [
            `checkov scan of ${abs}`,
            `passed=${summary.passed} failed=${summary.failed} skipped=${summary.skipped}`,
            "",
            ...(summary.top.length > 0 ? ["Failed checks:"].concat(summary.top.map((c) => `- [${c.severity}] ${c.id} ${c.name} @ ${c.resource}`)) : []),
          ]
          return {
            title: `iac_triage · ${summary.failed} failed · ${path.basename(abs)}`,
            metadata: {
              available: true,
              adapter: "checkov",
              passed: summary.passed,
              failed: summary.failed,
              skipped: summary.skipped,
              evidence_sha: evidenceSha,
            },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

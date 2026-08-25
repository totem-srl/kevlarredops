import { Effect, Schema } from "effect"
import path from "node:path"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { Observation } from "@pentestcode/core/cyber/observation"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import DESCRIPTION from "./binary-triage.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  path: Schema.String.annotate({ description: "Path to the binary to triage" }),
})

type ChecksecOutput = {
  checks?: Record<string, string>
}

function summarize(raw: string): { checks: Record<string, string>; findings: [string, string][] } {
  const parsed = JSON.parse(raw) as unknown
  const container = (
    Array.isArray(parsed) ? ((parsed[0] ?? {}) as ChecksecOutput) : ((parsed ?? {}) as ChecksecOutput)
  )
  const checks = container.checks ?? {}
  const findings: [string, string][] = Object.entries(checks)
    .filter(([, value]) => /no\b|disabled|missing|partial/i.test(String(value)))
    .slice(0, 20)
    .map(([name, value]) => [name, String(value)])
  return { checks, findings }
}

export const BinaryTriageTool = Tool.define(
  "binary_triage",
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
          const abs = path.isAbsolute(params.path) ? params.path : path.join(process.cwd(), params.path)

          if (!Bun.which("checksec")) {
            return {
              title: "binary_triage · unavailable",
              metadata: { available: false },
              output: 'Required adapter "checksec" is not installed or not on PATH. Install checksec (e.g. `brew install checksec` / pip install checksec.py) and retry.',
            }
          }

          yield* ctx.ask({
            permission: "binary_triage",
            patterns: [abs],
            always: [],
            metadata: {},
          })

          const proc = Bun.spawnSync(["checksec", "--output=json", "file", abs], {
            cwd: process.cwd(),
            stdout: "pipe",
            stderr: "pipe",
          })
          const stdout = proc.stdout.toString().trim()
          const stderr = proc.stderr.toString().trim()
          if (proc.exitCode !== 0) {
            return {
              title: "binary_triage · adapter failed",
              metadata: { available: true, exit_code: proc.exitCode },
              output: `checksec exited ${proc.exitCode}: ${stderr || stdout || "(no output)"}`,
            }
          }

          let summary: ReturnType<typeof summarize>
          try {
            summary = summarize(stdout)
          } catch {
            return {
              title: "binary_triage · parse failed",
              metadata: { available: true, target_kind: "path", path: abs, command: `checksec --output=json file ${abs}` },
              output: `Could not parse checksec JSON. Raw output:\n${stdout.slice(0, 4000)}`,
            }
          }

          const state = yield* store.get()
          let evidenceSha: string | undefined
          if (state) {
            evidenceSha = (
              yield* Effect.promise(() =>
                Evidence.put({
                  engagementName: state.name,
                  content: stdout,
                  mime: "application/json",
                  label: `binary triage ${params.path}`,
                  source: "binary_triage",
                }).catch(() => undefined),
              )
            )?.sha256
            for (const [name, value] of summary.findings) {
              yield* Effect.promise(() =>
                Observation.add({
                  engagementName: state.name,
                  subtype: "control-gap",
                  title: `Binary hardening gap: ${name}`,
                  severity: "low",
                  note: `${params.path}: ${name}=${value}; evidence ${evidenceSha ?? "unrecorded"}`,
                  tags: ["binary-triage"],
                }).catch(() => undefined),
              )
            }
          }

          const lines = [`checksec report for ${abs}`, ""]
          lines.push("Checks:")
          for (const [name, value] of Object.entries(summary.checks)) lines.push(`- ${name}: ${value}`)
          if (summary.findings.length > 0) {
            lines.push("", "Gaps (candidate findings):")
            for (const [name, value] of summary.findings) lines.push(`- ${name}: ${value}`)
          }
          return {
            title: `binary_triage · ${path.basename(abs)} · ${summary.findings.length} gap(s)`,
            metadata: {
              available: true,
              adapter: "checksec",
              target_kind: "path",
              path: abs,
              command: `checksec --output=json file ${abs}`,
              exit_code: proc.exitCode,
              gaps: summary.findings.length,
              evidence_sha: evidenceSha,
            },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

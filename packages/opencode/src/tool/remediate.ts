import { Effect, Schema } from "effect"
import fs from "node:fs/promises"
import path from "node:path"
import { Observation } from "@pentestcode/core/cyber/observation"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import DESCRIPTION from "./remediate.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  observation_id: Schema.String.annotate({ description: "Observation id to remediate" }),
  mode: Schema.optional(
    Schema.Literals(["patch", "advice"]).annotate({ description: "patch scaffolds a diff; advice gives steps (default patch)" }),
  ),
})

const FIXTURE_DIRS = ["juice-shop", "webgoat", "dvwa", "bwapp"]
const CONTEXT_LINES = 30
const FILE_REF_RE = /([A-Za-z0-9_.\-/]+\.[A-Za-z0-9]+)(?::(\d+))?/

function extractFileRef(obs: { evidence: string[]; note?: string }): { file: string; line: number } | undefined {
  for (const ref of obs.evidence) {
    const m = ref.replace(/^file:/, "").match(FILE_REF_RE)
    if (m) return { file: m[1]!, line: m[2] ? Number(m[2]) : 1 }
  }
  if (obs.note) {
    const m = obs.note.match(FILE_REF_RE)
    if (m) return { file: m[1]!, line: m[2] ? Number(m[2]) : 1 }
  }
  return undefined
}

function isFixture(file: string): boolean {
  const lower = file.toLowerCase()
  return FIXTURE_DIRS.some((dir) => lower.includes(dir))
}

function scaffoldPatch(lines: string[], targetLine: number): string {
  const start = Math.max(1, targetLine - CONTEXT_LINES)
  const end = Math.min(lines.length, targetLine + CONTEXT_LINES)
  const context = lines.slice(start - 1, end).map((l) => ` ${l}`)
  const insertOffset = targetLine - start
  context.splice(insertOffset + 1, 0, "+TODO(pentestcode-remediate): replace this marker with the actual fix")
  return [`@@ -${start},${end - start + 1} @@`, ...context].join("\n")
}

function adviceReferences(subtype: string, tags: string[]): string[] {
  const refs: string[] = []
  if (subtype === "vuln") refs.push("OWASP Top 10: https://owasp.org/www-project-top-ten/")
  if (subtype === "vuln" || subtype === "risk") refs.push("CWE: https://cwe.mitre.org/")
  if (subtype === "control-gap") refs.push("NIST CSF: https://www.nist.gov/cyberframework")
  for (const tag of tags) {
    if (/^(owasp|cwe|nist|asvs)/i.test(tag)) refs.push(`tag ref: ${tag}`)
  }
  return [...new Set(refs)]
}

function adviceSteps(severity: string | undefined): string[] {
  return [
    "Reproduce the finding locally and confirm it still exists on a current build.",
    "Identify the root cause in code (input handling, auth check, config, or dependency version).",
    severity === "high" || severity === "critical"
      ? "Prioritize a fix in the next sprint; consider interim mitigation (WAF rule, feature flag, access restriction)."
      : "Schedule a fix alongside related hardening work.",
    "Write a regression test that fails before and passes after the fix.",
    "Fix the root cause; avoid blacklisting specific payloads.",
    "Re-run the original probe to verify the finding no longer reproduces, then update the finding status.",
  ]
}

export const RemediateTool = Tool.define(
  "remediate",
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
              title: "remediate",
              metadata: {},
              output: "No active engagement. Initialize one first.",
            }
          }

          const observations = yield* Effect.promise(() => Observation.list(state.name))
          const obs = observations.find((o) => o.id === params.observation_id)
          if (!obs) {
            return {
              title: "remediate · unknown observation",
              metadata: {},
              output: `No observation "${params.observation_id}" in engagement ${state.name}. Use the observation tool list action first.`,
            }
          }

          const mode = params.mode ?? "patch"

          if (mode === "advice") {
            const payload = {
              observation_id: obs.id,
              title: obs.title,
              severity: obs.severity ?? "info",
              steps: adviceSteps(obs.severity),
              references: adviceReferences(obs.subtype, obs.tags ?? []),
            }
            yield* Effect.promise(() =>
              Evidence.put({
                engagementName: state.name,
                content: JSON.stringify(payload, null, 2),
                mime: "application/json",
                label: `remediation advice ${obs.id}`,
                source: "remediate",
              }).catch(() => undefined),
            )
            return {
              title: `remediate · advice · ${obs.severity ?? "info"}`,
              metadata: { mode: "advice", observation_id: obs.id },
              output: JSON.stringify(payload, null, 2),
            }
          }

          const found = extractFileRef(obs)

          if (!found) {
            const payload = {
              observation_id: obs.id,
              refused_patch_reason: "no file reference found in observation evidence or note",
              fallback_steps: adviceSteps(obs.severity),
              references: adviceReferences(obs.subtype, obs.tags ?? []),
            }
            return {
              title: `remediate · advice · ${obs.severity ?? "info"}`,
              metadata: { mode: "advice", observation_id: obs.id, found_file: false },
              output: JSON.stringify(payload, null, 2),
            }
          }

          if (isFixture(found.file)) {
            const payload = {
              observation_id: obs.id,
              refused_patch_reason: `${found.file} looks like a deliberately vulnerable training fixture; patches are refused`,
              fallback_steps: adviceSteps(obs.severity),
              references: adviceReferences(obs.subtype, obs.tags ?? []),
            }
            return {
              title: `remediate · refused (fixture) · ${found.file}`,
              metadata: { mode: "advice", observation_id: obs.id, found_file: true, refused_fixture: true },
              output: JSON.stringify(payload, null, 2),
            }
          }

          const abs = path.isAbsolute(found.file) ? found.file : path.join(process.cwd(), found.file)
          let content: string
          try {
            content = yield* Effect.promise(() => fs.readFile(abs, "utf8"))
          } catch {
            const payload = {
              observation_id: obs.id,
              refused_patch_reason: `could not read referenced file: ${abs}`,
              fallback_steps: adviceSteps(obs.severity),
            }
            return {
              title: `remediate · unreadable · ${found.file}`,
              metadata: { mode: "advice", observation_id: obs.id, found_file: true },
              output: JSON.stringify(payload, null, 2),
            }
          }

          const lines = content.split("\n")
          const line = Math.min(Math.max(found.line, 1), lines.length)
          const patch = scaffoldPatch(lines, line)
          const payload = {
            observation_id: obs.id,
            file: abs,
            line,
            rationale:
              "scaffold patch — calling agent must replace the TODO(pentestcode-remediate) marker with the actual fix before applying",
            risk: obs.severity === "high" || obs.severity === "critical" ? "medium" : "low",
            tested: false,
            patch,
          }
          yield* Effect.promise(() =>
            Evidence.put({
              engagementName: state.name,
              content: JSON.stringify(payload, null, 2),
              mime: "application/json",
              label: `remediation patch ${obs.id}`,
              source: "remediate",
            }).catch(() => undefined),
          )
          return {
            title: `remediate · patch · ${path.basename(abs)}:${line}`,
            metadata: { mode: "patch", observation_id: obs.id, found_file: true },
            output: JSON.stringify(payload, null, 2),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

import { Effect, Schema } from "effect"
import {
  isConditional,
  isNormalizedStep,
  type Play,
  type PlayRequirement,
  type PlayStep,
} from "@pentestcode/core/cyber/play/play"
import {
  runPlay,
  formatPlayResult,
  PlayNotFoundError,
  PlayArgError,
  type PlayEnvironment,
} from "@pentestcode/core/cyber/play/runner"
import { listPlays, getPlay, playIds } from "@pentestcode/core/cyber/play/registry"
import DESCRIPTION from "./runbook.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.optional(Schema.Literals(["list", "status", "run"]).annotate({ description: "default list" })),
  id: Schema.optional(Schema.String.annotate({ description: "play id (required for status/run)" })),
  args_json: Schema.optional(Schema.String.annotate({ description: 'JSON object of play args for run, e.g. {"target":"https://x"}' })),
})

const KNOWN_BINARIES = [
  "nmap",
  "gobuster",
  "ffuf",
  "nikto",
  "sqlmap",
  "nuclei",
  "curl",
  "httpx",
  "amass",
  "subfinder",
  "checksec",
]

function probeEnvironment(): PlayEnvironment {
  const binaries = new Set<string>(KNOWN_BINARIES.filter((name) => Bun.which(name) !== null))
  return {
    binaries,
    runtimes: { browser: Boolean(Bun.which("chromium") || Bun.which("google-chrome") || Bun.which("chromium-browser")) },
  }
}

function collectRequirements(steps: PlayStep[]): PlayRequirement[] {
  const out = new Map<string, PlayRequirement>()
  const visit = (step: PlayStep) => {
    if (isConditional(step)) return visit(step.then)
    if (!isNormalizedStep(step)) return
    for (const req of step.requires ?? []) {
      out.set(`${req.kind}:${req.id}:${req.missingAs}`, req)
    }
  }
  for (const step of steps) visit(step)
  return [...out.values()]
}

function missingRequirements(play: Play, environment: PlayEnvironment): PlayRequirement[] {
  return collectRequirements(play.steps).filter((req) =>
    req.kind === "binary" ? !environment.binaries.has(req.id) : environment.runtimes[req.id] !== true,
  )
}

function summarizePlay(play: Play, environment: PlayEnvironment) {
  const missing = missingRequirements(play, environment)
  const requiredMissing = missing.filter((req) => req.missingAs === "required")
  const status = requiredMissing.length > 0 ? "unavailable" : missing.length > 0 ? "degraded" : "ready"
  return {
    id: play.id,
    name: play.name,
    status,
    required_args: play.args.filter((a) => a.required).map((a) => a.name),
    missing_required: requiredMissing.map((req) => `${req.kind}:${req.id}`),
    missing_optional: missing.filter((req) => req.missingAs === "optional").map((req) => `${req.kind}:${req.id}`),
  }
}

export const RunbookTool = Tool.define(
  "runbook",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const action = params.action ?? "list"
          const environment = probeEnvironment()

          if (action === "list") {
            const summaries = listPlays().map((play) => summarizePlay(play, environment))
            const lines = [
              `Runbook readiness (${summaries.filter((s) => s.status === "ready").length}/${summaries.length} ready):`,
              "",
              ...summaries.map(
                (s) =>
                  `- ${s.id} · ${s.status} · args=${s.required_args.join(",") || "-"}${
                    s.missing_required.length > 0 ? ` · missing ${s.missing_required.join(",")}` : ""
                  }${s.missing_optional.length > 0 ? ` · optional-missing ${s.missing_optional.join(",")}` : ""}`,
              ),
            ]
            return {
              title: `runbook · list`,
              metadata: {
                ready: summaries.filter((s) => s.status === "ready").length,
                total: summaries.length,
              },
              output: lines.join("\n"),
            }
          }

          if (!params.id) {
            return { title: `runbook · ${action}`, metadata: {}, output: `Provide id for action = ${action}.` }
          }
          const play = getPlay(params.id)
          if (!play) {
            return {
              title: `runbook · ${params.id}`,
              metadata: { found: false },
              output: `Unknown play "${params.id}". Known: ${playIds().join(", ")}`,
            }
          }

          if (action === "status") {
            const summary = summarizePlay(play, environment)
            return {
              title: `runbook · status · ${play.id}`,
              metadata: { id: play.id, status: summary.status },
              output: JSON.stringify(summary, null, 2),
            }
          }

          yield* ctx.ask({
            permission: "runbook",
            patterns: [play.id],
            always: [],
            metadata: {},
          })

          let args: Record<string, unknown> = {}
          if (params.args_json) {
            try {
              args = JSON.parse(params.args_json) as Record<string, unknown>
            } catch {
              return {
                title: `runbook · ${play.id}`,
                metadata: { play: play.id },
                output: "args_json is not valid JSON.",
              }
            }
          }

          try {
            const result = runPlay({ id: play.id, args, environment })
            const summary = summarizePlay(play, environment)
            return {
              title: `runbook · ${result.play.id}`,
              metadata: {
                play: result.play.id,
                steps: result.trace.length,
                skipped: result.skipped.length,
                readiness: summary.status,
              },
              output: formatPlayResult(result),
            }
          } catch (error) {
            if (error instanceof PlayArgError || error instanceof PlayNotFoundError) {
              return {
                title: `runbook · ${play.id}`,
                metadata: { play: play.id },
                output: error.message,
              }
            }
            throw error
          }
        }).pipe(Effect.orDie),
    }
  }),
)

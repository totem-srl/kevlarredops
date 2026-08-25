import { Effect, Schema } from "effect"
import {
  runPlay,
  formatPlayResult,
  PlayNotFoundError,
  PlayArgError,
  type RunResult,
  type PlayEnvironment,
} from "@pentestcode/core/cyber/play/runner"
import { listPlays, getPlay, playIds } from "@pentestcode/core/cyber/play/registry"
import DESCRIPTION from "./play.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  id: Schema.optional(Schema.String.annotate({ description: "play id when action = run" })),
  action: Schema.optional(Schema.Literals(["list", "run"]).annotate({ description: "default run when id given" })),
  args_json: Schema.optional(Schema.String.annotate({ description: 'JSON object of play args, e.g. {"target":"https://x"}' })),
})

function probeEnvironment(): PlayEnvironment {
  const binaries = new Set<string>(
    ["nmap", "gobuster", "ffuf", "nikto", "sqlmap", "nuclei", "curl", "httpx", "amass", "subfinder"].filter(
      (name) => Bun.which(name) !== null,
    ),
  )
  return {
    binaries,
    runtimes: { browser: Boolean(Bun.which("chromium") || Bun.which("google-chrome") || Bun.which("chromium-browser")) },
  }
}

function availabilityOf(result: RunResult): { available: boolean; degraded: boolean } {
  const requiredSkipped = result.skipped.some((entry) => entry.reason.startsWith("missing required"))
  if (requiredSkipped && result.trace.length > 0) return { available: true, degraded: true }
  if (requiredSkipped) return { available: false, degraded: false }
  return { available: true, degraded: false }
}

export const PlayTool = Tool.define(
  "play",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          id?: string
          action?: "list" | "run"
          args_json?: string
        },
        ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const action = params.action ?? (params.id ? "run" : "list")

          if (action === "list" || !params.id) {
            const plays = listPlays()
            return {
              title: `plays · ${plays.length}`,
              metadata: { count: plays.length },
              output: plays
                .map((play) => `- ${play.id} · ${play.name} · args=${play.args.map((a) => a.name).join(",") || "-"}`)
                .join("\n"),
            }
          }

          const play = getPlay(params.id)
          if (!play) {
            return {
              title: `play · ${params.id}`,
              metadata: { found: false },
              output: `Unknown play "${params.id}". Known: ${playIds().join(", ")}`,
            }
          }

          let args: Record<string, unknown> = {}
          if (params.args_json) {
            try {
              args = JSON.parse(params.args_json) as Record<string, unknown>
            } catch {
              return {
                title: `play · ${play.id}`,
                metadata: { play: play.id },
                output: "args_json is not valid JSON.",
              }
            }
          }

          yield* ctx.ask({
            permission: "play",
            patterns: [play.id],
            always: [],
            metadata: {},
          })

          const environment = probeEnvironment()
          try {
            const result = runPlay({ id: play.id, args, environment })
            const availability = availabilityOf(result)
            return {
              title: `play · ${result.play.id}`,
              metadata: {
                play: result.play.id,
                steps: result.trace.length,
                skipped: result.skipped.length,
                ...availability,
              },
              output: formatPlayResult(result),
            }
          } catch (error) {
            if (error instanceof PlayArgError || error instanceof PlayNotFoundError) {
              return {
                title: `play · ${play.id}`,
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

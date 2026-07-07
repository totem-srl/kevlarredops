import { Effect, Schema } from "effect"
import { EngagementStore } from "@opencode-ai/core/engagement/store"
import { EngagementSchema } from "@opencode-ai/core/engagement/schema"
import { PentestEvent } from "@opencode-ai/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import DESCRIPTION from "./phase-control.txt"
import * as Tool from "./tool"

const PHASE_ORDER: EngagementSchema.PentestPhase[] = [
  "recon",
  "enumeration",
  "vuln_assess",
  "exploitation",
  "post_exploit",
  "reporting",
]

export const Parameters = Schema.Struct({
  action: Schema.Literals(["status", "next", "set"]),
  phase: Schema.optional(
    Schema.Literals(["recon", "enumeration", "vuln_assess", "exploitation", "post_exploit", "reporting"]),
  ).annotate({
    description: "Target phase (required for 'set' action)",
  }),
})

function formatPhaseList(currentPhase: EngagementSchema.PentestPhase): string {
  const lines: string[] = ["Phases:"]
  let passedCurrent = false
  for (const phase of PHASE_ORDER) {
    if (phase === currentPhase) {
      lines.push(`  > ${phase}  (current)`)
      passedCurrent = true
    } else if (!passedCurrent) {
      lines.push(`  + ${phase}`)
    } else {
      lines.push(`    ${phase}`)
    }
  }
  return lines.join("\n")
}

function formatStatus(state: EngagementSchema.State): string {
  const stats = EngagementSchema.summary(state)
  const lines: string[] = [
    formatPhaseList(state.current_phase),
    "",
    `Mode: ${state.mode}`,
    `Hosts: ${stats.hosts_discovered} | Vulns: ${stats.vulnerabilities} | Creds: ${stats.credentials} | Flags: ${stats.flags}`,
  ]
  return lines.join("\n")
}

export const PhaseControlTool = Tool.define(
  "phase_control",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const events = yield* EventV2Bridge.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, _ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()

          if (!state) {
            return {
              title: "phase_control",
              metadata: {},
              output: "No engagement loaded.",
            }
          }

          if (params.action === "status") {
            return {
              title: `Phase: ${state.current_phase}`,
              metadata: { phase: state.current_phase, mode: state.mode },
              output: formatStatus(state),
            }
          }

          if (params.action === "next") {
            const currentIndex = PHASE_ORDER.indexOf(state.current_phase)
            if (currentIndex === PHASE_ORDER.length - 1) {
              return {
                title: `Phase: ${state.current_phase}`,
                metadata: { phase: state.current_phase, mode: state.mode },
                output: `Already at final phase (reporting).\n\n${formatStatus(state)}`,
              }
            }
            const nextPhase = PHASE_ORDER[currentIndex + 1]!
            yield* store.setPhase(nextPhase)
            const updated = yield* store.get()
            if (updated) yield* store.save(updated)
            yield* events.publish(PentestEvent.PhaseTransitioned, {
              timestamp: Date.now(),
              engagementID: state.id,
              from: state.current_phase,
              to: nextPhase,
            })
            return {
              title: `Phase: ${nextPhase}`,
              metadata: { phase: nextPhase, previous: state.current_phase, mode: state.mode },
              output: `Advanced from ${state.current_phase} to ${nextPhase}.\n\n${formatStatus(updated ?? { ...state, current_phase: nextPhase })}`,
            }
          }

          // action === "set"
          if (!params.phase) {
            return {
              title: "phase_control",
              metadata: {},
              output: `Error: 'phase' parameter is required for 'set' action. Valid phases: ${PHASE_ORDER.join(", ")}`,
            }
          }

          yield* store.setPhase(params.phase)
          const updated = yield* store.get()
          if (updated) yield* store.save(updated)
          if (state.current_phase !== params.phase) {
            yield* events.publish(PentestEvent.PhaseTransitioned, {
              timestamp: Date.now(),
              engagementID: state.id,
              from: state.current_phase,
              to: params.phase,
            })
          }
          return {
            title: `Phase: ${params.phase}`,
            metadata: { phase: params.phase, previous: state.current_phase, mode: state.mode },
            output: `Phase set to ${params.phase}${state.current_phase !== params.phase ? ` (was ${state.current_phase})` : ""}.\n\n${formatStatus(updated ?? { ...state, current_phase: params.phase })}`,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

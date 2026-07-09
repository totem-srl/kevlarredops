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

const PHASE_SKILLS: Record<string, string> = {
  recon: "recon-phase",
  enumeration: "enumeration-phase",
  vuln_assess: "vuln-assessment-phase",
  exploitation: "exploitation-phase",
  post_exploit: "post-exploit-phase",
  reporting: "reporting-phase",
}

export const Parameters = Schema.Struct({
  action: Schema.Literals(["status", "next", "set"]),
  phase: Schema.optional(
    Schema.Literals(["recon", "enumeration", "vuln_assess", "exploitation", "post_exploit", "reporting"]),
  ).annotate({
    description: "Target phase (required for 'set' action)",
  }),
  force: Schema.optional(Schema.Boolean).annotate({
    description: "Force phase transition even if quality gates are not met (default: false)",
  }),
})

interface QualityGateResult {
  passed: boolean
  warnings: string[]
  missing: string[]
}

function evaluateQualityGate(state: EngagementSchema.State, fromPhase: EngagementSchema.PentestPhase): QualityGateResult {
  const s = EngagementSchema.summary(state)
  const warnings: string[] = []
  const missing: string[] = []

  switch (fromPhase) {
    case "recon": {
      if (s.hosts_discovered === 0) missing.push("No hosts discovered — recon incomplete")
      if (state.scope.targets.length === 0) warnings.push("Scope has no targets defined")
      const noServices = Object.values(state.hosts).every((h) => h.services.length === 0)
      if (s.hosts_discovered > 0 && noServices) missing.push("Hosts found but no services enumerated — run port scans first")
      break
    }
    case "enumeration": {
      if (s.unchecked_services > 0) warnings.push(`${s.unchecked_services} service(s) without version info — may miss vulnerabilities`)
      const totalServices = Object.values(state.hosts).reduce((sum, h) => sum + h.services.length, 0)
      if (totalServices === 0) missing.push("No services found — enumeration incomplete")
      break
    }
    case "vuln_assess": {
      if (s.vulnerabilities === 0) warnings.push("No vulnerabilities found — consider deeper enumeration")
      const confirmedVulns = Object.values(state.hosts).some((h) => h.vulns.some((v) => v.status === "confirmed" || v.status === "exploited"))
      if (s.vulnerabilities > 0 && !confirmedVulns) warnings.push("All vulns are 'suspected' — validate before exploitation")
      const unvalidated = EngagementSchema.unvalidatedVulns(state)
      if (unvalidated.length > 0) warnings.push(`${unvalidated.length} unvalidated finding(s) — spawn critic before proceeding`)
      break
    }
    case "exploitation": {
      if (s.hosts_compromised === 0) warnings.push("No hosts compromised yet")
      const exploitedVulns = Object.values(state.hosts).flatMap((h) => h.vulns.filter((v) => v.status === "exploited"))
      if (exploitedVulns.length === 0 && s.vulnerabilities > 0) warnings.push("Vulnerabilities exist but none marked as exploited")
      break
    }
    case "post_exploit": {
      const credCount = Object.keys(state.credentials).length
      if (credCount === 0) warnings.push("No credentials harvested during post-exploitation")
      const hostsWithAccess = Object.values(state.hosts).filter((h) => h.access.length > 0)
      const totalHosts = Object.keys(state.hosts).length
      if (hostsWithAccess.length < totalHosts && totalHosts > 1) {
        warnings.push(`Only ${hostsWithAccess.length}/${totalHosts} hosts have access — consider lateral movement`)
      }
      if (state.objectives) {
        const incompleteObj = Object.values(state.objectives).filter((o) => o.status !== "completed" && o.status !== "abandoned")
        if (incompleteObj.length > 0) warnings.push(`${incompleteObj.length} objective(s) not completed`)
      }
      break
    }
    case "reporting":
      break
  }

  return {
    passed: missing.length === 0,
    warnings,
    missing,
  }
}

function formatGateResult(gate: QualityGateResult): string {
  const lines: string[] = []
  if (gate.missing.length > 0) {
    lines.push("BLOCKED — quality gate requirements not met:")
    for (const m of gate.missing) lines.push(`  ✗ ${m}`)
  }
  if (gate.warnings.length > 0) {
    lines.push(gate.missing.length > 0 ? "Additional warnings:" : "Warnings:")
    for (const w of gate.warnings) lines.push(`  ⚠ ${w}`)
  }
  if (!gate.passed) {
    lines.push("")
    lines.push("Use force:true to skip quality gates and advance anyway.")
  }
  return lines.join("\n")
}

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

            // Quality gate check
            if (!params.force) {
              const gate = evaluateQualityGate(state, state.current_phase)
              if (!gate.passed) {
                return {
                  title: `Phase gate: ${state.current_phase}`,
                  metadata: { phase: state.current_phase, gate_passed: false, missing: gate.missing.length, warnings: gate.warnings.length },
                  output: `Cannot advance from ${state.current_phase} to ${nextPhase}.\n\n${formatGateResult(gate)}\n\n${formatStatus(state)}`,
                }
              }
              if (gate.warnings.length > 0) {
                // Allow but warn
                const warnText = formatGateResult(gate)
                yield* store.setPhase(nextPhase)
                const updated = yield* store.get()
                if (updated) yield* store.save(updated)
                yield* events.publish(PentestEvent.PhaseTransitioned, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  from: state.current_phase,
                  to: nextPhase,
                })
                const skillHint = PHASE_SKILLS[nextPhase]
                  ? `\n\nLoad phase knowledge: use the skill tool with name="${PHASE_SKILLS[nextPhase]}" for ${nextPhase} methodology, checklists, and tools.`
                  : ""
                return {
                  title: `Phase: ${nextPhase}`,
                  metadata: { phase: nextPhase, previous: state.current_phase, mode: state.mode, gate_warnings: gate.warnings.length },
                  output: `Advanced from ${state.current_phase} to ${nextPhase} (with warnings).\n\n${warnText}\n\n${formatStatus(updated ?? { ...state, current_phase: nextPhase })}${skillHint}`,
                }
              }
            }

            yield* store.setPhase(nextPhase)
            const updated = yield* store.get()
            if (updated) yield* store.save(updated)
            yield* events.publish(PentestEvent.PhaseTransitioned, {
              timestamp: Date.now(),
              engagementID: state.id,
              from: state.current_phase,
              to: nextPhase,
            })
            const skillHint = PHASE_SKILLS[nextPhase]
              ? `\n\nLoad phase knowledge: use the skill tool with name="${PHASE_SKILLS[nextPhase]}" for ${nextPhase} methodology, checklists, and tools.`
              : ""
            return {
              title: `Phase: ${nextPhase}`,
              metadata: { phase: nextPhase, previous: state.current_phase, mode: state.mode },
              output: `Advanced from ${state.current_phase} to ${nextPhase}.\n\n${formatStatus(updated ?? { ...state, current_phase: nextPhase })}${skillHint}`,
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

          // Quality gate check for forward transitions
          const targetIndex = PHASE_ORDER.indexOf(params.phase)
          const currentIndex2 = PHASE_ORDER.indexOf(state.current_phase)
          if (!params.force && targetIndex > currentIndex2) {
            // Check gates for all phases being skipped
            for (let i = currentIndex2; i < targetIndex; i++) {
              const gate = evaluateQualityGate(state, PHASE_ORDER[i]!)
              if (!gate.passed) {
                return {
                  title: `Phase gate: ${PHASE_ORDER[i]!}`,
                  metadata: { phase: state.current_phase, gate_passed: false },
                  output: `Cannot advance past ${PHASE_ORDER[i]!}.\n\n${formatGateResult(gate)}\n\n${formatStatus(state)}`,
                }
              }
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
          const setSkillHint = state.current_phase !== params.phase && PHASE_SKILLS[params.phase]
            ? `\n\nLoad phase knowledge: use the skill tool with name="${PHASE_SKILLS[params.phase]}" for ${params.phase} methodology, checklists, and tools.`
            : ""
          return {
            title: `Phase: ${params.phase}`,
            metadata: { phase: params.phase, previous: state.current_phase, mode: state.mode },
            output: `Phase set to ${params.phase}${state.current_phase !== params.phase ? ` (was ${state.current_phase})` : ""}.\n\n${formatStatus(updated ?? { ...state, current_phase: params.phase })}${setSkillHint}`,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

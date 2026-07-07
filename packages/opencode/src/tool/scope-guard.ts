import { Effect } from "effect"
import { EngagementStore } from "@opencode-ai/core/engagement/store"
import { ScopeMatcher } from "@opencode-ai/core/engagement/scope-matcher"
import { PentestEvent } from "@opencode-ai/schema/pentest-event"
import type { EventV2Bridge } from "@/event-v2-bridge"

export class ScopeViolationError {
  readonly _tag = "ScopeViolationError"
  constructor(
    readonly targets: string[],
    readonly reasons: string[],
  ) {}

  get message(): string {
    const lines = ["SCOPE VIOLATION — command blocked."]
    for (let i = 0; i < this.targets.length; i++) {
      lines.push(`  Target: ${this.targets[i]} — ${this.reasons[i]}`)
    }
    lines.push("All targets must be within the engagement scope. Use scope_check to verify targets.")
    return lines.join("\n")
  }
}

export function checkCommandScope(
  command: string,
  store: EngagementStore.Interface,
  events?: EventV2Bridge.Service["Service"],
) {
  return Effect.gen(function* () {
    const state = yield* store.get()
    if (!state) return
    if (state.scope.targets.length === 0) return

    const targets = ScopeMatcher.extractTargetsFromCommand(command)
    if (targets.length === 0) return

    const violations: { target: string; reason: string }[] = []

    for (const target of targets) {
      const result = ScopeMatcher.checkScope(target, state.scope)
      if (!result.inScope) {
        const reason =
          result.reason === "excluded"
            ? `explicitly excluded (${result.matchedRule})`
            : `not in scope — no matching rule`
        violations.push({ target, reason })
      }
    }

    if (violations.length > 0) {
      if (events) {
        yield* events.publish(PentestEvent.ScopeViolated, {
          timestamp: Date.now(),
          engagementID: state.id,
          targets: violations.map((v) => v.target),
          command,
        })
      }
      return yield* Effect.fail(
        new ScopeViolationError(
          violations.map((v) => v.target),
          violations.map((v) => v.reason),
        ),
      )
    }
  })
}

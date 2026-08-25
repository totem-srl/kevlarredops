import { Effect, Schema } from "effect"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { getPlay } from "@pentestcode/core/cyber/play/registry"
import DESCRIPTION from "./pwn-bootstrap.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Target to bootstrap: a URL (https://...), an IPv4/CIDR, or a domain name" }),
})

const URL_RE = /^https?:\/\//i
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i

type TargetKind = "url" | "ip" | "domain"

function classify(target: string): TargetKind {
  if (URL_RE.test(target)) return "url"
  if (IP_RE.test(target)) return "ip"
  if (DOMAIN_RE.test(target)) return "domain"
  return "url"
}

const PLAN: Record<TargetKind, { playId: string }> = {
  url: { playId: "web-surface" },
  ip: { playId: "network-surface" },
  domain: { playId: "osint-target" },
}

function slugify(target: string): string {
  const base = target
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48)
  return base || "operation"
}

export const PwnBootstrapTool = Tool.define(
  "pwn_bootstrap",
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
          const trimmed = params.target.trim()
          const kind = classify(trimmed)
          const plan = PLAN[kind]
          const play = getPlay(plan.playId)
          if (!play) {
            return {
              title: "pwn_bootstrap",
              metadata: {},
              output: `Internal error: play "${plan.playId}" not found in registry.`,
            }
          }

          let name = slugify(trimmed)
          const existing = yield* store.load(name)
          if (existing) name = `${name}-${Date.now()}`

          yield* store.create(name)
          yield* store.updateScope({ targets: [trimmed] })
          yield* store.setPhase("recon")

          return {
            title: `pwn_bootstrap · ${name}`,
            metadata: {
              engagement: name,
              kind,
              play_id: plan.playId,
            },
            output: [
              `Engagement "${name}" bootstrapped for ${kind} target ${trimmed}.`,
              `Scope set to [${trimmed}]; phase = recon.`,
              "",
              `Recommended starting play: ${plan.playId}`,
              `Run it via the play tool (action run, id ${plan.playId}) or the runbook tool for readiness checks.`,
            ].join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

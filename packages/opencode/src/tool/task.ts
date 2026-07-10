import * as Tool from "./tool"
import DESCRIPTION from "./task.txt"
import { ToolJsonSchema } from "./json-schema"
import { SessionV1 } from "@pentestcode/core/v1/session"
import { BackgroundJob } from "@/background/job"
import { Session } from "@/session/session"
import { SessionID, MessageID } from "../session/schema"
import { MessageV2 } from "../session/message-v2"
import { Agent } from "../agent/agent"
import { deriveSubagentSessionPermission } from "../agent/subagent-permissions"
import type { SessionPrompt } from "../session/prompt"
import { Config } from "@/config/config"
import { Effect, Exit, Schema, Scope } from "effect"
import { EffectBridge } from "@/effect/bridge"
import { RuntimeFlags } from "@/effect/runtime-flags"
import { Database } from "@pentestcode/core/database/database"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { EngagementSchema } from "@pentestcode/core/engagement/schema"

export interface TaskPromptOps {
  cancel(sessionID: SessionID): Effect.Effect<void>
  resolvePromptParts(template: string): Effect.Effect<SessionPrompt.PromptInput["parts"]>
  prompt(input: SessionPrompt.PromptInput): Effect.Effect<SessionV1.WithParts>
}

const id = "task"
const BACKGROUND_DESCRIPTION = [
  "Background mode: background=true launches the subagent asynchronously and returns immediately.",
  "Foreground is the default; use it when you need the result before continuing.",
  "Use background only for independent work that can run while you continue elsewhere.",
  "You will be notified automatically when it finishes.",
].join(" ")
const BACKGROUND_STARTED = [
  "The task is working in the background. You will be notified automatically when it finishes.",
  "DO NOT sleep, poll for progress, ask the task for status, or duplicate this task's work — avoid working with the same files or topics it is using.",
  "Work on non-overlapping tasks, or briefly tell the user what you launched and end your response.",
].join("\n")
const BACKGROUND_UPDATED = [
  "Additional context sent to the running background task.",
  "The task is still working in the background. You will be notified automatically when it finishes.",
  "DO NOT sleep, poll for progress, ask the task for status, or duplicate this task's work — avoid working with the same files or topics it is using.",
  "Work on non-overlapping tasks, or briefly tell the user what you sent and end your response.",
].join("\n")

const BaseParameterFields = {
  description: Schema.String.annotate({ description: "A short (3-5 words) description of the task" }),
  prompt: Schema.String.annotate({ description: "The task for the agent to perform" }),
  subagent_type: Schema.String.annotate({ description: "The type of specialized agent to use for this task" }),
  task_id: Schema.optional(Schema.String).annotate({
    description:
      "This should only be set if you mean to resume a previous task (you can pass a prior task_id and the task will continue the same subagent session as before instead of creating a fresh one)",
  }),
  command: Schema.optional(Schema.String).annotate({ description: "The command that triggered this task" }),
}

const BaseParameters = Schema.Struct(BaseParameterFields)

export const Parameters = Schema.Struct({
  ...BaseParameterFields,
  background: Schema.optional(Schema.Boolean).annotate({
    description:
      "Run the agent in the background. You will be notified when it completes. DO NOT sleep, poll, or proactively check on its progress",
  }),
})

function renderOutput(input: {
  sessionID: SessionID
  state: "running" | "completed" | "error"
  summary?: string
  text: string
}) {
  const tag = input.state === "error" ? "task_error" : "task_result"
  return [
    `<task id="${input.sessionID}" state="${input.state}">`,
    ...(input.summary ? [`<summary>${input.summary}</summary>`] : []),
    `<${tag}>`,
    input.text,
    `</${tag}>`,
    "</task>",
  ].join("\n")
}

function buildContextSummary(
  params: { description: string; subagent_type: string },
  sessionID: string,
  outcome: "completed" | "error",
  text: string,
): EngagementSchema.AgentContextSummary {
  const findings: string[] = []
  const failures: string[] = []
  const next: string[] = []

  for (const line of text.split("\n")) {
    const lower = line.toLowerCase().trim()
    if (!lower) continue
    if (
      lower.includes("found") ||
      lower.includes("discovered") ||
      lower.includes("identified") ||
      lower.includes("confirmed")
    ) {
      findings.push(line.trim().slice(0, 200))
    } else if (
      lower.includes("failed") ||
      lower.includes("error") ||
      lower.includes("denied") ||
      lower.includes("timeout")
    ) {
      failures.push(line.trim().slice(0, 200))
    } else if (
      lower.includes("recommend") ||
      lower.includes("next") ||
      lower.includes("should") ||
      lower.includes("suggest")
    ) {
      next.push(line.trim().slice(0, 200))
    }
  }

  // Fall back to truncation if no heuristic matches
  if (findings.length === 0 && failures.length === 0 && next.length === 0) {
    findings.push(text.slice(0, 500))
  }

  return {
    id: crypto.randomUUID().slice(0, 8),
    agent_type: params.subagent_type,
    timestamp: new Date().toISOString(),
    task_description: params.description,
    outcome,
    key_findings: findings.slice(0, 10),
    failed_attempts: failures.slice(0, 10),
    recommended_next: next.slice(0, 10),
  }
}

function formatPriorContext(contexts: EngagementSchema.AgentContextSummary[]): string {
  const lines: string[] = [`<prior-agent-context agent_type="${contexts[0]?.agent_type ?? "unknown"}">`]
  for (const ctx of contexts) {
    lines.push(`  <run time="${ctx.timestamp}" outcome="${ctx.outcome}" task="${ctx.task_description}">`)
    if (ctx.key_findings.length > 0) {
      lines.push(`    Findings: ${ctx.key_findings.join("; ")}`)
    }
    if (ctx.failed_attempts.length > 0) {
      lines.push(`    Failed: ${ctx.failed_attempts.join("; ")}`)
    }
    if (ctx.recommended_next.length > 0) {
      lines.push(`    Next: ${ctx.recommended_next.join("; ")}`)
    }
    lines.push(`  </run>`)
  }
  lines.push(`</prior-agent-context>`)
  return lines.join("\n")
}

function formatInterruptAlert(alert: EngagementSchema.Alert): string {
  return [
    `<interrupt-alert source="${alert.source_agent ?? "unknown"}" severity="${alert.severity}">`,
    `URGENT: ${alert.title}`,
    ...(alert.host_ip ? [`Host: ${alert.host_ip}`] : []),
    ...(alert.details ? [alert.details] : []),
    `This alert was raised by a running subagent and requires immediate attention.`,
    `</interrupt-alert>`,
  ].join("\n")
}

export const TaskTool = Tool.define(
  id,
  Effect.gen(function* () {
    const agent = yield* Agent.Service
    const background = yield* BackgroundJob.Service
    const config = yield* Config.Service
    const sessions = yield* Session.Service
    const scope = yield* Scope.Scope
    const flags = yield* RuntimeFlags.Service
    const database = yield* Database.Service
    const engagementStore = yield* EngagementStore.Service

    const run = Effect.fn("TaskTool.execute")(function* (
      params: Schema.Schema.Type<typeof Parameters>,
      ctx: Tool.Context,
    ) {
      const cfg = yield* config.get()
      const isPentestCoordinator = ctx.agent === "pentest" || ctx.agent === "recon"
      const runInBackground = params.background === true || (params.background !== false && isPentestCoordinator)
      if (runInBackground && !flags.experimentalBackgroundSubagents && !isPentestCoordinator) {
        return yield* Effect.fail(
          new Error("Background subagents require OPENCODE_EXPERIMENTAL_BACKGROUND_SUBAGENTS=true"),
        )
      }

      if (!ctx.extra?.bypassAgentCheck) {
        yield* ctx.ask({
          permission: id,
          patterns: [params.subagent_type],
          always: ["*"],
          metadata: {
            description: params.description,
            subagent_type: params.subagent_type,
          },
        })
      }

      const next = yield* agent.get(params.subagent_type)
      if (!next) {
        return yield* Effect.fail(new Error(`Unknown agent type: ${params.subagent_type} is not a valid agent type`))
      }

      const session = params.task_id
        ? yield* sessions.get(SessionID.make(params.task_id)).pipe(Effect.catchCause(() => Effect.succeed(undefined)))
        : undefined
      const parent = yield* sessions.get(ctx.sessionID)
      const childPermission = deriveSubagentSessionPermission({
        parentSessionPermission: parent.permission ?? [],
        subagent: next,
      })
      const childToolDenies = [
        ...(next.permission.some((rule) => rule.permission === "todowrite")
          ? []
          : [{ permission: "todowrite" as const, pattern: "*" as const, action: "deny" as const }]),
        ...(next.permission.some((rule) => rule.permission === id)
          ? []
          : [{ permission: id, pattern: "*" as const, action: "deny" as const }]),
        ...(cfg.experimental?.primary_tools?.map((permission) => ({
          permission,
          pattern: "*" as const,
          action: "deny" as const,
        })) ?? []),
      ]
      const nextSession =
        session ??
        (yield* sessions.create({
          parentID: ctx.sessionID,
          title: params.description + ` (@${next.name} subagent)`,
          agent: next.name,
          permission: [
            ...childPermission,
            ...childToolDenies.filter(
              (deny) =>
                !childPermission.some(
                  (rule) =>
                    rule.permission === deny.permission && rule.pattern === deny.pattern && rule.action === deny.action,
                ),
            ),
          ],
        }))

      const msg = yield* MessageV2.get({ sessionID: ctx.sessionID, messageID: ctx.messageID }).pipe(
        Effect.provideService(Database.Service, database),
        Effect.orDie,
      )
      if (msg.info.role !== "assistant") return yield* Effect.fail(new Error("Not an assistant message"))
      const variant = msg.info.variant

      const model = next.model ?? {
        modelID: msg.info.modelID,
        providerID: msg.info.providerID,
      }
      const metadata = {
        parentSessionId: ctx.sessionID,
        sessionId: nextSession.id,
        model,
        ...(runInBackground ? { background: true } : {}),
      }

      yield* ctx.metadata({
        title: params.description,
        metadata,
      })

      const ops = ctx.extra?.promptOps as TaskPromptOps
      if (!ops) return yield* Effect.fail(new Error("TaskTool requires promptOps in ctx.extra"))

      // Agent Context Carry: inject prior context from same-type agents on fresh spawn
      const priorContexts = yield* engagementStore.getAgentContexts(params.subagent_type, 5)
      let augmentedPrompt = params.prompt
      if (priorContexts.length > 0 && !params.task_id) {
        augmentedPrompt = formatPriorContext(priorContexts) + "\n\n" + params.prompt
      }

      const runTask = Effect.fn("TaskTool.runTask")(function* () {
        const parts = yield* ops.resolvePromptParts(augmentedPrompt)
        const result = yield* ops.prompt({
          messageID: MessageID.ascending(),
          sessionID: nextSession.id,
          model: {
            modelID: model.modelID,
            providerID: model.providerID,
          },
          variant: next.model ? undefined : variant,
          agent: next.name,
          parts,
        })
        return result.parts.findLast((item) => item.type === "text")?.text ?? ""
      })

      const inject = Effect.fn("TaskTool.injectBackgroundResult")(function* (
        state: "running" | "completed" | "error",
        text: string,
      ) {
        const currentParent = yield* sessions.get(ctx.sessionID)
        yield* ops
          .prompt({
            sessionID: ctx.sessionID,
            agent: currentParent.agent ?? ctx.agent,
            variant,
            parts: [
              {
                type: "text",
                synthetic: true,
                text: renderOutput({
                  sessionID: nextSession.id,
                  state,
                  summary:
                    state === "completed"
                      ? `Background task completed: ${params.description}`
                      : state === "error"
                        ? `Background task failed: ${params.description}`
                        : `Interrupt alert for: ${params.description}`,
                  text,
                }),
              },
            ],
          })
          .pipe(Effect.ignore, Effect.forkIn(scope, { startImmediately: true }))
      })

      const notify = Effect.fn("TaskTool.notifyBackgroundResult")(function* (jobID: string) {
        yield* background.wait({ id: jobID }).pipe(
          Effect.flatMap((result) =>
            Effect.gen(function* () {
              if (result.info?.status === "completed") {
                const text = result.info.output ?? ""
                const ctxSummary = buildContextSummary(params, nextSession.id, "completed", text)
                yield* engagementStore.addAgentContext(ctxSummary)
                yield* inject("completed", text)
              } else if (result.info?.status === "error") {
                const text = result.info.error ?? ""
                const ctxSummary = buildContextSummary(params, nextSession.id, "error", text)
                yield* engagementStore.addAgentContext(ctxSummary)
                yield* inject("error", text)
              }
            }),
          ),
          Effect.forkIn(scope, { startImmediately: true }),
        )
      })

      if (yield* background.extend({ id: nextSession.id, run: runTask() })) {
        return {
          title: params.description,
          metadata: {
            ...metadata,
            background: true,
            jobId: nextSession.id,
          },
          output: renderOutput({
            sessionID: nextSession.id,
            state: "running",
            summary: "Background task updated",
            text: BACKGROUND_UPDATED,
          }),
        }
      }

      const info = yield* background.start({
        id: nextSession.id,
        type: id,
        title: params.description,
        metadata,
        onPromote: Effect.all([
          ctx.metadata({
            title: params.description,
            metadata: { ...metadata, background: true, jobId: nextSession.id },
          }),
          notify(nextSession.id),
        ]),
        run: runTask().pipe(Effect.onInterrupt(() => ops.cancel(nextSession.id))),
      })

      function backgroundResult() {
        return {
          title: params.description,
          metadata: {
            ...metadata,
            background: true,
            jobId: info.id,
          },
          output: renderOutput({
            sessionID: nextSession.id,
            state: "running",
            summary: "Background task started",
            text: BACKGROUND_STARTED,
          }),
        }
      }

      if (runInBackground) {
        yield* notify(info.id)
        // Fork interrupt alert watcher for background subagent
        yield* Effect.gen(function* () {
          while (true) {
            yield* Effect.sleep("2 seconds")
            const alerts = yield* engagementStore.drainInterruptAlerts()
            for (const alert of alerts) {
              yield* inject("running", formatInterruptAlert(alert))
            }
          }
        }).pipe(Effect.interruptible, Effect.forkIn(scope, { startImmediately: true }))
        return backgroundResult()
      }

      const runCancel = yield* EffectBridge.make()
      const cancel = ops.cancel(nextSession.id)

      function onAbort() {
        runCancel.fork(cancel)
      }

      return yield* Effect.acquireUseRelease(
        Effect.sync(() => {
          ctx.abort.addEventListener("abort", onAbort)
        }),
        () =>
          Effect.gen(function* () {
            const result = yield* Effect.raceFirst(
              background.wait({ id: nextSession.id }).pipe(Effect.map((waited) => waited.info)),
              background.waitForPromotion(nextSession.id),
            )
            if (result?.metadata?.background === true) return backgroundResult()
            if (result?.status === "error") {
              const errText = result.error ?? "Task failed"
              const ctxSummary = buildContextSummary(params, nextSession.id, "error", errText)
              yield* engagementStore.addAgentContext(ctxSummary)
              return yield* Effect.fail(new Error(errText))
            }
            if (result?.status === "cancelled") return yield* Effect.fail(new Error("Task cancelled"))
            const outputText = result?.output ?? ""
            const ctxSummary = buildContextSummary(params, nextSession.id, "completed", outputText)
            yield* engagementStore.addAgentContext(ctxSummary)
            return {
              title: params.description,
              metadata,
              output: renderOutput({ sessionID: nextSession.id, state: "completed", text: outputText }),
            }
          }),
        (_, exit) =>
          Effect.gen(function* () {
            if (Exit.hasInterrupts(exit))
              yield* Effect.all([cancel, background.cancel(nextSession.id)], { discard: true })
          }).pipe(
            Effect.ensuring(
              Effect.sync(() => {
                ctx.abort.removeEventListener("abort", onAbort)
              }),
            ),
          ),
      )
    })

    return {
      description: flags.experimentalBackgroundSubagents
        ? [DESCRIPTION, BACKGROUND_DESCRIPTION].join("\n\n")
        : DESCRIPTION,
      parameters: Parameters,
      jsonSchema: flags.experimentalBackgroundSubagents ? undefined : ToolJsonSchema.fromSchema(BaseParameters),
      execute: (params: Schema.Schema.Type<typeof Parameters>, ctx: Tool.Context) =>
        run(params, ctx).pipe(Effect.orDie),
    }
  }),
)

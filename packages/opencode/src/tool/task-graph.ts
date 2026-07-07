import { Effect, Schema } from "effect"
import { EngagementStore } from "@opencode-ai/core/engagement/store"
import { TaskGraph } from "@opencode-ai/core/engagement/task-graph"
import { PentestEvent } from "@opencode-ai/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import DESCRIPTION from "./task-graph.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals([
    "plan",
    "dispatch",
    "complete",
    "fail",
    "abandon",
    "list_ready",
    "list_all",
    "status",
  ]).annotate({
    description: "Task graph operation to perform.",
  }),
  data: Schema.optional(Schema.Unknown).annotate({
    description: "Action-specific data. See tool description for required fields per action.",
  }),
})

const NO_ENGAGEMENT = "No engagement loaded. Use state_update create_engagement first."

function formatTask(t: TaskGraph.TaskNode): string {
  const parts = [`[${t.status.toUpperCase()}]`, t.id]
  if (t.priority) parts.push(`(${t.priority})`)
  parts.push(t.description)
  if (t.assignedAgent) parts.push(`→ ${t.assignedAgent}`)
  if (t.target) parts.push(`@ ${t.target}`)
  if (t.dependsOn.length > 0) parts.push(`deps:[${t.dependsOn.join(",")}]`)
  return parts.join(" ")
}

export const TaskGraphTool = Tool.define(
  "task_graph",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const events = yield* EventV2Bridge.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, _ctx: Tool.Context) =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }

          const d = (params.data ?? {}) as Record<string, any>

          switch (params.action) {
            case "plan": {
              const tasks = d.tasks as Array<{
                id: string
                description: string
                assignedAgent?: string
                priority?: TaskGraph.TaskPriority
                target?: string
                technique?: string
                phase?: string
                dependsOn?: string[]
              }>
              if (!tasks || !Array.isArray(tasks) || tasks.length === 0) {
                return { title: "Error", metadata: {}, output: "Error: data.tasks array is required for plan." }
              }
              const now = new Date().toISOString()
              const newNodes: TaskGraph.TaskNode[] = tasks.map((t) => ({
                id: t.id,
                description: t.description,
                status: "planned" as const,
                assignedAgent: t.assignedAgent,
                priority: t.priority,
                target: t.target,
                technique: t.technique,
                phase: t.phase,
                dependsOn: t.dependsOn ?? [],
                createdAt: now,
                updatedAt: now,
              }))
              let graph = yield* store.getTaskGraph()
              graph = TaskGraph.addTasks(graph, newNodes)
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              for (const node of newNodes) {
                yield* events.publish(PentestEvent.TaskCreated, {
                  timestamp: Date.now(),
                  engagementID: state.id,
                  taskId: node.id,
                  description: node.description,
                  assignedAgent: node.assignedAgent,
                })
              }
              const ready = TaskGraph.getReady(graph)
              return {
                title: `Planned ${newNodes.length} tasks`,
                metadata: {},
                output: `Added ${newNodes.length} tasks. ${ready.length} ready for dispatch.\n${newNodes.map(formatTask).join("\n")}`,
              }
            }

            case "dispatch": {
              const id = d.id as string
              if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for dispatch." }
              let graph = yield* store.getTaskGraph()
              const task = graph[id]
              if (!task) return { title: "Error", metadata: {}, output: `Task ${id} not found.` }
              if (task.status !== "ready" && task.status !== "planned") {
                return { title: "Error", metadata: {}, output: `Task ${id} is ${task.status}, cannot dispatch.` }
              }
              graph = TaskGraph.updateTask(graph, id, {
                status: "dispatched",
                assignedAgent: d.assignedAgent as string | undefined ?? task.assignedAgent,
                sessionId: d.sessionId as string | undefined,
              })
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Dispatched ${id}`,
                metadata: {},
                output: `Task ${id} dispatched${d.assignedAgent ? ` to ${d.assignedAgent}` : ""}.`,
              }
            }

            case "complete": {
              const id = d.id as string
              if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for complete." }
              let graph = yield* store.getTaskGraph()
              if (!graph[id]) return { title: "Error", metadata: {}, output: `Task ${id} not found.` }
              graph = TaskGraph.completeTask(graph, id, d.result as string | undefined)
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.TaskCompleted, {
                timestamp: Date.now(),
                engagementID: state.id,
                taskId: id,
                status: "completed",
                result: d.result as string | undefined,
              })
              const nowReady = TaskGraph.getReady(graph)
              return {
                title: `Completed ${id}`,
                metadata: {},
                output: `Task ${id} completed.${nowReady.length > 0 ? ` ${nowReady.length} tasks now ready: ${nowReady.map((t) => t.id).join(", ")}` : ""}`,
              }
            }

            case "fail": {
              const id = d.id as string
              if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for fail." }
              let graph = yield* store.getTaskGraph()
              if (!graph[id]) return { title: "Error", metadata: {}, output: `Task ${id} not found.` }
              graph = TaskGraph.failTask(graph, id, d.result as string | undefined)
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.TaskCompleted, {
                timestamp: Date.now(),
                engagementID: state.id,
                taskId: id,
                status: "failed",
                result: d.result as string | undefined,
              })
              const blocked = TaskGraph.getBlocked(graph)
              return {
                title: `Failed ${id}`,
                metadata: {},
                output: `Task ${id} failed.${blocked.length > 0 ? ` ${blocked.length} tasks now blocked.` : ""}`,
              }
            }

            case "abandon": {
              const id = d.id as string
              if (!id) return { title: "Error", metadata: {}, output: "Error: data.id is required for abandon." }
              let graph = yield* store.getTaskGraph()
              if (!graph[id]) return { title: "Error", metadata: {}, output: `Task ${id} not found.` }
              graph = TaskGraph.abandonTask(graph, id)
              yield* store.setTaskGraph(graph)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Abandoned ${id}`,
                metadata: {},
                output: `Task ${id} abandoned.`,
              }
            }

            case "list_ready": {
              const graph = yield* store.getTaskGraph()
              const ready = TaskGraph.getReady(graph)
              if (ready.length === 0) {
                return { title: "No ready tasks", metadata: {}, output: "No tasks ready for dispatch." }
              }
              return {
                title: `${ready.length} ready tasks`,
                metadata: {},
                output: `Ready tasks:\n${ready.map(formatTask).join("\n")}`,
              }
            }

            case "list_all": {
              const graph = yield* store.getTaskGraph()
              const all = Object.values(graph)
              if (all.length === 0) {
                return { title: "No tasks", metadata: {}, output: "Task graph is empty." }
              }
              const counts = TaskGraph.statusSummary(graph)
              const header = Object.entries(counts).map(([k, v]) => `${k}:${v}`).join(" ")
              return {
                title: `${all.length} tasks`,
                metadata: {},
                output: `Tasks (${header}):\n${all.map(formatTask).join("\n")}`,
              }
            }

            case "status": {
              const graph = yield* store.getTaskGraph()
              const all = Object.values(graph)
              if (all.length === 0) {
                return { title: "No tasks", metadata: {}, output: "Task graph is empty." }
              }
              const counts = TaskGraph.statusSummary(graph)
              const running = TaskGraph.getRunning(graph)
              const ready = TaskGraph.getReady(graph)
              const lines = [
                `Total: ${all.length} tasks`,
                Object.entries(counts).map(([k, v]) => `  ${k}: ${v}`).join("\n"),
              ]
              if (running.length > 0) {
                lines.push(`\nActive: ${running.map((t) => `${t.id}→${t.assignedAgent ?? "?"}`).join(", ")}`)
              }
              if (ready.length > 0) {
                lines.push(`Ready to dispatch: ${ready.map((t) => t.id).join(", ")}`)
              }
              return {
                title: `Task status`,
                metadata: {},
                output: lines.join("\n"),
              }
            }

            default:
              return { title: "Error", metadata: {}, output: `Unknown action: ${params.action}` }
          }
        }).pipe(Effect.orDie),
    }
  }),
)

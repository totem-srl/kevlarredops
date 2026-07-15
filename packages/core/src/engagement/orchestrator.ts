export * as Orchestrator from "./orchestrator"

import { TaskGraph } from "./task-graph"
import type { ResolvedVector } from "./schema"

// Deterministic, LLM-free scheduling core for AR1. This module NEVER spawns and
// NEVER decides that the engagement is finished — it only computes, from the
// task DAG, what MAY run next. Every strategic decision stays with the
// coordinator (the LLM). The three quality risks of moving orchestration into
// the harness are encoded here as testable invariants:
//
//   Risk 1 (lost adaptation): `waveStatus().quiescent` tells the harness when to
//     WAKE the coordinator; this module offers no auto-advance, so a new wave is
//     only ever launched after the coordinator has seen the previous results
//     (Wave-confirm).
//   Risk 3 (over-eager dispatch): `selectWave()` enforces the concurrency cap and
//     skips nodes whose vector is already settled in the resolved-vectors ledger.
//   Premature completion: there is deliberately NO `isComplete()` — the harness
//     cannot end an engagement. `hasOutstandingWork()` only reports pending work;
//     whether the engagement is done is the coordinator's call against objectives.

export const DEFAULT_CONCURRENCY = 3

const PRIORITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

function byPriorityThenAge(a: TaskGraph.TaskNode, b: TaskGraph.TaskNode): number {
  const pa = a.priority ? (PRIORITY_RANK[a.priority] ?? 2) : 2
  const pb = b.priority ? (PRIORITY_RANK[b.priority] ?? 2) : 2
  if (pa !== pb) return pa - pb
  return a.createdAt.localeCompare(b.createdAt)
}

/**
 * Does this ready node target a vector the ledger has already settled as a dead
 * end? Deliberately CONSERVATIVE: only a `resolved` (definitively dead) vector
 * blocks a spawn, and only when the same target is named AND the technique/
 * description clearly overlaps. Over-skipping would itself cut coverage (a
 * quality regression), so ambiguity always favors running the node.
 */
export function matchResolvedVector(
  node: TaskGraph.TaskNode,
  vectors: readonly ResolvedVector[],
): string | undefined {
  const target = node.target?.trim().toLowerCase()
  if (!target) return undefined
  const technique = (node.technique ?? node.description ?? "").trim().toLowerCase()
  if (!technique) return undefined
  for (const v of vectors) {
    if (v.status !== "resolved") continue
    const vt = v.target.trim().toLowerCase()
    if (vt !== target && !vt.includes(target) && !target.includes(vt)) continue
    const vv = v.vector.trim().toLowerCase()
    if (technique.includes(vv) || vv.includes(technique)) {
      return `vector already resolved (dead end): ${v.target} :: ${v.vector}`
    }
  }
  return undefined
}

export interface WaveSelection {
  /** Launch these now (ready, under the cap, not a settled dead end). */
  spawn: TaskGraph.TaskNode[]
  /** Ready but over the concurrency cap — eligible for the next wave. */
  deferred: TaskGraph.TaskNode[]
  /** Ready but blocked by the resolved-vectors ledger, with the reason. */
  skipped: { node: TaskGraph.TaskNode; reason: string }[]
}

/**
 * Compute the set of ready nodes that MAY be spawned right now, honoring the
 * concurrency cap (counting nodes already in flight) and the resolved-vectors
 * ledger. Pure: returns a selection, launches nothing.
 */
export function selectWave(
  graph: TaskGraph.TaskNodes,
  opts?: { concurrency?: number; inFlight?: number; resolvedVectors?: readonly ResolvedVector[] },
): WaveSelection {
  const cap = Math.max(1, opts?.concurrency ?? DEFAULT_CONCURRENCY)
  // Prefer a caller-supplied REAL in-flight count (from the background-job
  // registry) over the graph-derived one: graph status can lag reality, and the
  // rolling pump needs an accurate free-slot count to avoid over/under-filling.
  const inFlight = opts?.inFlight ?? TaskGraph.getRunning(graph).length // running | dispatched
  const slots = Math.max(0, cap - inFlight)
  const ordered = [...TaskGraph.getReady(graph)].sort(byPriorityThenAge)

  const spawn: TaskGraph.TaskNode[] = []
  const deferred: TaskGraph.TaskNode[] = []
  const skipped: { node: TaskGraph.TaskNode; reason: string }[] = []
  const vectors = opts?.resolvedVectors ?? []

  for (const node of ordered) {
    const dead = matchResolvedVector(node, vectors)
    if (dead) {
      skipped.push({ node, reason: dead })
      continue
    }
    if (spawn.length < slots) spawn.push(node)
    else deferred.push(node)
  }
  return { spawn, deferred, skipped }
}

export interface WaveStatus {
  inFlight: TaskGraph.TaskNode[]
  ready: TaskGraph.TaskNode[]
  blocked: TaskGraph.TaskNode[]
  completed: number
  failed: number
  abandoned: number
  total: number
  /**
   * True when nothing is in flight. This is the ONLY signal the harness uses to
   * decide it is time to wake the coordinator for the next wave — it never
   * launches the next wave itself (Wave-confirm / Risk 1 mitigation).
   */
  quiescent: boolean
}

export function waveStatus(graph: TaskGraph.TaskNodes): WaveStatus {
  const all = Object.values(graph)
  const inFlight = TaskGraph.getRunning(graph)
  const ready = TaskGraph.getReady(graph)
  const blocked = TaskGraph.getBlocked(graph)
  const completed = all.filter((t) => t.status === "completed").length
  const failed = all.filter((t) => t.status === "failed").length
  const abandoned = all.filter((t) => t.status === "abandoned").length
  return {
    inFlight,
    ready,
    blocked,
    completed,
    failed,
    abandoned,
    total: all.length,
    quiescent: inFlight.length === 0,
  }
}

/**
 * Whether the DAG still has work pending (in flight, ready, or blocked-and-
 * recoverable). This ONLY reports; it is not a completion verdict. The harness
 * must never treat `false` as "engagement done" — that judgment belongs to the
 * coordinator, weighed against objectives and coverage.
 */
export function hasOutstandingWork(graph: TaskGraph.TaskNodes): boolean {
  const s = waveStatus(graph)
  return s.inFlight.length > 0 || s.ready.length > 0 || s.blocked.length > 0
}

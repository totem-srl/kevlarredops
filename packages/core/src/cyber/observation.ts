import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

const ENGAGEMENTS_DIR = path.join(os.homedir(), ".pentestcode", "engagements")
const EVENTS_FILE = "observations.jsonl"

export type Subtype = "vuln" | "code-smell" | "intel-fact" | "flag" | "ioc" | "control-gap" | "risk"
export type Severity = "info" | "low" | "medium" | "high" | "critical"
export type Status = "open" | "triaged" | "confirmed" | "resolved" | "false-positive"

export type Observation = {
  id: string
  subtype: Subtype
  title: string
  severity?: Severity
  confidence?: string
  status: Status
  note?: string
  tags: string[]
  evidence: string[]
  at: string
  updated_at: string
}

export type Event =
  | ({ type: "observation_added"; at: string; id: string } & Omit<Observation, "status" | "tags" | "evidence" | "at" | "updated_at"> & {
      status?: Status
      tags?: string[]
    })
  | { type: "observation_updated"; at: string; id: string; patch: Partial<Omit<Observation, "id" | "at">> }
  | { type: "observation_removed"; at: string; id: string }
  | { type: "observation_evidence_linked"; at: string; id: string; evidence: string }

function dirFor(engagementName: string): string {
  return path.join(ENGAGEMENTS_DIR, engagementName)
}

function eventsPath(engagementName: string): string {
  return path.join(dirFor(engagementName), EVENTS_FILE)
}

let counter = 0

function newId(): string {
  counter += 1
  return `obs_${Date.now().toString(36)}${counter.toString(36).padStart(3, "0")}`
}

async function readEvents(engagementName: string): Promise<Event[]> {
  try {
    const raw = await fs.readFile(eventsPath(engagementName), "utf8")
    const events: Event[] = []
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue
      try {
        events.push(JSON.parse(line) as Event)
      } catch {
        // skip malformed lines
      }
    }
    return events
  } catch {
    return []
  }
}

async function appendEvent(engagementName: string, event: Event): Promise<void> {
  await fs.mkdir(dirFor(engagementName), { recursive: true })
  await fs.appendFile(eventsPath(engagementName), `${JSON.stringify(event)}\n`, { mode: 0o600 })
}

export function project(events: Event[]): Observation[] {
  const byId = new Map<string, Observation>()
  for (const event of events) {
    if (event.type === "observation_added") {
      byId.set(event.id, {
        id: event.id,
        subtype: event.subtype,
        title: event.title,
        severity: event.severity,
        confidence: event.confidence,
        status: event.status ?? "open",
        note: event.note,
        tags: [...(event.tags ?? [])],
        evidence: [],
        at: event.at,
        updated_at: event.at,
      })
      continue
    }
    if (event.type === "observation_updated") {
      const existing = byId.get(event.id)
      if (!existing) continue
      Object.assign(existing, { ...event.patch, updated_at: event.at })
      continue
    }
    if (event.type === "observation_evidence_linked") {
      const existing = byId.get(event.id)
      if (!existing) continue
      if (!existing.evidence.includes(event.evidence)) existing.evidence.push(event.evidence)
      existing.updated_at = event.at
      continue
    }
    if (event.type === "observation_removed") {
      byId.delete(event.id)
    }
  }
  return [...byId.values()]
}

export async function list(engagementName: string): Promise<Observation[]> {
  return project(await readEvents(engagementName))
}

export async function add(input: {
  engagementName: string
  subtype: Subtype
  title: string
  severity?: Severity
  confidence?: string
  note?: string
  tags?: string[]
}): Promise<Observation> {
  const at = new Date().toISOString()
  const id = newId()
  await appendEvent(input.engagementName, {
    type: "observation_added",
    at,
    id,
    subtype: input.subtype,
    title: input.title,
    severity: input.severity,
    confidence: input.confidence,
    note: input.note,
    tags: input.tags ?? [],
  })
  return {
    id,
    subtype: input.subtype,
    title: input.title,
    severity: input.severity,
    confidence: input.confidence,
    status: "open",
    note: input.note,
    tags: input.tags ?? [],
    evidence: [],
    at,
    updated_at: at,
  }
}

export async function update(
  engagementName: string,
  id: string,
  patch: Partial<Pick<Observation, "title" | "severity" | "confidence" | "status" | "note" | "tags" | "subtype">>,
): Promise<boolean> {
  const all = await list(engagementName)
  if (!all.some((o) => o.id === id)) return false
  await appendEvent(engagementName, { type: "observation_updated", at: new Date().toISOString(), id, patch })
  return true
}

export async function remove(engagementName: string, id: string): Promise<boolean> {
  const all = await list(engagementName)
  if (!all.some((o) => o.id === id)) return false
  await appendEvent(engagementName, { type: "observation_removed", at: new Date().toISOString(), id })
  return true
}

export async function linkEvidence(engagementName: string, id: string, evidenceRef: string): Promise<boolean> {
  const all = await list(engagementName)
  if (!all.some((o) => o.id === id)) return false
  await appendEvent(engagementName, {
    type: "observation_evidence_linked",
    at: new Date().toISOString(),
    id,
    evidence: evidenceRef,
  })
  return true
}

export function severityCounts(observations: Observation[]): Record<string, number> {
  const counts: Record<string, number> = { none: 0, info: 0, low: 0, medium: 0, high: 0, critical: 0 }
  for (const obs of observations) {
    counts[obs.severity ?? "none"] = (counts[obs.severity ?? "none"] ?? 0) + 1
  }
  return counts
}

export * as Observation from "./observation"

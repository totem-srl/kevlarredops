export * as EngagementSchema from "./schema"

import { Schema } from "effect"

export const ID = Schema.String.pipe(Schema.brand("Engagement.ID"))
export type ID = typeof ID.Type

export const Severity = Schema.Literals(["critical", "high", "medium", "low", "info"])
export type Severity = typeof Severity.Type

export const VulnStatus = Schema.Literals(["suspected", "confirmed", "exploited", "false_positive"])
export type VulnStatus = typeof VulnStatus.Type

export const AccessLevel = Schema.Literals(["none", "user", "root", "system"])
export type AccessLevel = typeof AccessLevel.Type

export const PentestPhase = Schema.Literals([
  "recon",
  "enumeration",
  "vuln_assess",
  "exploitation",
  "post_exploit",
  "reporting",
])
export type PentestPhase = typeof PentestPhase.Type

export const PentestMode = Schema.Literals(["auto", "free", "guided"])
export type PentestMode = typeof PentestMode.Type

export const TaskNodeStatus = Schema.Literals(["pending", "in_progress", "done", "abandoned"])
export type TaskNodeStatus = typeof TaskNodeStatus.Type

export const ObjectiveStatus = Schema.Literals(["not_started", "in_progress", "completed", "blocked", "abandoned"])
export type ObjectiveStatus = typeof ObjectiveStatus.Type

export const ObjectivePriority = Schema.Literals(["critical", "high", "medium", "low"])
export type ObjectivePriority = typeof ObjectivePriority.Type

export const ObjectiveCategory = Schema.Literals(["ctf", "pentest", "bounty", "red_team", "custom"])
export type ObjectiveCategory = typeof ObjectiveCategory.Type

export const Service = Schema.Struct({
  port: Schema.Number,
  protocol: Schema.optional(Schema.String),
  service: Schema.optional(Schema.String),
  version: Schema.optional(Schema.String),
  state: Schema.optional(Schema.String),
  banner: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Service" })
export type Service = typeof Service.Type

export const EvidenceItem = Schema.Struct({
  tool: Schema.String,
  command: Schema.optional(Schema.String),
  output: Schema.String,
  timestamp: Schema.optional(Schema.String),
  confidence: Schema.optional(Schema.Number),
}).annotate({ identifier: "Engagement.EvidenceItem" })
export type EvidenceItem = typeof EvidenceItem.Type

export const Vulnerability = Schema.Struct({
  id: Schema.optional(Schema.String),
  title: Schema.String,
  service_port: Schema.optional(Schema.Number),
  severity: Schema.optional(Severity),
  status: Schema.optional(VulnStatus),
  confidence: Schema.optional(Schema.Number),
  description: Schema.optional(Schema.String),
  evidence: Schema.optional(Schema.String),
  evidence_items: Schema.optional(Schema.Array(EvidenceItem)),
  references: Schema.optional(Schema.Array(Schema.String)),
  mitre_attack_id: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Vulnerability" })
export type Vulnerability = typeof Vulnerability.Type

export const Credential = Schema.Struct({
  id: Schema.String,
  cred_type: Schema.optional(Schema.String),
  username: Schema.optional(Schema.String),
  value: Schema.optional(Schema.String),
  source: Schema.optional(Schema.String),
  valid_for: Schema.optional(Schema.Array(Schema.String)),
  confidence: Schema.optional(Schema.Number),
  domain: Schema.optional(Schema.String),
  ticket_type: Schema.optional(Schema.String),
  service_principal: Schema.optional(Schema.String),
  ticket_expiry: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Credential" })
export type Credential = typeof Credential.Type

export const Access = Schema.Struct({
  access_type: Schema.String,
  username: Schema.String,
  level: Schema.optional(AccessLevel),
  confidence: Schema.optional(Schema.Number),
  credential_id: Schema.optional(Schema.String),
  details: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Access" })
export type Access = typeof Access.Type

export const DomainInfo = Schema.Struct({
  domain: Schema.optional(Schema.String),
  is_dc: Schema.optional(Schema.Boolean),
  computer_account: Schema.optional(Schema.String),
  forest: Schema.optional(Schema.String),
  site: Schema.optional(Schema.String),
  functional_level: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.DomainInfo" })
export type DomainInfo = typeof DomainInfo.Type

export const Host = Schema.Struct({
  ip: Schema.String,
  hostname: Schema.optional(Schema.String),
  os: Schema.optional(Schema.String),
  domain_info: Schema.optional(DomainInfo),
  services: Schema.Array(Service),
  vulns: Schema.Array(Vulnerability),
  access: Schema.Array(Access),
  notes: Schema.Array(Schema.String),
}).annotate({ identifier: "Engagement.Host" })
export type Host = typeof Host.Type

export const AttackStep = Schema.Struct({
  timestamp: Schema.String,
  source: Schema.String,
  target: Schema.String,
  technique: Schema.String,
  result: Schema.String,
  success: Schema.optional(Schema.Boolean),
  mitre_attack_id: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.AttackStep" })
export type AttackStep = typeof AttackStep.Type

export const Objective = Schema.Struct({
  id: Schema.String,
  title: Schema.String,
  description: Schema.optional(Schema.String),
  status: ObjectiveStatus,
  priority: Schema.optional(ObjectivePriority),
  category: Schema.optional(ObjectiveCategory),
  target_hosts: Schema.optional(Schema.Array(Schema.String)),
  linked_vulns: Schema.optional(Schema.Array(Schema.String)),
  linked_creds: Schema.optional(Schema.Array(Schema.String)),
  flags: Schema.optional(Schema.Array(Schema.String)),
  evidence: Schema.optional(Schema.String),
  notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Objective" })
export type Objective = typeof Objective.Type

export const Scope = Schema.Struct({
  targets: Schema.Array(Schema.String),
  excludes: Schema.Array(Schema.String),
  notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Scope" })
export type Scope = typeof Scope.Type

export const TaskTreeNode = Schema.Struct({
  id: Schema.String,
  parent_id: Schema.optional(Schema.String),
  description: Schema.String,
  status: Schema.optional(TaskNodeStatus),
  difficulty: Schema.optional(Schema.Number),
  target: Schema.optional(Schema.String),
  technique: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.TaskTreeNode" })
export type TaskTreeNode = typeof TaskTreeNode.Type

export const Trust = Schema.Struct({
  target_domain: Schema.String,
  trust_type: Schema.optional(Schema.String),
  trust_direction: Schema.optional(Schema.String),
  is_transitive: Schema.optional(Schema.Boolean),
}).annotate({ identifier: "Engagement.Trust" })
export type Trust = typeof Trust.Type

export const DomainState = Schema.Struct({
  domain_name: Schema.String,
  forest: Schema.optional(Schema.String),
  domain_sid: Schema.optional(Schema.String),
  trusts: Schema.optional(Schema.Array(Trust)),
  domain_controllers: Schema.optional(Schema.Array(Schema.String)),
  domain_admins: Schema.optional(Schema.Array(Schema.String)),
  gpo_names: Schema.optional(Schema.Array(Schema.String)),
  password_policy: Schema.optional(Schema.Struct({
    min_length: Schema.optional(Schema.Number),
    lockout_threshold: Schema.optional(Schema.Number),
    lockout_duration: Schema.optional(Schema.String),
    complexity_enabled: Schema.optional(Schema.Boolean),
  })),
}).annotate({ identifier: "Engagement.DomainState" })
export type DomainState = typeof DomainState.Type

export const RelationType = Schema.Literals([
  "EXPLOITED_VIA",
  "CREDENTIAL_FROM",
  "REACHABLE_FROM",
  "TRUSTS",
  "MEMBER_OF",
  "ADMIN_OF",
  "PIVOT_TO",
  "AUTHENTICATES_TO",
  "LATERAL_MOVE",
  "CONTROLS",
])
export type RelationType = typeof RelationType.Type

export const EntityType = Schema.Literals(["host", "credential", "vuln", "service", "domain", "user", "group"])
export type EntityType = typeof EntityType.Type

export const Relationship = Schema.Struct({
  source_type: EntityType,
  source_id: Schema.String,
  rel_type: RelationType,
  target_type: EntityType,
  target_id: Schema.String,
  metadata: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Relationship" })
export type Relationship = typeof Relationship.Type

// --- Decision Memory ---

export const DecisionOutcome = Schema.Literals(["pending", "successful", "failed", "abandoned", "superseded"])
export type DecisionOutcome = typeof DecisionOutcome.Type

export const Decision = Schema.Struct({
  id: Schema.String,
  timestamp: Schema.String,
  phase: PentestPhase,
  decision: Schema.String,
  reasoning: Schema.String,
  alternatives: Schema.optional(Schema.Array(Schema.String)),
  outcome: Schema.optional(DecisionOutcome),
  outcome_notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.Decision" })
export type Decision = typeof Decision.Type

export const DECISIONS_MAX_ENTRIES = 100

// --- Alert Queue ---

export const AlertSeverity = Schema.Literals(["critical", "high", "medium", "info"])
export type AlertSeverity = typeof AlertSeverity.Type

export const Alert = Schema.Struct({
  id: Schema.String,
  timestamp: Schema.String,
  severity: AlertSeverity,
  source_agent: Schema.optional(Schema.String),
  title: Schema.String,
  details: Schema.optional(Schema.String),
  host_ip: Schema.optional(Schema.String),
  acknowledged: Schema.optional(Schema.Boolean),
  ttl_minutes: Schema.optional(Schema.Number),
}).annotate({ identifier: "Engagement.Alert" })
export type Alert = typeof Alert.Type

export const ALERTS_MAX_ACTIVE = 50
export const ALERTS_DEFAULT_TTL_MINUTES = 60

// --- Live Sessions (shells, tunnels, listeners) ---

export const SessionType = Schema.Literals(["shell", "listener", "tunnel", "socks_proxy", "port_forward"])
export type SessionType = typeof SessionType.Type

export const LiveSession = Schema.Struct({
  id: Schema.String,
  session_type: SessionType,
  host_ip: Schema.String,
  port: Schema.optional(Schema.Number),
  username: Schema.optional(Schema.String),
  pid: Schema.optional(Schema.Number),
  established_at: Schema.String,
  last_seen: Schema.optional(Schema.String),
  alive: Schema.optional(Schema.Boolean),
  details: Schema.optional(Schema.String),
  local_port: Schema.optional(Schema.Number),
  remote_target: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.LiveSession" })
export type LiveSession = typeof LiveSession.Type

// --- Network Segmentation ---

export const NetworkSegment = Schema.Struct({
  id: Schema.String,
  name: Schema.optional(Schema.String),
  cidr: Schema.String,
  vlan: Schema.optional(Schema.Number),
  gateway: Schema.optional(Schema.String),
  reachable_from: Schema.optional(Schema.Array(Schema.String)),
  pivot_host: Schema.optional(Schema.String),
  notes: Schema.optional(Schema.String),
}).annotate({ identifier: "Engagement.NetworkSegment" })
export type NetworkSegment = typeof NetworkSegment.Type

export const State = Schema.Struct({
  id: ID,
  name: Schema.String,
  created_at: Schema.String,
  updated_at: Schema.String,
  scope: Scope,
  hosts: Schema.Record(Schema.String, Host),
  credentials: Schema.Record(Schema.String, Credential),
  flags: Schema.Array(Schema.String),
  attack_path: Schema.Array(AttackStep),
  task_tree: Schema.Array(TaskTreeNode),
  task_graph: Schema.optional(Schema.Record(Schema.String, Schema.Unknown)),
  objectives: Schema.optional(Schema.Record(Schema.String, Objective)),
  domain: Schema.optional(DomainState),
  relationships: Schema.optional(Schema.Array(Relationship)),
  alerts: Schema.optional(Schema.Array(Alert)),
  live_sessions: Schema.optional(Schema.Array(LiveSession)),
  network_segments: Schema.optional(Schema.Array(NetworkSegment)),
  current_phase: PentestPhase,
  mode: PentestMode,
  notes: Schema.Array(Schema.String),
}).annotate({ identifier: "Engagement.State" })
export type State = typeof State.Type

export const ChangelogEntry = Schema.Struct({
  timestamp: Schema.String,
  action: Schema.String,
  entity_type: Schema.String,
  entity_id: Schema.optional(Schema.String),
  summary: Schema.String,
}).annotate({ identifier: "Engagement.ChangelogEntry" })
export type ChangelogEntry = typeof ChangelogEntry.Type

export const CHANGELOG_MAX_ENTRIES = 500

export function toDiffContext(entries: ChangelogEntry[], maxEntries = 20): string | undefined {
  if (entries.length === 0) return undefined
  const recent = entries.slice(-maxEntries)
  const lines: string[] = ["Changes since last turn:"]
  for (const e of recent) {
    const ts = e.timestamp.split("T")[1]?.slice(0, 8) ?? e.timestamp
    lines.push(`  [${ts}] ${e.action} ${e.entity_type}${e.entity_id ? ` (${e.entity_id})` : ""}: ${e.summary}`)
  }
  if (entries.length > maxEntries) {
    lines.push(`  ... and ${entries.length - maxEntries} earlier changes`)
  }
  return lines.join("\n")
}

export function unvalidatedVulns(state: State): Array<{ ip: string; vuln: Vulnerability }> {
  const result: Array<{ ip: string; vuln: Vulnerability }> = []
  for (const [ip, host] of Object.entries(state.hosts)) {
    for (const vuln of host.vulns) {
      if (vuln.status === "suspected" || (!vuln.status && (vuln.confidence === undefined || vuln.confidence < 0.8))) {
        result.push({ ip, vuln })
      }
    }
  }
  return result
}

export function criticHint(state: State): string | undefined {
  const unvalidated = unvalidatedVulns(state)
  if (unvalidated.length === 0) return undefined
  const byHost = new Map<string, string[]>()
  for (const { ip, vuln } of unvalidated) {
    const list = byHost.get(ip) ?? []
    list.push(`${vuln.title} [${(vuln.severity ?? "medium").toUpperCase()}]`)
    byHost.set(ip, list)
  }
  const lines = [`${unvalidated.length} unvalidated finding(s) — spawn "critic" subagent to validate:`]
  for (const [ip, vulns] of byHost) {
    lines.push(`  ${ip}: ${vulns.join(", ")}`)
  }
  return lines.join("\n")
}

export function activeAlerts(state: State): Alert[] {
  const now = Date.now()
  return (state.alerts ?? []).filter((a) => {
    if (a.acknowledged) return false
    const ttl = (a.ttl_minutes ?? ALERTS_DEFAULT_TTL_MINUTES) * 60 * 1000
    const created = new Date(a.timestamp).getTime()
    return now - created < ttl
  })
}

export function aliveSessions(state: State): LiveSession[] {
  return (state.live_sessions ?? []).filter((s) => s.alive !== false)
}

export function toOODAContext(state: State, recentChanges: ChangelogEntry[]): string {
  const s = summary(state)
  const lines: string[] = ["<situation-awareness>"]

  // Changes
  if (recentChanges.length > 0) {
    lines.push(`  Recent changes: ${recentChanges.length} mutations since last turn`)
    const byType = new Map<string, number>()
    for (const e of recentChanges) {
      byType.set(e.entity_type, (byType.get(e.entity_type) ?? 0) + 1)
    }
    lines.push(`    ${[...byType.entries()].map(([k, v]) => `${k}:${v}`).join(" ")}`)
  }

  // Coverage
  const totalHosts = s.hosts_discovered
  const enumerated = Object.values(state.hosts).filter((h) => h.services.length > 0).length
  const assessed = Object.values(state.hosts).filter((h) => h.vulns.length > 0).length
  const accessed = s.hosts_compromised
  lines.push(`  Coverage: ${totalHosts} hosts → ${enumerated} enumerated → ${assessed} assessed → ${accessed} compromised`)
  if (s.unchecked_services > 0) lines.push(`  Gaps: ${s.unchecked_services} services without version info`)

  // Unvalidated findings
  const unval = unvalidatedVulns(state)
  if (unval.length > 0) lines.push(`  Unvalidated: ${unval.length} finding(s) need critic review`)

  // Alerts
  const alerts = activeAlerts(state)
  if (alerts.length > 0) {
    lines.push(`  ALERTS (${alerts.length}):`)
    for (const a of alerts.slice(0, 5)) {
      lines.push(`    [${a.severity.toUpperCase()}] ${a.title}${a.host_ip ? ` on ${a.host_ip}` : ""}${a.source_agent ? ` (from ${a.source_agent})` : ""}`)
    }
    if (alerts.length > 5) lines.push(`    ... and ${alerts.length - 5} more`)
  }

  // Live sessions
  const sessions = aliveSessions(state)
  if (sessions.length > 0) {
    lines.push(`  Live sessions (${sessions.length}):`)
    for (const sess of sessions) {
      const detail = sess.session_type === "tunnel" || sess.session_type === "port_forward"
        ? ` → ${sess.remote_target ?? "?"}${sess.local_port ? ` local:${sess.local_port}` : ""}`
        : sess.username ? ` as ${sess.username}` : ""
      lines.push(`    ${sess.session_type}: ${sess.host_ip}${sess.port ? `:${sess.port}` : ""}${detail}`)
    }
  }

  // Network segments
  const segments = state.network_segments ?? []
  if (segments.length > 0) {
    lines.push(`  Network segments (${segments.length}):`)
    for (const seg of segments) {
      const pivot = seg.pivot_host ? ` via ${seg.pivot_host}` : ""
      const reach = seg.reachable_from?.length ? ` reachable_from:[${seg.reachable_from.join(",")}]` : ""
      lines.push(`    ${seg.id}: ${seg.cidr}${seg.vlan !== undefined ? ` VLAN:${seg.vlan}` : ""}${pivot}${reach}`)
    }
  }

  // Ready tasks
  const pending = state.task_tree.filter((t) => t.status === "pending")
  const inProgress = state.task_tree.filter((t) => t.status === "in_progress")
  if (inProgress.length > 0 || pending.length > 0) {
    lines.push(`  Tasks: ${inProgress.length} in-progress, ${pending.length} pending`)
  }

  // Objectives progress
  if (state.objectives) {
    const objs = Object.values(state.objectives)
    const completed = objs.filter((o) => o.status === "completed").length
    const blocked = objs.filter((o) => o.status === "blocked").length
    if (objs.length > 0) {
      lines.push(`  Objectives: ${completed}/${objs.length} completed${blocked > 0 ? `, ${blocked} blocked` : ""}`)
    }
  }

  lines.push("</situation-awareness>")
  return lines.join("\n")
}

export function summary(state: State) {
  const hostCount = Object.keys(state.hosts).length
  const compromised = Object.values(state.hosts).filter((h) => h.access.length > 0).length
  const vulnCount = Object.values(state.hosts).reduce((sum, h) => sum + h.vulns.length, 0)
  const credCount = Object.keys(state.credentials).length
  const flagCount = state.flags.length
  const uncheckedServices = Object.values(state.hosts).reduce(
    (sum, h) => sum + h.services.filter((s) => !s.version).length,
    0,
  )
  const objectives = state.objectives ? Object.values(state.objectives) : []
  return {
    hosts_discovered: hostCount,
    hosts_compromised: compromised,
    vulnerabilities: vulnCount,
    credentials: credCount,
    flags: flagCount,
    attack_steps: state.attack_path.length,
    unchecked_services: uncheckedServices,
    current_phase: state.current_phase,
    mode: state.mode,
    objectives_total: objectives.length,
    objectives_completed: objectives.filter((o) => o.status === "completed").length,
    objectives_in_progress: objectives.filter((o) => o.status === "in_progress").length,
    objectives_blocked: objectives.filter((o) => o.status === "blocked").length,
  }
}

export function toCompactContext(state: State, maxHosts = 20): string {
  const s = summary(state)
  const data: Record<string, unknown> = {
    scope: { targets: state.scope.targets, excludes: state.scope.excludes },
    summary: s,
    phase: state.current_phase,
    mode: state.mode,
    hosts: {} as Record<string, unknown>,
  }

  const hostEntries = Object.entries(state.hosts).slice(0, maxHosts)
  for (const [ip, host] of hostEntries) {
    const h: Record<string, unknown> = {
      services: host.services.map((svc) => ({
        port: svc.port,
        service: svc.service,
        version: svc.version || undefined,
      })),
    }
    if (host.hostname) h.hostname = host.hostname
    if (host.os) h.os = host.os
    if (host.vulns.length > 0)
      h.vulns = host.vulns.map((v) => ({
        title: v.title,
        severity: v.severity,
        status: v.status,
        ...(v.confidence !== undefined ? { conf: v.confidence } : {}),
      }))
    if (host.access.length > 0)
      h.access = host.access.map((a) => ({
        type: a.access_type,
        user: a.username,
        level: a.level,
        ...(a.confidence !== undefined ? { conf: a.confidence } : {}),
      }))
    ;(data.hosts as Record<string, unknown>)[ip] = h
  }

  if (state.domain) {
    const dom: Record<string, unknown> = { name: state.domain.domain_name }
    if (state.domain.forest) dom.forest = state.domain.forest
    if (state.domain.domain_controllers?.length) dom.dcs = state.domain.domain_controllers
    if (state.domain.domain_admins?.length) dom.admins = state.domain.domain_admins
    if (state.domain.trusts?.length) dom.trusts = state.domain.trusts.map((t) => t.target_domain)
    data.domain = dom
  }

  if (state.flags.length > 0) data.flags = state.flags
  if (state.task_tree.length > 0) {
    const pending = state.task_tree.filter((t) => t.status === "pending" || t.status === "in_progress")
    if (pending.length > 0) data.pending_tasks = pending.map((t) => ({ id: t.id, desc: t.description, target: t.target }))
  }

  if (state.objectives) {
    const objs = Object.values(state.objectives)
    if (objs.length > 0) {
      data.objectives = objs.map((o) => {
        const compact: Record<string, unknown> = { id: o.id, title: o.title, status: o.status }
        if (o.priority) compact.priority = o.priority
        if (o.category) compact.category = o.category
        if (o.target_hosts && o.target_hosts.length > 0) compact.target_hosts = o.target_hosts
        if (o.flags && o.flags.length > 0) compact.flags = o.flags
        if (o.evidence) compact.evidence = o.evidence
        return compact
      })
      const completed = objs.filter((o) => o.status === "completed").length
      data.objectives_progress = `${completed}/${objs.length} completed`
    }
  }

  if (state.relationships && state.relationships.length > 0) {
    data.relationships = state.relationships.map((r) => `${r.source_type}:${r.source_id}-[${r.rel_type}]->${r.target_type}:${r.target_id}`)
  }

  const alerts = activeAlerts(state)
  if (alerts.length > 0) {
    data.alerts = alerts.map((a) => ({
      severity: a.severity,
      title: a.title,
      ...(a.host_ip ? { host: a.host_ip } : {}),
      ...(a.source_agent ? { from: a.source_agent } : {}),
    }))
  }

  const sessions = aliveSessions(state)
  if (sessions.length > 0) {
    data.live_sessions = sessions.map((s) => ({
      type: s.session_type,
      host: s.host_ip,
      ...(s.port ? { port: s.port } : {}),
      ...(s.username ? { user: s.username } : {}),
      ...(s.remote_target ? { target: s.remote_target } : {}),
    }))
  }

  const segments = state.network_segments ?? []
  if (segments.length > 0) {
    data.network_segments = segments.map((seg) => ({
      id: seg.id,
      cidr: seg.cidr,
      ...(seg.vlan !== undefined ? { vlan: seg.vlan } : {}),
      ...(seg.pivot_host ? { pivot: seg.pivot_host } : {}),
      ...(seg.reachable_from?.length ? { reachable_from: seg.reachable_from } : {}),
    }))
  }

  return JSON.stringify(data, undefined, 2)
}

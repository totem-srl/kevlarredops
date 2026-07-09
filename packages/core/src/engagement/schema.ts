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

  return JSON.stringify(data, undefined, 2)
}

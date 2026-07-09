import { Effect, Schema } from "effect"
import { EngagementStore } from "@opencode-ai/core/engagement/store"
import { EngagementSchema } from "@opencode-ai/core/engagement/schema"
import { PentestEvent } from "@opencode-ai/schema/pentest-event"
import { EventV2Bridge } from "@/event-v2-bridge"
import DESCRIPTION from "./state-update.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals([
    "add_host",
    "delete_host",
    "add_vuln",
    "update_vuln",
    "delete_vuln",
    "add_credential",
    "delete_credential",
    "add_access",
    "set_phase",
    "set_mode",
    "update_scope",
    "add_flag",
    "add_note",
    "add_attack_step",
    "create_engagement",
    "load_engagement",
    "reload_engagement",
    "set_domain",
    "update_domain",
    "add_objective",
    "update_objective",
    "complete_objective",
    "add_relationship",
    "delete_relationship",
  ]).annotate({
    description: "The mutation to perform on the engagement state.",
  }),
  data: Schema.Unknown.annotate({
    description: "Action-specific data. See tool description for required fields per action.",
  }),
})

const NO_ENGAGEMENT = "No engagement loaded. Use create_engagement or load_engagement first."

function countsLine(state: EngagementSchema.State): string {
  const s = EngagementSchema.summary(state)
  const objStr = s.objectives_total > 0 ? ` obj:${s.objectives_completed}/${s.objectives_total}` : ""
  return `[${state.name}] phase:${s.current_phase} hosts:${s.hosts_discovered} vulns:${s.vulnerabilities} creds:${s.credentials} flags:${s.flags}${objStr}`
}

export const StateUpdateTool = Tool.define(
  "state_update",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const events = yield* EventV2Bridge.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, _ctx: Tool.Context): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const raw = params.data ?? {}
          const d = (typeof raw === "string" ? JSON.parse(raw) : raw) as Record<string, any>

          switch (params.action) {
            // --- Lifecycle ---
            case "create_engagement": {
              const name = d.name as string
              if (!name) {
                return { title: "Error", metadata: {}, output: "Error: data.name is required for create_engagement." }
              }
              const state = yield* store.create(name)
              return {
                title: `Created ${name}`,
                metadata: { name },
                output: `Engagement "${name}" created (id: ${state.id}). Phase: ${state.current_phase}, Mode: ${state.mode}.`,
              }
            }

            case "load_engagement": {
              const name = d.name as string
              if (!name) {
                return { title: "Error", metadata: {}, output: "Error: data.name is required for load_engagement." }
              }
              const state = yield* store.load(name)
              if (!state) {
                const available = yield* store.listEngagements()
                return {
                  title: "Not Found",
                  metadata: {},
                  output: `Engagement "${name}" not found.${available.length > 0 ? ` Available: ${available.join(", ")}` : ""}`,
                }
              }
              return {
                title: `Loaded ${name}`,
                metadata: { name },
                output: `Engagement "${name}" loaded. ${countsLine(state)}`,
              }
            }

            case "reload_engagement": {
              const current = yield* store.get()
              if (!current) {
                return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              }
              const state = yield* store.load(current.name)
              if (!state) {
                return { title: "Error", metadata: {}, output: `Failed to reload engagement "${current.name}" from disk.` }
              }
              return {
                title: `Reloaded ${current.name}`,
                metadata: {},
                output: `Engagement "${current.name}" reloaded from disk. ${countsLine(state)}`,
              }
            }

            // --- Mutations (require loaded engagement) ---
            case "add_host": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const ip = d.ip as string
              if (!ip) {
                return { title: "Error", metadata: {}, output: "Error: data.ip is required for add_host." }
              }
              const hostData: Partial<{ -readonly [K in keyof EngagementSchema.Host]: EngagementSchema.Host[K] }> = {}
              if (d.hostname) hostData.hostname = d.hostname as string
              if (d.os) hostData.os = d.os as string
              if (d.services && Array.isArray(d.services)) {
                hostData.services = d.services as EngagementSchema.Service[]
              }
              const host = yield* store.addHost(ip, hostData)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.HostDiscovered, {
                timestamp: Date.now(),
                engagementID: state.id,
                ip,
                hostname: host.hostname,
                serviceCount: host.services.length,
              })
              return {
                title: `Host ${ip}`,
                metadata: { ip },
                output: `Host ${ip} added/updated.${host.hostname ? ` hostname:${host.hostname}` : ""}${host.os ? ` os:${host.os}` : ""} services:${host.services.length}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "delete_host": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const ip = d.ip as string
              if (!ip) {
                return { title: "Error", metadata: {}, output: "Error: data.ip is required for delete_host." }
              }
              const deleted = yield* store.deleteHost(ip)
              if (!deleted) {
                return { title: "Error", metadata: {}, output: `Host ${ip} not found.` }
              }
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Deleted ${ip}`,
                metadata: { ip },
                output: `Host ${ip} deleted.${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_vuln": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const hostIp = d.host_ip as string
              const title = d.title as string
              if (!hostIp || !title) {
                return { title: "Error", metadata: {}, output: "Error: data.host_ip and data.title are required for add_vuln." }
              }
              if (!state.hosts[hostIp]) {
                return { title: "Error", metadata: {}, output: `Error: Host ${hostIp} not found. Add the host first.` }
              }
              const vuln = {
                id: d.id || `vuln-${Date.now()}`,
                title,
                severity: d.severity || "medium",
                status: d.status || "suspected",
                confidence: d.confidence as number | undefined,
                description: d.description || "",
                evidence: d.evidence || "",
                evidence_items: d.evidence_items as EngagementSchema.EvidenceItem[] | undefined,
                service_port: d.service_port,
                references: d.references || [],
                mitre_attack_id: d.mitre_attack_id,
              } as EngagementSchema.Vulnerability
              yield* store.addVuln(hostIp, vuln)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.VulnFound, {
                timestamp: Date.now(),
                engagementID: state.id,
                hostIp,
                title,
                severity: vuln.severity ?? "medium",
                status: vuln.status ?? "suspected",
              })
              return {
                title: `Vuln: ${title}`,
                metadata: { host_ip: hostIp, severity: vuln.severity },
                output: `Vulnerability added to ${hostIp}: [${(vuln.severity ?? "medium").toUpperCase()}] ${title} (${vuln.status ?? "suspected"})${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "update_vuln": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const hostIp = d.host_ip as string
              const vulnId = d.vuln_id as string
              if (!hostIp || !vulnId) {
                return { title: "Error", metadata: {}, output: "Error: data.host_ip and data.vuln_id are required for update_vuln." }
              }
              const patch: Record<string, unknown> = {}
              if (d.status !== undefined) patch.status = d.status
              if (d.severity !== undefined) patch.severity = d.severity
              if (d.confidence !== undefined) patch.confidence = d.confidence
              if (d.evidence !== undefined) patch.evidence = d.evidence
              if (d.evidence_items !== undefined) patch.evidence_items = d.evidence_items
              if (d.description !== undefined) patch.description = d.description
              if (d.title !== undefined) patch.title = d.title
              const ok = yield* store.updateVuln(hostIp, vulnId, patch as Partial<{ -readonly [K in keyof EngagementSchema.Vulnerability]: EngagementSchema.Vulnerability[K] }>)
              if (!ok) {
                return { title: "Error", metadata: {}, output: `Vuln "${vulnId}" not found on host ${hostIp}.` }
              }
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              const changedFields = Object.keys(patch).join(", ")
              return {
                title: `Vuln updated: ${vulnId}`,
                metadata: { host_ip: hostIp, vuln_id: vulnId },
                output: `Vulnerability "${vulnId}" on ${hostIp} updated (${changedFields}).${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "delete_vuln": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const hostIp = d.host_ip as string
              const vulnId = d.vuln_id as string
              if (!hostIp || !vulnId) {
                return { title: "Error", metadata: {}, output: "Error: data.host_ip and data.vuln_id are required for delete_vuln." }
              }
              const deleted = yield* store.deleteVuln(hostIp, vulnId)
              if (!deleted) {
                return { title: "Error", metadata: {}, output: `Vuln "${vulnId}" not found on host ${hostIp}.` }
              }
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Vuln deleted: ${vulnId}`,
                metadata: { host_ip: hostIp, vuln_id: vulnId },
                output: `Vulnerability "${vulnId}" deleted from ${hostIp}.${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_credential": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              const username = d.username as string
              if (!id || !username) {
                return { title: "Error", metadata: {}, output: "Error: data.id and data.username are required for add_credential." }
              }
              const cred = {
                cred_type: d.cred_type || "password",
                username,
                value: d.value || "",
                source: d.source || "",
                valid_for: d.valid_for || [],
                confidence: d.confidence as number | undefined,
                domain: d.domain as string | undefined,
                ticket_type: d.ticket_type as string | undefined,
                service_principal: d.service_principal as string | undefined,
                ticket_expiry: d.ticket_expiry as string | undefined,
              } as Omit<EngagementSchema.Credential, "id">
              yield* store.addCredential(id, cred)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.CredentialFound, {
                timestamp: Date.now(),
                engagementID: state.id,
                credId: id,
                username,
                credType: d.cred_type as string || "password",
              })
              return {
                title: `Cred: ${username}`,
                metadata: { id, username },
                output: `Credential added: ${username} (${d.cred_type || "password"}) id:${id}${d.source ? ` source:${d.source}` : ""}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "delete_credential": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for delete_credential." }
              }
              const deleted = yield* store.deleteCredential(id)
              if (!deleted) {
                return { title: "Error", metadata: {}, output: `Credential "${id}" not found.` }
              }
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Cred deleted: ${id}`,
                metadata: { id },
                output: `Credential "${id}" deleted.${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_access": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const hostIp = d.host_ip as string
              const accessType = d.access_type as string
              const username = d.username as string
              if (!hostIp || !accessType || !username) {
                return {
                  title: "Error",
                  metadata: {},
                  output: "Error: data.host_ip, data.access_type, and data.username are required for add_access.",
                }
              }
              if (!state.hosts[hostIp]) {
                return { title: "Error", metadata: {}, output: `Error: Host ${hostIp} not found. Add the host first.` }
              }
              const access = {
                access_type: accessType,
                username,
                level: d.level || "user",
                confidence: d.confidence as number | undefined,
                credential_id: d.credential_id,
                details: d.details || "",
              } as EngagementSchema.Access
              yield* store.addAccess(hostIp, access)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.AccessGained, {
                timestamp: Date.now(),
                engagementID: state.id,
                hostIp,
                username,
                level: access.level ?? "user",
                accessType,
              })
              return {
                title: `Access: ${hostIp}`,
                metadata: { host_ip: hostIp, username, level: access.level },
                output: `Access added to ${hostIp}: ${accessType} as ${username} (${access.level ?? "user"})${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "set_phase": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const phase = d.phase as EngagementSchema.PentestPhase
              if (!phase) {
                return { title: "Error", metadata: {}, output: "Error: data.phase is required for set_phase." }
              }
              const oldPhase = state.current_phase
              yield* store.setPhase(phase)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.PhaseTransitioned, {
                timestamp: Date.now(),
                engagementID: state.id,
                from: oldPhase,
                to: phase,
              })
              return {
                title: `Phase: ${phase}`,
                metadata: { old_phase: oldPhase, new_phase: phase },
                output: `Phase changed: ${oldPhase} -> ${phase}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "set_mode": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const mode = d.mode as EngagementSchema.PentestMode
              if (!mode) {
                return { title: "Error", metadata: {}, output: "Error: data.mode is required for set_mode." }
              }
              const oldMode = state.mode
              yield* store.setMode(mode)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Mode: ${mode}`,
                metadata: { old_mode: oldMode, new_mode: mode },
                output: `Mode changed: ${oldMode} -> ${mode}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "update_scope": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const scopeUpdate: Partial<{ -readonly [K in keyof EngagementSchema.Scope]: EngagementSchema.Scope[K] }> = {}
              if (d.targets) scopeUpdate.targets = d.targets as string[]
              if (d.excludes) scopeUpdate.excludes = d.excludes as string[]
              if (d.notes !== undefined) scopeUpdate.notes = d.notes as string
              yield* store.updateScope(scopeUpdate)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              const scope = updated?.scope ?? state.scope
              yield* events.publish(PentestEvent.ScopeUpdated, {
                timestamp: Date.now(),
                engagementID: state.id,
                targets: scope.targets,
                excludes: scope.excludes,
              })
              return {
                title: "Scope updated",
                metadata: {},
                output: `Scope updated. Targets: ${scope.targets.join(", ") || "(none)"}. Excludes: ${scope.excludes.join(", ") || "(none)"}${scope.notes ? `. Notes: ${scope.notes}` : ""}`,
              }
            }

            case "add_flag": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const flag = d.flag as string
              if (!flag) {
                return { title: "Error", metadata: {}, output: "Error: data.flag is required for add_flag." }
              }
              const updated = { ...state, flags: [...state.flags, flag] }
              yield* store.save(updated)
              yield* events.publish(PentestEvent.FlagCaptured, {
                timestamp: Date.now(),
                engagementID: state.id,
                flag,
                totalCount: updated.flags.length,
              })
              return {
                title: `Flag captured`,
                metadata: { flag, count: updated.flags.length },
                output: `Flag captured (#${updated.flags.length}): ${flag}\n${countsLine(updated)}`,
              }
            }

            case "add_note": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const note = d.note as string
              if (!note) {
                return { title: "Error", metadata: {}, output: "Error: data.note is required for add_note." }
              }
              const updated = { ...state, notes: [...state.notes, note] }
              yield* store.save(updated)
              return {
                title: "Note added",
                metadata: { count: updated.notes.length },
                output: `Note added (#${updated.notes.length}): ${note}`,
              }
            }

            case "add_attack_step": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const source = d.source as string
              const target = d.target as string
              const technique = d.technique as string
              const result = d.result as string
              if (!source || !target || !technique || !result) {
                return {
                  title: "Error",
                  metadata: {},
                  output: "Error: data.source, data.target, data.technique, and data.result are required for add_attack_step.",
                }
              }
              const step = {
                timestamp: new Date().toISOString(),
                source,
                target,
                technique,
                result,
                success: d.success !== undefined ? Boolean(d.success) : true,
                mitre_attack_id: d.mitre_attack_id as string | undefined,
              } as EngagementSchema.AttackStep
              const updated = { ...state, attack_path: [...state.attack_path, step] }
              yield* store.save(updated)
              yield* events.publish(PentestEvent.AttackStepRecorded, {
                timestamp: Date.now(),
                engagementID: state.id,
                source,
                target,
                technique,
                success: step.success ?? true,
              })
              return {
                title: `Attack: ${technique}`,
                metadata: { source, target, technique, success: step.success },
                output: `Attack step recorded: ${source} -> ${target} via ${technique} (${step.success ? "SUCCESS" : "FAILED"}): ${result}${step.mitre_attack_id ? ` [${step.mitre_attack_id}]` : ""}\n${countsLine(updated)}`,
              }
            }

            case "set_domain": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const domainName = d.domain_name as string
              if (!domainName) {
                return { title: "Error", metadata: {}, output: "Error: data.domain_name is required for set_domain." }
              }
              const domain: EngagementSchema.DomainState = {
                domain_name: domainName,
                forest: d.forest as string | undefined,
                domain_sid: d.domain_sid as string | undefined,
                domain_controllers: d.domain_controllers as string[] | undefined,
                domain_admins: d.domain_admins as string[] | undefined,
                gpo_names: d.gpo_names as string[] | undefined,
                trusts: d.trusts as EngagementSchema.Trust[] | undefined,
                password_policy: d.password_policy as EngagementSchema.DomainState["password_policy"],
              }
              yield* store.setDomain(domain)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Domain: ${domainName}`,
                metadata: { domain: domainName },
                output: `Domain set: ${domainName}${domain.forest ? ` forest:${domain.forest}` : ""}${domain.domain_controllers?.length ? ` DCs:${domain.domain_controllers.join(",")}` : ""}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "update_domain": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              if (!state.domain) {
                return { title: "Error", metadata: {}, output: "No domain set. Use set_domain first." }
              }
              const patch: Record<string, unknown> = {}
              for (const key of ["domain_name", "forest", "domain_sid", "domain_controllers", "domain_admins", "gpo_names", "trusts", "password_policy"]) {
                if (d[key] !== undefined) patch[key] = d[key]
              }
              yield* store.updateDomain(patch)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              const changedFields = Object.keys(patch).join(", ")
              return {
                title: `Domain updated`,
                metadata: { changed: changedFields },
                output: `Domain "${state.domain.domain_name}" updated (${changedFields}).${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_objective": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              const title = d.title as string
              if (!id || !title) {
                return { title: "Error", metadata: {}, output: "Error: data.id and data.title are required for add_objective." }
              }
              const objective: EngagementSchema.Objective = {
                id,
                title,
                description: d.description as string | undefined,
                status: (d.status as EngagementSchema.ObjectiveStatus) || "not_started",
                priority: d.priority as EngagementSchema.ObjectivePriority | undefined,
                category: d.category as EngagementSchema.ObjectiveCategory | undefined,
                target_hosts: d.target_hosts as string[] | undefined,
                linked_vulns: d.linked_vulns as string[] | undefined,
                linked_creds: d.linked_creds as string[] | undefined,
                flags: d.flags as string[] | undefined,
                evidence: d.evidence as string | undefined,
                notes: d.notes as string | undefined,
              }
              yield* store.addObjective(objective)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              yield* events.publish(PentestEvent.ObjectiveAdded, {
                timestamp: Date.now(),
                engagementID: state.id,
                objectiveId: id,
                title,
                priority: objective.priority,
                category: objective.category,
              })
              return {
                title: `Objective: ${title}`,
                metadata: { id, priority: objective.priority },
                output: `Objective added: [${id}] "${title}" (${objective.status})${objective.priority ? ` priority:${objective.priority}` : ""}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "update_objective": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for update_objective." }
              }
              const objectives = state.objectives ?? {}
              if (!objectives[id]) {
                const available = Object.keys(objectives)
                return {
                  title: "Error",
                  metadata: {},
                  output: `Objective "${id}" not found.${available.length > 0 ? ` Known: ${available.join(", ")}` : " No objectives defined."}`,
                }
              }
              const patch: Record<string, unknown> = {}
              if (d.title !== undefined) patch.title = d.title
              if (d.description !== undefined) patch.description = d.description
              if (d.status !== undefined) patch.status = d.status
              if (d.priority !== undefined) patch.priority = d.priority
              if (d.category !== undefined) patch.category = d.category
              if (d.target_hosts !== undefined) patch.target_hosts = d.target_hosts
              if (d.linked_vulns !== undefined) patch.linked_vulns = d.linked_vulns
              if (d.linked_creds !== undefined) patch.linked_creds = d.linked_creds
              if (d.flags !== undefined) patch.flags = d.flags
              if (d.evidence !== undefined) patch.evidence = d.evidence
              if (d.notes !== undefined) patch.notes = d.notes
              yield* store.updateObjective(id, patch)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              const changedFields = Object.keys(patch).join(", ")
              yield* events.publish(PentestEvent.ObjectiveUpdated, {
                timestamp: Date.now(),
                engagementID: state.id,
                objectiveId: id,
                field: changedFields,
                newValue: JSON.stringify(patch),
              })
              return {
                title: `Objective updated: ${id}`,
                metadata: { id, changed: changedFields },
                output: `Objective "${id}" updated (${changedFields}).${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "complete_objective": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const id = d.id as string
              if (!id) {
                return { title: "Error", metadata: {}, output: "Error: data.id is required for complete_objective." }
              }
              const objectives = state.objectives ?? {}
              if (!objectives[id]) {
                return { title: "Error", metadata: {}, output: `Objective "${id}" not found.` }
              }
              const evidence = d.evidence as string | undefined
              yield* store.completeObjective(id, evidence)
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              const obj = objectives[id]!
              const completedCount = Object.values(updated?.objectives ?? {}).filter((o) => o.status === "completed").length
              const totalCount = Object.keys(updated?.objectives ?? {}).length
              yield* events.publish(PentestEvent.ObjectiveCompleted, {
                timestamp: Date.now(),
                engagementID: state.id,
                objectiveId: id,
                title: obj.title,
              })
              return {
                title: `Objective completed: ${obj.title}`,
                metadata: { id, completed: completedCount, total: totalCount },
                output: `Objective "${obj.title}" [${id}] COMPLETED.${evidence ? ` Evidence: ${evidence}` : ""}\nProgress: ${completedCount}/${totalCount} objectives.${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "add_relationship": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const sourceType = d.source_type as string
              const sourceId = d.source_id as string
              const relType = d.rel_type as string
              const targetType = d.target_type as string
              const targetId = d.target_id as string
              if (!sourceType || !sourceId || !relType || !targetType || !targetId) {
                return {
                  title: "Error",
                  metadata: {},
                  output: "Error: data.source_type, data.source_id, data.rel_type, data.target_type, and data.target_id are required for add_relationship.",
                }
              }
              const rel = {
                source_type: sourceType,
                source_id: sourceId,
                rel_type: relType,
                target_type: targetType,
                target_id: targetId,
                metadata: d.metadata as string | undefined,
              } as EngagementSchema.Relationship
              const added = yield* store.addRelationship(rel)
              if (!added) {
                return {
                  title: "Relationship exists",
                  metadata: {},
                  output: `Relationship already exists: ${sourceType}:${sourceId} --[${relType}]--> ${targetType}:${targetId}`,
                }
              }
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Rel: ${relType}`,
                metadata: { source: sourceId, target: targetId, rel_type: relType },
                output: `Relationship added: ${sourceType}:${sourceId} --[${relType}]--> ${targetType}:${targetId}${d.metadata ? ` (${d.metadata})` : ""}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            case "delete_relationship": {
              const state = yield* store.get()
              if (!state) return { title: "Error", metadata: {}, output: NO_ENGAGEMENT }
              const sourceId = d.source_id as string
              const relType = d.rel_type as string
              const targetId = d.target_id as string
              if (!sourceId || !relType || !targetId) {
                return {
                  title: "Error",
                  metadata: {},
                  output: "Error: data.source_id, data.rel_type, and data.target_id are required for delete_relationship.",
                }
              }
              const deleted = yield* store.deleteRelationship(sourceId, relType, targetId)
              if (!deleted) {
                return { title: "Error", metadata: {}, output: `Relationship not found: ${sourceId} --[${relType}]--> ${targetId}` }
              }
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Rel deleted`,
                metadata: { source: sourceId, target: targetId },
                output: `Relationship deleted: ${sourceId} --[${relType}]--> ${targetId}${updated ? `\n${countsLine(updated)}` : ""}`,
              }
            }

            default: {
              return { title: "Error", metadata: {}, output: `Unknown action: ${params.action}` }
            }
          }
        }).pipe(Effect.orDie),
    }
  }),
)

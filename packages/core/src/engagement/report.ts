import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { Schema } from "effect"
import { EngagementSchema } from "./schema"
import { ScopeMatcher } from "./scope-matcher"
import { Evidence } from "../cyber/evidence"
import { FindingLifecycle } from "../cyber/finding-lifecycle"
import { FindingStore } from "../cyber/finding-store"

export const SECTIONS = [
  "executive_summary",
  "objectives",
  "scope",
  "findings",
  "attack_path",
  "credentials",
  "recommendations",
] as const
export type Section = (typeof SECTIONS)[number]
export type Format = "markdown" | "json" | "html"
const severityOrder = ["critical", "high", "medium", "low", "info"]

function redactor(state: EngagementSchema.State) {
  const secrets = Object.values(state.credentials)
    .flatMap((credential) => {
      if (!credential.value) return []
      return [
        credential.value,
        encodeURIComponent(credential.value),
        ...(credential.username ? [Buffer.from(`${credential.username}:${credential.value}`).toString("base64")] : []),
      ]
    })
    .concat([...state.flags])
    .filter(Boolean)
    .sort((a, b) => b.length - a.length)
  return (text: string) => secrets.reduce((value, secret) => value.split(secret).join("[REDACTED]"), text)
}

export function redact(state: EngagementSchema.State, input: unknown): unknown {
  const clean = redactor(state)
  function visit(value: unknown): unknown {
    if (typeof value === "string") return clean(value)
    if (Array.isArray(value)) return value.map(visit)
    if (value && typeof value === "object")
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, visit(item)]))
    return value
  }
  return visit(input)
}

export async function build(input: EngagementSchema.State, selected: readonly Section[] = SECTIONS) {
  const state = (() => {
    try {
      return Schema.decodeUnknownSync(EngagementSchema.State)(input)
    } catch {
      throw new Error("Engagement report input is malformed; sensitive state is not displayed")
    }
  })()
  const clean = redactor(state)
  const ledger = await FindingStore.load(state.name)
  const records = FindingLifecycle.normalizeFindingRecords(ledger)
  await Evidence.list(state.name)
  const findings = await Promise.all(
    records.map(async (record) => {
      const reasons: string[] = []
      const resolution = FindingLifecycle.isVerifiedResolution(record)
      if (!FindingLifecycle.isReportableFinding(record) && !resolution) {
        if (record.superseded_by) reasons.push("Superseded finding")
        if (record.status !== "verified") reasons.push(`Finding status: ${record.status}`)
        if (!record.evidence_refs.length) reasons.push("No evidence references")
        if (!record.replay.present && !record.replay.exemption?.rationale.trim())
          reasons.push("No replay material or reasoned exemption")
      }
      if (record.target) {
        const scope = ScopeMatcher.checkScope(record.target, state.scope)
        if (!scope.inScope) reasons.push("Target is outside the current authorized scope")
      } else reasons.push("Affected target is not recorded")
      const revisions = ledger.filter((revision) => revision.id === record.id)
      const refs = [
        ...new Set(
          revisions.flatMap((revision) => [
            ...revision.evidence_refs,
            ...(revision.retests ?? []).flatMap((retest) => retest.evidence_refs),
          ]),
        ),
      ]
      const evidence = await Promise.all(
        refs.map(async (ref) => {
          try {
            const stored = await Evidence.get(state.name, ref)
            if (!stored) {
              reasons.push("Evidence artifact is missing")
              return undefined
            }
            return { ...stored.entry, label: clean(stored.entry.label), source: clean(stored.entry.source) }
          } catch (error) {
            reasons.push(error instanceof Error ? clean(error.message) : "Evidence cannot be verified")
            return undefined
          }
        }),
      )
      return {
        id: clean(record.id),
        title: clean(record.title),
        target: clean(record.target ?? "Not recorded"),
        severity: severityOrder.includes(record.severity ?? "") ? record.severity! : "info",
        status: record.status,
        detail: clean(record.detail ?? ""),
        owner: clean(record.owner?.trim() || "Unassigned"),
        reviewer: clean(record.reviewer?.trim() || "Not recorded"),
        impact: clean(record.impact?.trim() || "Not recorded"),
        remediation: clean(record.remediation?.trim() || "Not recorded"),
        reproduction_steps: (record.reproduction_steps ?? []).map(clean),
        review_note: clean(record.review_note ?? ""),
        retests: (record.retests ?? []).map((retest) => ({
          outcome: retest.outcome,
          reviewer: clean(retest.reviewer),
          note: clean(retest.note),
          at: clean(retest.at),
          evidence_refs: retest.evidence_refs.map(clean),
        })),
        history: revisions.map((revision) => ({
          status: revision.status,
          at: clean(revision.at),
          reviewer: clean(revision.reviewer ?? "Not recorded"),
          note: clean(revision.review_note ?? ""),
          evidence_refs: revision.evidence_refs.map(clean),
        })),
        replay: record.replay.present
          ? { present: true }
          : {
              present: false,
              exemption: record.replay.exemption
                ? { category: record.replay.exemption.category, rationale: clean(record.replay.exemption.rationale) }
                : undefined,
            },
        evidence: evidence.filter((entry) => entry !== undefined),
        reasons: [...new Set(reasons)],
        reportable: record.status === "verified" && reasons.length === 0,
        resolved: resolution && reasons.length === 0,
        recorded_at: clean(record.at),
        superseded_by: record.superseded_by ? clean(record.superseded_by) : undefined,
      }
    }),
  )
  const verified = findings
    .filter((finding) => finding.reportable)
    .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity) || a.id.localeCompare(b.id))
  const excluded = findings.filter(
    (finding) => finding.superseded_by || finding.status === "rejected" || finding.status === "stale",
  )
  const resolved = findings.filter((finding) => finding.resolved)
  const pending = findings.filter((finding) => !finding.reportable && !finding.resolved && !excluded.includes(finding))
  const linked = new Set(records.map((record) => record.id))
  const observations = Object.entries(state.hosts).flatMap(([target, host]) =>
    host.vulns.flatMap((vuln) => {
      if (vuln.id && linked.has(vuln.id)) return []
      if (vuln.status === "false_positive") return []
      return [
        {
          id: clean(
            vuln.id ??
              `obs_${createHash("sha256")
                .update(JSON.stringify([target, vuln.service_port, vuln.title]))
                .digest("hex")
                .slice(0, 16)}`,
          ),
          title: clean(vuln.title),
          target: clean(`${target}${vuln.service_port === undefined ? "" : `:${vuln.service_port}`}`),
          severity: vuln.severity ?? "info",
          reported_status: vuln.status ?? "suspected",
          detail: clean(vuln.description ?? ""),
          reasons: ["Scanner observation requires finding promotion with stored evidence and replay or exemption"],
        },
      ]
    }),
  )
  const summary = {
    reportable_findings: verified.length,
    resolved_findings: resolved.length,
    awaiting_verification: pending.length + observations.length,
    excluded_findings:
      excluded.length +
      Object.values(state.hosts)
        .flatMap((host) => host.vulns)
        .filter((vuln) => vuln.status === "false_positive" && (!vuln.id || !linked.has(vuln.id))).length,
    severity: Object.fromEntries(
      severityOrder.map((severity) => [severity, verified.filter((finding) => finding.severity === severity).length]),
    ),
    hosts_observed: Object.keys(state.hosts).length,
    credentials_recorded: Object.keys(state.credentials).length,
    snapshot_review: pending.length + observations.length ? "requires_review" : "no_pending_findings",
    phase: state.current_phase,
    mode: state.mode,
  }
  const sections = {
    executive_summary: summary,
    objectives: Object.values(state.objectives ?? {}).map((objective) => ({
      id: clean(objective.id),
      title: clean(objective.title),
      status: objective.status,
      priority: objective.priority,
      description: clean(objective.description ?? ""),
      evidence: clean(objective.evidence ?? ""),
    })),
    scope: {
      targets: state.scope.targets.map(clean),
      excludes: state.scope.excludes.map(clean),
      discovered_not_authorized: (state.scope.discovered_targets ?? []).map(clean),
      notes: clean(state.scope.notes ?? ""),
    },
    findings: { verified, resolved, verification_queue: [...pending, ...observations], excluded },
    attack_path: state.attack_path.map((step) => ({
      timestamp: clean(step.timestamp),
      source: clean(step.source),
      target: clean(step.target),
      technique: clean(step.technique),
      result: clean(step.result),
      success: step.success,
      mitre_attack_id: step.mitre_attack_id ? clean(step.mitre_attack_id) : undefined,
    })),
    credentials: Object.values(state.credentials).map((credential) => ({
      id: clean(credential.id),
      username: clean(credential.username ?? ""),
      type: clean(credential.cred_type ?? "password"),
      source: clean(credential.source ?? ""),
      valid_for: (credential.valid_for ?? []).map(clean),
      value: "[REDACTED]",
    })),
    recommendations: verified.map((finding) => ({
      finding_id: finding.id,
      priority: finding.severity,
      owner: finding.owner,
      action:
        finding.remediation !== "Not recorded"
          ? finding.remediation
          : `Record remediation guidance and retest ${finding.title} on ${finding.target}; retain the original evidence and record the new result.`,
    })),
  }
  const evidence = [
    ...new Map(
      [...verified, ...resolved].flatMap((finding) => finding.evidence).map((entry) => [entry.sha256, entry]),
    ).values(),
  ]
  return {
    format_version: 1,
    engagement: {
      id: clean(state.id),
      name: clean(state.name),
      created_at: clean(state.created_at),
      snapshot_at: clean(state.updated_at),
    },
    policy: {
      human_review_required: true,
      verification:
        "Operator-recorded verification; evidence bytes checked against SHA-256. Replay material is recorded, not independently re-executed by this exporter.",
      retest:
        "Operator-recorded retests are required for resolution. Reviewer labels and outcomes are recorded assertions; absence from a scan never closes a finding.",
      coverage: "A snapshot of recorded findings, not proof that every authorized asset or vulnerability was tested.",
      redaction:
        "Credential values and known credentials in text are redacted; inspect other sensitive information before sharing. Raw evidence blobs are not embedded.",
    },
    summary,
    evidence_manifest: selected.includes("findings") ? evidence : [],
    sections: Object.fromEntries(selected.map((section) => [section, sections[section]])) as Partial<typeof sections>,
  }
}

export type Data = Awaited<ReturnType<typeof build>>

function markdown(text: string) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/([\\`*_{}\[\]#|])/g, "\\$1")
    .replace(/\r?\n/g, " ")
}

export function renderMarkdown(data: Data) {
  const out = [
    `# KevlarRedOps · Assessment report`,
    "",
    `**Engagement:** ${markdown(data.engagement.name)}`,
    `**Snapshot:** ${markdown(data.engagement.snapshot_at)}`,
    "",
    "> Operator review required. This snapshot does not establish complete assessment coverage.",
    "",
  ]
  const sections = data.sections
  if (sections.executive_summary) {
    out.push(
      "## Executive summary",
      "",
      `- Verified, reportable findings: **${data.summary.reportable_findings}**`,
      `- Resolved with retest: **${data.summary.resolved_findings}**`,
      `- Awaiting verification: **${data.summary.awaiting_verification}**`,
      `- Excluded / rejected: **${data.summary.excluded_findings}**`,
      `- Hosts observed: **${data.summary.hosts_observed}**`,
      "",
    )
  }
  if (sections.scope) {
    out.push(
      "## Authorized scope",
      "",
      "Targets:",
      ...sections.scope.targets.map((target) => `- ${markdown(target)}`),
      "",
      "Exclusions:",
      ...sections.scope.excludes.map((target) => `- ${markdown(target)}`),
      "",
      "Discovered targets do not extend authorization:",
      ...sections.scope.discovered_not_authorized.map((target) => `- ${markdown(target)}`),
      "",
      markdown(sections.scope.notes),
      "",
    )
  }
  if (sections.findings) {
    out.push("## Reviewed findings · verified and resolved", "")
    if (!sections.findings.verified.length) out.push("No findings currently meet the reporting gate.", "")
    for (const finding of [...sections.findings.verified, ...sections.findings.resolved]) {
      out.push(
        `### ${markdown(finding.title)}`,
        "",
        `- ID: ${markdown(finding.id)}`,
        `- Target: ${markdown(finding.target)}`,
        `- Severity: ${finding.severity}`,
        `- Verification: ${finding.status}`,
        `- Owner: ${markdown(finding.owner)}`,
        `- Reviewer label: ${markdown(finding.reviewer)}`,
        "",
        markdown(finding.detail),
        "",
        `**Impact:** ${markdown(finding.impact)}`,
        `**Remediation:** ${markdown(finding.remediation)}`,
        "",
        "Reproduction steps:",
        ...finding.reproduction_steps.map((step, index) => `${index + 1}. ${markdown(step)}`),
        "",
        "Retest history:",
        ...finding.retests.map(
          (retest) =>
            `- ${markdown(retest.at)} · ${retest.outcome} · ${markdown(retest.reviewer)}: ${markdown(retest.note)} · ${retest.evidence_refs.map(markdown).join(", ")}`,
        ),
        "",
        finding.replay.present
          ? "Replay material recorded."
          : `Replay exemption: ${markdown(finding.replay.exemption?.rationale ?? "")}`,
        "",
        "Evidence:",
        ...finding.evidence.map(
          (entry) => `- SHA-256: \`${entry.sha256}\` · ${entry.size} bytes · ${markdown(entry.label)}`,
        ),
        "",
      )
    }
    out.push("## Verification queue", "")
    if (!sections.findings.verification_queue.length) out.push("No pending findings.", "")
    for (const finding of sections.findings.verification_queue)
      out.push(
        `### ${markdown(finding.title)}`,
        `- Target: ${markdown(finding.target)}`,
        `- Reason: ${finding.reasons.map(markdown).join("; ")}`,
        markdown(finding.detail),
        "",
      )
    out.push(
      `Resolved with retest: ${sections.findings.resolved.length}. Excluded ledger findings: ${sections.findings.excluded.length}. Rejected and stale findings are not remediation recommendations.`,
      "",
    )
  }
  if (sections.objectives) {
    out.push("## Objectives", "")
    for (const objective of sections.objectives)
      out.push(
        `- **${markdown(objective.title)}** · ${objective.status} · ${markdown(objective.description)}`,
        ...(objective.evidence ? [`  Evidence: ${markdown(objective.evidence)}`] : []),
      )
    out.push("")
  }
  if (sections.attack_path) {
    out.push(
      "## Recorded attack path",
      "",
      "| Time | Source | Target | Technique | Result |",
      "| --- | --- | --- | --- | --- |",
    )
    for (const step of sections.attack_path)
      out.push(
        `| ${markdown(step.timestamp)} | ${markdown(step.source)} | ${markdown(step.target)} | ${markdown(step.technique)} | ${step.success ? "Success" : "Failed"}: ${markdown(step.result)} |`,
      )
    out.push("")
  }
  if (sections.credentials) {
    out.push(
      "## Credentials · values redacted",
      "",
      "| Username | Type | Source | Valid for |",
      "| --- | --- | --- | --- |",
    )
    for (const credential of sections.credentials)
      out.push(
        `| ${markdown(credential.username)} | ${markdown(credential.type)} | ${markdown(credential.source)} | ${credential.valid_for.map(markdown).join(", ")} |`,
      )
    out.push("")
  }
  if (sections.recommendations) {
    out.push(
      "## Remediation and retest",
      "",
      ...sections.recommendations.map(
        (item) => `- **${item.priority} · ${markdown(item.finding_id)}**: ${markdown(item.action)}`,
      ),
      "",
    )
    if (!sections.recommendations.length) out.push("Validate queued observations before making remediation claims.", "")
  }
  out.push(
    "## Report policy",
    "",
    data.policy.verification,
    "",
    data.policy.retest,
    "",
    data.policy.coverage,
    "",
    data.policy.redaction,
  )
  return out.join("\n")
}

function escape(text: string) {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
}

export function renderHtml(data: Data) {
  const sections = data.sections
  const body: string[] = []
  const heading = (title: string) => `<h2>${escape(title)}</h2>`
  const table = (headers: string[], rows: string[][]) =>
    `<div class="table-wrap"><table><thead><tr>${headers.map((header) => `<th scope="col">${escape(header)}</th>`).join("")}</tr></thead><tbody>${rows.length ? rows.map((row) => `<tr>${row.map((cell) => `<td>${escape(cell)}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${headers.length}" class="note">No records in this snapshot.</td></tr>`}</tbody></table></div>`
  if (sections.executive_summary)
    body.push(
      `<section>${heading("Assessment overview")}<div class="metrics"><div><strong>${data.summary.reportable_findings}</strong><span>Verified findings</span></div><div><strong>${data.summary.awaiting_verification}</strong><span>Awaiting verification</span></div><div><strong>${data.summary.excluded_findings}</strong><span>Excluded / rejected</span></div><div><strong>${data.summary.hosts_observed}</strong><span>Hosts observed</span></div></div><p class="note">Counts describe recorded findings. They do not establish complete assessment coverage.</p></section>`,
    )
  if (sections.scope)
    body.push(
      `<section>${heading("Authorized scope")}${table(["Authorized targets", "Exclusions", "Discovered · not authorization"], [[sections.scope.targets.join("\n") || "None recorded", sections.scope.excludes.join("\n") || "None recorded", sections.scope.discovered_not_authorized.join("\n") || "None recorded"]])}<p>${escape(sections.scope.notes)}</p></section>`,
    )
  if (sections.findings) {
    body.push(
      `<section>${heading("Reviewed findings · verified and resolved")}${sections.findings.verified.length || sections.findings.resolved.length ? "" : '<p class="empty">No finding currently meets the reporting gate.</p>'}`,
    )
    for (const finding of [...sections.findings.verified, ...sections.findings.resolved])
      body.push(
        `<article class="finding"><div class="finding-meta"><span class="badge ${finding.status === "resolved" ? "resolved" : finding.severity}">${escape(finding.status === "resolved" ? "resolved" : finding.severity)}</span><code>${escape(finding.id)}</code></div><h3>${escape(finding.title)}</h3><p class="target">${escape(finding.target)}</p><p>${escape(finding.detail)}</p>${table(["Owner", "Reviewer label"], [[finding.owner, finding.reviewer]])}<h4>Impact</h4><p>${escape(finding.impact)}</p><h4>Remediation</h4><p>${escape(finding.remediation)}</p><h4>Reproduction steps</h4><ol>${finding.reproduction_steps.map((step) => `<li>${escape(step)}</li>`).join("")}</ol><h4>Retest history</h4>${table(
          ["Time", "Outcome", "Reviewer", "Note", "Evidence SHA-256"],
          finding.retests.map((retest) => [
            retest.at,
            retest.outcome,
            retest.reviewer,
            retest.note,
            retest.evidence_refs.join("\n"),
          ]),
        )}<p class="note">${finding.replay.present ? "Replay material recorded; operator review required." : `Replay exemption: ${escape(finding.replay.exemption?.rationale ?? "")}`}</p>${table(
          ["SHA-256", "Bytes", "Evidence label"],
          finding.evidence.map((entry) => [entry.sha256, String(entry.size), entry.label]),
        )}</article>`,
      )
    body.push(
      `</section><section>${heading("Verification queue")}<p class="note">These observations are not confirmed vulnerabilities. Resolved with retest: ${sections.findings.resolved.length}.</p>${table(
        ["Observation", "Target", "Reason"],
        sections.findings.verification_queue.map((finding) => [
          finding.title,
          finding.target,
          finding.reasons.join("; "),
        ]),
      )}<p>${sections.findings.excluded.length} rejected or stale ledger findings excluded from remediation.</p></section>`,
    )
  }
  if (sections.objectives)
    body.push(
      `<section>${heading("Objectives")}${table(
        ["Objective", "Status", "Evidence"],
        sections.objectives.map((objective) => [objective.title, objective.status, objective.evidence]),
      )}</section>`,
    )
  if (sections.attack_path)
    body.push(
      `<section>${heading("Recorded attack path")}${table(
        ["Time", "Source", "Target", "Technique", "Result"],
        sections.attack_path.map((step) => [
          step.timestamp,
          step.source,
          step.target,
          step.technique,
          `${step.success ? "Success" : "Failed"}: ${step.result}`,
        ]),
      )}</section>`,
    )
  if (sections.credentials)
    body.push(
      `<section>${heading("Credentials · values redacted")}${table(
        ["Username", "Type", "Source", "Valid for"],
        sections.credentials.map((credential) => [
          credential.username,
          credential.type,
          credential.source,
          credential.valid_for.join(", "),
        ]),
      )}</section>`,
    )
  if (sections.recommendations)
    body.push(
      `<section>${heading("Remediation and retest")}<ul>${sections.recommendations.map((item) => `<li><strong>${escape(item.finding_id)}</strong> · ${escape(item.action)}</li>`).join("")}</ul>${sections.recommendations.length ? "" : "<p>Validate queued observations before making remediation claims.</p>"}</section>`,
    )
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'"><title>${escape(data.engagement.name)} · KevlarRedOps report</title><style>
:root{color-scheme:light;--ink:#1c2927;--paper:#f6f4ee;--line:#d4d9d1;--accent:#b7472e}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.65 system-ui,sans-serif}main{max-width:1100px;margin:auto;padding:56px 36px}header{border-top:6px solid var(--ink);border-bottom:1px solid var(--line);padding:26px 0 32px}.eyebrow{font:600 12px/1.4 monospace;letter-spacing:.18em;text-transform:uppercase;color:var(--accent)}h1{font:500 clamp(32px,5vw,60px)/1.12 Georgia,serif;overflow-wrap:anywhere;margin:18px 0}h2{font:500 30px/1.25 Georgia,serif;margin:0 0 24px}h3{font:600 22px/1.35 system-ui;margin:12px 0}section{padding:36px 0;border-bottom:1px solid var(--line)}.subtitle,.note{color:#54645c;font-size:14px}.review{border-left:3px solid var(--accent);padding:12px 18px;background:#efe6da;margin-top:22px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line)}.metrics div{background:var(--paper);padding:22px}.metrics strong{display:block;font:500 48px/1.1 Georgia,serif}.metrics span{font-size:13px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left;font-size:14px}th{font-size:12px;text-transform:uppercase;letter-spacing:.05em;padding:12px 10px;background:#e8ece5}td{padding:14px 10px;border-bottom:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere;vertical-align:top}code{font:12px monospace;overflow-wrap:anywhere}.finding{padding:24px;border:1px solid var(--line);margin:18px 0;background:#fffdf8;break-inside:avoid}.finding-meta{display:flex;align-items:center;gap:14px}.badge{font-size:11px;font-weight:700;text-transform:uppercase;background:#e6ebe2;padding:4px 10px}.resolved{background:#d6e8d8;color:#254c35}.critical,.high{background:#f6d9cf;color:#822b20}.medium{background:#f0e2bf;color:#6b5416}.target{font:13px monospace;color:#54645c}.empty{border:1px dashed var(--line);padding:18px}footer{font-size:12px;color:#54645c;margin-top:28px}p{overflow-wrap:anywhere;white-space:pre-wrap}@media(max-width:700px){main{padding:24px 18px}.metrics{grid-template-columns:repeat(2,1fr)}.metrics div{padding:16px}.finding{padding:16px}}@media print{body{background:white;font-size:11px}main{padding:0;max-width:none}header{padding:12px 0}h1{font-size:36px}h2{font-size:24px}section{padding:20px 0}.metrics strong{font-size:32px}table{font-size:11px}thead{display:table-header-group}.table-wrap{overflow:visible}.finding{background:white}}
</style></head><body><main><header><div class="eyebrow">KevlarRedOps / assessment report</div><h1>${escape(data.engagement.name)}</h1><p class="subtitle">Snapshot ${escape(data.engagement.snapshot_at)} · ${escape(data.summary.phase)} · ${escape(data.summary.mode)}</p><div class="review"><strong>Operator review required.</strong> Verified entries have stored evidence with matching hashes. Replay material is recorded; this exporter does not re-execute it.</div></header>${body.join("")}<footer><strong>Report policy</strong><p>${escape(data.policy.retest)}</p><p>${escape(data.policy.coverage)}</p><p>${escape(data.policy.redaction)}</p></footer></main></body></html>`
}

export function render(data: Data, format: Format) {
  if (format === "json") return JSON.stringify(data, null, 2)
  if (format === "html") return renderHtml(data)
  return renderMarkdown(data)
}

export async function write(destination: string, output: string) {
  const file = path.resolve(destination)
  await fs.mkdir(path.dirname(file), { recursive: true })
  const temporary = `${file}.${crypto.randomUUID()}.tmp`
  try {
    await fs.writeFile(temporary, output, { mode: 0o600 })
    await fs.rename(temporary, file)
  } finally {
    await fs.rm(temporary, { force: true })
  }
  return { path: file, bytes: Buffer.byteLength(output), sha256: createHash("sha256").update(output).digest("hex") }
}

export * as EngagementReport from "./report"

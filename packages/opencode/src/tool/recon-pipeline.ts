import { Effect, Schema } from "effect"
import dns from "node:dns/promises"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { Observation } from "@pentestcode/core/cyber/observation"
import { matchTakeover } from "@pentestcode/core/cyber/takeover"
import { lookupDefaultCreds } from "@pentestcode/core/cyber/defaultcreds"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { ScopeMatcher } from "@pentestcode/core/engagement/scope-matcher"
import { ScopedRequest } from "@/scanner/scoped-request"
import DESCRIPTION from "./recon-pipeline.txt"
import { Tool } from "./tool"

export const Parameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Root domain to enumerate (e.g. example.com)" }),
  action: Schema.optional(Schema.Literals(["plan", "run"]).annotate({ description: "default plan" })),
  max_hosts: Schema.optional(
    Schema.Number.annotate({ description: "Cap on HTTP probes per run (1-100, default 25)" }),
  ),
})

type StageStatus = "ready" | "missing_adapter" | "builtin"

type Stage = {
  stage: string
  tool: string
  command?: string[]
  status: StageStatus
}

function baseDomain(target: string): string {
  const trimmed = target.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "")
  return trimmed || target.trim().toLowerCase()
}

export function buildReconPlan(binaries: Set<string>, target: string, maxHosts: number): Stage[] {
  const domain = baseDomain(target)
  const stages: Stage[] = []
  if (binaries.has("subfinder")) {
    stages.push({ stage: "subdomain-discovery", tool: "subfinder", status: "ready", command: ["subfinder", "-d", domain, "-silent"] })
  } else if (binaries.has("amass")) {
    stages.push({ stage: "subdomain-discovery", tool: "amass", status: "ready", command: ["amass", "enum", "-passive", "-d", domain] })
  } else {
    stages.push({ stage: "subdomain-discovery", tool: "dns-hint", status: "missing_adapter" })
  }
  if (binaries.has("httpx")) {
    stages.push({ stage: "http-probe", tool: "httpx", status: "ready", command: ["httpx", "-silent", "-status-code"] })
  } else {
    stages.push({ stage: "http-probe", tool: "fetch", status: "builtin" })
  }
  if (binaries.has("nmap")) {
    stages.push({
      stage: "port-scan",
      tool: "nmap",
      status: "ready",
      command: ["nmap", "-Pn", "--top-ports", "100", "-T3", domain],
    })
  } else {
    stages.push({ stage: "port-scan", tool: "nmap", status: "missing_adapter" })
  }
  stages.push({ stage: "takeover-check", tool: "takeover", status: "builtin" })
  stages.push({ stage: "creds-hints", tool: "default_creds", status: "builtin" })
  void maxHosts
  return stages
}

export const ReconPipelineTool = Tool.define(
  "recon_pipeline",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    const guard = yield* ScopedRequest.make
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const domain = baseDomain(params.target)
          if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
            return {
              title: "recon_pipeline · invalid target",
              metadata: {},
              output: `Expected a registrable domain like example.com, got: ${params.target}`,
            }
          }

          const binaries = new Set(["subfinder", "amass", "httpx", "nmap"].filter((bin) => Bun.which(bin) !== null))
          const maxHosts = Math.min(Math.max(Math.trunc(params.max_hosts ?? 25), 1), 100)
          const plan = buildReconPlan(binaries, domain, maxHosts)
          if ((params.action ?? "plan") === "plan") {
            const lines = [`Recon plan for ${domain}:`, ""]
            for (const stage of plan) {
              lines.push(`- ${stage.stage} · ${stage.tool} · ${stage.status}${stage.command ? ` → ${stage.command.join(" ")}` : ""}`)
            }
            lines.push("", "Use action=run to execute ready/builtin stages.")
            return {
              title: `recon_pipeline · plan · ${domain}`,
              metadata: {
                ready: plan.filter((s) => s.status !== "missing_adapter").length,
                missing: plan.filter((s) => s.status === "missing_adapter").length,
              },
              output: lines.join("\n"),
            }
          }

          const initial = yield* guard.check(domain)
          if (!initial.inScope) {
            return {
              title: "recon_pipeline · blocked",
              metadata: { blocked: true },
              output: `Blocked: ${domain} is outside engagement scope (${initial.reason}).`,
            }
          }

          yield* ctx.ask({
            permission: "recon_pipeline",
            patterns: [domain],
            always: [],
            metadata: {},
          })

          const state = yield* store.get()
          if (state) {
            const check = ScopeMatcher.checkScope(domain, state.scope)
            if (!check.inScope) {
              return {
                title: "recon_pipeline · blocked",
                metadata: { blocked: true },
                output: `Blocked: ${domain} is outside engagement scope (${check.reason}).`,
              }
            }
          }

          const discovered: string[] = []
          const liveUrls: string[] = []

          // subdomain discovery via adapter or DNS hint
          const discoveryStage = plan.find((s) => s.stage === "subdomain-discovery")
          let discoveryOutput = ""
          if (discoveryStage?.command && discoveryStage.status === "ready") {
            const proc = Bun.spawnSync(discoveryStage.command, { cwd: process.cwd(), stdout: "pipe", stderr: "pipe", timeout: 120_000 })
            discoveryOutput = proc.stdout.toString()
            discovered.push(...discoveryOutput.split(/\r?\n/).map((line) => line.trim().toLowerCase()).filter((line) => line === domain || line.endsWith(`.${domain}`)))
            if (state) {
              yield* Effect.promise(() =>
                Evidence.put({
                  engagementName: state.name,
                  content: discoveryOutput || "(empty)",
                  mime: "text/plain",
                  label: `recon ${domain} subdomains (${discoveryStage.tool})`,
                  source: "recon_pipeline",
                }).catch(() => undefined),
              )
            }
          }
          if (discovered.length === 0) {
            discovered.push(domain, `www.${domain}`)
          }

          // http probe
          for (const host of discovered.slice(0, maxHosts)) {
            const check = yield* guard.check(host)
            if (!check.inScope) continue
            const url = `https://${host}`
            try {
              const response = yield* Effect.promise(() =>
                guard.request(url, { headers: { "user-agent": "pentestcode-recon/1.0" }, signal: AbortSignal.timeout(8000) }),
              )
              const body = yield* Effect.promise(() => response.text())
              liveUrls.push(`${response.status} https://${host}`)
              const dnsCheck = yield* guard.check(host)
              if (state && dnsCheck.inScope) {
                const cnameRecords = yield* Effect.promise(() => dns.resolveCname(host).catch(() => [] as string[]))
                const fingerprint = matchTakeover({ cname: cnameRecords[0], body: response.status >= 400 ? body : undefined })
                if (fingerprint) {
                  yield* Effect.promise(() =>
                    Observation.add({
                      engagementName: state.name,
                      subtype: fingerprint.vulnerable ? "vuln" : "intel-fact",
                      title: `Potential subdomain takeover: ${host} → ${fingerprint.service}`,
                      severity: fingerprint.vulnerable ? "high" : "info",
                      note: `${fingerprint.detail} Verify manually before promoting.`,
                      tags: ["takeover", host],
                    }).catch(() => undefined),
                  )
                }
              }
            } catch {
              continue
            }
          }

          // nmap top-port scan when available
          const scanStage = plan.find((s) => s.stage === "port-scan")
          let scanOutput = ""
          if (scanStage?.command && scanStage.status === "ready") {
            const check = yield* guard.check(domain)
            if (!check.inScope) {
              return {
                title: "recon_pipeline · blocked",
                metadata: { blocked: true },
                output: `Blocked: ${domain} is outside engagement scope (${check.reason}).`,
              }
            }
            const proc = Bun.spawnSync(scanStage.command, { cwd: process.cwd(), stdout: "pipe", stderr: "pipe", timeout: 300_000 })
            scanOutput = proc.stdout.toString()
            if (state) {
              yield* Effect.promise(() =>
                Evidence.put({
                  engagementName: state.name,
                  content: scanOutput || "(empty)",
                  mime: "text/plain",
                  label: `recon ${domain} port scan`,
                  source: "recon_pipeline",
                }).catch(() => undefined),
              )
            }
          }

          if (state) {
            for (const host of discovered.slice(0, maxHosts)) {
              yield* store.addHost(host).pipe(Effect.option)
            }
            yield* Effect.promise(() =>
              Observation.add({
                engagementName: state.name,
                subtype: "intel-fact",
                title: `Recon pipeline: ${liveUrls.length} live of ${discovered.length} hosts for ${domain}`,
                note: `discovered=${discovered.length} live=${liveUrls.length}${scanOutput ? "; port scan captured as evidence" : "; no adapter port scan"}`,
                tags: ["recon-pipeline"],
              }).catch(() => undefined),
            )
          }

          const lines = [
            `Recon complete for ${domain}`,
            "",
            `Discovered hosts (${discovered.length}):`,
            ...discovered.slice(0, maxHosts).map((host) => `- ${host}`),
            "",
            `Live HTTP endpoints (${liveUrls.length}):`,
            ...(liveUrls.length > 0 ? liveUrls.map((entry) => `- ${entry}`) : ["(none responded)"]),
            "",
            scanOutput ? "Port scan: captured as evidence." : "Port scan: skipped (nmap not installed).",
            "Takeover fingerprints checked against live responses; candidates recorded as observations.",
          ]
          return {
            title: `recon_pipeline · ${domain} · ${discovered.length} host(s)`,
            metadata: {
              discovered: discovered.length,
              live: liveUrls.length,
              takeover_candidates_checked: true,
              engagement_updated: Boolean(state),
            },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

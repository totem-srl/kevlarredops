import { Effect, Schema } from "effect"
import dns from "node:dns/promises"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { Observation } from "@pentestcode/core/cyber/observation"
import { matchTakeover, type TakeoverFingerprint } from "@pentestcode/core/cyber/takeover"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { ScopeMatcher } from "@pentestcode/core/engagement/scope-matcher"
import { extractForms, extractLinks } from "@/scanner/crawl"
import { analyzeJs } from "@/scanner/js-analyzer"
import { dirFuzz, type FuzzHit } from "@/scanner/dir-fuzzer"
import DESCRIPTION from "./bounty-hunt.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Absolute http(s) URL of the bounty target" }),
  fuzz: Schema.optional(Schema.Boolean.annotate({ description: "Also run built-in directory fuzz (default false)" })),
  timeout_ms: Schema.optional(Schema.Number.annotate({ description: "Per-request timeout in ms (default 10000, max 60000)" })),
})

export type BountySignal = {
  severity: "high" | "medium" | "low" | "info"
  title: string
  detail: string
}

export const SECURITY_HEADERS: { name: string; why: string }[] = [
  { name: "content-security-policy", why: "missing Content-Security-Policy enables XSS payload persistence" },
  { name: "strict-transport-security", why: "missing HSTS allows protocol downgrade and cookie theft" },
  { name: "x-frame-options", why: "missing X-Frame-Options/frame-ancestors permits clickjacking" },
  { name: "x-content-type-options", why: "missing X-Content-Type-Options allows MIME sniffing" },
  { name: "referrer-policy", why: "missing Referrer-Policy leaks URLs (and tokens) to third parties" },
]

export function rankHeaderSignals(headers: Record<string, string>): BountySignal[] {
  const lower: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v
  const signals: BountySignal[] = []
  for (const header of SECURITY_HEADERS) {
    if (lower[header.name] === undefined) {
      signals.push({ severity: "low", title: `Missing security header: ${header.name}`, detail: header.why })
    }
  }
  const techs = [lower["server"], lower["x-powered-by"]].filter(Boolean)
  if (techs.length > 0) {
    signals.push({
      severity: "info",
      title: "Server technology disclosed",
      detail: techs.join("; "),
    })
  }
  return signals
}

export const OPENAPI_PROBE_PATHS = [
  "/openapi.json",
  "/swagger.json",
  "/api-docs",
  "/v2/api-docs",
  "/v3/api-docs",
  "/api/openapi.json",
  "/api/swagger.json",
  "/swagger/doc.json",
]

export async function discoverOpenApi(
  base: URL,
  timeoutMs: number,
): Promise<{ url: string; version: string } | undefined> {
  for (const path of OPENAPI_PROBE_PATHS) {
    try {
      const response = await fetch(new URL(path, base).toString(), {
        headers: { "user-agent": "pentestcode-bounty/1.0", accept: "application/json" },
        signal: AbortSignal.timeout(timeoutMs),
      })
      if (!response.ok) continue
      const contentType = response.headers.get("content-type") ?? ""
      if (!contentType.includes("json")) continue
      const body = (await response.json()) as unknown
      if (typeof body === "object" && body !== null) {
        const record = body as Record<string, unknown>
        const version =
          typeof record.openapi === "string"
            ? `openapi ${record.openapi}`
            : typeof record.swagger === "string"
              ? `swagger ${record.swagger}`
              : undefined
        if (version && (record.paths !== undefined || record.info !== undefined)) {
          return { url: new URL(path, base).toString(), version }
        }
      }
    } catch {
      // unreachable probe paths are expected
    }
  }
  return undefined
}

export function rankBountySignals(input: {
  secrets: { kind: string; match: string }[]
  takeover?: TakeoverFingerprint | null
  takeoverHost?: string
  endpoints: string[]
  spaRoutes: string[]
  fuzzHits: FuzzHit[]
}): BountySignal[] {
  const signals: BountySignal[] = []
  if (input.takeover && input.takeover.vulnerable) {
    signals.push({
      severity: "high",
      title: `Subdomain takeover candidate (${input.takeover.service})`,
      detail: `${input.takeoverHost ?? "host"} points at a ${input.takeover.service} endpoint: ${input.takeover.detail}`,
    })
  }
  if (input.secrets.length > 0) {
    signals.push({
      severity: "high",
      title: `${input.secrets.length} potential secret(s) in client-side JavaScript`,
      detail: input.secrets.map((s) => `${s.kind}: ${s.match.slice(0, 40)}`).join("; "),
    })
  }
  const apiEndpoints = input.endpoints.filter((e) => /\/(api|v[12])\//i.test(e))
  if (apiEndpoints.length > 0) {
    signals.push({
      severity: "medium",
      title: `${apiEndpoints.length} API endpoint(s) leaked in JS bundles`,
      detail: [...new Set(apiEndpoints)].slice(0, 15).join(", "),
    })
  }
  const interestingDirs = input.fuzzHits.filter((hit) => [200, 401, 403].includes(hit.status))
  if (interestingDirs.length > 0) {
    signals.push({
      severity: "medium",
      title: `${interestingDirs.length} interesting path(s) from directory fuzz`,
      detail: interestingDirs.map((hit) => `${hit.status} ${hit.path}`).join(", "),
    })
  }
  if (input.spaRoutes.length > 0) {
    signals.push({
      severity: "info",
      title: `${input.spaRoutes.length} SPA route(s) discovered`,
      detail: [...new Set(input.spaRoutes)].slice(0, 20).join(", "),
    })
  }
  return signals
}

function renderReport(target: string, input: {
  routes: number
  forms: number
  signals: BountySignal[]
  fuzzTested: number
  openApi?: { url: string; version: string } | undefined
}): string {
  const lines = [
    `# Bug bounty sweep · ${target}`,
    "",
    `Surface: ${input.routes} link(s), ${input.forms} form(s), ${input.fuzzTested} fuzz probe(s)`,
    "",
    "## Ranked signals",
    ...(input.signals.length > 0
      ? input.signals.map((signal) => `- [${signal.severity.toUpperCase()}] ${signal.title}\n  ${signal.detail}`)
      : ["(no signals — target looks clean at this depth)"]),
    "",
    "## Next steps",
    "- Reproduce each HIGH signal manually and capture evidence before promoting it (finding tool).",
    "- Feed discovered forms/routes into appsec_probe for payload-level checks.",
    "- Check any API endpoints against the cve/knowledge tools for known issues.",
    ...(input.openApi ? [`- Pull ${input.openApi.url} and enumerate every documented operation in scope.`] : []),
  ]
  return lines.join("\n")
}

export const BountyHuntTool = Tool.define(
  "bounty_hunt",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          let base: URL
          try {
            base = new URL(params.target)
          } catch {
            return { title: "bounty_hunt · invalid url", metadata: {}, output: `Not an absolute URL: ${params.target}` }
          }
          if (base.protocol !== "http:" && base.protocol !== "https:") {
            return { title: "bounty_hunt · invalid scheme", metadata: {}, output: `Only http/https supported.` }
          }

          const state = yield* store.get()
          if (state && state.scope.targets.length > 0 && state.mode !== "free") {
            const check = ScopeMatcher.checkScope(base.hostname, state.scope)
            if (!check.inScope) {
              return {
                title: "bounty_hunt · blocked",
                metadata: { blocked: true },
                output: `Blocked: ${base.hostname} is outside engagement scope (${check.reason}).`,
              }
            }
          }

          yield* ctx.ask({
            permission: "bounty_hunt",
            patterns: [base.origin],
            always: [],
            metadata: {},
          })

          const timeoutMs = Math.min(Math.max(Math.trunc(params.timeout_ms ?? 10_000), 1_000), 60_000)

          const page = yield* Effect.promise(() =>
            fetch(base.toString(), {
              headers: { "user-agent": "pentestcode-bounty/1.0" },
              redirect: "follow",
              signal: AbortSignal.timeout(timeoutMs),
            }),
          )
          const html = yield* Effect.promise(() => page.text())

          const routes = extractLinks(html, base)
          const forms = extractForms(html)
          const js = yield* Effect.promise(() => analyzeJs({ url: base.toString(), timeoutMs }))
          const fuzzHits: FuzzHit[] = []
          let fuzzTested = 0
          if (params.fuzz === true) {
            const fuzzResult = yield* Effect.promise(() => dirFuzz({ baseUrl: base.toString(), timeoutMs }))
            fuzzHits.push(...fuzzResult.hits)
            fuzzTested = fuzzResult.tested
          }

          const cnameRecords = yield* Effect.promise(() => dns.resolveCname(base.hostname).catch(() => [] as string[]))
          const takeover = matchTakeover({ cname: cnameRecords[0], body: page.status >= 400 ? html : undefined })

          const responseHeaders: Record<string, string> = {}
          page.headers.forEach((value, key) => {
            responseHeaders[key] = value
          })
          const headerSignals = rankHeaderSignals(responseHeaders)

          const openApi = yield* Effect.promise(() => discoverOpenApi(base, Math.min(timeoutMs, 8000)))

          const signals = [
            ...rankBountySignals({
              secrets: js.secrets,
              takeover,
              takeoverHost: cnameRecords[0] ?? base.hostname,
              endpoints: js.endpoints,
              spaRoutes: js.spaRoutes,
              fuzzHits,
            }),
            ...headerSignals,
            ...(openApi
              ? ([
                  {
                    severity: "medium",
                    title: `API specification exposed (${openApi.version})`,
                    detail: `${openApi.url} — enumerate documented endpoints before manual testing`,
                  } satisfies BountySignal,
                ] as BountySignal[])
              : []),
          ]

          const evidenceSha = state
            ? (
                yield* Effect.promise(() =>
                  Evidence.put({
                    engagementName: state.name,
                    content: JSON.stringify(
                      {
                        target: params.target,
                        status: page.status,
                        routes: routes.map((r) => r.toString()).slice(0, 200),
                        forms,
                        js: { filesAnalyzed: js.filesAnalyzed, secrets: js.secrets, endpoints: js.endpoints, spaRoutes: js.spaRoutes },
                        takeover: takeover ? { service: takeover.service, vulnerable: takeover.vulnerable, host: cnameRecords[0] } : null,
                        headers: responseHeaders,
                        openapi: openApi ?? null,
                        fuzz: { tested: fuzzTested, hits: fuzzHits },
                        signals,
                      },
                      null,
                      2,
                    ),
                    mime: "application/json",
                    label: `bounty sweep ${base.host}`,
                    source: "bounty_hunt",
                  }).catch(() => undefined),
                )
              )?.sha256
            : undefined

          if (state) {
            for (const signal of signals.filter((s) => s.severity !== "info")) {
              yield* Effect.promise(() =>
                Observation.add({
                  engagementName: state.name,
                  subtype: signal.severity === "high" ? "vuln" : "risk",
                  title: `[bounty] ${signal.title}`,
                  severity: signal.severity,
                  note: signal.detail,
                  tags: ["bounty-hunt", base.hostname],
                }).catch(() => undefined),
              )
            }
            if (evidenceSha) {
              yield* Effect.promise(() =>
                Observation.add({
                  engagementName: state.name,
                  subtype: "intel-fact",
                  title: `[bounty] sweep summary for ${base.host}`,
                  note: `${signals.length} signal(s); full report in evidence ${evidenceSha}`,
                  tags: ["bounty-hunt"],
                }).catch(() => undefined),
              )
            }
          }

          return {
            title: `bounty_hunt · ${signals.length} signal(s) · ${base.host}`,
            metadata: {
              signals: signals.length,
              high: signals.filter((s) => s.severity === "high").length,
              medium: signals.filter((s) => s.severity === "medium").length,
              routes: routes.length,
              forms: forms.length,
              fuzz_tested: fuzzTested,
              evidence_sha: evidenceSha,
            },
            output: renderReport(params.target, {
              routes: routes.length,
              forms: forms.length,
              signals,
              fuzzTested,
              openApi,
            }),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

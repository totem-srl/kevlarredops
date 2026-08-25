import { Effect, Schema } from "effect"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { Observation } from "@pentestcode/core/cyber/observation"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { ScopeMatcher } from "@pentestcode/core/engagement/scope-matcher"
import { extractForms, extractLinks, type CrawlForm } from "@/scanner/crawl"
import DESCRIPTION from "./appsec-probe.txt"
import * as Tool from "./tool"

const MAX_EVIDENCE_BODY = 64000
const MARKER = "pentestcode-xss"

export const Parameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Absolute http(s) URL of the target to probe" }),
  checks: Schema.optional(
    Schema.Array(
      Schema.Literals(["sqli_search", "xss_search", "broken_auth_jwt", "idor_basket", "weak_cors"]),
    ).annotate({ description: "Subset of checks to run (default: all)" }),
  ),
  timeout_ms: Schema.optional(
    Schema.Number.annotate({ description: "Per-request timeout in ms (500-120000, default 15000)" }),
  ),
})

type ProbeCheck = NonNullable<Schema.Schema.Type<typeof Parameters>["checks"]>[number]

type ProbeRequest = {
  check: ProbeCheck
  method: string
  url: string
  headers?: Record<string, string>
  body?: string
}

type ProbeResponse = {
  check: ProbeCheck
  method: string
  url: string
  status?: number
  headers?: Record<string, string>
  body?: string
  truncated?: boolean
  error?: string
  elapsed_ms?: number
  replay?: string
}

type Candidate = {
  check: ProbeCheck
  severity: "low" | "medium" | "high"
  title: string
  route: string
  confidence: number
  rationale: string
}

function shq(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`
}

function replayOf(req: ProbeRequest): string {
  const parts = [`curl -i -X ${req.method} ${shq(req.url)}`]
  for (const [k, v] of Object.entries(req.headers ?? {})) parts.push(`-H ${shq(`${k}: ${v}`)}`)
  if (req.body !== undefined) parts.push(`--data-raw ${shq(req.body)}`)
  return parts.join(" \\\n  ")
}

function normalizeTarget(target: string): URL | undefined {
  try {
    const url = new URL(target)
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined
    url.hash = ""
    return url
  } catch {
    return undefined
  }
}

function textInputName(form: CrawlForm): string | undefined {
  const blocked = new Set(["password", "pass", "submit", "csrf", "csrf_token", "_csrf", "token", "authenticity_token"])
  const name = form.inputs.find((input) => !blocked.has(input.toLowerCase()) && !input.toLowerCase().includes("password"))
  return name ?? form.inputs[0]
}

function isAuthForm(form: CrawlForm): boolean {
  const hasPassword = form.inputs.some((input) => input.toLowerCase().includes("password"))
  const keywords = /login|auth|signin|session|token/i
  return hasPassword && keywords.test(form.action)
}

function buildInjected(
  base: URL,
  route: URL,
  field: string,
  payload: string,
): { url: URL; body?: string } {
  const url = new URL(route.toString())
  if (url.searchParams.size > 0 || field === "") {
    url.searchParams.set(field || "q", payload)
    return { url }
  }
  return { url, body: JSON.stringify({ [field]: payload }) }
}

function idorRewrite(route: URL): URL | undefined {
  const url = new URL(route.toString())
  const numericParam = [...url.searchParams.keys()].find((key) =>
    /^(id|user|account|item|object|basket)$/i.test(key),
  )
  if (numericParam && /^\d+$/.test(url.searchParams.get(numericParam) ?? "")) {
    url.searchParams.set(numericParam, "1")
    return url
  }
  let rewritten = false
  const path = url.pathname.replace(/\/(\d+)(?=\/|$)/, (_m, digits: string) => {
    rewritten = true
    return "/1".concat(digits.length > 1 ? "" : "")
  })
  if (rewritten) {
    url.pathname = path
    return url
  }
  return undefined
}

async function sendProbe(req: ProbeRequest, timeoutMs: number): Promise<ProbeResponse> {
  const started = Date.now()
  try {
    const response = await fetch(req.url, {
      method: req.method,
      headers: {
        "user-agent": "pentestcode-appsec-probe/1.0",
        accept: "application/json,text/html;q=0.9,*/*;q=0.8",
        ...(req.body !== undefined ? { "content-type": "application/json" } : {}),
        ...req.headers,
      },
      body: req.body,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    })
    const headers: Record<string, string> = {}
    response.headers.forEach((value, key) => {
      headers[key] = value
    })
    const text = await response.text()
    const truncated = text.length > MAX_EVIDENCE_BODY
    return {
      check: req.check,
      method: req.method,
      url: req.url,
      status: response.status,
      headers,
      body: truncated ? text.slice(0, MAX_EVIDENCE_BODY) : text,
      truncated,
      elapsed_ms: Date.now() - started,
      replay: replayOf(req),
    }
  } catch (error) {
    return {
      check: req.check,
      method: req.method,
      url: req.url,
      error: error instanceof Error ? error.message : String(error),
      elapsed_ms: Date.now() - started,
      replay: replayOf(req),
    }
  }
}

function includesAny(haystack: string, needles: string[]): boolean {
  const lower = haystack.toLowerCase()
  return needles.some((needle) => lower.includes(needle))
}

function analyze(responses: ProbeResponse[], evilOrigin: string): Candidate[] {
  const candidates: Candidate[] = []
  for (const res of responses) {
    const text = `${JSON.stringify(res.headers ?? {})}\n${res.body ?? ""}`
    switch (res.check) {
      case "sqli_search": {
        const hit = includesAny(text, ["sqlite", "sql syntax", "sequelize", 'near "', "database error"])
        candidates.push({
          check: "sqli_search",
          severity: hit ? "high" : "medium",
          title: hit ? "SQL error surfaced from injected payload" : "SQLi probe sent — no obvious SQL error in response",
          route: res.url,
          confidence: hit ? 760 : 620,
          rationale: hit
            ? "response contains database/sql error indicators after injecting ' OR 1=1--"
            : "payload delivered; manual verification required to rule out blind SQLi",
        })
        break
      }
      case "xss_search": {
        const reflected = (res.body ?? "").includes(MARKER) || (res.body ?? "").toLowerCase().includes("<script")
        candidates.push({
          check: "xss_search",
          severity: reflected ? "medium" : "low",
          title: reflected ? `marker ${MARKER} reflected in response` : "XSS marker not reflected",
          route: res.url,
          confidence: reflected ? 720 : 520,
          rationale: reflected
            ? "injected script marker appears unescaped in the response body — verify context and executability"
            : "no reflection observed; try other injection points manually",
        })
        break
      }
      case "broken_auth_jwt": {
        const signal = includesAny(text, ["jwt", "bearer", "token", "authorization"])
        candidates.push({
          check: "broken_auth_jwt",
          severity: signal ? "medium" : "low",
          title: signal ? "auth response carries token material worth reviewing" : "no token signals on login response",
          route: res.url,
          confidence: signal ? 700 : 540,
          rationale: signal
            ? "dummy credentials may have been accepted or token details leaked — inspect headers/body manually"
            : "dummy login rejected cleanly or no auth surface found",
        })
        break
      }
      case "idor_basket": {
        const ok = res.status === 200
        candidates.push({
          check: "idor_basket",
          severity: ok ? "high" : "medium",
          title: ok ? "rewritten object id returned 200 — possible IDOR" : "rewritten id did not yield success",
          route: res.url,
          confidence: ok ? 760 : 560,
          rationale: ok
            ? "object accessible after rewriting its identifier to 1 — confirm cross-tenant access manually"
            : "target responded non-200 or errored; IDOR unlikely via this vector",
        })
        break
      }
      case "weak_cors": {
        const acao = res.headers?.["access-control-allow-origin"]
        const acac = res.headers?.["access-control-allow-credentials"]
        const weak = acao === "*" || acao === evilOrigin
        if (weak) {
          candidates.push({
            check: "weak_cors",
            severity: "medium",
            title: `CORS reflects arbitrary origin (${acao})${acac === "true" ? " with credentials" : ""}`,
            route: res.url,
            confidence: 760,
            rationale: `evil origin ${evilOrigin} echoed in access-control-allow-origin${
              acac === "true" ? "; allow-credentials true makes it exploitable" : ""
            }`,
          })
        }
        break
      }
    }
  }
  return candidates
}

function renderOutput(input: {
  target: string
  plan: ProbeRequest[]
  skipped: string[]
  candidates: Candidate[]
  responses: ProbeResponse[]
}): string {
  const lines: string[] = []
  lines.push(`# AppSec probe · ${input.target}`, "", "## Probe Plan")
  if (input.plan.length === 0) lines.push("(no probes)")
  for (const req of input.plan) lines.push(`- ${req.check} → ${req.method} ${req.url}`)
  if (input.skipped.length > 0) {
    lines.push("", "Skipped:")
    for (const reason of input.skipped) lines.push(`- ${reason}`)
  }
  lines.push("", "## Candidate Findings")
  if (input.candidates.length === 0) lines.push("(none)")
  for (const c of input.candidates) {
    lines.push(`- [${c.severity}] (${c.confidence}/1000) ${c.title} @ ${c.route}`)
    lines.push(`  ${c.rationale}`)
  }
  lines.push("", "## Probe Responses")
  for (const res of input.responses) {
    const detail =
      res.error !== undefined
        ? `error: ${res.error}`
        : `${res.status} · ${res.body?.length ?? 0} bytes`
    lines.push(`- ${res.check} · ${res.method} ${res.url} → ${detail}`)
  }
  lines.push("", "Candidates are UNVERIFIED. Confirm manually, capture evidence, then promote via the finding tool.")
  return lines.join("\n")
}

export const AppsecProbeTool = Tool.define(
  "appsec_probe",
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
          const base = normalizeTarget(params.target)
          if (!base) {
            return {
              title: "appsec_probe · invalid target",
              metadata: {},
              output: `Target must be an absolute http(s) URL, got: ${params.target}`,
            }
          }

          const state = yield* store.get()
          if (state && state.scope.targets.length > 0 && state.mode !== "free") {
            const check = ScopeMatcher.checkScope(base.hostname, state.scope)
            if (!check.inScope) {
              return {
                title: "appsec_probe · blocked",
                metadata: { blocked: true },
                output: `Blocked: ${base.hostname} is outside engagement scope (${check.reason}).`,
              }
            }
          }

          yield* ctx.ask({
            permission: "appsec_probe",
            patterns: [base.origin],
            always: [],
            metadata: { target: params.target },
          })

          const timeoutMs = Math.min(Math.max(Math.trunc(params.timeout_ms ?? 15000), 500), 120_000)
          const allChecks: ProbeCheck[] = ["sqli_search", "xss_search", "broken_auth_jwt", "idor_basket", "weak_cors"]
          const wanted = new Set<ProbeCheck>(params.checks ?? allChecks)
          const skipped: string[] = []

          let html = ""
          try {
            const page = yield* Effect.promise(() =>
              fetch(base.toString(), {
                headers: { "user-agent": "pentestcode-appsec-probe/1.0" },
                redirect: "follow",
                signal: AbortSignal.timeout(timeoutMs),
              }),
            )
            html = yield* Effect.promise(() => page.text())
          } catch (error) {
            return {
              title: `appsec_probe · unreachable · ${base.hostname}`,
              metadata: {},
              output: `Could not fetch target page: ${error instanceof Error ? error.message : String(error)}`,
            }
          }

          const forms = extractForms(html).map((form) => ({
            ...form,
            actionUrl: (() => {
              try {
                return new URL(form.action || base.pathname, base)
              } catch {
                return undefined
              }
            })(),
          }))
          const routes = extractLinks(html, base)

          const reflectedForm = forms.find((f) => f.actionUrl && textInputName(f))
          const fallbackRoute =
            routes.find((r) => r.searchParams.size > 0) ??
            routes.find((r) => /search|query|find|filter/i.test(r.pathname)) ??
            routes[0]
          const injectedField = reflectedForm?.inputs ? (textInputName(reflectedForm) ?? "") : ""

          const plan: ProbeRequest[] = []

          const injectTarget = reflectedForm?.actionUrl ?? fallbackRoute
          if (!injectTarget) skipped.push("no reflective form or route observed on the target page")

          if (wanted.has("sqli_search") && injectTarget) {
            const built = buildInjected(base, injectTarget, injectedField, "' OR 1=1--")
            plan.push({
              check: "sqli_search",
              method: built.body !== undefined ? "POST" : "GET",
              url: built.url.toString(),
              body: built.body,
            })
          }
          if (wanted.has("xss_search") && injectTarget) {
            const built = buildInjected(base, injectTarget, injectedField, `<script>${MARKER}</script>`)
            plan.push({
              check: "xss_search",
              method: built.body !== undefined ? "POST" : "GET",
              url: built.url.toString(),
              body: built.body,
            })
          }

          const authForm = forms.find(isAuthForm)
          if (wanted.has("broken_auth_jwt")) {
            if (authForm?.actionUrl) {
              const identityField = authForm.inputs.find((i) => /email|user|identity/i.test(i)) ?? "username"
              plan.push({
                check: "broken_auth_jwt",
                method: (authForm.method || "post").toUpperCase() === "GET" ? "GET" : "POST",
                url: authForm.actionUrl.toString(),
                body: JSON.stringify({ [identityField]: "probe@example.invalid", password: "probe" }),
              })
            } else {
              skipped.push("no login-style form observed for broken_auth_jwt")
            }
          }

          if (wanted.has("idor_basket")) {
            const idorRoute = routes.map(idorRewrite).find((r) => r !== undefined) ?? (() => {
              const numericPath = routes.find((r) => /\/\d+(\/|$)/.test(r.pathname) || /[?&](?:id|basket)=\d+/i.test(r.search))
              return numericPath ? idorRewrite(numericPath) : undefined
            })()
            if (idorRoute) {
              plan.push({ check: "idor_basket", method: "GET", url: idorRoute.toString() })
            } else {
              skipped.push("no numeric-id route/param observed for idor_basket")
            }
          }

          const evilOrigin = "https://evil.example.invalid"
          if (wanted.has("weak_cors")) {
            const corsRoute = routes[0] ?? base
            plan.push({
              check: "weak_cors",
              method: "GET",
              url: corsRoute.toString(),
              headers: { origin: evilOrigin },
            })
          }

          const responses: ProbeResponse[] = []
          for (const req of plan) {
            responses.push(yield* Effect.promise(() => sendProbe(req, timeoutMs)))
          }
          const candidates = analyze(responses, evilOrigin)

          const evidenceSha = state
            ? (
                yield* Effect.promise(() =>
                  Evidence.put({
                    engagementName: state.name,
                    content: JSON.stringify({ target: params.target, plan, candidates, responses }, null, 2),
                    mime: "application/json",
                    label: `appsec probe ${base.host}`,
                    source: "appsec_probe",
                  }).catch(() => undefined),
                )
              )?.sha256
            : undefined

          let observationId: string | undefined
          if (state) {
            const anyHigh = candidates.some((c) => c.severity === "high")
            const observation = yield* Effect.promise(() =>
              Observation.add({
                engagementName: state.name,
                subtype: "risk",
                title: `AppSec probe candidates on ${base.host}`,
                severity: anyHigh ? "high" : candidates.length > 0 ? "medium" : "info",
                note: `${candidates.length} candidate(s); evidence ${evidenceSha ?? "unrecorded"}`,
                tags: ["appsec-probe"],
              }).catch(() => undefined),
            )
            observationId = observation?.id
            const linked = observation?.id
            const sha = evidenceSha
            if (linked && sha) {
              yield* Effect.promise(() => Observation.linkEvidence(state.name, linked, sha).catch(() => false))
            }
          }

          return {
            title: `appsec_probe · ${candidates.length} candidate(s) · ${base.host}`,
            metadata: {
              checks_run: plan.map((p) => p.check),
              skipped: skipped.length,
              candidates: candidates.length,
              high: candidates.filter((c) => c.severity === "high").length,
              observation_id: observationId,
              evidence_sha: evidenceSha,
            },
            output: renderOutput({ target: params.target, plan, skipped, candidates, responses }),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

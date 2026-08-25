import { Effect, Schema } from "effect"
import fs from "node:fs/promises"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { Vault } from "@pentestcode/core/cyber/vault"
import { checkStrictOpsec } from "@pentestcode/core/cyber/boundary"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { ScopeMatcher } from "@pentestcode/core/engagement/scope-matcher"
import { readLevel } from "./opsec"
import DESCRIPTION from "./http-request.txt"
import * as Tool from "./tool"

const MAX_BODY_PREVIEW = 8000
const MAX_EVIDENCE_BODY = 64000

export const Parameters = Schema.Struct({
  url: Schema.String.annotate({ description: "Absolute http(s) URL to request" }),
  method: Schema.optional(
    Schema.Literals(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]).annotate({
      description: "HTTP method (default GET)",
      default: "GET",
    }),
  ),
  headers: Schema.optional(
    Schema.String.annotate({
      description: "Request headers as multiline 'Key: Value' lines",
    }),
  ),
  body: Schema.optional(Schema.String.annotate({ description: "Request body" })),
  timeout_s: Schema.optional(Schema.Number.annotate({ description: "Timeout in seconds (default 15, max 120)" })),
})

function parseHeaders(raw: string | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (!raw) return out
  for (const line of raw.split(/\r?\n/)) {
    const idx = line.indexOf(":")
    if (idx <= 0) continue
    const key = line.slice(0, idx).trim()
    const value = line.slice(idx + 1).trim()
    if (key && value) out[key] = value
  }
  return out
}

function shq(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`
}

function curlReplay(input: { method: string; url: string; headers: Record<string, string>; body?: string }): string {
  const parts = [`curl -i -X ${input.method} ${shq(input.url)}`]
  for (const [key, value] of Object.entries(input.headers)) parts.push(`-H ${shq(`${key}: ${value}`)}`)
  if (input.body !== undefined) parts.push(`--data-raw ${shq(input.body)}`)
  return parts.join(" \\\n  ")
}

export const HttpRequestTool = Tool.define(
  "http_request",
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
          let target: URL
          try {
            target = new URL(params.url)
          } catch {
            return {
              title: "http_request · invalid url",
              metadata: {},
              output: `Not a valid absolute URL: ${params.url}`,
            }
          }
          if (target.protocol !== "http:" && target.protocol !== "https:") {
            return {
              title: "http_request · invalid scheme",
              metadata: {},
              output: `Only http/https supported, got ${target.protocol}`,
            }
          }

          const state = yield* store.get()
          if (state && state.scope.targets.length > 0 && state.mode !== "free") {
            const check = ScopeMatcher.checkScope(params.url, state.scope)
            if (!check.inScope) {
              return {
                title: "http_request · blocked",
                metadata: { blocked: true, reason: check.reason },
                output: `Blocked: ${params.url} is outside the engagement scope (${check.reason}). Adjust scope via scope tools before requesting.`,
              }
            }
          }

          const level = yield* Effect.promise(() => readLevel(state?.name))
          if (level === "strict") {
            const denied = checkStrictOpsec(params.url)
            if (denied) {
              return {
                title: "http_request · opsec denied",
                metadata: { blocked: true, reason: denied.reason },
                output: `Blocked by strict opsec: ${denied.reason}.`,
              }
            }
          }

          yield* ctx.ask({
            permission: "http_request",
            patterns: [params.url],
            always: ["*"],
            metadata: { method: params.method ?? "GET", host: target.hostname },
          })

          const headers: Record<string, string> = {}
          const active = yield* Effect.promise(() => Vault.activeIdentity().catch(() => undefined))
          const identity = active ? Vault.resolveIdentityValue(active.key, active.value) : undefined
          if (identity?.headers) Object.assign(headers, identity.headers)
          if (identity?.mode === "cookies" && identity.cookies) headers["Cookie"] = identity.cookies
          Object.assign(headers, parseHeaders(params.headers))

          const timeoutMs = Math.min(Math.max((params.timeout_s ?? 15) * 1000, 500), 120_000)
          const method = params.method ?? "GET"

          const started = Date.now()
          let response: Response
          try {
            response = yield* Effect.promise(() =>
              fetch(params.url, {
                method,
                headers,
                body: params.body !== undefined && method !== "GET" && method !== "HEAD" ? params.body : undefined,
                redirect: "manual",
                signal: AbortSignal.any([AbortSignal.timeout(timeoutMs), ...(ctx.abort ? [ctx.abort] : [])]),
              }),
            )
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error)
            return {
              title: `http_request · failed · ${method} ${target.hostname}`,
              metadata: { ok: false, error: message },
              output: `Request failed: ${message}`,
            }
          }
          const elapsed = Date.now() - started

          const responseHeaders: Record<string, string> = {}
          response.headers.forEach((value, key) => {
            responseHeaders[key] = value
          })
          const bodyText = yield* Effect.promise(() => response.text())

          const headerLines = Object.entries(responseHeaders)
            .map(([k, v]) => `${k}: ${v}`)
            .join("\n")
          const truncatedPreview = bodyText.length > MAX_BODY_PREVIEW
          const preview = truncatedPreview ? `${bodyText.slice(0, MAX_BODY_PREVIEW)}\n... (${bodyText.length - MAX_BODY_PREVIEW} more bytes)` : bodyText

          const replay = curlReplay({ method, url: params.url, headers, body: params.body })

          if (state) {
            const evidenceBody = bodyText.length > MAX_EVIDENCE_BODY
            yield* Effect.promise(() =>
              Evidence.put({
                engagementName: state.name,
                content: JSON.stringify(
                  {
                    request: { method, url: params.url, headers, body: params.body },
                    response: {
                      status: response.status,
                      headers: responseHeaders,
                      body: evidenceBody ? bodyText.slice(0, MAX_EVIDENCE_BODY) : bodyText,
                      truncated: evidenceBody,
                    },
                    replay,
                  },
                  null,
                  2,
                ),
                mime: "application/json",
                label: `${method} ${params.url}`,
                source: "http_request",
              }).catch(() => undefined),
            )
          }

          return {
            title: `http_request · ${response.status} · ${method} ${target.hostname}`,
            metadata: {
              status: response.status,
              elapsed_ms: elapsed,
              contentLength: Number(responseHeaders["content-length"] ?? bodyText.length),
              identity_used: identity?.key,
            },
            output: [
              `Response Headers:`,
              headerLines || "(none)",
              "",
              `Body preview (${bodyText.length} bytes${truncatedPreview ? ", truncated" : ""}):`,
              preview,
              "",
              `Replay:`,
              replay,
            ].join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

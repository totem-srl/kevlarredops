export type BoundaryMode = "allow" | "deny" | "ask"

export type Boundary = {
  default: BoundaryMode
  in_scope: string[]
  out_of_scope: string[]
}

export type Decision = {
  verdict: "allow" | "deny" | "ask"
  matched?: string
  reason: string
}

export class ScopeDeniedError extends Error {
  readonly request: string
  readonly decision: Decision
  constructor(request: string, decision: Decision, operation: string) {
    super(`operation "${operation}" blocked by scope boundary: ${request} -> ${decision.verdict} (${decision.reason})`)
    this.request = request
    this.decision = decision
  }
}

// Third-party intel hosts that leak queried domains to outside services.
// Strict opsec mode denies these even when otherwise allowed.
export const OPSEC_BLOCKLIST = [
  "crt.sh",
  "otx.alienvault.com",
  "www.virustotal.com",
  "virustotal.com",
  "api.shodan.io",
  "shodan.io",
  "urlscan.io",
  "web.archive.org",
]

function escapeRegex(input: string): string {
  return input.replace(/[.+?^${}()|[\]\\]/g, "\\$&")
}

function globToRegex(pattern: string): RegExp {
  const escaped = escapeRegex(pattern).replace(/\*/g, ".*")
  return new RegExp(`^${escaped}$`, "i")
}

function matchesHost(host: string, pattern: string): boolean {
  const p = pattern.toLowerCase().trim()
  const h = host.toLowerCase().trim()
  if (!p) return false
  if (p === h) return true
  if (p.startsWith("*.")) return h === p.slice(2) || h.endsWith(p.slice(1))
  if (h.startsWith("*.")) return false
  return false
}

function matchesPathPrefix(pathname: string, prefix: string): boolean {
  const p = prefix.toLowerCase()
  const normalized = p.endsWith("/") ? p : `${p}/`
  return pathname.toLowerCase().startsWith(normalized)
}

function matchPattern(pattern: string, url: URL): boolean {
  const p = pattern.trim()
  if (!p) return false

  if (/^https?:\/\//i.test(p)) {
    try {
      const parsed = new URL(p)
      if (!matchesHost(url.hostname, parsed.hostname)) return false
      if ((parsed.port || "") !== url.port && parsed.port && url.port) return false
      if (parsed.pathname && parsed.pathname !== "/") {
        return matchesPathPrefix(url.pathname, parsed.pathname)
      }
      return true
    } catch {
      return false
    }
  }

  if (p.includes("/")) {
    // host/path form
    const idx = p.indexOf("/")
    const hostPart = p.slice(0, idx)
    const pathPart = p.slice(idx)
    if (!matchesHost(url.hostname, hostPart)) return false
    if (pathPart === "*" || pathPart === "/*") return true
    if (pathPart.includes("*")) return globToRegex(pathPart).test(url.pathname)
    return matchesPathPrefix(url.pathname, pathPart)
  }

  if (p.includes("*")) return matchesHost(url.hostname, p)

  return matchesHost(url.hostname, p)
}

export function evaluate(boundary: Boundary, request: string): Decision {
  let url: URL
  try {
    url = new URL(request)
  } catch {
    return {
      verdict: boundary.default === "allow" ? "allow" : boundary.default,
      reason: `not a URL ("${request}"); applying default mode`,
    }
  }

  const hostAndPath = `${url.hostname}${url.pathname}`

  for (const pattern of boundary.out_of_scope) {
    if (matchPattern(pattern, url)) {
      return { verdict: "deny", matched: pattern, reason: `explicitly out of scope (${pattern})` }
    }
  }

  for (const pattern of boundary.in_scope) {
    if (matchPattern(pattern, url)) {
      return { verdict: "allow", matched: pattern, reason: `in scope (${pattern})` }
    }
  }

  return { verdict: boundary.default, reason: `no explicit rule matched "${hostAndPath}"; default is ${boundary.default}` }
}

export function checkStrictOpsec(request: string): Decision | undefined {
  try {
    const url = new URL(request)
    for (const host of OPSEC_BLOCKLIST) {
      if (matchesHost(url.hostname, host)) {
        return { verdict: "deny", matched: host, reason: `strict opsec: third-party intel host (${host}) leaks queried names` }
      }
    }
    return undefined
  } catch {
    return undefined
  }
}

export function evaluateStrict(boundary: Boundary, request: string): Decision {
  const blocklisted = checkStrictOpsec(request)
  if (blocklisted) return blocklisted

  const base = evaluate(boundary, request)
  if (base.verdict === "ask") {
    const isLocal =
      /^https?:\/\//i.test(request) &&
      (() => {
        try {
          const u = new URL(request)
          return ["localhost", "127.0.0.1", "::1", "0.0.0.0"].includes(u.hostname)
        } catch {
          return false
        }
      })()
    if (!isLocal) {
      return { verdict: "deny", matched: base.matched, reason: `strict opsec upgrades ask to deny: ${base.reason}` }
    }
  }
  return base
}

export function defaultBoundary(): Boundary {
  return { default: "ask", in_scope: [], out_of_scope: [] }
}

export * as Boundary from "./boundary"

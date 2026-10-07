import { createPacer, type Pacer } from "./pacer"
import type { ScopedRequest } from "./scoped-request"

const INTERESTING_STATUS = new Set([200, 201, 204, 301, 302, 307, 308, 401, 403])

export const BUILTIN_WORDLIST = [
  "admin", "administrator", "api", "api/v1", "api/v2", "app", "app.js", "assets", "backup",
  "backup.sql", "backups", "bin", "blog", "cgi-bin", "composer.json", "config", "config.php",
  "console", "dashboard", "db", "db.sql", "debug", "dev", ".env", ".env.bak", ".env.local",
  ".git", ".git/config", ".git/HEAD", ".htaccess", ".htpasswd", "images", "img", "index.html",
  "info.php", "install", "js", "json", "login", "logout", "mail", "manage", "manager",
  "media", "old", "panel", "phpinfo.php", "phpmyadmin", "private", "robots.txt", "secret",
  "server-status", "setup", "sitemap.xml", "sql", "src", "static", "status", "swagger",
  "swagger.json", "swagger-ui", "temp", "test", "tmp", "uploads", "user", "users", "vendor",
  "web.config", "wp-admin", "wp-content", "wp-content/uploads", "wp-includes", "wp-json",
  "www", ".well-known", "graphql", "graphiql", "playground", "actuator", "actuator/health",
  "actuator/env", "actuator/heapdump", "actuator/mappings", "api-docs", "v2/api-docs",
  "v3/api-docs", "openapi.json", "api/config", "api/settings", "api/user", "api/users",
  "api/products", "api/Products/1", "api/basket", "api/track_order", "rest", "rest/v1",
  "admin-panel", "administrator/login", "jmx-console", "manager/html",
]

const EXTENSIONS = ["", ".html", ".php", ".bak", ".old", ".txt", ".json"]

export type FuzzHit = {
  path: string
  url: string
  status: number
  length: number
}

async function probe(
  base: URL,
  candidate: string,
  timeoutMs: number,
  request: ScopedRequest.Request,
): Promise<{ status: number; length: number } | undefined> {
  const target = new URL(candidate, base)
  try {
    const response = await request(target.toString(), {
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "manual",
      headers: { "user-agent": "pentestcode-scanner/1.0" },
    })
    await response.arrayBuffer()
    return { status: response.status, length: Number(response.headers.get("content-length") ?? 0) }
  } catch {
    return undefined
  }
}

export async function dirFuzz(input: {
  baseUrl: string
  wordlist?: string[]
  timeoutMs?: number
  concurrency?: number
  rps?: number
  request?: ScopedRequest.Request
}): Promise<{ hits: FuzzHit[]; tested: number }> {
  const base = new URL(input.baseUrl)
  if (!base.pathname.endsWith("/")) base.pathname = `${base.pathname}/`
  const timeoutMs = input.timeoutMs ?? 8_000
  const concurrency = input.concurrency ?? 10
  const pace: Pacer = input.rps ? createPacer(input.rps) : async () => {}

  // baseline: a random path should 404; remember its status+length to filter soft-404s
  const baselinePath = `numasec_404_check_${Date.now()}`
  let baselineStatus = 404
  let baselineLength = -1
  if (input.rps) {
    await pace()
    const baseline = await probe(base, baselinePath, timeoutMs, input.request ?? fetch)
    if (baseline && !INTERESTING_STATUS.has(baseline.status)) {
      baselineStatus = baseline.status
      baselineLength = baseline.length
    }
  } else {
    const baseline = await probe(base, baselinePath, timeoutMs, input.request ?? fetch)
    if (baseline && !INTERESTING_STATUS.has(baseline.status)) {
      baselineStatus = baseline.status
      baselineLength = baseline.length
    }
  }

  const candidates: string[] = []
  for (const word of input.wordlist ?? BUILTIN_WORDLIST) {
    candidates.push(word)
    for (const ext of EXTENSIONS.slice(1)) {
      candidates.push(`${word}${ext}`)
    }
  }

  const hits: FuzzHit[] = []
  const seen = new Set<string>()

  if (input.rps) {
    for (const candidate of candidates) {
      await pace()
      const result = await probe(base, candidate, timeoutMs, input.request ?? fetch)
      if (!result) continue
      if (!INTERESTING_STATUS.has(result.status)) continue
      if (result.status === baselineStatus && Math.abs(result.length - baselineLength) <= 50) continue
      const key = `${candidate}:${result.status}`
      if (seen.has(key)) continue
      seen.add(key)
      hits.push({
        path: candidate,
        url: new URL(candidate, base).toString(),
        status: result.status,
        length: result.length,
      })
    }
    return { hits, tested: candidates.length + 1 }
  }

  for (let i = 0; i < candidates.length; i += concurrency) {
    const batch = candidates.slice(i, i + concurrency)
    const results = await Promise.all(
      batch.map(async (candidate) => {
        const result = await probe(base, candidate, timeoutMs, input.request ?? fetch)
        return { candidate, result }
      }),
    )
    for (const { candidate, result } of results) {
      if (!result) continue
      if (!INTERESTING_STATUS.has(result.status)) continue
      if (result.status === baselineStatus && Math.abs(result.length - baselineLength) <= 50) continue
      const key = `${candidate}:${result.status}`
      if (seen.has(key)) continue
      seen.add(key)
      hits.push({
        path: candidate,
        url: new URL(candidate, base).toString(),
        status: result.status,
        length: result.length,
      })
    }
  }

  return { hits, tested: candidates.length }
}

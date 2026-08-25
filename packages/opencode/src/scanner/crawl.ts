const TECH_SIGNATURES: { name: string; pattern: RegExp }[] = [
  { name: "Express", pattern: /x-powered-by:\s*Express/i },
  { name: "PHP", pattern: /(\.php(?:\s|$)|x-powered-by:\s*php|phpsessid)/i },
  { name: "Nginx", pattern: /server:\s*nginx/i },
  { name: "Apache", pattern: /server:\s*apache/i },
  { name: "Cloudflare", pattern: /(server:\s*cloudflare|__cfduid|cf-ray)/i },
  { name: "ASP.NET", pattern: /(x-aspnet-version|x-powered-by:\s*asp\.net|aspx?)/i },
  { name: "Drupal", pattern: /(drupal|sites\/default\/files)/i },
  { name: "WordPress", pattern: /(wp-content|wp-includes|wp-json)/i },
  { name: "Django", pattern: /(csrfmiddlewaretoken|__admin_media_prefix__)/i },
  { name: "Flask", pattern: /(flask|werkzeug\/)/i },
  { name: "Laravel", pattern: /(laravel_session|xsrf-token)/i },
  { name: "Next.js", pattern: /(__next|\/_next\/static)/i },
  { name: "Nuxt", pattern: /(__nuxt|\/_nuxt\/)/i },
  { name: "React", pattern: /(react(-dom)?[.@-]|data-reactroot)/i },
  { name: "Angular", pattern: /(ng-version|angular[.@-])/i },
  { name: "Vue", pattern: /(vue[.@-]|data-v-app)/i },
  { name: "GraphQL", pattern: /(__schema|graphql)/i },
]

export type CrawlForm = {
  action: string
  method: string
  inputs: string[]
}

export type CrawlResult = {
  urls: string[]
  forms: CrawlForm[]
  technologies: string[]
  openapi?: string
  sitemap: string[]
  robotsDisallowed: string[]
  elapsed: number
}

function sameOrigin(base: URL, candidate: string): URL | undefined {
  try {
    const url = new URL(candidate, base)
    if (url.origin !== base.origin) return undefined
    if (url.hash) url.hash = ""
    return url
  } catch {
    return undefined
  }
}

export function extractLinks(html: string, base: URL): URL[] {
  const out = new Set<string>()
  const attr = /\b(?:href|src|action)\s*=\s*["']([^"'#\s]+)["']/gi
  let match: RegExpExecArray | null
  while ((match = attr.exec(html)) !== null) {
    const resolved = sameOrigin(base, match[1]!)
    if (resolved && /^https?:$/.test(resolved.protocol)) out.add(resolved.toString())
  }
  return [...out].map((u) => new URL(u))
}

export function extractForms(html: string): CrawlForm[] {
  const forms: CrawlForm[] = []
  const formRe = /<form\b[^>]*>([\s\S]*?)<\/form>/gi
  const actionRe = /action\s*=\s*["']([^"']*)["']/i
  const methodRe = /method\s*=\s*["']([^"']*)["']/i
  const inputRe = /<input\b[^>]*name\s*=\s*["']([^"']+)["']/gi
  let match: RegExpExecArray | null
  while ((match = formRe.exec(html)) !== null) {
    const block = match[0]
    const inner = match[1] ?? ""
    const inputs: string[] = []
    let inputMatch: RegExpExecArray | null
    while ((inputMatch = inputRe.exec(inner)) !== null) {
      inputs.push(inputMatch[1]!)
    }
    forms.push({
      action: block.match(actionRe)?.[1] ?? "",
      method: (block.match(methodRe)?.[1] ?? "GET").toUpperCase(),
      inputs,
    })
  }
  return forms
}

async function fetchText(url: string, timeoutMs: number): Promise<{ body: string; headers: Headers } | undefined> {
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "follow",
      headers: { "user-agent": "pentestcode-scanner/1.0" },
    })
    const body = await response.text()
    return { body, headers: response.headers }
  } catch {
    return undefined
  }
}

async function fetchRobots(origin: string, timeoutMs: number): Promise<string[]> {
  const result = await fetchText(`${origin}/robots.txt`, timeoutMs)
  if (!result) return []
  return result.body
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.toLowerCase().startsWith("disallow:"))
    .map((line) => line.slice("disallow:".length).trim())
    .filter(Boolean)
}

async function fetchSitemap(origin: string, timeoutMs: number): Promise<string[]> {
  const result = await fetchText(`${origin}/sitemap.xml`, timeoutMs)
  if (!result || !result.body.includes("<loc")) return []
  return [...result.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]!).slice(0, 200)
}

async function detectOpenAPI(origin: string, timeoutMs: number): Promise<string | undefined> {
  for (const path of ["/openapi.json", "/swagger.json", "/api-docs", "/v2/api-docs", "/v3/api-docs"]) {
    const result = await fetchText(`${origin}${path}`, timeoutMs)
    if (result && (result.body.includes("openapi") || result.body.includes("swagger"))) {
      return `${origin}${path}`
    }
  }
  return undefined
}

export async function crawl(input: {
  startUrl: string
  maxUrls?: number
  maxDepth?: number
  timeoutMs?: number
}): Promise<CrawlResult> {
  const started = Date.now()
  const maxUrls = input.maxUrls ?? 100
  const maxDepth = input.maxDepth ?? 3
  const timeoutMs = input.timeoutMs ?? 10_000

  const base = new URL(input.startUrl)
  const urls: string[] = []
  const technologies = new Set<string>()
  const forms: CrawlForm[] = []
  const seen = new Set<string>()
  const queue: { url: URL; depth: number }[] = [{ url: base, depth: 0 }]

  while (queue.length > 0 && seen.size < maxUrls) {
    const item = queue.shift()!
    const key = item.url.toString().replace(/\/$/, "")
    if (seen.has(key)) continue
    seen.add(key)

    const result = await fetchText(item.url.toString(), timeoutMs)
    if (!result) continue
    urls.push(item.url.toString())

    for (const tech of TECH_SIGNATURES) {
      if (tech.pattern.test(result.body)) technologies.add(tech.name)
    }

    const serverHeader = result.headers.get("server")
    if (serverHeader) technologies.add(`server:${serverHeader}`)
    const poweredBy = result.headers.get("x-powered-by")
    if (poweredBy) technologies.add(`x-powered-by:${poweredBy}`)

    forms.push(...extractForms(result.body))

    if (item.depth < maxDepth) {
      for (const link of extractLinks(result.body, item.url)) {
        const linkKey = link.toString().replace(/\/$/, "")
        if (!seen.has(linkKey) && !queue.some((q) => q.url.toString().replace(/\/$/, "") === linkKey)) {
          queue.push({ url: link, depth: item.depth + 1 })
        }
      }
    }
  }

  const [robotsDisallowed, sitemap, openapi] = await Promise.all([
    fetchRobots(base.origin, timeoutMs),
    fetchSitemap(base.origin, timeoutMs),
    detectOpenAPI(base.origin, timeoutMs),
  ])

  return {
    urls,
    forms,
    technologies: [...technologies],
    openapi,
    sitemap,
    robotsDisallowed,
    elapsed: Date.now() - started,
  }
}

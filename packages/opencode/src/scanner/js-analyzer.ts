const SECRET_PATTERNS: { label: string; pattern: RegExp }[] = [
  { label: "aws_access_key", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "google_api_key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { label: "slack_token", pattern: /\bxox[abprs]-[0-9A-Za-z-]{10,}\b/g },
  { label: "github_token", pattern: /\bgh[pousr]_[0-9A-Za-z]{20,}\b/g },
  { label: "jwt", pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b/g },
  { label: "private_key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { label: "bearer_token_literal", pattern: /["']Bearer\s+[A-Za-z0-9._-]{20,}["']/g },
  { label: "generic_api_key", pattern: /(?:api[_-]?key|apikey|api[_-]?token)\s*[:=]\s*["'][0-9a-zA-Z._-]{16,}["']/gi },
  { label: "database_url", pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s"'<>]{8,}/g },
  { label: "stripe_secret_key", pattern: /\bsk_(?:live|test)_[0-9a-zA-Z]{16,}\b/g },
  { label: "stripe_publishable_key", pattern: /\bpk_(?:live|test)_[0-9a-zA-Z]{16,}\b/g },
  { label: "mailgun_key", pattern: /\bkey-[0-9a-zA-Z]{32}\b/g },
  { label: "twilio_sid_and_secret", pattern: /\bAC[0-9a-f]{32}\b/g },
  { label: "sendgrid_key", pattern: /\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b/g },
]

const ENDPOINT_PATTERNS: RegExp[] = [
  /["'](\/api\/[0-9a-zA-Z_./{}-]*)["']/g,
  /["'](\/v[1-9][0-9]?\/[0-9a-zA-Z_./{}-]*)["']/g,
  /\bfetch\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /\baxios\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/g,
  /url\s*:\s*["'`](\/[^"'`]+)["'`]/g,
  /endpoint\s*:\s*["'`](\/[^"`]+)["'`]/g,
]

const SPA_ROUTE_PATTERNS: RegExp[] = [
  /\bpath\s*:\s*["']([/~][^"']*)["']/g,
  /\bto\s*:\s*["']([/~][^"']*)["']/g,
  /\b<Route\b[^>]*\bpath=["']([^"']+)["']/g,
]

const CHATBOT_INDICATORS = [
  "intercom", "drift", "tawk", "zendesk", "crisp", "livechat", "hubspot",
  "freshchat", "tidio", "olark", "smartsupp", "liveperson", "purechat",
]

function dedupe(values: string[]): string[] {
  return [...new Set(values)]
}

export type JsAnalysis = {
  url: string
  filesAnalyzed: number
  secrets: { kind: string; match: string }[]
  endpoints: string[]
  spaRoutes: string[]
  chatbotIndicators: string[]
}

function analyzeText(text: string): Pick<JsAnalysis, "secrets" | "endpoints" | "spaRoutes" | "chatbotIndicators"> {
  const secrets: { kind: string; match: string }[] = []
  for (const { label, pattern } of SECRET_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags)
    let match: RegExpExecArray | null
    while ((match = re.exec(text)) !== null) {
      secrets.push({ kind: label, match: match[0].slice(0, 120) })
      if (!re.global) break
    }
  }

  const endpoints: string[] = []
  for (const pattern of ENDPOINT_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags)
    let match: RegExpExecArray | null
    while ((match = re.exec(text)) !== null) {
      const value = (match[1] ?? "").trim()
      if (value.length > 1 && value.length < 300) endpoints.push(value)
    }
  }

  const spaRoutes: string[] = []
  for (const pattern of SPA_ROUTE_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags)
    let match: RegExpExecArray | null
    while ((match = re.exec(text)) !== null) {
      const value = (match[1] ?? "").trim()
      if (value.length > 0 && value.length < 200) spaRoutes.push(value)
    }
  }

  const lower = text.toLowerCase()
  const chatbotIndicators = CHATBOT_INDICATORS.filter((indicator) => lower.includes(indicator))

  return { secrets, endpoints: dedupe(endpoints), spaRoutes: dedupe(spaRoutes), chatbotIndicators }
}

async function fetchText(url: string, timeoutMs: number): Promise<string | undefined> {
  try {
    const response = await fetch(url, {
      signal: AbortSignal.timeout(timeoutMs),
      headers: { "user-agent": "pentestcode-scanner/1.0" },
    })
    return await response.text()
  } catch {
    return undefined
  }
}

export async function analyzeJs(input: { url: string; timeoutMs?: number; maxFiles?: number }): Promise<JsAnalysis> {
  const timeoutMs = input.timeoutMs ?? 10_000
  const maxFiles = input.maxFiles ?? 20

  const pageUrl = new URL(input.url)
  const html = (await fetchText(pageUrl.toString(), timeoutMs)) ?? ""
  const combined: string[] = [html]

  const scriptSrcs = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)]
    .map((m) => m[1]!)
    .filter((src) => src.toLowerCase().includes(".js"))
    .slice(0, maxFiles)

  let filesAnalyzed = 1
  for (const src of scriptSrcs) {
    let jsUrl: URL
    try {
      jsUrl = new URL(src, pageUrl)
    } catch {
      continue
    }
    if (jsUrl.origin !== pageUrl.origin) continue
    const text = await fetchText(jsUrl.toString(), timeoutMs)
    if (text === undefined) continue
    combined.push(text)
    filesAnalyzed += 1
  }

  return {
    url: input.url,
    filesAnalyzed,
    ...analyzeText(combined.join("\n")),
  }
}

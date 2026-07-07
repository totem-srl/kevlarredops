export * as ScopeMatcher from "./scope-matcher"

import type { EngagementSchema } from "./schema"

export function ipToInt(ip: string): number | undefined {
  const parts = ip.split(".")
  if (parts.length !== 4) return undefined
  const nums = parts.map(Number)
  if (nums.some((n) => isNaN(n) || n < 0 || n > 255)) return undefined
  return ((nums[0]! << 24) + (nums[1]! << 16) + (nums[2]! << 8) + nums[3]!) >>> 0
}

export function isIp(s: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)
}

export function isCidr(s: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(s)
}

export function isInCidr(ip: string, cidr: string): boolean {
  const [network, bits] = cidr.split("/")
  if (!bits || !network) return false
  const prefix = Number(bits)
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0
  const ipInt = ipToInt(ip)
  const netInt = ipToInt(network)
  if (ipInt === undefined || netInt === undefined) return false
  return (ipInt & mask) === (netInt & mask)
}

export function matchesWildcard(target: string, pattern: string): boolean {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1)
    return target.endsWith(suffix) || target === pattern.slice(2)
  }
  return false
}

export function isSubdomainOf(target: string, domain: string): boolean {
  return target.endsWith("." + domain)
}

export function extractHost(target: string): string {
  try {
    if (target.includes("://")) {
      const url = new URL(target)
      return url.hostname
    }
  } catch {
    // not a URL
  }
  const portMatch = target.match(/^([^:]+):\d+$/)
  if (portMatch && portMatch[1]) {
    return portMatch[1]
  }
  return target
}

export function matchesScopeEntry(target: string, entry: string): boolean {
  if (target === entry) return true
  if (isIp(target) && isCidr(entry)) return isInCidr(target, entry)
  if (entry.startsWith("*.")) return matchesWildcard(target, entry)
  if (!isIp(target) && !isIp(entry) && !isCidr(entry)) return isSubdomainOf(target, entry)
  return false
}

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?\b/g
const DOMAIN_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi

const IGNORE_IPS = new Set(["127.0.0.1", "0.0.0.0", "255.255.255.255"])
const IGNORE_DOMAINS = new Set([
  "github.com", "google.com", "example.com", "localhost",
  "apt.get", "pip.install",
])

export function extractTargetsFromCommand(command: string): string[] {
  const targets = new Set<string>()

  for (const match of command.matchAll(IP_RE)) {
    const ip = match[0]!
    const base = ip.split("/")[0]!
    if (!IGNORE_IPS.has(base)) targets.add(ip)
  }

  for (const match of command.matchAll(DOMAIN_RE)) {
    const domain = match[0]!.toLowerCase()
    if (!IGNORE_DOMAINS.has(domain) && domain.includes(".")) {
      targets.add(domain)
    }
  }

  return [...targets]
}

export type ScopeResult =
  | { inScope: true; matchedRule: string }
  | { inScope: false; matchedRule: string | null; reason: "excluded" | "not_matched" }

export function checkScope(target: string, scope: EngagementSchema.Scope): ScopeResult {
  const host = extractHost(target)

  for (const exclude of scope.excludes) {
    if (matchesScopeEntry(host, exclude)) {
      return { inScope: false, matchedRule: `excluded: ${exclude}`, reason: "excluded" }
    }
  }

  for (const entry of scope.targets) {
    if (matchesScopeEntry(host, entry)) {
      return { inScope: true, matchedRule: entry }
    }
  }

  return { inScope: false, matchedRule: null, reason: "not_matched" }
}

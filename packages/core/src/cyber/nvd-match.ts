export type NvdVersionRange = {
  criteria: string
  vulnerable?: boolean
  versionStartIncluding?: string
  versionStartExcluding?: string
  versionEndIncluding?: string
  versionEndExcluding?: string
  matchCriteriaId?: string
}

type CpeNode = {
  cpeMatch?: NvdVersionRange[]
  cpe_match?: NvdVersionRange[]
  children?: CpeNode[]
  nodes?: CpeNode[]
  negate?: boolean
  operator?: string
}

export type NormalizedComponent = {
  name: string
  version?: string
  aliases?: string[]
  cpe_candidates?: string[]
}

export type ApplicabilityState = "applicable" | "conditional" | "possible" | "not_applicable" | "unknown"
export type ApplicabilityConfidence = "low" | "medium" | "high" | "unknown"

export type NvdApplicability = {
  state: ApplicabilityState
  confidence: ApplicabilityConfidence
  reason: string
  matched_criteria?: string
  affected_range?: string
  version_match: boolean | "unknown"
  preconditions: string[]
  verification_steps: string[]
}

export function collectNvdRanges(nodes: CpeNode[] | undefined): NvdVersionRange[] {
  if (!nodes) return []
  const out: NvdVersionRange[] = []
  for (const node of nodes) {
    out.push(...(node.cpeMatch ?? node.cpe_match ?? []))
    out.push(...collectNvdRanges(node.children))
    out.push(...collectNvdRanges(node.nodes))
  }
  return out.filter((r) => r.vulnerable !== false)
}

export function cpeProduct(criteria: string): { vendor: string; product: string; version?: string } {
  const parts = criteria.split(":")
  return {
    vendor: (parts[3] ?? "").replace(/_/g, " ").toLowerCase(),
    product: (parts[4] ?? "").replace(/_/g, " ").toLowerCase(),
    version: parts[5] && parts[5] !== "*" ? parts[5].replace(/_/g, " ").toLowerCase() : undefined,
  }
}

export function normalizeVersion(input: string): string {
  return input
    .toLowerCase()
    .replace(/^v/, "")
    .split("")
    .map((ch) => ("[-+~_]".includes(ch) ? "." : ch))
    .join("")
    .split(".")
    .map((part) => part.replace(/[^a-z0-9]/g, ""))
    .filter((part) => part.length > 0)
    .join(".")
}

export function compareVersion(a: string, b: string): number {
  const pa = normalizeVersion(a).split(".")
  const pb = normalizeVersion(b).split(".")
  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i++) {
    const sa = pa[i] ?? "0"
    const sb = pb[i] ?? "0"
    const na = Number(sa)
    const nb = Number(sb)
    if (!Number.isNaN(na) && !Number.isNaN(nb)) {
      if (na !== nb) return na < nb ? -1 : 1
      continue
    }
    const cmp = sa.localeCompare(sb)
    if (cmp !== 0) return cmp < 0 ? -1 : 1
  }
  return 0
}

export function inRange(version: string | undefined, range: NvdVersionRange): boolean | "unknown" {
  const criteriaVersion = range.criteria.split(":")[5]
  const hasBounds =
    range.versionStartIncluding ||
    range.versionStartExcluding ||
    range.versionEndIncluding ||
    range.versionEndExcluding

  if (!hasBounds) {
    if (!criteriaVersion || criteriaVersion === "*" || criteriaVersion === "-") return "unknown"
    if (!version) return false
    return compareVersion(version, criteriaVersion) === 0
  }

  if (!version) return "unknown"
  const v = normalizeVersion(version)

  if (range.versionStartIncluding && compareVersion(v, range.versionStartIncluding) < 0) return false
  if (range.versionStartExcluding && compareVersion(v, range.versionStartExcluding) <= 0) return false
  if (range.versionEndIncluding && compareVersion(v, range.versionEndIncluding) > 0) return false
  if (range.versionEndExcluding && compareVersion(v, range.versionEndExcluding) >= 0) return false
  return true
}

function productMatches(component: NormalizedComponent, product: string, vendor: string): boolean {
  const names = [component.name.toLowerCase(), ...(component.aliases ?? []).map((a) => a.toLowerCase())]
  for (const name of names) {
    if (name === product || name === vendor || name === `${vendor} ${product}`) return true
    if (product.includes(name) || name.includes(product)) return true
  }
  for (const candidate of component.cpe_candidates ?? []) {
    const cand = cpeProduct(candidate)
    if (cand.product === product) return true
  }
  return false
}

function summaryMentionsComponent(summary: string, component: NormalizedComponent): boolean {
  const s = summary.toLowerCase()
  const names = [component.name.toLowerCase(), ...(component.aliases ?? []).map((a) => a.toLowerCase())]
  return names.some((name) => name.length > 2 && s.includes(name))
}

function nginxPreconditions(summary: string): { preconditions: string[]; verification: string[] } {
  const preconditions: string[] = []
  const verification: string[] = []
  const s = summary.toLowerCase()
  if (s.includes("resolver") || s.includes("dns")) {
    preconditions.push("nginx configured with a resolver block or DNS-based upstream resolution")
    verification.push("check nginx.conf for resolver directives and upstream definitions using DNS names")
  }
  if (s.includes("http/3") || s.includes("quic")) {
    preconditions.push("HTTP/3 / QUIC listener enabled")
    verification.push("confirm QUIC listener active on the deployed nginx build")
  }
  return { preconditions, verification }
}

export function evaluateNvdApplicability(input: {
  component: NormalizedComponent
  ranges: NvdVersionRange[]
  summary?: string
}): NvdApplicability {
  const { component, ranges } = input

  if (ranges.length === 0) {
    return {
      state: "unknown",
      confidence: "low",
      reason: "no CPE ranges present in the advisory",
      version_match: "unknown",
      preconditions: [],
      verification_steps: [],
    }
  }

  let bestRange: NvdVersionRange | undefined
  let bestResult: boolean | "unknown" = false

  for (const range of ranges) {
    const { vendor, product } = cpeProduct(range.criteria)
    if (!productMatches(component, product, vendor)) continue
    const result = inRange(component.version, range)
    if (result === true) {
      bestRange = range
      bestResult = true
      break
    }
    if (result === "unknown") {
      bestRange = range
      bestResult = "unknown"
    }
    if (result === false && bestResult === false) {
      bestRange = range
    }
  }

  if (bestResult === true && bestRange) {
    const extra = input.summary ? nginxPreconditions(input.summary) : { preconditions: [], verification: [] }
    return {
      state: "applicable",
      confidence: component.version ? "high" : "medium",
      reason: `version ${component.version ?? "<unknown>"} falls within ${bestRange.criteria}`,
      matched_criteria: bestRange.criteria,
      affected_range: [
        bestRange.versionStartIncluding,
        bestRange.versionStartExcluding,
        bestRange.versionEndIncluding,
        bestRange.versionEndExcluding,
      ]
        .filter(Boolean)
        .join(" / "),
      version_match: true,
      preconditions: extra.preconditions,
      verification_steps: extra.verification.length > 0 ? extra.verification : ["confirm the deployed artifact matches the identified version"],
    }
  }

  if (bestResult === "unknown" && bestRange) {
    return {
      state: "conditional",
      confidence: "medium",
      reason: `component product matched (${cpeProduct(bestRange.criteria).product}) but installed version is unknown`,
      matched_criteria: bestRange.criteria,
      affected_range: [
        bestRange.versionStartIncluding,
        bestRange.versionStartExcluding,
        bestRange.versionEndIncluding,
        bestRange.versionEndExcluding,
      ]
        .filter(Boolean)
        .join(" / "),
      version_match: "unknown",
      preconditions: ["determine the exact deployed version"],
      verification_steps: ["fingerprint the deployed component version and re-evaluate against the affected range"],
    }
  }

  if (input.summary && summaryMentionsComponent(input.summary, component)) {
    return {
      state: "possible",
      confidence: "low",
      reason: `summary mentions "${component.name}" but no CPE range matched the product`,
      version_match: "unknown",
      preconditions: ["manually confirm the component is actually affected"],
      verification_steps: ["read the advisory references and compare against the deployment"],
    }
  }

  return {
    state: "not_applicable",
    confidence: component.version ? "high" : "medium",
    reason: "no CPE range matched this component's product/version",
    version_match: false,
    preconditions: [],
    verification_steps: [],
  }
}

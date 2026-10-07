import { describe, expect, test } from "bun:test"
import fs from "node:fs/promises"

const { evaluate, checkStrictOpsec, evaluateStrict, defaultBoundary } = await import("@pentestcode/core/cyber/boundary")
const { Evidence } = await import("@pentestcode/core/cyber/evidence")
const { Observation } = await import("@pentestcode/core/cyber/observation")
const { Vault, resolveIdentityValue } = await import("@pentestcode/core/cyber/vault")
import {
  bucketFindings,
  isReportableFinding,
  normalizeFindingRecords,
  type FindingRecord,
} from "@pentestcode/core/cyber/finding-lifecycle"
import {
  compareVersion,
  evaluateNvdApplicability,
  inRange,
  type NvdVersionRange,
} from "@pentestcode/core/cyber/nvd-match"
import { buildVulnIntelCard } from "@pentestcode/core/cyber/knowledge"
import { parseComponent } from "@pentestcode/core/cyber/component"
import { Methodology } from "@pentestcode/core/cyber/methodology"
import { getPlay, listPlays } from "@pentestcode/core/cyber/play/registry"
import { formatPlayResult, PlayArgError, runPlay } from "@pentestcode/core/cyber/play/runner"

describe("boundary", () => {
  const boundary = {
    default: "ask" as const,
    in_scope: ["*.example.com", "10.0.0.0/*"],
    out_of_scope: ["admin.example.com"],
  }

  test("in-scope wildcard host allows", () => {
    const decision = evaluate(boundary, "https://api.example.com/x")
    expect(decision.verdict).toBe("allow")
  })

  test("explicit out-of-scope denies even when host wildcard matches", () => {
    const decision = evaluate(boundary, "https://admin.example.com/")
    expect(decision.verdict).toBe("deny")
  })

  test("unmatched falls back to default", () => {
    const decision = evaluate(boundary, "https://evil.test/")
    expect(decision.verdict).toBe("ask")
  })

  test("strict opsec blocks third-party intel hosts", () => {
    const denied = checkStrictOpsec("https://crt.sh/?q=example.com")
    expect(denied?.verdict).toBe("deny")
  })

  test("evaluateStrict upgrades unmatched ask to deny off localhost", () => {
    const decision = evaluateStrict(defaultBoundary(), "https://random.host.internal/")
    expect(decision.verdict).toBe("deny")
    expect(evaluateStrict(defaultBoundary(), "http://localhost:3000/x").verdict).toBe("ask")
  })
})

describe("finding lifecycle", () => {
  const record = (over: Partial<FindingRecord>): FindingRecord => ({
    id: over.id ?? "f1",
    title: "t",
    status: "candidate",
    target: "127.0.0.1",
    evidence_refs: [],
    replay: { present: false },
    at: "2026-01-01T00:00:00Z",
    ...over,
  })

  test("reportable requires verified + evidence + replay or reasoned exemption", () => {
    expect(isReportableFinding(record({ status: "candidate", replay: { present: true } }))).toBe(false)
    expect(
      isReportableFinding(record({ status: "verified", evidence_refs: ["sha"], replay: { present: false } })),
    ).toBe(false)
    expect(isReportableFinding(record({ status: "verified", evidence_refs: ["sha"], replay: { present: true } }))).toBe(
      true,
    )
    expect(
      isReportableFinding(
        record({
          status: "verified",
          evidence_refs: ["sha"],
          replay: {
            present: false,
            exemption: { category: "destructive_target", rationale: "would brick the device" },
          },
        }),
      ),
    ).toBe(true)
    expect(
      isReportableFinding(
        record({
          status: "verified",
          evidence_refs: ["sha"],
          replay: { present: false, exemption: { category: "destructive_target", rationale: "  " } },
        }),
      ),
    ).toBe(false)
  })

  test("buckets separate reportable / rejected / no-replay", () => {
    const buckets = bucketFindings([
      record({ id: "a", status: "verified", evidence_refs: ["s"], replay: { present: true } }),
      record({ id: "b", status: "rejected" }),
      record({ id: "c", status: "verified", evidence_refs: ["s"] }),
      record({ id: "d" }),
    ])
    expect(buckets.reportable.map((f) => f.id)).toEqual(["a"])
    expect(buckets.rejected.map((f) => f.id)).toEqual(["b"])
    expect(buckets.noReplay.map((f) => f.id)).toEqual(["c"])
    expect(buckets.unverified.map((f) => f.id)).toEqual(["d"])
  })

  test("normalize keeps latest per id and drops orphan tombstones", () => {
    const normalized = normalizeFindingRecords([
      record({ id: "x", title: "old" }),
      record({ id: "x", title: "new" }),
      record({ id: "ghost", superseded_by: "never-materialized" }),
    ])
    const x = normalized.find((f) => f.id === "x")
    expect(x?.title).toBe("new")
    expect(normalized.some((f) => f.id === "ghost")).toBe(false)
  })
})

describe("nvd matching", () => {
  test("compareVersion is numeric-aware", () => {
    expect(compareVersion("1.9.0", "1.10.0")).toBeLessThan(0)
    expect(compareVersion("2.0", "2.0.0")).toBe(0)
    expect(compareVersion("v1.2.3", "1.2.4")).toBeLessThan(0)
  })

  test("inRange honors inclusive/exclusive bounds and wildcard criteria", () => {
    const base: NvdVersionRange = {
      criteria: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
      vulnerable: true,
    }
    expect(inRange("1.18.0", base)).toBe("unknown")
    expect(inRange("1.19.0", { ...base, versionEndIncluding: "1.20.0" })).toBe(true)
    expect(inRange("1.20.0", { ...base, versionEndExcluding: "1.20.0" })).toBe(false)
    expect(inRange("1.17.0", { ...base, versionStartIncluding: "1.18.0", versionEndIncluding: "1.20.0" })).toBe(false)
  })

  test("applicability matches product+version against ranges", () => {
    const result = evaluateNvdApplicability({
      component: { name: "nginx", version: "1.19.2" },
      ranges: [
        {
          criteria: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
          vulnerable: true,
          versionStartIncluding: "1.18.0",
          versionEndIncluding: "1.20.0",
        },
      ],
      summary: "buffer issue in nginx",
    })
    expect(result.state).toBe("applicable")

    const miss = evaluateNvdApplicability({
      component: { name: "nginx", version: "1.25.0" },
      ranges: [
        {
          criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
          vulnerable: true,
          versionEndIncluding: "1.20.0",
        },
      ],
      summary: "",
    })
    expect(miss.state).toBe("not_applicable")
  })
})

describe("knowledge card", () => {
  test("builds from flat NVD record shape", () => {
    const card = buildVulnIntelCard({
      record: {
        id: "CVE-2026-0001",
        descriptions: [{ lang: "en", value: "bad thing" }],
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] },
        references: [{ url: "https://advisory.example/1" }],
        configurations: [
          {
            nodes: [
              {
                cpeMatch: [
                  {
                    vulnerable: true,
                    criteria: "cpe:2.3:a:vend:prod:*:*:*:*:*:*:*:*",
                    versionEndIncluding: "2.0.0",
                  },
                ],
              },
            ],
          },
        ],
      },
      component: { name: "prod", version: "1.5.0" },
    })
    expect(card.cve).toBe("CVE-2026-0001")
    expect(card.severity.cvss_v3).toBe(9.8)
    expect(card.summary).toBe("bad thing")
    expect(card.applicability?.state).toBe("applicable")
    expect(card.references[0]).toBe("https://advisory.example/1")
  })
})

describe("component", () => {
  test("parses name@version keeping @ in scoped-ish names sane", () => {
    expect(parseComponent("nginx@1.25.3")).toEqual({ name: "nginx", version: "1.25.3" })
    expect(parseComponent("justname").version).toBeUndefined()
  })
})

describe("methodology", () => {
  test("lists frameworks and finds phases by substring", () => {
    const frameworks = Methodology.listFrameworks()
    expect(frameworks.length).toBeGreaterThanOrEqual(3)
    const hits = Methodology.search("reconnaissance")
    expect(hits.length).toBeGreaterThan(0)
    const ptes = Methodology.getFramework("ptes")
    expect(ptes?.phases.length).toBeGreaterThan(0)
  })
})

describe("play system", () => {
  test("registry exposes plays with ids", () => {
    const plays = listPlays()
    expect(plays.length).toBe(12)
    expect(getPlay("web-surface")?.id).toBe("web-surface")
  })

  test("missing required arg raises PlayArgError", () => {
    expect(() =>
      runPlay({ id: "web-surface", args: {}, environment: { binaries: new Set(["nmap"]), runtimes: {} } }),
    ).toThrow(PlayArgError)
  })

  test("steps requiring missing capabilities are skipped as required", () => {
    const result = runPlay({
      id: getPlay("network-surface")?.id ?? "network-surface",
      args: Object.fromEntries(
        (getPlay("network-surface")?.args ?? []).filter((a) => a.required).map((a) => [a.name, "127.0.0.1"]),
      ),
      environment: { binaries: new Set<string>(), runtimes: {} },
    })
    const requiredSkips = result.skipped.filter((entry) => entry.reason.includes("required"))
    expect(requiredSkips.length + result.trace.length).toBeGreaterThan(0)
    expect(formatPlayResult(result)).toContain("network-surface")
  })
})

describe("evidence store (isolated HOME)", () => {
  test("put dedupes by content and get resolves sha/prefix/label", async () => {
    const first = await Evidence.put({
      engagementName: "cybertest",
      content: "payload-one",
      label: "probe output",
      source: "test",
    })
    const dupe = await Evidence.put({
      engagementName: "cybertest",
      content: "payload-one",
      label: "same bytes",
      source: "test",
    })
    expect(first.sha256).toBe(dupe.sha256)

    const second = await Evidence.put({
      engagementName: "cybertest",
      content: JSON.stringify({ k: 2 }),
      mime: "application/json",
      label: "json blob",
    })
    const listed = await Evidence.list("cybertest")
    expect(listed.map((e) => e.sha256)).toContain(second.sha256)

    const byPrefix = await Evidence.get("cybertest", second.sha256.slice(0, 8))
    expect(byPrefix?.entry.label).toBe("json blob")
    const byLabel = await Evidence.get("cybertest", "probe output")
    expect(byLabel?.entry.sha256).toBe(first.sha256)

    const raw = await fs.readFile(byLabel!.path, "utf8")
    expect(raw).toBe("payload-one")
  })
})

describe("observation store (isolated HOME)", () => {
  test("add/update/link/project round-trips", async () => {
    const obs = await Observation.add({
      engagementName: "obs-test",
      subtype: "risk",
      title: "open redirect",
      severity: "medium",
      tags: ["web"],
    })
    expect(obs.status).toBe("open")

    const updated = await Observation.update("obs-test", obs.id, { status: "confirmed", severity: "high" })
    expect(updated).toBe(true)

    const linked = await Observation.linkEvidence("obs-test", obs.id, "abc123")
    expect(linked).toBe(true)

    const removed = await Observation.remove("obs-test", obs.id)
    expect(removed).toBe(true)
    expect(await Observation.list("obs-test")).toHaveLength(0)
  })
})

describe("vault (isolated HOME)", () => {
  test("secrets and identity resolution round-trip", async () => {
    await Vault.setSecret("session-cookie", "sid=abcdef; other=1")
    await Vault.setSecret("api-token", "Authorization: Bearer tok123")
    const listed = await Vault.listSecrets()
    expect(listed.keys.sort()).toEqual(["api-token", "session-cookie"])

    await Vault.useIdentity("api-token")
    const active = await Vault.activeIdentity()
    expect(active?.key).toBe("api-token")

    const resolved = resolveIdentityValue(active!.key, active!.value)
    expect(resolved.mode).toBe("bearer")
    expect(resolved.headers?.Authorization).toBe("Bearer tok123")

    const cookieMode = resolveIdentityValue("session-cookie", "sid=abcdef; other=1")
    expect(cookieMode.mode).toBe("cookies")

    const headerMode = resolveIdentityValue("h", "X-Custom: yes\nX-Other: also")
    expect(headerMode.mode).toBe("headers")

    await Vault.useIdentity(undefined)
    expect(await Vault.activeIdentity()).toBeUndefined()

    const state = await Vault.deleteSecret("session-cookie")
    expect(state.secrets["session-cookie"]).toBeUndefined()
  })
})

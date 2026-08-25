import { describe, expect, test } from "bun:test"
import { rankBountySignals, rankHeaderSignals, OPENAPI_PROBE_PATHS } from "@/tool/bounty-hunt"

describe("rankBountySignals", () => {
  test("secrets rank high", () => {
    const signals = rankBountySignals({
      secrets: [{ kind: "aws-access-key", match: "AKIAIOSFODNN7EXAMPLE" }],
      endpoints: [],
      spaRoutes: [],
      fuzzHits: [],
    })
    expect(signals[0]?.severity).toBe("high")
    expect(signals[0]?.title).toContain("secret")
  })

  test("vulnerable takeover ranks above secrets (listed first)", () => {
    const signals = rankBountySignals({
      secrets: [{ kind: "slack-token", match: "xoxb-123" }],
      takeover: { service: "AWS S3", cnamePattern: /x/, vulnerable: true, detail: "dangling" },
      takeoverHost: "stale.example.com",
      endpoints: [],
      spaRoutes: [],
      fuzzHits: [],
    })
    expect(signals[0]?.title).toContain("takeover")
    expect(signals).toHaveLength(2)
  })

  test("non-vulnerable fingerprint produces no signal", () => {
    const signals = rankBountySignals({
      secrets: [],
      takeover: { service: "Shopify", cnamePattern: /x/, vulnerable: false, detail: "mitigated" },
      endpoints: [],
      spaRoutes: [],
      fuzzHits: [],
    })
    expect(signals).toHaveLength(0)
  })

  test("api endpoints and fuzz hits rank medium; spa routes info", () => {
    const signals = rankBountySignals({
      secrets: [],
      endpoints: ["/api/users", "/v1/orders", "/static/logo.png"],
      spaRoutes: ["/dashboard"],
      fuzzHits: [
        { path: ".env", url: "https://x/.env", status: 200, length: 100 },
        { path: "admin", url: "https://x/admin", status: 403, length: 0 },
      ],
    })
    const severities = signals.map((s) => s.severity)
    expect(severities).toContain("medium")
    expect(severities).toContain("info")
    expect(severities.every((s) => s !== "high")).toBe(true)
    expect(signals.filter((s) => s.severity === "medium").length).toBe(2)
  })
})

describe("rankHeaderSignals", () => {
  test("empty headers flag every security header", () => {
    const signals = rankHeaderSignals({})
    const low = signals.filter((s) => s.severity === "low")
    expect(low.length).toBe(5)
  })

  test("present headers are not flagged; tech disclosure is info", () => {
    const signals = rankHeaderSignals({
      "Content-Security-Policy": "default-src 'self'",
      "Strict-Transport-Security": "max-age=63072000",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      Server: "nginx/1.24.0",
    })
    expect(signals.filter((s) => s.severity === "low")).toHaveLength(0)
    expect(signals.some((s) => s.severity === "info" && s.title.includes("technology"))).toBe(true)
  })
})

describe("openapi probe paths", () => {
  test("covers common spec locations", () => {
    expect(OPENAPI_PROBE_PATHS.length).toBeGreaterThanOrEqual(8)
    expect(OPENAPI_PROBE_PATHS).toContain("/openapi.json")
    expect(OPENAPI_PROBE_PATHS).toContain("/swagger.json")
  })
})

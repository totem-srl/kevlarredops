import { describe, expect, test } from "bun:test"
import { rankBountySignals } from "@/tool/bounty-hunt"

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

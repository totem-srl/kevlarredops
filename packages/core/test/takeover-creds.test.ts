import { describe, expect, test } from "bun:test"
import { matchTakeover, TAKEOVER_FINGERPRINTS } from "@pentestcode/core/cyber/takeover"
import { DEFAULT_CREDS, lookupDefaultCreds } from "@pentestcode/core/cyber/defaultcreds"

describe("takeover", () => {
  test("fingerprints cover major services", () => {
    expect(TAKEOVER_FINGERPRINTS.length).toBeGreaterThanOrEqual(10)
    const services = TAKEOVER_FINGERPRINTS.map((f) => f.service)
    for (const expected of ["AWS S3", "GitHub Pages", "Heroku", "Azure Web Apps"]) {
      expect(services).toContain(expected)
    }
  })

  test("cname match identifies vulnerable service", () => {
    const hit = matchTakeover({ cname: "missing-bucket.s3.amazonaws.com" })
    expect(hit?.service).toBe("AWS S3")
    expect(hit?.vulnerable).toBe(true)
  })

  test("github.io apex matches", () => {
    expect(matchTakeover({ cname: "org.github.io" })?.service).toBe("GitHub Pages")
  })

  test("unrelated cname returns null", () => {
    expect(matchTakeover({ cname: "cdn.example-corp.com" })).toBeNull()
  })

  test("body marker fallback works", () => {
    const hit = matchTakeover({ body: "NoSuchBucket: the specified bucket does not exist" })
    expect(hit?.service).toBe("AWS S3")
  })
})

describe("defaultcreds", () => {
  test("dataset is curated", () => {
    expect(DEFAULT_CREDS.length).toBeGreaterThanOrEqual(25)
    for (const cred of DEFAULT_CREDS) {
      expect(cred.product.length).toBeGreaterThan(0)
      expect(cred.service.length).toBeGreaterThan(0)
    }
  })

  test("lookup by product substring", () => {
    const hits = lookupDefaultCreds("tomcat")
    expect(hits.length).toBeGreaterThanOrEqual(2)
    expect(hits.every((h) => h.product.toLowerCase().includes("tomcat"))).toBe(true)
  })

  test("lookup by service key", () => {
    expect(lookupDefaultCreds("grafana")[0]?.username).toBe("admin")
  })

  test("case-insensitive and no-match empty", () => {
    expect(lookupDefaultCreds("GRAFANA").length).toBeGreaterThan(0)
    expect(lookupDefaultCreds("definitely-not-a-product")).toEqual([])
  })
})

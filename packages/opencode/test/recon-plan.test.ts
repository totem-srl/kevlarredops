import { describe, expect, test } from "bun:test"
import { buildReconPlan } from "@/tool/recon-pipeline"

describe("buildReconPlan", () => {
  test("empty environment marks adapters missing and keeps builtins", () => {
    const plan = buildReconPlan(new Set(), "example.com", 25)
    const byStage = new Map(plan.map((s) => [s.stage, s]))
    expect(byStage.get("subdomain-discovery")?.status).toBe("missing_adapter")
    expect(byStage.get("port-scan")?.status).toBe("missing_adapter")
    expect(byStage.get("http-probe")?.tool).toBe("fetch")
    expect(byStage.get("takeover-check")?.status).toBe("builtin")
    expect(byStage.get("creds-hints")?.status).toBe("builtin")
  })

  test("full environment produces ready stages with target in discovery/scan commands", () => {
    const plan = buildReconPlan(new Set(["subfinder", "httpx", "nmap"]), "example.com", 25)
    const byStage = new Map(plan.map((s) => [s.stage, s]))
    expect(byStage.get("subdomain-discovery")?.command?.join(" ")).toContain("example.com")
    expect(byStage.get("port-scan")?.command?.join(" ")).toContain("example.com")
    expect(byStage.get("http-probe")?.status).toBe("ready")
  })

  test("amass fallback used when subfinder absent", () => {
    const plan = buildReconPlan(new Set(["amass"]), "example.com", 25)
    expect(plan[0]?.tool).toBe("amass")
  })
})

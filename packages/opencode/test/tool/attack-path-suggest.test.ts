import { describe, expect, test } from "bun:test"
import { computeFeasibilityScore } from "@/tool/attack-path-suggest"

describe("computeFeasibilityScore", () => {
  test("empty edges returns 1.0", () => {
    expect(computeFeasibilityScore([])).toBe(1.0)
  })

  test("low cost edge gives high score", () => {
    const edges = [{ from: "a", to: "b", relType: "MEMBER_OF", cost: 5, metadata: "", opsecLevel: "silent" as const }]
    const score = computeFeasibilityScore(edges)
    expect(score).toBeGreaterThan(0.9)
    expect(score).toBeLessThanOrEqual(1.0)
  })

  test("high cost edge gives lower score", () => {
    const edges = [{ from: "a", to: "b", relType: "SYNTHETIC", cost: 100, metadata: "", opsecLevel: "noisy" as const }]
    const score = computeFeasibilityScore(edges)
    expect(score).toBeLessThan(0.6)
    expect(score).toBeGreaterThan(0)
  })

  test("multiple hops reduce score multiplicatively", () => {
    const edge = { from: "a", to: "b", relType: "LATERAL_MOVE", cost: 30, metadata: "", opsecLevel: "quiet" as const }
    const singleHop = computeFeasibilityScore([edge])
    const twoHop = computeFeasibilityScore([edge, edge])
    expect(twoHop).toBeLessThan(singleHop)
    expect(twoHop).toBeGreaterThan(0)
  })

  test("score stays in [0.1, 0.99] range per hop", () => {
    const extremeEdge = { from: "a", to: "b", relType: "TEST", cost: 500, metadata: "", opsecLevel: "noisy" as const }
    const score = computeFeasibilityScore([extremeEdge])
    expect(score).toBeGreaterThanOrEqual(0.1)
    expect(score).toBeLessThanOrEqual(0.99)
  })

  test("infinity cost gives minimum score", () => {
    const infEdge = { from: "a", to: "b", relType: "EXPIRED", cost: Infinity, metadata: "", opsecLevel: "noisy" as const }
    const score = computeFeasibilityScore([infEdge])
    expect(score).toBe(0.1)
  })
})

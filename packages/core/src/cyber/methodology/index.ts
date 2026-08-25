import type { Framework, Phase } from "./types"

import mitreData from "./data/mitre-attack.json"
import ptesData from "./data/ptes.json"
import wstgData from "./data/wstg.json"

export type { Framework, Phase, Technique } from "./types"

const frameworks: Record<string, Framework> = {
  [mitreData.id]: mitreData as Framework,
  [ptesData.id]: ptesData as Framework,
  [wstgData.id]: wstgData as Framework,
}

export function listFrameworks(): Framework[] {
  return Object.values(frameworks)
}

export function getFramework(id: string): Framework | undefined {
  return frameworks[id]
}

export function frameworkIds(): string[] {
  return Object.keys(frameworks)
}

export function findPhase(frameworkId: string, phaseId: string): Phase | undefined {
  return frameworks[frameworkId]?.phases.find((p) => p.id === phaseId)
}

function normalize(input: string): string {
  return input.toLowerCase()
}

export function search(query: string): { framework: string; phase: string; technique: string; description?: string }[] {
  const q = normalize(query.trim())
  if (!q) return []
  const results: { framework: string; phase: string; technique: string; description?: string }[] = []
  for (const fw of listFrameworks()) {
    for (const phase of fw.phases) {
      if (normalize(phase.name).includes(q) || phase.id.toLowerCase().includes(q)) {
        results.push({ framework: fw.id, phase: phase.id, technique: `phase:${phase.name}` })
      }
      for (const technique of phase.techniques) {
        if (
          normalize(technique.name).includes(q) ||
          technique.id.toLowerCase().includes(q) ||
          (technique.description && normalize(technique.description).includes(q))
        ) {
          results.push({
            framework: fw.id,
            phase: phase.id,
            technique: `${technique.id} ${technique.name}`,
            description: technique.description,
          })
        }
      }
    }
  }
  return results
}

export * as Methodology from "."

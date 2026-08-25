export type NormalizedComponent = {
  name: string
  version?: string
  aliases?: string[]
  cpe_candidates?: string[]
}

// Parses "name@version" style strings commonly produced by lockfile/manifest scans.
export function parseComponent(input: string): NormalizedComponent {
  const trimmed = input.trim()
  const at = trimmed.lastIndexOf("@")
  if (at > 0) {
    return { name: trimmed.slice(0, at), version: trimmed.slice(at + 1) }
  }
  return { name: trimmed }
}

export function componentLabel(component: NormalizedComponent): string {
  return component.version ? `${component.name}@${component.version}` : component.name
}

export * as Component from "./component"

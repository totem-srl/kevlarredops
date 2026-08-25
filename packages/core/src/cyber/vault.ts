import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

const VAULT_DIR = path.join(os.homedir(), ".pentestcode")
const VAULT_FILE = path.join(VAULT_DIR, "vault.json")

export type SecretRecord = {
  value: string
  updated_at: string
}

export type VaultState = {
  secrets: Record<string, SecretRecord>
  active_identity?: string
  active_identity_set_at?: string
}

export type ResolvedIdentity = {
  key: string
  mode: "headers" | "cookies" | "bearer" | "raw"
  headers?: Record<string, string>
  cookies?: string
}

function emptyState(): VaultState {
  return { secrets: {} }
}

async function readState(): Promise<VaultState> {
  try {
    const raw = await fs.readFile(VAULT_FILE, "utf8")
    return { ...emptyState(), ...(JSON.parse(raw) as Partial<VaultState>) }
  } catch {
    return emptyState()
  }
}

async function writeState(state: VaultState): Promise<void> {
  await fs.mkdir(VAULT_DIR, { recursive: true })
  await fs.writeFile(VAULT_FILE, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 })
}

export async function setSecret(key: string, value: string): Promise<VaultState> {
  if (!key.trim()) throw new Error("secret key must not be empty")
  const state = await readState()
  state.secrets[key] = { value, updated_at: new Date().toISOString() }
  await writeState(state)
  return state
}

export async function deleteSecret(key: string): Promise<VaultState> {
  const state = await readState()
  delete state.secrets[key]
  if (state.active_identity === key) {
    delete state.active_identity
    delete state.active_identity_set_at
  }
  await writeState(state)
  return state
}

export async function listSecrets(): Promise<{ keys: string[]; active_identity?: string }> {
  const state = await readState()
  return { keys: Object.keys(state.secrets), active_identity: state.active_identity }
}

export async function getSecretValue(key: string): Promise<string | undefined> {
  const state = await readState()
  return state.secrets[key]?.value
}

export async function useIdentity(key?: string): Promise<VaultState> {
  const state = await readState()
  if (!key) {
    delete state.active_identity
    delete state.active_identity_set_at
  } else {
    if (!state.secrets[key]) throw new Error(`identity "${key}" not found in vault`)
    state.active_identity = key
    state.active_identity_set_at = new Date().toISOString()
  }
  await writeState(state)
  return state
}

export async function activeIdentity(): Promise<{ key: string; value: string } | undefined> {
  const state = await readState()
  const key = state.active_identity
  if (!key) return undefined
  const record = state.secrets[key]
  if (!record) return undefined
  return { key, value: record.value }
}

// Parses common identity descriptor formats into structured auth material:
//   "Header-Name: value" lines            -> headers mode
//   "Cookie: k=v; k2=v2" or "k=v; k2=v2"  -> cookies mode
//   "Authorization: Bearer x" / "Bearer x" -> bearer mode
export function resolveIdentityValue(key: string, value: string): ResolvedIdentity {
  let text = value.trim()

  const bearerDirect = text.match(/^Bearer\s+(.+)$/i)
  if (bearerDirect) {
    return { key, mode: "bearer", headers: { Authorization: `Bearer ${bearerDirect[1]!.trim()}` } }
  }

  const headerLines: Record<string, string> = {}
  let sawHeaderSyntax = false
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed) continue
    const m = trimmed.match(/^([A-Za-z0-9_-]+)\s*:\s*(.+)$/)
    if (!m) {
      sawHeaderSyntax = false
      break
    }
    sawHeaderSyntax = true
    headerLines[m[1]!] = m[2]!.trim()
  }
  if (sawHeaderSyntax && Object.keys(headerLines).length > 0) {
    const lower = Object.keys(headerLines).reduce<Record<string, string>>((acc, k) => {
      acc[k.toLowerCase()] = k
      return acc
    }, {})
    if (lower["cookie"]) {
      const cookieKey = lower["cookie"]!
      return { key, mode: "cookies", cookies: headerLines[cookieKey]! }
    }
    if (lower["authorization"]) {
      const authKey = lower["authorization"]!
      const authVal = headerLines[authKey]!
      const bearer = authVal.match(/^Bearer\s+(.+)$/i)
      if (bearer) return { key, mode: "bearer", headers: { Authorization: authVal } }
    }
    return { key, mode: "headers", headers: headerLines }
  }

  if (/^[\w.-]+=[^;]*(;\s*[\w.-]+=[^;]*)*$/.test(text)) {
    return { key, mode: "cookies", cookies: text }
  }

  return { key, mode: "raw" }
}

export * as Vault from "./vault"

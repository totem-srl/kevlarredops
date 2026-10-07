import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Schema } from "effect"
import { FindingLifecycle } from "./finding-lifecycle"
import { KeyedMutex } from "../effect/keyed-mutex"

const decode = Schema.decodeUnknownSync(Schema.Array(FindingLifecycle.RecordSchema))
const locks = KeyedMutex.makeUnsafe<string>()
export const withLock = locks.withLock

export function directory(name: string) {
  if (!name.trim() || name === "." || name === ".." || /[/\\\0]/.test(name)) {
    throw new Error("Engagement name must be a single directory name")
  }
  return path.join(process.env.OPENCODE_TEST_HOME ?? os.homedir(), ".pentestcode", "engagements", name)
}

export async function load(name: string): Promise<FindingLifecycle.FindingRecord[]> {
  const file = path.join(directory(name), "findings-lifecycle.json")
  const raw = await fs.readFile(file, "utf8").catch((error: unknown) => {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") return undefined
    throw error
  })
  if (raw === undefined) return []
  try {
    return [...decode(JSON.parse(raw))]
  } catch {
    throw new Error("Invalid finding ledger. Repair findings-lifecycle.json before promoting or exporting findings.")
  }
}

export async function save(name: string, records: FindingLifecycle.FindingRecord[]) {
  decode(records)
  const dir = directory(name)
  await fs.mkdir(dir, { recursive: true, mode: 0o700 })
  const file = path.join(dir, "findings-lifecycle.json")
  const temporary = `${file}.${crypto.randomUUID()}.tmp`
  try {
    await fs.writeFile(temporary, JSON.stringify(records, null, 2), { mode: 0o600 })
    await fs.rename(temporary, file)
  } finally {
    await fs.rm(temporary, { force: true })
  }
}

export * as FindingStore from "./finding-store"

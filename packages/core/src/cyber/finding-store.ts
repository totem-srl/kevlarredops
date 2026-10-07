import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Effect, Schema } from "effect"
import { FindingLifecycle } from "./finding-lifecycle"
import { KeyedMutex } from "../effect/keyed-mutex"

const decode = Schema.decodeUnknownSync(Schema.Array(FindingLifecycle.RecordSchema))
const locks = KeyedMutex.makeUnsafe<string>()
const LockSchema = Schema.Struct({ token: Schema.String, pid: Schema.Number, created_at: Schema.String })
export const withLock =
  (name: string) =>
  <A, E, R>(work: Effect.Effect<A, E, R>) =>
    locks.withLock(name)(
      Effect.uninterruptibleMask((restore) =>
        Effect.gen(function* () {
          const token = crypto.randomUUID()
          const file = path.join(directory(name), "findings.lock")
          yield* Effect.promise(async () => {
            await fs.mkdir(directory(name), { recursive: true, mode: 0o700 })
            const handle = await fs.open(file, "wx", 0o600).catch((error: unknown) => {
              if (error instanceof Error && "code" in error && error.code === "EEXIST") {
                throw new Error(
                  "Finding ledger is busy. Retry after the writer finishes. After a crash, inspect findings.lock before removing it.",
                )
              }
              throw error
            })
            try {
              await handle.writeFile(JSON.stringify({ token, pid: process.pid, created_at: new Date().toISOString() }))
            } catch (error) {
              await fs.rm(file, { force: true })
              throw error
            } finally {
              await handle.close()
            }
          })
          return yield* restore(work).pipe(
            Effect.ensuring(
              Effect.promise(async () => {
                const content = await fs.readFile(file, "utf8").catch((error: unknown) => {
                  if (error instanceof Error && "code" in error && error.code === "ENOENT")
                    throw new Error("Finding lock disappeared during the write; inspect the ledger before retrying.")
                  throw error
                })
                const lock = (() => {
                  try {
                    return Schema.decodeUnknownSync(LockSchema)(JSON.parse(content))
                  } catch {
                    throw new Error("Finding lock is malformed; inspect findings.lock before removing it.")
                  }
                })()
                if (lock.token !== token)
                  throw new Error("Finding lock ownership changed; inspect findings.lock before removing it.")
                await fs.rm(file)
              }),
            ),
          )
        }),
      ),
    )

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

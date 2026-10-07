import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { Evidence } from "../src/cyber/evidence"
import { FindingStore } from "../src/cyber/finding-store"
import { FindingLifecycle } from "../src/cyber/finding-lifecycle"

async function owned(run: (name: string) => Promise<void>) {
  if (!process.env.OPENCODE_TEST_HOME) throw new Error("The test preload must isolate user data")
  const name = `integrity-${crypto.randomUUID()}`
  try {
    await run(name)
  } finally {
    await fs.rm(FindingStore.directory(name), { recursive: true, force: true })
  }
}

test("evidence resolution accepts exact hashes, nonambiguous prefixes and unique labels", () =>
  owned(async (name) => {
    const entry = await Evidence.put({
      engagementName: name,
      content: "owned lab evidence",
      mime: "text/plain",
      label: "proof",
    })
    for (const ref of [entry.sha256, entry.sha256.slice(0, 12), "proof"])
      expect((await Evidence.get(name, ref))?.entry.sha256).toBe(entry.sha256)
    expect(await Evidence.get(name, "")).toBeUndefined()
    expect(await Evidence.get(name, "missing")).toBeUndefined()
  }))

test("changing stored bytes with the same length invalidates evidence", () =>
  owned(async (name) => {
    const entry = await Evidence.put({ engagementName: name, content: "owned", mime: "text/plain" })
    const found = await Evidence.get(name, entry.sha256)
    await fs.writeFile(found!.path, "other")
    await expect(Evidence.get(name, entry.sha256)).rejects.toThrow("integrity")
  }))

test("a missing blob does not resolve and another engagement cannot supply the proof", () =>
  owned(async (name) => {
    const entry = await Evidence.put({ engagementName: name, content: "owned", mime: "text/plain" })
    expect(await Evidence.get(`${name}-other`, entry.sha256)).toBeUndefined()
    const found = await Evidence.get(name, entry.sha256)
    await fs.rm(found!.path)
    expect(await Evidence.get(name, entry.sha256)).toBeUndefined()
  }))

test("duplicate labels with different hashes require explicit SHA selection", () =>
  owned(async (name) => {
    const first = await Evidence.put({ engagementName: name, content: "first", label: "proof" })
    await Evidence.put({ engagementName: name, content: "second", label: "proof" })
    await expect(Evidence.get(name, "proof")).rejects.toThrow("Ambiguous")
    expect((await Evidence.get(name, first.sha256))?.entry.sha256).toBe(first.sha256)
  }))

test("repeated metadata for one hash remains an unambiguous artifact", () =>
  owned(async (name) => {
    const first = await Evidence.put({ engagementName: name, content: "same", label: "first" })
    await Evidence.put({ engagementName: name, content: "same", label: "second" })
    expect((await Evidence.get(name, first.sha256))?.entry.sha256).toBe(first.sha256)
  }))

test("corrupt or unsafe evidence manifests fail visibly", () =>
  owned(async (name) => {
    const entry = await Evidence.put({ engagementName: name, content: "owned" })
    const manifest = path.join(FindingStore.directory(name), "evidence", "manifest.jsonl")
    await fs.writeFile(manifest, JSON.stringify({ ...entry, ext: "/../../unsafe" }))
    await expect(Evidence.list(name)).rejects.toThrow("Invalid evidence manifest")
    await fs.writeFile(manifest, "{broken\n")
    await expect(Evidence.get(name, entry.sha256)).rejects.toThrow("Invalid evidence manifest")
  }))

test("invalid engagement names cannot leave the engagement directory", async () => {
  for (const name of ["../elsewhere", "..", ".", "a/b", "a\\b", ""])
    await expect(Evidence.list(name)).rejects.toThrow("single directory")
})

test("malformed finding records cannot overwrite a valid ledger", () =>
  owned(async (name) => {
    const record: FindingLifecycle.FindingRecord = {
      id: "owned",
      title: "Owned",
      target: "127.0.0.1",
      status: "candidate",
      evidence_refs: [],
      replay: { present: false },
      at: "2026-10-07",
    }
    await FindingStore.save(name, [record])
    const file = path.join(FindingStore.directory(name), "findings-lifecycle.json")
    expect((await fs.stat(file)).mode & 0o777).toBe(0o600)
    expect(await FindingStore.load(name)).toEqual([record])
    await fs.writeFile(file, '[{"id":"bad"}]')
    await expect(FindingStore.load(name)).rejects.toThrow("Invalid finding ledger")
  }))

test("superseded records never count as reportable and have their own bucket", () => {
  const record: FindingLifecycle.FindingRecord = {
    id: "old",
    title: "Old",
    target: "127.0.0.1",
    status: "verified",
    evidence_refs: ["proof"],
    replay: { present: true },
    superseded_by: "new",
    at: "2026-10-07",
  }
  expect(FindingLifecycle.isReportableFinding(record)).toBe(false)
  expect(FindingLifecycle.bucketFindings([record]).superseded).toEqual([record])
  expect(FindingLifecycle.isReportableFinding({ ...record, superseded_by: undefined, target: undefined })).toBe(false)
})

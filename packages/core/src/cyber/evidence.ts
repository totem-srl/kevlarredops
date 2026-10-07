import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"

const ENGAGEMENTS_DIR = path.join(process.env.OPENCODE_TEST_HOME ?? os.homedir(), ".pentestcode", "engagements")
const MANIFEST_FILE = "manifest.jsonl"
const BLOBS_DIR = "blobs"

export type Entry = {
  sha256: string
  ext: string
  size: number
  mime: string
  label: string
  source: string
  at: string
}

function engagementDir(engagementName: string): string {
  return path.join(ENGAGEMENTS_DIR, engagementName)
}

function evidenceDir(engagementName: string): string {
  return path.join(engagementDir(engagementName), "evidence")
}

function manifestPath(engagementName: string): string {
  return path.join(evidenceDir(engagementName), MANIFEST_FILE)
}

function blobPath(engagementName: string, sha256: string, ext: string): string {
  return path.join(evidenceDir(engagementName), BLOBS_DIR, `${sha256}${ext}`)
}

const MIME_EXT: Record<string, string> = {
  "text/html": ".html",
  "application/json": ".json",
  "text/plain": ".txt",
  "text/markdown": ".md",
  "image/png": ".png",
  "image/jpeg": ".jpg",
  "image/gif": ".gif",
  "image/webp": ".webp",
  "image/svg+xml": ".svg",
  "application/pdf": ".pdf",
  "application/xml": ".xml",
  "text/xml": ".xml",
  "application/zip": ".zip",
  "application/gzip": ".gz",
  "application/x-tar": ".tar",
  "video/mp4": ".mp4",
  "audio/mpeg": ".mp3",
  "application/wasm": ".wasm",
  "application/octet-stream": ".bin",
}

function sniffExtFromMime(mime: string): string {
  const base = mime.split(";")[0]!.trim().toLowerCase()
  return MIME_EXT[base] ?? ".bin"
}

async function readManifest(engagementName: string): Promise<Entry[]> {
  const entries: Entry[] = []
  try {
    const raw = await fs.readFile(manifestPath(engagementName), "utf8")
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue
      try {
        entries.push(JSON.parse(line) as Entry)
      } catch {
        // skip malformed manifest lines
      }
    }
  } catch {
    // no manifest yet
  }
  return entries
}

async function appendManifestLine(engagementName: string, entry: Entry): Promise<void> {
  await fs.mkdir(evidenceDir(engagementName), { recursive: true })
  await fs.appendFile(manifestPath(engagementName), `${JSON.stringify(entry)}\n`, { mode: 0o600 })
}

export async function put(input: {
  engagementName: string
  content: Uint8Array | string
  mime?: string
  label?: string
  source?: string
}): Promise<Entry> {
  const buf = typeof input.content === "string" ? Buffer.from(input.content, "utf8") : Buffer.from(input.content)
  const sha256 = createHash("sha256").update(buf).digest("hex")
  const mime = input.mime ?? (Buffer.isBuffer(buf) && buf.length === 0 ? "text/plain" : "application/octet-stream")

  let textPreview: string | undefined
  if (mime.startsWith("text/") || mime.includes("json") || mime.includes("xml") || mime === "application/javascript") {
    textPreview = buf.toString("utf8").slice(0, 4096).toLowerCase()
    if (textPreview.includes("<html") || textPreview.includes("<!doctype html")) return finalize(".html", "text/html")
    if (textPreview.includes("{") || textPreview.includes("[")) {
      try {
        JSON.parse(textPreview.length < buf.length ? buf.toString("utf8") : textPreview)
        return finalize(".json", "application/json")
      } catch {
        // fall through to declared mime
      }
    }
  }

  return finalize(sniffExtFromMime(mime), mime)

  async function finalize(ext: string, resolvedMime: string): Promise<Entry> {
    const existing = await readManifest(input.engagementName)
    const prior = existing.find((e) => e.sha256 === sha256 && e.label === (input.label ?? ""))
    const target = blobPath(input.engagementName, sha256, ext)
    await fs.mkdir(path.dirname(target), { recursive: true })
    await fs.writeFile(target, buf, { mode: 0o600 })
    if (prior) return prior
    const entry: Entry = {
      sha256,
      ext,
      size: buf.length,
      mime: resolvedMime,
      label: input.label ?? "",
      source: input.source ?? "",
      at: new Date().toISOString(),
    }
    await appendManifestLine(input.engagementName, entry)
    return entry
  }
}

export async function list(engagementName: string): Promise<Entry[]> {
  return readManifest(engagementName)
}

export async function get(
  engagementName: string,
  ref: string,
): Promise<{ path: string; entry: Entry } | undefined> {
  const entries = await readManifest(engagementName)
  const bySha = entries.find((e) => e.sha256 === ref || e.sha256.startsWith(ref))
  const match = bySha ?? entries.find((e) => e.label === ref)
  if (!match) return undefined
  const target = blobPath(engagementName, match.sha256, match.ext)
  try {
    await fs.access(target)
    return { path: target, entry: match }
  } catch {
    return undefined
  }
}

export * as Evidence from "./evidence"

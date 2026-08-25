import { Effect, Schema } from "effect"
import fs from "node:fs/promises"
import path from "node:path"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import DESCRIPTION from "./file-triage.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  path: Schema.String.annotate({ description: "Path to the file to triage" }),
  max_strings: Schema.optional(Schema.Number.annotate({ description: "Max strings shown (default 40)" })),
  min_length: Schema.optional(Schema.Number.annotate({ description: "Min printable run length (default 6)" })),
})

const MAGIC: [number[], string][] = [
  [[0x7f, 0x45, 0x4c, 0x46], "ELF executable"],
  [[0x4d, 0x5a], "Windows PE (MZ)"],
  [[0xca, 0xfe, 0xba, 0xbe], "Mach-O fat / Java class"],
  [[0xcf, 0xfa, 0xed, 0xfe], "Mach-O 64-bit"],
  [[0xff, 0xd8, 0xff], "JPEG image"],
  [[0x89, 0x50, 0x4e, 0x47], "PNG image"],
  [[0x25, 0x50, 0x44, 0x46], "PDF document"],
  [[0x50, 0x4b, 0x03, 0x04], "ZIP archive"],
  [[0x1f, 0x8b], "GZIP archive"],
  [[0x42, 0x4d], "BMP image"],
]

export function sniffMagic(bytes: Uint8Array): string | undefined {
  for (const [prefix, label] of MAGIC) {
    if (prefix.every((byte, i) => bytes[i] === byte)) return label
  }
  if (bytes[0] === 0x23 && bytes[1] === 0x21) return "Script (shebang)"
  return undefined
}

export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0
  const counts = new Array<number>(256).fill(0)
  for (const byte of bytes) counts[byte] += 1
  let entropy = 0
  for (const count of counts) {
    if (count === 0) continue
    const p = count / bytes.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

export function extractStrings(
  bytes: Uint8Array,
  minLength: number,
): string[] {
  const out: string[] = []
  let current = ""
  for (const byte of bytes) {
    if (byte >= 0x20 && byte <= 0x7e) {
      current += String.fromCharCode(byte)
    } else {
      if (current.length >= minLength) out.push(current)
      current = ""
    }
  }
  if (current.length >= minLength) out.push(current)
  return out
}

const INTERESTING_RE =
  /(https?:\/\/|\/(?:usr|etc|bin|tmp|proc)\/|[A-Za-z]:\\\\|password|passwd|token|secret|api[_-]?key|flag\{|CTF\{|BEGIN .* PRIVATE KEY)/i

export const FileTriageTool = Tool.define(
  "file_triage",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const abs = path.isAbsolute(params.path) ? params.path : path.join(process.cwd(), params.path)
          let bytes: Uint8Array
          try {
            bytes = new Uint8Array(yield* Effect.promise(() => fs.readFile(abs)))
          } catch {
            return { title: "file_triage · unreadable", metadata: {}, output: `Could not read ${abs}` }
          }

          const kind = sniffMagic(bytes.subarray(0, 8))
          const entropy = shannonEntropy(bytes)
          const minLength = Math.max(Math.trunc(params.min_length ?? 6), 3)
          const allStrings = extractStrings(bytes, minLength)
          const interesting = allStrings.filter((s) => INTERESTING_RE.test(s)).slice(0, params.max_strings ?? 40)
          const shown = allStrings.slice(0, params.max_strings ?? 40)

          // entropy over the middle region too — packed sections usually sit away from headers
          const midStart = Math.floor(bytes.length / 3)
          const midEntropy = shannonEntropy(bytes.subarray(midStart, midStart + Math.min(bytes.length, 262_144)))

          const lines = [
            `${abs}`,
            `size: ${bytes.length} bytes · type: ${kind ?? "unknown (no known magic)"}`,
            `entropy: overall ${entropy.toFixed(2)} /8.00 · middle region ${midEntropy.toFixed(2)}`,
            entropy > 7.5 ? "⚠ high entropy — likely packed/compressed/encrypted" : "",
            "",
            ...(interesting.length > 0 ? [`Interesting strings (${interesting.length}):`, ...interesting.map((s) => `  ! ${s.slice(0, 160)}`), ""] : []),
            `First strings (${Math.min(shown.length, shown.length)}):`,
            ...shown.map((s) => `  ${s.slice(0, 160)}`),
          ].filter((l) => l !== "")

          const state = yield* store.get()
          let evidenceSha: string | undefined
          if (state) {
            evidenceSha = (
              yield* Effect.promise(() =>
                Evidence.put({
                  engagementName: state.name,
                  content: lines.join("\n"),
                  mime: "text/plain",
                  label: `file triage ${path.basename(abs)}`,
                  source: "file_triage",
                }).catch(() => undefined),
              )
            )?.sha256
          }

          return {
            title: `file_triage · ${(kind ?? "unknown").split(" ")[0]} · H=${entropy.toFixed(1)} · ${path.basename(abs)}`,
            metadata: {
              size: bytes.length,
              type: kind,
              entropy,
              mid_entropy: midEntropy,
              strings_total: allStrings.length,
              strings_interesting: interesting.length,
              evidence_sha: evidenceSha,
            },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

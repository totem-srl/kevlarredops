import { Effect, Schema } from "effect"
import { createHash, createHmac } from "node:crypto"
import DESCRIPTION from "./crypto.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  op: Schema.Literals(["hash", "hmac", "encode", "decode", "jwt_decode", "xor"]).annotate({ description: "operation" }),
  input: Schema.optional(Schema.String.annotate({ description: "input string" })),
  algo: Schema.optional(
    Schema.Literals(["sha256", "sha1", "md5", "sha512"]).annotate({ description: "hash algorithm, default sha256" }),
  ),
  codec: Schema.optional(
    Schema.Literals(["base64", "base64url", "hex", "url", "rot13"]).annotate({
      description: "codec for encode/decode",
    }),
  ),
  key: Schema.optional(Schema.String.annotate({ description: "key for hmac/xor" })),
  input_encoding: Schema.optional(
    Schema.Literals(["utf8", "base64", "hex"]).annotate({ description: "how to read input for hash/hmac/xor, default utf8" }),
  ),
  encoding: Schema.optional(
    Schema.Literals(["hex", "base64", "base64url"]).annotate({ description: "output encoding for hash/hmac/xor, default hex" }),
  ),
})

function rot13(input: string): string {
  return input.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97
    return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base)
  })
}

function jwtDecode(token: string) {
  const parts = token.split(".")
  if (parts.length !== 3 || parts.some((part) => part.length === 0)) return undefined
  const decode = (part: string) => {
    try {
      return JSON.parse(Buffer.from(part, "base64url").toString("utf8"))
    } catch {
      return undefined
    }
  }
  const header = decode(parts[0])
  const payload = decode(parts[1])
  if (header === undefined || payload === undefined) return undefined
  return { header, payload, signature_hex: Buffer.from(parts[2], "base64url").toString("hex") }
}

export const CryptoTool = Tool.define(
  "crypto",
  Effect.gen(function* () {
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          op: "hash" | "hmac" | "encode" | "decode" | "jwt_decode" | "xor"
          input?: string
          algo?: "sha256" | "sha1" | "md5" | "sha512"
          codec?: "base64" | "base64url" | "hex" | "url" | "rot13"
          key?: string
          input_encoding?: "utf8" | "base64" | "hex"
          encoding?: "hex" | "base64" | "base64url"
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          if (!params.input && params.op !== "encode" && params.op !== "decode") {
            return { title: `crypto ${params.op}`, metadata: { op: params.op }, output: "Provide input." }
          }
          const inputEncoding = params.input_encoding ?? "utf8"
          const outputEncoding = params.encoding ?? "hex"
          const buf =
            inputEncoding === "base64"
              ? Buffer.from(params.input ?? "", "base64")
              : inputEncoding === "hex"
                ? Buffer.from(params.input ?? "", "hex")
                : Buffer.from(params.input ?? "", "utf8")

          if (params.op === "hash") {
            const digest = createHash(params.algo ?? "sha256").update(buf).digest(outputEncoding)
            return {
              title: `crypto hash · ${params.algo ?? "sha256"}`,
              metadata: { op: "hash", algo: params.algo ?? "sha256" },
              output: digest,
            }
          }

          if (params.op === "hmac") {
            if (!params.key) return { title: "crypto hmac", metadata: { op: "hmac" }, output: "Provide key for hmac." }
            const digest = createHmac(params.algo ?? "sha256", params.key).update(buf).digest(outputEncoding)
            return {
              title: `crypto hmac · ${params.algo ?? "sha256"}`,
              metadata: { op: "hmac", algo: params.algo ?? "sha256" },
              output: digest,
            }
          }

          if (params.op === "xor") {
            if (!params.key) return { title: "crypto xor", metadata: { op: "xor" }, output: "Provide key for xor." }
            const keyBuf = Buffer.from(params.key, "utf8")
            const out = Buffer.alloc(buf.length)
            for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ keyBuf[i % keyBuf.length]
            return {
              title: "crypto xor",
              metadata: { op: "xor", bytes: out.length },
              output: out.toString(outputEncoding === "base64url" ? "base64url" : outputEncoding),
            }
          }

          if (params.op === "jwt_decode") {
            const decoded = jwtDecode(params.input!)
            if (!decoded) {
              return { title: "crypto jwt_decode", metadata: { op: "jwt_decode" }, output: "Not a decodable JWT (need header.payload.signature)." }
            }
            return {
              title: "crypto jwt_decode",
              metadata: { op: "jwt_decode", alg: decoded.header.alg },
              output: JSON.stringify(decoded, null, 2),
            }
          }

          const value = params.input ?? ""
          const codec = params.codec ?? "base64"
          let result: string
          if (params.op === "encode") {
            result =
              codec === "rot13"
                ? rot13(value)
                : codec === "url"
                  ? encodeURIComponent(value)
                  : Buffer.from(value, "utf8").toString(codec === "base64url" ? "base64url" : codec)
          } else {
            result =
              codec === "rot13"
                ? rot13(value)
                : codec === "url"
                  ? decodeURIComponent(value)
                  : Buffer.from(value, codec === "base64url" ? "base64url" : codec).toString("utf8")
          }
          return {
            title: `crypto ${params.op} · ${codec}`,
            metadata: { op: params.op, codec },
            output: result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

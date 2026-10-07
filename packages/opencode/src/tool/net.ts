import { Effect, Schema } from "effect"
import net from "node:net"
import dgram from "node:dgram"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import { ScopeMatcher } from "@pentestcode/core/engagement/scope-matcher"
import DESCRIPTION from "./net.txt"
import { Tool } from "./tool"

export const Parameters = Schema.Struct({
  op: Schema.Literals(["tcp_send", "udp_send", "banner_grab"]).annotate({ description: "network operation" }),
  host: Schema.String.annotate({ description: "target hostname or IP" }),
  port: Schema.Number.annotate({ description: "target port (1-65535)" }),
  payload: Schema.optional(Schema.String.annotate({ description: "bytes to send when op = tcp_send/udp_send" })),
  payload_encoding: Schema.optional(
    Schema.Literals(["utf8", "hex", "base64"]).annotate({ description: "default utf8" }),
  ),
  timeout_ms: Schema.optional(Schema.Number.annotate({ description: "timeout in ms, 100-30000, default 5000" })),
  read_bytes: Schema.optional(Schema.Number.annotate({ description: "max response bytes, default 16384, max 1MiB" })),
})

function formatBytes(buf: Buffer): string {
  const printable = buf.toString("latin1").replace(/[^\x20-\x7e]/g, ".")
  const hex = Array.from(buf.subarray(0, 256))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ")
  return `text: ${printable.slice(0, 2000)}\nhex[0..256]: ${hex}`
}

function decodePayload(payload: string | undefined, encoding: string | undefined): Buffer {
  if (!payload) return Buffer.alloc(0)
  if (encoding === "hex") return Buffer.from(payload.replace(/\s+/g, ""), "hex")
  if (encoding === "base64") return Buffer.from(payload, "base64")
  return Buffer.from(payload, "utf8")
}

function tcpSession(input: {
  host: string
  port: number
  timeoutMs: number
  readBytes: number
  send?: Buffer
}): Promise<{ data: Buffer; elapsed_ms: number; error?: string }> {
  return new Promise((resolvePromise) => {
    const started = Date.now()
    const chunks: Buffer[] = []
    let received = 0
    let settled = false
    const socket = new net.Socket()
    const finish = (error?: string) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolvePromise({ data: Buffer.concat(chunks), elapsed_ms: Date.now() - started, error })
    }
    socket.setTimeout(input.timeoutMs)
    socket.on("connect", () => {
      if (input.send && input.send.length > 0) socket.write(input.send)
    })
    socket.on("data", (chunk) => {
      chunks.push(chunk)
      received += chunk.length
      if (received >= input.readBytes) finish()
    })
    socket.on("timeout", () => finish())
    socket.on("error", (err) => finish(err.message))
    socket.on("close", () => finish())
    socket.connect(input.port, input.host)
  })
}

function udpSend(input: {
  host: string
  port: number
  payload: Buffer
  timeoutMs: number
  readBytes: number
}): Promise<{ data: Buffer; elapsed_ms: number; error?: string }> {
  return new Promise((resolvePromise) => {
    const started = Date.now()
    const socket = dgram.createSocket("udp4")
    let settled = false
    const finish = (data: Buffer, error?: string) => {
      if (settled) return
      settled = true
      try {
        socket.close()
      } catch {
        // already closed
      }
      resolvePromise({ data, elapsed_ms: Date.now() - started, error })
    }
    socket.on("message", (msg) => finish(msg.subarray(0, input.readBytes)))
    socket.on("error", (err) => finish(Buffer.alloc(0), err.message))
    setTimeout(() => finish(Buffer.alloc(0)), input.timeoutMs).unref()
    socket.send(input.payload, input.port, input.host, (err) => {
      if (err) finish(Buffer.alloc(0), err.message)
    })
  })
}

export const NetTool = Tool.define(
  "net",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: {
          op: "tcp_send" | "udp_send" | "banner_grab"
          host: string
          port: number
          payload?: string
          payload_encoding?: "utf8" | "hex" | "base64"
          timeout_ms?: number
          read_bytes?: number
        },
        _ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          const state = yield* store.get()
          if (state) {
            const check = ScopeMatcher.checkScope(params.host, state.scope)
            if (!check.inScope) {
              return {
                title: `net · ${params.host}:${params.port}`,
                metadata: { op: params.op, out_of_scope: true },
                output: `Blocked: ${params.host} is outside engagement scope (${check.reason ?? "no match"}).`,
              }
            }
          }

          const port = Math.floor(params.port)
          if (!(port >= 1 && port <= 65535)) {
            return { title: "net", metadata: { op: params.op }, output: "Port must be 1-65535." }
          }
          const timeoutMs = Math.min(Math.max(params.timeout_ms ?? 5000, 100), 30000)
          const readBytes = Math.min(params.read_bytes ?? 16384, 1024 * 1024)

          const result =
            params.op === "udp_send"
              ? yield* Effect.promise(() =>
                  udpSend({
                    host: params.host,
                    port,
                    payload: decodePayload(params.payload, params.payload_encoding),
                    timeoutMs,
                    readBytes,
                  }),
                )
              : yield* Effect.promise(() =>
                  tcpSession({
                    host: params.host,
                    port,
                    timeoutMs,
                    readBytes,
                    send: params.op === "tcp_send" ? decodePayload(params.payload, params.payload_encoding) : undefined,
                  }),
                )

          return {
            title: `net ${params.op} · ${params.host}:${port}`,
            metadata: {
              op: params.op,
              host: params.host,
              port,
              bytes: result.data.length,
              elapsed_ms: result.elapsed_ms,
              error: result.error,
            },
            output:
              result.data.length === 0
                ? `${result.error ? `error: ${result.error}\n` : ""}No response within ${timeoutMs}ms.`
                : formatBytes(result.data),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

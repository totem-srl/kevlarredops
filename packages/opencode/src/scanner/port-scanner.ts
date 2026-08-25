import net from "node:net"

export const TOP_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
  1521, 2049, 3000, 3001, 3306, 3389, 4000, 5000, 5173, 5432, 5900, 6379, 8000,
  8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017,
]

const SERVICE_SIGNATURES: Array<[RegExp | string, string]> = [
  [/^SSH-/, "ssh"],
  [/^220[ -]/, "ftp-or-smtp"],
  [/^220.*SMTP/, "smtp"],
  [/\+OK\b/i, "pop3"],
  [/\* OK\b/i, "imap"],
  [/^HTTP\//, "http"],
  ["json-api", "json-api"],
  ["<html", "html"],
  [/mysql/i, "mysql"],
  [/postgresql/i, "postgresql"],
  [/-ERR|\+PONG/, "redis"],
  [/mongodb/i, "mongodb"],
]

function classifyBanner(banner: string): string {
  const lower = banner.slice(0, 512)
  for (const [pattern, service] of SERVICE_SIGNATURES) {
    if (pattern instanceof RegExp ? pattern.test(lower) : lower.includes(pattern)) return service
  }
  return "unknown"
}

function probePort(host: string, port: number, timeoutMs: number): Promise<{ status: string; banner?: string; service?: string }> {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    let settled = false
    const chunks: Buffer[] = []

    const finish = (result: { status: string; banner?: string; service?: string }) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(result)
    }

    socket.setTimeout(timeoutMs)
    socket.once("connect", () => {
      socket.setTimeout(2000)
    })
    socket.on("data", (data) => {
      chunks.push(data)
      const text = Buffer.concat(chunks).toString("utf8")
      if (text.length >= 32 || text.includes("\n")) {
        finish({ status: "open", banner: text.trim().slice(0, 512), service: classifyBanner(text) })
      }
    })
    socket.on("timeout", () => {
      if (chunks.length > 0) {
        const text = Buffer.concat(chunks).toString("utf8").trim().slice(0, 512)
        finish({ status: "open", banner: text || undefined, service: text ? classifyBanner(text) : undefined })
      } else {
        finish({ status: "open-no-banner" })
      }
    })
    socket.once("error", () => finish({ status: "closed" }))
    socket.connect(port, host)
  })
}

async function runBatches<T, R>(items: T[], size: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = []
  for (let i = 0; i < items.length; i += size) {
    results.push(...(await Promise.all(items.slice(i, i + size).map(worker))))
  }
  return results
}

export interface PortScanResult {
  host: string
  ports: Array<{ port: number; status: string; service?: string; banner?: string }>
  openCount: number
}

export async function scanPorts(host: string, options?: { ports?: number[]; timeoutMs?: number }): Promise<PortScanResult> {
  const ports = options?.ports ?? TOP_PORTS
  const timeoutMs = options?.timeoutMs ?? 3000
  const ports_ = await runBatches(ports, 50, async (port) => ({ port, ...await probePort(host, port, timeoutMs) }))
  const open = ports_.filter((entry) => entry.status.startsWith("open"))
  return { host, ports: open, openCount: open.length }
}

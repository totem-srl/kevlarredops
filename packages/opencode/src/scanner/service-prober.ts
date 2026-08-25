import net from "node:net"

interface Probe {
  name: string
  payload?: string | Uint8Array
  match: (banner: string) => boolean | undefined
}

const PROBES: Probe[] = [
  { name: "http", payload: `GET / HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n`, match: (b) => b.startsWith("HTTP/") },
  { name: "redis", payload: `PING\r\n`, match: (b) => (b.includes("+PONG") || b.includes("-ERR") || b.includes("-NOAUTH")) },
  { name: "memcached", payload: `version\r\n`, match: (b) => b.startsWith("VERSION") },
  { name: "rdp", payload: new Uint8Array([0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00]), match: (b) => b.charCodeAt(0) === 0x03 && b.charCodeAt(1) === 0x00 },
]

function passiveMatch(banner: string): string | undefined {
  if (/^SSH-/.test(banner)) return "ssh"
  if (/^220[ -]/.test(banner)) return banner.toUpperCase().includes("SMTP") ? "smtp" : "ftp"
  if (/\+OK\b/i.test(banner)) return "pop3"
  if (/\* OK\b/i.test(banner)) return "imap"
  if (/^HTTP\//.test(banner)) return "http"
  if (/mysql/i.test(banner)) return "mysql"
  if (/postgresql/i.test(banner)) return "postgresql"
  return undefined
}

interface ProbeOutcome {
  service?: string
  detail?: string
}

function sendProbe(host: string, port: number, timeoutMs: number): Promise<ProbeOutcome> {
  return new Promise((resolve) => {
    const socket = new net.Socket()
    let settled = false
    let wroteProbe = false
    let probeIndex = 0
    const chunks: Buffer[] = []

    const finish = (outcome: ProbeOutcome) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(outcome)
    }

    const collect = (): string => Buffer.concat(chunks).toString("latin1")

    const nextStep = () => {
      if (wroteProbe) {
        finish({ detail: collect().trim().slice(0, 512) })
        return
      }
      if (probeIndex >= PROBES.length) {
        finish({})
        return
      }
      const probe = PROBES[probeIndex++]
      wroteProbe = true
      socket.write(probe.payload!)
    }

    socket.setTimeout(timeoutMs)
    socket.on("connect", () => socket.setTimeout(2000))
    socket.on("data", (data) => {
      chunks.push(data)
      const banner = collect()
      if (!wroteProbe) {
        const passive = passiveMatch(banner)
        if (passive) finish({ service: passive, detail: banner.trim().slice(0, 512) })
      } else {
        for (let i = probeIndex - 1; i >= 0; i--) {
          const verdict = PROBES[i].match(banner)
          if (verdict === true) finish({ service: PROBES[i].name, detail: banner.trim().slice(0, 512) })
          if (verdict === false) break
        }
      }
      nextStep()
    })
    socket.on("timeout", () => nextStep())
    socket.once("error", () => finish({}))
    socket.connect(port, host)
  })
}

export interface ServiceProbeResult {
  host: string
  port: number
  service?: string
  confidence: "banner" | "probe" | "none"
  detail?: string
}

export async function probeService(host: string, port: number, timeoutMs = 5000): Promise<ServiceProbeResult> {
  const outcome = await sendProbe(host, port, timeoutMs)
  if (outcome.service) {
    const isPassive = passiveMatch(outcome.detail ?? "") === outcome.service
    return { host, port, service: outcome.service, confidence: isPassive ? "banner" : "probe", detail: outcome.detail }
  }
  return { host, port, confidence: "none", detail: outcome.detail }
}

export function formatServiceProbes(result: ServiceProbeResult[]): string {
  const lines = result.map((r) => {
    const label = r.service ?? "unidentified"
    const extra = r.detail && r.service ? ` — ${r.detail.split(/\r?\n/)[0].slice(0, 120)}` : ""
    return `${r.host}:${r.port} → ${label} (${r.confidence})${extra}`
  })
  return lines.join("\n")
}

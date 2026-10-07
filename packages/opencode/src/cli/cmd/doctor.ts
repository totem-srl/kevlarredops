import { cmd } from "./cmd"

export const DoctorCommand = cmd({
  command: "doctor",
  describe: "check local prerequisites and saved scope without scanning or calling a provider",
  builder: (yargs) =>
    yargs
      .option("engagement", {
        type: "string",
        describe: "Validate a saved engagement and its finding/evidence ledgers",
      })
      .option("json", { type: "boolean", default: false, describe: "Structured local check results" })
      .option("strict", {
        type: "boolean",
        default: false,
        describe: "Exit 2 for missing required prerequisites or invalid engagement data",
      }),
  async handler(args) {
    const { readFile } = await import("node:fs/promises")
    const { join, dirname } = await import("node:path")
    const { Schema } = await import("effect")
    const { Global } = await import("@pentestcode/core/global")
    const { Auth } = await import("@/auth")
    const { FindingStore } = await import("@pentestcode/core/cyber/finding-store")
    const { Evidence } = await import("@pentestcode/core/cyber/evidence")
    const { EngagementSchema } = await import("@pentestcode/core/engagement/schema")
    const checks: { name: string; status: "pass" | "warn" | "fail" | "not_run"; detail: string; next_step?: string }[] =
      []
    checks.push({ name: "runtime", status: "pass", detail: `Bun ${Bun.version}; ${process.platform}/${process.arch}` })
    checks.push({
      name: "git",
      status: Bun.which("git") ? "pass" : "fail",
      detail: Bun.which("git") ? "Git executable found" : "Git is missing",
      next_step: "Install Git and rerun doctor.",
    })
    const configured = [
      "ANTHROPIC_API_KEY",
      "OPENAI_API_KEY",
      "GOOGLE_GENERATIVE_AI_API_KEY",
      "GEMINI_API_KEY",
      "OPENROUTER_API_KEY",
    ].filter((name) => Boolean(process.env[name]))
    let stored = 0
    try {
      const sources = process.env.OPENCODE_AUTH_CONTENT
        ? [process.env.OPENCODE_AUTH_CONTENT]
        : await Promise.all(
            [join(Global.Path.data, "auth.json"), join(dirname(Global.Path.data), "opencode", "auth.json")].map(
              (file) =>
                readFile(file, "utf8").catch((error: unknown) => {
                  if (error instanceof Error && "code" in error && error.code === "ENOENT") return "{}"
                  throw error
                }),
            ),
          )
      stored = sources.flatMap((source) =>
        Object.keys(Schema.decodeUnknownSync(Schema.Record(Schema.String, Auth.Info))(JSON.parse(source))),
      ).length
      checks.push({
        name: "provider_configuration",
        status: stored || configured.length ? "pass" : "warn",
        detail:
          stored || configured.length
            ? "Provider credential configuration found locally; values are not displayed"
            : "No supported environment credentials or saved provider credentials found; custom/local endpoints were not evaluated",
        next_step: "Use pentestcode providers login or configure a local provider; then select a model.",
      })
    } catch {
      checks.push({
        name: "provider_configuration",
        status: "fail",
        detail: "Provider credential configuration is unreadable or malformed; values are not displayed",
        next_step: "Repair the local auth configuration or use pentestcode providers login.",
      })
    }
    const tools = [
      { name: "nmap", purpose: "host and service discovery" },
      { name: "subfinder", purpose: "subdomain discovery" },
      { name: "nuclei", purpose: "template-based checks" },
      { name: "ffuf", purpose: "external fuzzing adapter" },
      { name: "curl", purpose: "shell HTTP workflows" },
      { name: "docker", purpose: "optional execution environment" },
    ].map((tool) => ({ ...tool, available: Boolean(Bun.which(tool.name)) }))
    checks.push({
      name: "optional_tools",
      status: tools.every((tool) => tool.available) ? "pass" : "warn",
      detail:
        tools
          .filter((tool) => !tool.available)
          .map((tool) => tool.name)
          .join(", ") || "All listed executables found",
      next_step:
        "Install only the external tools needed by your engagement. Availability does not prove functionality or isolation.",
    })
    if (args.engagement) {
      try {
        const file = join(FindingStore.directory(args.engagement), "state.json")
        const state = Schema.decodeUnknownSync(EngagementSchema.State)(JSON.parse(await readFile(file, "utf8")))
        if (state.name !== args.engagement) throw new Error("identity mismatch")
        const records = await FindingStore.load(state.name)
        const evidence = await Evidence.list(state.name)
        await Promise.all(
          evidence.map((entry) =>
            Evidence.get(state.name, entry.sha256).then((value) => {
              if (!value) throw new Error("missing evidence")
            }),
          ),
        )
        checks.push({
          name: "engagement_scope",
          status: state.scope.targets.length ? "pass" : "fail",
          detail: `${state.scope.targets.length} authorized target entries; ${state.scope.excludes.length} exclusions; ${(state.scope.discovered_targets ?? []).length} discovered entries (not authorization); mode ${state.mode}`,
          next_step: "Confirm authorization and exclusions with the operator before executing tests.",
        })
        checks.push({
          name: "stored_evidence",
          status: "pass",
          detail: `${records.length} lifecycle records; ${evidence.length} manifest entries; stored evidence bytes checked against hashes`,
        })
      } catch {
        checks.push({
          name: "engagement_data",
          status: "fail",
          detail: "Saved engagement, finding ledger or evidence is missing, malformed or fails integrity checks",
          next_step: "Check the saved engagement name and repair the data. Doctor does not overwrite it.",
        })
      }
    } else
      checks.push({
        name: "engagement_scope",
        status: "not_run",
        detail: "No saved engagement selected",
        next_step: "Rerun doctor --engagement <name> after initializing the engagement.",
      })
    checks.push({
      name: "live_provider",
      status: "not_run",
      detail: "No network or model request made; local credential presence does not prove provider access",
    })
    checks.push({
      name: "execution_isolation",
      status: "not_run",
      detail: "OS/container/network isolation was not verified; tool availability does not prove containment",
    })
    const result = { local_checks_only: true, checks, tools }
    if (args.json) console.log(JSON.stringify(result, null, 2))
    else {
      console.log("KevlarRedOps · local preflight\n")
      for (const check of checks)
        console.log(
          `${check.status.toUpperCase().padEnd(7)} ${check.name}: ${check.detail}${check.next_step ? `\n        ${check.next_step}` : ""}`,
        )
    }
    if (
      args.strict &&
      checks.some(
        (check) => check.status === "fail" || (check.name === "provider_configuration" && check.status === "warn"),
      )
    )
      process.exitCode = 2
  },
})

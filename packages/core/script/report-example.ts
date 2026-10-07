import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Effect } from "effect"
import { FindingReview } from "../src/cyber/finding-review"
import { EngagementSchema } from "../src/engagement/schema"
import { EngagementReport } from "../src/engagement/report"

// Synthetic owned fixture, never an assessment of an external target.
const fixtureHome = await fs.mkdtemp(path.join(os.tmpdir(), "kevlar-report-example-"))
process.env.OPENCODE_TEST_HOME = fixtureHome
const state: EngagementSchema.State = {
  id: EngagementSchema.ID.make("owned-lab-demo"),
  name: "owned-lab-demonstration",
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  current_phase: "reporting",
  mode: "guided",
  scope: {
    targets: ["127.0.0.1"],
    excludes: [],
    discovered_targets: ["127.0.0.2"],
    notes: "Synthetic demonstration from an operator-owned loopback fixture. No external target was tested.",
  },
  hosts: {
    "127.0.0.1": {
      ip: "127.0.0.1",
      services: [],
      access: [],
      notes: [],
      vulns: [
        { id: "reviewed-demo", title: "Reviewed fixture configuration", severity: "medium", status: "confirmed" },
        {
          id: "pending-demo",
          title: "Scanner observation awaiting review",
          severity: "critical",
          status: "suspected",
          description: "Synthetic scanner observation; verification has not been completed.",
        },
        { id: "dismissed-demo", title: "Rejected fixture observation", severity: "high", status: "false_positive" },
      ],
    },
  },
  credentials: {
    lab: { id: "lab", username: "lab-operator", value: "synthetic-secret-never-share", source: "Owned fixture" },
  },
  flags: [],
  attack_path: [],
  task_tree: [],
  notes: [],
}
async function record(input: FindingReview.Input) {
  const result = await Effect.runPromise(FindingReview.change(state, input))
  if ("error" in result) throw new Error(result.error)
}
try {
  await record({
    action: "promote",
    key: "reviewed-demo",
    title: "Reviewed fixture configuration · demonstration",
    target: "127.0.0.1",
    severity: "medium",
    summary:
      "Synthetic example showing reviewed evidence and actionable remediation. This is not a real vulnerability assessment.",
    owner: "Platform team",
    reviewer: "Demo operator",
    note: "Reviewed synthetic capture",
    impact: "Fixture exposes synthetic configuration through a debug route.",
    remediation: "Remove the debug route from the deployed fixture and retest the response.",
    reproduction_steps: ["Request the operator-owned debug route", "Inspect the synthetic configuration response"],
    replay: "Synthetic original command and configuration result. Demonstration only.",
  })
  await record({
    action: "promote",
    key: "fixed-demo",
    title: "Corrected fixture route · demonstration",
    target: "127.0.0.1",
    severity: "low",
    owner: "Application team",
    impact: "Synthetic fixture route was exposed.",
    remediation: "Restrict the fixture route to authorized operators.",
    reviewer: "Demo operator",
    note: "Recorded original synthetic finding",
    replay: "Synthetic original fixture route returns 200. Demonstration only.",
  })
  await record({
    action: "retest",
    key: "fixed-demo",
    outcome: "resolved",
    reviewer: "Demo operator",
    note: "Synthetic retest confirms the fixture route is restricted",
    replay: `${new Date().toISOString()}: Synthetic retest command returns 403 after fixture correction. Demonstration only.`,
  })
  const data = await EngagementReport.build(state)
  const destination = process.argv[2] ?? path.resolve(import.meta.dir, "../../../docs/examples/owned-lab-report.html")
  const receipt = await EngagementReport.write(destination, EngagementReport.renderHtml(data))
  console.log(JSON.stringify({ ...receipt, summary: data.summary }))
} finally {
  await fs.rm(fixtureHome, { recursive: true, force: true })
}

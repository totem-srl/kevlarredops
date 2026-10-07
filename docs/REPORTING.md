# Reports and local preflight

KevlarRedOps exports a saved engagement as Markdown, JSON or a self-contained HTML
document. The `report` CLI makes no model call. The agent's `report_gen` tool uses the
same snapshot builder. This makes review and export possible without spending model
tokens or asking an agent to rewrite the evidence.

Download and open the [HTML example](examples/owned-lab-report.html) to inspect the
layout offline. It was produced by the exporter with synthetic, owned loopback data:
one eligible finding, one resolved retest, one pending observation and one excluded false positive. It is
a demonstration, not evidence of a vulnerability in a real target.

Regenerate the synthetic example from `packages/core` with
`bun script/report-example.ts`. The generator uses the real finding-review workflow
inside an isolated temporary home and deletes only its fixture data when finished.

## Review observations before promotion

Parser output remains an observation until a lifecycle finding is promoted. Even a
legacy host vulnerability marked `confirmed` or `exploited` stays in the verification
queue unless its ID links to an eligible lifecycle finding. `false_positive` observations
and rejected, stale or superseded findings do not increase verified severity counts or
produce remediation recommendations.

Use the `evidence` tool to capture proof. Use `finding` with `action: promote`, a stable
`key`, an affected `target` authorized by the current scope, a title and severity. Supply
either replay material (command and output) or a structured exemption category with a
nonempty rationale. Example tool arguments for an owned loopback lab:

```json
{
  "action": "promote",
  "key": "lab-review-01",
  "title": "Reviewed lab observation",
  "target": "127.0.0.1",
  "severity": "medium",
  "evidence": ["lab response"],
  "replay_exemption_category": "operator_controlled_state",
  "replay_exemption_rationale": "The operator-owned fixture resets after capture."
}
```

The evidence label must resolve uniquely to a stored artifact in this engagement.
An exact SHA-256 or an unambiguous prefix of at least eight hexadecimal characters
also works. Promotion stores canonical hashes and rejects missing, ambiguous or altered
artifacts. Repeated promotion preserves previous replay when no replacement is supplied.
Concurrent mutations within one process are serialized per engagement. A cooperative
`findings.lock` also prevents another CLI process from writing the ledger concurrently;
the second writer fails with a busy message instead of dropping a revision. Finding
ledger writes use private temporary files and
atomic replacement. Unreadable or malformed ledgers fail visibly instead of becoming an
empty successful report.

The lock contains a token, process ID and acquisition time. Normal failure or interruption
releases the owned lock. A mutation finishes its finite filesystem commit before honoring
interruption so that a still-running write cannot overlap the next writer. After a hard
process kill, inspect `findings.lock`, confirm its owner is no longer running, and remove
only that stale lock before retrying. There is no automatic expiry or lock stealing.
This is a local filesystem lock, not a distributed database transaction.

At export, the report checks lifecycle eligibility, current authorized scope, artifact
presence, byte length and SHA-256 again. A removed artifact, changed bytes or a newly
excluded target moves the finding into review with a reason. Integrity proves that the
stored bytes match the manifest. Operator-recorded verification and replay material do
not prove that the exporter independently reproduced the vulnerability.

`finding` with `action: list` uses the same audit and shows blocking reasons, including
scanner observations awaiting promotion. List eligibility therefore agrees with the report
for the same state and stored evidence.

## Assign remediation and record a retest

Every finding can carry `owner`, `reviewer`, `impact`, `remediation` and ordered
`reproduction_steps`. An update appends a revision and leaves verification status intact.
Reviewer labels are supplied by the operator; they do not establish verified identity.
The CLI requires a reviewer and a nonempty review note for every mutation. The agent's
existing promotion/rejection calls remain compatible; its new update/retest calls require
the same review fields.

```sh
pentestcode findings lab --action promote --id lab-review-01 --target 127.0.0.1 \
  --severity medium --title "Owned lab debug exposure" --proof initial-proof.txt \
  --reviewer operator --note "Reviewed command and captured result"
pentestcode findings lab --action update --id lab-review-01 --owner platform-team \
  --impact "Debug configuration exposed" --remediation "Remove the public debug route" \
  --reproduction "Request the owned debug route" "Check returned configuration" \
  --reviewer operator --note "Assigned correction"
pentestcode findings lab --action retest --id lab-review-01 --outcome resolved \
  --proof retest-proof.txt --reviewer operator --note "Route returns 404 after correction"
pentestcode findings lab --json
pentestcode findings lab --action history --id lab-review-01
```

`--proof` reads a UTF-8 file containing the recorded command and result, limited to
10 MiB. It imports a private evidence artifact; it does not execute the command. Existing
artifacts can be selected with `--evidence`; a replay exemption needs both
`--replay-exemption-category` and `--replay-exemption-rationale`.

A retest needs replay material or a reasoned exemption and at least one distinct artifact
captured after the previous finding revision. Include the retest timestamp and result in
the capture; submitting identical bytes or the original proof does not establish a new
test. Capture timestamps and outcomes are operator records, not independent attestations.

- `resolved` moves the finding to a separate resolved group and removes it from active
  severity counts and remediation recommendations.
- `still_vulnerable` preserves or reopens the active verified finding.
- `inconclusive` moves the finding to the verification queue; it does not claim a fix.

Original revisions and evidence references remain in the ledger. Reports include the
revision timeline, retest outcomes, reviewers and evidence hashes, and audit all referenced
historical artifacts as well as the current proof. Missing or altered original proof blocks
an audited resolution. A bare `resolved` flag without a matching latest retest is not enough.
Absence from a later scan never closes a finding. IDs remain local to the engagement;
cross-engagement matching and automatic comparison are not implemented.

`finding` tool actions `update` and `retest` use the same core workflow as the CLI.
History output redacts recorded credential values and contains no raw proof blobs.
Recommendations use recorded remediation guidance, with an explicit request for guidance
when it has not been supplied.

## Export a snapshot

```sh
pentestcode report lab --format markdown --output lab-report.md
pentestcode report lab --format html --output lab-report.html
pentestcode report lab --format json --fail-on-pending
pentestcode report lab --format json --section scope objectives
```

The saved engagement name is required. Without `--output`, the report goes to stdout.
File exports use atomic replacement, mode `0600` on POSIX, and return a SHA-256 receipt.
The agent tool requests edit permission for the destination before writing. The CLI
honors an explicit destination supplied by the operator. HTML includes no JavaScript,
remote fonts, images or other remote assets, escapes supplied text, and has responsive
and print styles. Open it locally and use the browser's Print / Save as PDF when needed.

`--fail-on-pending` still exports the snapshot, then returns exit code **2** if observations
or lifecycle records await verification. A normal successful export returns **0**.
Invalid input or unreadable data fails instead of claiming a clean assessment.

Available sections: `executive_summary`, `objectives`, `scope`, `findings`, `attack_path`,
`credentials`, `recommendations`. The default includes all. The JSON envelope always
includes snapshot identity, summary and report policy; omitted sections do not expose
their contents. Artifact metadata is included only when selecting `findings`.

### JSON compatibility

JSON is now a report envelope with `format_version: 1`, `engagement`, `policy`, `summary`,
`evidence_manifest` and `sections`. It replaces the previous raw engagement serialization
and is **not a state backup**. Consumers of the former raw JSON export must adapt to this
version. Stored engagement state is not migrated or overwritten by exporting a report.
The new report fields are additive: `summary.resolved_findings` and
`sections.findings.resolved` separate corrected findings from active risks. Finding
ledgers now also accept the `resolved` status and optional remediation/retest fields.
Older code rejects a ledger containing `resolved`; use a compatible reader and retain a
private ledger/evidence backup before downgrading. All concurrent writers must use the
new locking workflow; older binaries do not participate in its cooperative lock.
Exports from the same state and ledger are deterministic; snapshot time comes from the
stored state, not from an invented completion time. Pending records can be newer than
that state timestamp, and each lifecycle finding includes its own recorded time.

### Review before sharing

All formats replace recorded credential values, URI-encoded values, Basic-auth values
and captured flags in free text. Credential rows never include the original values.
Raw evidence blobs are not embedded; the report carries hashes and metadata. Other
sensitive material, unrecorded secrets and new encodings still require operator review.
Private output permissions do not encrypt a report or make automatic publication safe.

Every report states that it is a snapshot of recorded findings, requires human review,
and does not establish complete assessment coverage. Exemption rationale remains visible.
Neither an empty verification queue nor a zero verified count proves that a system is safe.

## Check local prerequisites

```sh
pentestcode doctor
pentestcode doctor --engagement lab --json --strict
```

Doctor checks Bun, Git, presence and shape of saved provider credentials or supported
environment credential variables, optional executable availability, and (when selected)
saved engagement scope and evidence integrity. It displays counts and check statuses,
not credential values. It does not scan, install tools, execute them or call a provider.

`--strict` returns **2** for required failures, malformed engagement/evidence data, or no
recognized provider credential configuration. Missing optional tools produce warnings.
A custom credential-free local provider may need manual review: doctor does not evaluate
all provider configurations. Local credential presence does not establish provider access.
Live provider access and OS/container/network isolation are always reported `not_run`.

## Validation and product direction

The regression suites cover missing/tampered/ambiguous evidence, corrupt ledgers,
scope changes, supersession, credential redaction, escaped HTML, permission denial,
concurrent promotion and real CLI exit codes. Run from the package directories:

```sh
# packages/core
bun test test/evidence-integrity.test.ts test/finding-review.test.ts test/cyber.test.ts
# packages/opencode
bun test test/tool/trusted-reports.test.ts --timeout 30000
```

The [competitor analysis](research/COMPETITORS-2026-10.md) motivates this work. Run budgets,
complete run manifests, durable run cancellation/resume and comparison across engagements
remain further product priorities. Ownership and evidence-backed operator retests within
an engagement are implemented by the workflow above.

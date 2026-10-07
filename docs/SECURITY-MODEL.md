# Security model and validation

KevlarRedOps is a research tool that can launch processes with the host user's authority.
Use it only on systems you own or operate, or for which you hold explicit testing permission.
An engagement's scope records authorized destinations; discovering another host or subnet
does not grant permission to test it.

This document describes implemented controls and their limits. It is not a certification,
a claim of Anthropic approval, or evidence of third-party adoption.

## Shell execution boundaries

Both shell implementations read the active engagement before process execution:

| Control | Legacy shell | V2 core bash | Verification |
| --- | --- | --- | --- |
| Recognized target outside active scope is blocked | Yes | Yes | Regression tests assert no file creation or process dispatch |
| Exclusions take priority over allowed targets | Yes | Yes | Excluded IP within an allowed CIDR remains blocked |
| `free` mode respects active shell scope | Yes | Yes | Explicit mode regression tests |
| Discovered subnets do not expand authorization | Yes | Yes | Network discovery fixtures cannot authorize execution |
| Active empty scope authorizes no recognized targets | Yes | Yes | Empty-scope regression tests |
| Command approval does not add targets to scope | Yes | Yes | No automatic scope update; V2 also tests scope changes during approval |

The control is at the tool's process boundary, alongside existing command permissions.
It does not replace the permission service or apply a global authorization policy in the tool registry.
If there is no active engagement, the normal shell permission flow remains available.

Implementation:

- [Legacy shell](../packages/opencode/src/tool/shell.ts)
- [V2 core bash](../packages/core/src/tool/bash.ts)
- [Scope matching and command target extraction](../packages/core/src/engagement/scope-matcher.ts)

## Direct HTTP and socket boundaries

The legacy `http_request` and `net` tools check explicit destinations against the active
engagement's scope. An active empty scope permits no destination, exclusions take priority,
and `free` mode does not bypass the check. Denied HTTP requests, TCP sends, banner grabs,
and UDP sends return before network dispatch. These tools check their explicit host or URL
directly; they do not depend on the shell command extractor's hostname heuristics.

`http_request` reads the engagement after the existing permission request resolves, so a
scope change or an engagement activated during approval applies to the pending request.
HTTP redirects remain manual. With no active engagement, the existing HTTP permission flow
and raw socket behavior remain available.

Implementation and verification:

- [HTTP request tool](../packages/opencode/src/tool/http-request.ts)
- [Raw network tool](../packages/opencode/src/tool/net.ts)
- [Network regression tests](../packages/opencode/test/tool/network-scope.test.ts): real
  loopback servers count requests, connections, and datagrams, including positive cases.

## Scanner request boundaries

The legacy `appsec_probe`, `bounty_hunt`, and `recon_pipeline` tools deny an
out-of-scope initial target before permission approval, then check the current
engagement again after approval. Empty scope and exclusions apply in `free` mode.
Recon planning remains available because it does not execute network operations.

Their HTTP operations use a shared request boundary which rereads the active
engagement for every request and always uses manual redirects. AppSec checks
discovered form actions before sending a probe and reports out-of-scope probes
as skipped. Bounty's JavaScript, directory-fuzzing and OpenAPI helpers receive the
same request boundary. Recon checks discovered hosts before HTTP/CNAME probes and
checks the root target again before the optional port-scan process starts.
Discovery output must match the root domain or a dot-separated subdomain.

The [scanner scope regressions](../packages/opencode/test/tool/scanner-scope.test.ts)
exercise denied initial targets, scope changes during approval and between page
fetch and probing, form actions outside scope, script/OpenAPI redirects, authorized
loopback requests, and planning without authorization. The tests do not run a live
Recon scan or certify the behavior of external adapter binaries.

Implementation: [shared request boundary](../packages/opencode/src/scanner/scoped-request.ts),
[AppSec](../packages/opencode/src/tool/appsec-probe.ts),
[Bounty](../packages/opencode/src/tool/bounty-hunt.ts),
[Recon](../packages/opencode/src/tool/recon-pipeline.ts).

## Limits and containment

Command extraction is a heuristic. It recognizes literal IPs and selected hostname patterns,
filters filenames and code tokens, and uses a finite TLD list. It cannot establish all destinations
of scripts, shell variables, subprocesses, redirects, tunnels, DNS resolution, or downloaded code.
Some hosts and loopback addresses are ignored by the extractor. An unrecognized destination
can pass the shell check; a warning is not a denial.

Other specialized legacy tools and external adapters have separate scope implementations; some still allow
mode-dependent overrides. The shell and direct network regression tests do not prove containment of those tools,
plugins, MCP servers, or delegated agents. Scope state also uses the existing engagement store;
this change does not establish isolation between concurrent engagements.

Use a disposable VM or container with a restricted account and an independently enforced
egress policy allowing only the authorized lab destinations. Configure and test those restrictions
outside KevlarRedOps. This repository does not provision or verify them for you.
Mount only the files required for the engagement, and avoid mounting host credentials,
cloud configuration, or unrelated projects. Record the authorized targets and exclusions
before starting, and preserve the tested commit and environment configuration.

Treat engagement state, credentials, command output, and reports as sensitive.
Use lab credentials, redact shared evidence, and define retention and deletion procedures
for the environment you operate. The report exporter redacts recorded credential values,
their URI-encoded values and Basic-auth representations in text; it does not embed raw evidence
blobs. This is a limited sharing safeguard, not general DLP: other sensitive text and raw blobs
still require review. See [reporting](REPORTING.md). Do not interpret this guide as a promise
of encrypted storage or provider data-retention settings.

## Reproducible regression checks

Install the locked dependencies with the repository's supported Bun version. Run tests from
the package directories, not the repository root:

```sh
cd packages/core
bun test test/scope-matcher.test.ts test/scope-matcher-extraction.test.ts test/tool-bash.test.ts
bun typecheck
cd ../opencode
bun test test/tool/shell.test.ts
bun test test/tool/network-scope.test.ts
bun test test/tool/scanner-scope.test.ts test/scanner.test.ts
bun test test/config/config.test.ts --test-name-pattern 'global config updates refresh'
bun typecheck
```

The shell scope fixtures use documentation-only IP addresses and temporary files or mocked process
dispatch; they do not scan or connect to a target. The direct network fixtures connect only to
owned loopback HTTP, TCP, and UDP servers on ephemeral ports. Vault, evidence, and OPSEC paths
honor the existing test-home environment variable, isolating those tests from user data.
The legacy shell tests check whether a marker file
was actually created. The V2 tests check the process service boundary, including a scope change
while command approval is pending. Matching tests also cover internal network hostnames and
public suffixes such as `.zip`, `.mov`, and `.security` while retaining code-token regressions.

CI results, runtime containment, identity verification, and project adoption are separate evidence.
CI explicitly runs the legacy shell, direct network, scanner, and global config cache regressions alongside the core tests and API gates.
The inherited Turbo task still references the previous `opencode` package name; it does not
prove that the complete legacy `pentestcode` suite runs. Restoring that full suite is separate
validation work, and a passing shell regression file is not a full legacy-suite result.

Use [MAINTAINERS.md](../MAINTAINERS.md) for the named role, [ADOPTION.md](ADOPTION.md) for attributable
adoption figures, and [SECURITY.md](../SECURITY.md) for private vulnerability reporting.
Report newly found vulnerabilities privately rather than adding sensitive reproduction details
to a public issue.

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

## Limits and containment

Command extraction is a heuristic. It recognizes literal IPs and selected hostname patterns,
filters filenames and code tokens, and uses a finite TLD list. It cannot establish all destinations
of scripts, shell variables, subprocesses, redirects, tunnels, DNS resolution, or downloaded code.
Some hosts and loopback addresses are ignored by the extractor. An unrecognized destination
can pass the shell check; a warning is not a denial.

Specialized legacy network tools have separate scope implementations; some still allow
mode-dependent overrides. The shell regression tests do not prove containment of those tools,
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
for the environment you operate. Do not interpret this guide as a promise of encrypted storage,
automatic redaction, or provider data-retention settings.

## Reproducible regression checks

Install the locked dependencies with the repository's supported Bun version. Run tests from
the package directories, not the repository root:

```sh
cd packages/core
bun test test/scope-matcher.test.ts test/scope-matcher-extraction.test.ts test/tool-bash.test.ts
bun typecheck
cd ../opencode
bun test test/tool/shell.test.ts
bun typecheck
```

The scope fixtures use documentation-only IP addresses and temporary files or mocked process
dispatch; they do not scan or connect to a target. The legacy tests check whether a marker file
was actually created. The V2 tests check the process service boundary, including a scope change
while command approval is pending. Matching tests also cover internal network hostnames and
public suffixes such as `.zip`, `.mov`, and `.security` while retaining code-token regressions.

CI results, runtime containment, identity verification, and project adoption are separate evidence.
CI explicitly runs the legacy shell regression file alongside the core tests and API gates.
The inherited Turbo task still references the previous `opencode` package name; it does not
prove that the complete legacy `pentestcode` suite runs. Restoring that full suite is separate
validation work, and a passing shell regression file is not a full legacy-suite result.

Use [MAINTAINERS.md](../MAINTAINERS.md) for the named role, [ADOPTION.md](ADOPTION.md) for attributable
adoption figures, and [SECURITY.md](../SECURITY.md) for private vulnerability reporting.
Report newly found vulnerabilities privately rather than adding sensitive reproduction details
to a public issue.

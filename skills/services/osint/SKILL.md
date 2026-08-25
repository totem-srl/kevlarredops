---
name: svc-osint
description: Open-source intelligence and external attack-surface discovery. Use when mapping a target's public footprint before active testing. Triggers - breach credential research, leaked secrets in public repos, cloud storage enumeration, email/personnel discovery, external recon kickoff for an authorized engagement.
tags: [recon, enumeration]
---

# OSINT & External Attack Surface

Passive-first intelligence gathering. Everything here runs against THIRD-PARTY sources, not the target — but the output shapes every later phase.

## Detect

```bash
# Breach / credential exposure
# HIBP-style lookups via API or curated dumps — NEVER query the target itself
curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/<email>?truncateResponse=true"

# Public code search (secrets + internal hostnames)
gh api "search/code?q=<domain>+password" --jq '.items[].html_url'
gh api "search/code?q=org:<org>+AKIA" --jq '.items[].path'

# Email / personnel harvest
curl -s "https://api.hunter.io/v2/domain-search?domain=<domain>&limit=10"

# Cloud storage discovery
for name in <domain> <brand> <brand>-prod <brand>-backup; do
  curl -s -o /dev/null -w "%{http_code} $name\n" "https://$name.s3.amazonaws.com/"
done
```

Also: certificate transparency (`svc-dns` AXFR/CT section), Google dorking (`recon-phase`), Shodan/Censys org-wide views, web archive for deleted-but-referenced endpoints.

## Decide

| Signal | Action |
| --- | --- |
| Email appears in breach dumps | Record pattern (Season!2024 style) → targeted wordlist for `cred_spray` later |
| Secrets found in public repo | Verify ONE cheap call max (`web-js-secrets` verify rule) → report immediately, repo may go private |
| S3/GCS bucket readable | List keys once, note sensitive-looking objects — do NOT mass-download |
| Employee names/titles | Map to likely AD username conventions (first.last → flast → firstl) |
| Exposed staging/dev hostnames | Feed to `scope_check` — often OUT of contractual scope despite being owned |

## Exploit → PROVE IMPACT

OSINT alone is rarely impact — its proof is what it enables:

- Breach-derived password guess works on a live login → that is `cred_spray`'s confirmed finding, not OSINT's.
- Repo secret authenticates successfully → screenshot the successful call, redact half the key, record as Credential.
- Readable bucket contains real PII/secrets → quote ONE object path + redacted sample. Listing ≠ impact.
- Username convention derived → validated by a single successful auth anywhere in the engagement.

Record everything via `state_update`. A leak you cannot act on still goes in as Info with source URL.

## Tooling

- `state_update` — every artifact with source URL and date.
- `add_credential` — verified secrets become Credentials immediately.
- `cred_spray` — the lockout-aware consumer of breach-pattern guesses. Never spray raw breach passwords directly.
- `web-js-secrets` — same verify-one-call discipline applies here.
- `scope_check` — BEFORE acting on any discovered hostname. Acquisitions and staging boxes are frequent out-of-scope traps.

## Pitfalls

- Querying the TARGET to confirm an OSINT lead converts passive recon into active testing — do it only after phase transition and scope check.
- Breach data is stale: passwords cracked from 2021 dumps rarely survive 2026 rotation. Use them as pattern evidence, not gospel.
- Downloading bulk data from open buckets can violate computer-misuse laws even when the bucket is misconfigured. One proof object, then stop.
- People data (names, photos, personal emails) has privacy-law exposure. Collect minimum needed for the engagement, redact in reports.
- Third-party APIs rate-limit and LOG your queries. Spread lookups; never burn an API key on a single session of hundreds of queries.
- GitHub code search requires auth and misses private forks. Absence of results ≠ absence of leaks.

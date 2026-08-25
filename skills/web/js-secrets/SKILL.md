---
name: web-js-secrets
description: Client-side JavaScript analysis for leaked secrets, source maps, and hidden API surface. Use when mapping a web target's attack surface or hunting hardcoded credentials in bundles. Triggers - source map, .js.map, API key in JavaScript, endpoint discovery, webpack bundle, linkfinder, js file analysis.
tags: [recon, vuln_assess]
---

# JavaScript Secrets & Surface

## When this fires
Any authenticated or public web app during RECON/VULN-ASSESSMENT — every `.js` file is configuration the server shipped to you.

## Detect (tool-first)
1. Crawl → collect all script URLs (main bundle + lazy chunks).
2. Pull source maps first — they restore original file names, comments, and unminified code:
```bash
for u in $(cat /tmp/js-urls.txt); do
  curl -s "$u.map" | head -c 200 | grep -q "sources" && echo "MAP: $u.map"
done
```
3. Grep recovered sources for high-signal keys:
```bash
grep -rEn "(api[_-]?key|secret|token|password|Bearer |AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,})" /tmp/js-src/
```
4. Extract endpoints (`linkfinder`-style regex on `"/api/...` strings) — undocumented routes often skip authz review.

## Decide
- Secret-looking string → verify it's live before claiming: one cheap authenticated call against the service it belongs to (S3 bucket list, API `/me`, JWT decode). Dead/placeholder keys are noise.
- Source map present on prod → information-disclosure finding on its own (Low/Medium) even without secrets.
- New endpoints found → feed into api-testing skill authz matrix (BOLA/mass-assignment checks).

## Exploit → PROVE IMPACT
**Proof required:** the secret WORKS — a successful authenticated call output (redact half the key in report), or data returned from an undocumented endpoint a normal user flow never exposes. A grep hit alone is suspected.

## Tooling
Findings into `state_update`; working keys into `cred-spray`'s sibling flow (add_credential); new API routes → `api-testing` skill; `report_gen` picks up confirmed credentials automatically.

## False positives / pitfalls
- Public client IDs / Firebase config blocks are BY DESIGN public — not findings unless paired with open rules (e.g., permissive Firestore rules verified with a read).
- Minified variable names cause false key matches — confirm format matches provider pattern before testing.
- Test ONE verification call per key — repeated attempts against third-party APIs burns rate limits and logs.
- Never exfiltrate or reuse found secrets beyond single proof call; record owner + rotate recommendation.

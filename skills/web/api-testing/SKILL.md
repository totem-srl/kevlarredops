---
name: web-api-testing
description: API penetration testing for REST and GraphQL — auth bypass, BOLA/IDOR, mass assignment, injection over JSON, introspection, batching abuse. Use when the target exposes an API (Swagger/OpenAPI, /api/*, GraphQL endpoint, mobile-app backend) or when webapp testing finds JSON transport. Triggers - swagger.json, openapi.yaml, graphql, introspection, BOLA, IDOR on an API id, Authorization Bearer, API key, rate-limit bypass, mass assignment.
tags: [vuln_assess, exploitation]
---

# API Testing (REST & GraphQL)

## When this fires
Target ships an API surface: OpenAPI/Swagger docs, `/api/*` routes, `/graphql`, `/api/graphql`, a mobile backend, or any handler that speaks JSON. Also fire it when ordinary web testing reveals tokens (`Authorization: Bearer`, `X-API-Key`) or object IDs in JSON bodies.

## Recon (machine-readable first)
```bash
# Spec discovery — a spec is an automatic test plan
for p in swagger.json openapi.json api-docs swagger/v1/swagger.json openapi.yaml \
         /api/swagger.json /api/v3/api-docs /graphql/schema.json; do
  curl -s -o /dev/null -w "%{http_code} $p\n" "http://<t>/$p"
done

# GraphQL probe — introspection tells you if the door is open
curl -s "http://<t>/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } } }"}'

# If introspection is blocked, get the shape anyway:
#   field suggestions (__schema misses but misspelled fields leak: "Did you mean ...")
#   GET vs POST routing quirks, /graphql, /api/graphql, /v1/graphql alternates
```
Save the spec, then enumerate endpoints + auth requirements per route BEFORE probing. Feed findings into `state_update` (hosts/services/vulns).

## Decide — attack matrix by weakness class
- **AuthN**: no auth on some routes (spec says required, server doesn't enforce); JWT flaws → run every token through `jwt_analyze` (alg=none, kid injection, weak HMAC secret, missing exp, role claim tampering); API keys in response bodies/logs.
- **BOLA / IDOR** (OWASP API #1): swap IDs across users/orgs in path AND body AND non-obvious fields (`account_uuid`, `order_id`). GUID ≠ safe — leak via listing endpoints, export jobs, referers.
- **Mass assignment**: add privileged fields to create/update payloads (`"role":"admin"`, `"is_admin":true`, `"price":0`) — spec documents the full schema; servers often bind it all.
- **Injection over JSON**: SQLi/NoSQLi/SSTI inside JSON values — same payloads as `web-sqli`, but remember type confusion: `"id":{"$gt":""}` (Mongo), `"id": {"toString":{}}`, string→object/array swaps (`"id":["1"]`).
- **GraphQL-specific**: introspection dump → find mutations + sensitive queries first; document-level denial (`{ a{b{c...}}}` depth bombs); batching/alias brute force (`query{ u1:user(id:1){email} u2:user(id:2){email} ... }` defeats per-request rate limits); field-level authz gaps (mutation allowed, query forbidden).
- **Rate limiting / business logic**: rotate X-Forwarded-For/X-Originating-IP, case tricks on paths (`/API/`), parameter pollution; race conditions on redeem/transfer/signup via parallel sends.

## Exploit → PROVE IMPACT
- BOLA: fetch another tenant's real record — show two accounts, cross-read, screenshot/diff. 
- Mass assignment: escalate a self-registered user to admin, then show admin-only access granted.
- Injection: extract data exactly as `web-sqli` requires (canary row / file read).
- Auth bypass: hit a documented admin route as a fresh low-priv user; capture 200 + sensitive body.
**Proof required:** cross-account data, privilege actually gained, or extracted secret. "The API returned my own data" is not a finding.

## Tooling
`curl` for probes; save interesting raw requests for replay/race scripts; `jwt_analyze` on every JWT; `nuclei` has API templates (exposed GraphiQL, swagger UI, spring actuator via `/api/v3/api-docs`) → `nuclei_parse`; log everything into `state_query`/`state_update` so the graph links API vulns to their hosts.

## False positives / pitfalls
- Spec documents more than the server implements — probe before claiming.
- 401 on one method may hide 200 on another (PATCH vs PUT vs POST; HEAD leaks).
- Rate limits keyed on IP can be shared infrastructure — confirm you're not DoS-ing other tenants; stop immediately if collateral impact appears.
- GraphQL errors differ per engine (Apollo/Graphene/Hasura) — fingerprint before assuming syntax.

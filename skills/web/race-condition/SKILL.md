---
name: web-race-condition
description: Race-condition detection and proof for state-changing endpoints — limit bypass, double-spend, TOCTOU. Use when an endpoint enforces a one-time or bounded rule (coupon, vote, redeem, transfer, withdraw, MFA) and you suspect parallel requests slip past it. Triggers - coupon reuse, vote multiple times, gift card redemption, balance going negative, last-byte sync, single-packet attack, simultaneous requests.
tags: [vuln_assess, exploitation]
---

# Race Conditions

## When this fires
A rule lives server-side ("once per user", "max 1", "balance ≥ amount") but check-and-act aren't atomic. Any state-changing endpoint that a business rule bounds is a candidate.

## Detect (tool-first)
1. Pick ONE endpoint with a clear rule. Capture a valid request (session + CSRF token if needed).
2. Fire N≈20 identical requests in one synchronized burst — HTTP/2 single-packet attack preferred:
```bash
# no Burp: parallel curl from one file of pre-built requests
seq 20 | xargs -P20 -I{} curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  'http://<t>/api/redeem' -H 'Cookie: session=<s>' -d 'code=XMAS2024'
```
3. Check server-side state after the burst (GET balance / order list), not just status codes.

## Decide
- Limit-style (`once per user`) → burst the action endpoint directly.
- TOCTOU (read-balance then debit) → two-step flows: burst transfers slightly under balance ×N.
- Multi-endpoint races (arm in A, exploit in B) → send mixed batches: N×A then N×B back-to-back in one connection group.
- Endpoint queues through a worker (status stays `pending` mid-flight) → requests serialize; race likely dead, note and move on.

## Exploit → PROVE IMPACT
Ramp deliberately: 20 parallel first; on partial success re-run at 30–50. Use identifiable test values (own account, smallest amounts).
**Proof required:** durable state change — negative/incorrect balance, two successful redemptions both honored, item shipped twice, MFA bypassed to a logged-in session. Two `200` responses are a lead, never proof. Record before/after state side by side.

## Tooling
`state_update` the confirmed finding with before→after evidence; `report_gen` wording states the business rule broken and quantified loss. `shell` carries the bursts.

## False positives / pitfalls
- Idempotency keys / nonce fields deduplicating requests = working defense, not a finding.
- Rate limiter tripping mid-burst masquerades as a fix — verify 429s vs real rejection logic.
- Connection jitter desyncs the burst; keep `-P` count ≤ local port budget, retry ramp before declaring patched.
- NEVER flood production (hundreds+ requests) — minimal burst, test account, reversible amounts only; stop and ask operator if the endpoint touches real funds or other users.

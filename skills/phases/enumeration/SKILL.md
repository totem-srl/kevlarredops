---
name: enumeration-phase
tags: [enumeration]
description: Active enumeration phase — port scanning, service detection, banner grabbing. Use when the current phase is ENUMERATION.
---

# Active Enumeration Checklist

Escalate scanning incrementally — quick discovery first, deep scans after.

## Host Discovery
```bash
nmap -sn <cidr> -oG discovery.gnmap
```

## Port Scanning (tiered)
```bash
# Quick top ports
nmap -sS --top-ports 1000 --min-rate 3000 -oA quick <target>

# Full TCP
nmap -sS -p- --min-rate 5000 -oA full_tcp <target>

# UDP top 20
nmap -sU --top-ports 20 -oA udp <target>
```

## Service & Version Detection
```bash
nmap -sV -sC -p <found_ports> -oA services <target>
# Aggressive if needed
nmap -A -p <found_ports> -oA aggressive <target>
```

## Banner Grabbing
```bash
nc -nv <ip> <port>
nmap -sV --script=banner -p <port> <target>
curl -sI http://<target>:<port>
```

## Web Enumeration
```bash
# Directory brute-force
gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak -o dirs.txt
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403

# Virtual host discovery
ffuf -u http://<target> -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <default_size>

# Technology fingerprinting
whatweb http://<target> -a 3
nikto -h http://<target>
```

## SMB Enumeration (port 445)
```bash
enum4linux-ng -A <target>
smbclient -N -L //<target>
crackmapexec smb <target> --shares
nmap --script smb-enum-shares,smb-enum-users -p 445 <target>
```

## LDAP Enumeration (port 389/636)
```bash
ldapsearch -x -H ldap://<target> -b "" -s base namingContexts
ldapsearch -x -H ldap://<target> -b "<base_dn>" "(objectclass=*)"
```

## SNMP Enumeration (port 161)
```bash
snmpwalk -v2c -c public <target>
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>
```

## NFS Enumeration (port 2049)
```bash
showmount -e <target>
nmap --script nfs-ls,nfs-showmount -p 2049 <target>
```

## Phase Completion Criteria
Move to VULN_ASSESS when:
- All open ports identified on all in-scope hosts
- Services and versions detected
- Web directories enumerated
- Protocol-specific enumeration complete
- All findings recorded in engagement state

## Output Rules
- Always use quiet/filtered output flags. Only show successful results.
- Redirect large output to files. Never paste >50 lines of raw tool output.
- Use parser tools (nmap_parse, cme_parse, gobuster_parse, nuclei_parse) for auto-processing.

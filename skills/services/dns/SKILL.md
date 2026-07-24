---
name: svc-dns
description: DNS attack techniques — zone transfer, subdomain enumeration/takeover, cache poisoning. Use when DNS is found or you're mapping a domain. Triggers - port 53, named/bind, AXFR zone transfer, dangling CNAME, subdomain takeover, wildcard DNS.
---

# DNS Attack Reference

## Zone Transfer (AXFR)
```bash
dig AXFR <domain> @<ns_server>
host -t AXFR <domain> <ns_server>
dnsrecon -d <domain> -a
```

## DNS Enumeration
```bash
# Record types
dig <domain> ANY +noall +answer
dig <domain> A +short
dig <domain> AAAA +short
dig <domain> MX +short
dig <domain> NS +short
dig <domain> TXT +short
dig <domain> SOA +short
dig <domain> SRV +short

# Reverse DNS for IP range
dnsrecon -r <cidr>

# Brute force subdomains
dnsrecon -d <domain> -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt
dnsenum <domain>
fierce --domain <domain>
```

## Subdomain Takeover
```bash
# Check for dangling CNAME records
dig CNAME <subdomain>
# If CNAME points to unclaimed resource (S3, Heroku, GitHub Pages, Azure) → takeover

# Automated check
subjack -w subdomains.txt -t 20 -o takeover_results.txt
nuclei -t takeovers/ -l subdomains.txt
```

## DNS Cache Poisoning
```bash
# Check if recursion is open
dig @<target> example.com +recurse

# Test cache snooping (non-recursive query for cached records)
dig @<target> <popular_domain> +norecurse
```

## DNS Tunneling Detection
```bash
# Unusually long subdomains or high query volume to single domain
# Tools: iodine, dnscat2 for establishing DNS tunnels
```

---
name: svc-dns
tags: [recon, enumeration, exploitation]
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

## Decide — Attack Order
1. Zone transfer attempt first (instant win if misconfigured, cheap to test)
2. Record harvest: MX/TXT/SRV expose mail hosts, cloud providers, internal hostnames
3. Subdomain enum → resolved hosts feed gobuster/nuclei pipeline
4. Takeover check on EVERY CNAME — highest-value DNS finding

## Prove Impact
- Subdomain takeover: serve content on the hijacked host and fetch it back — dangling CNAME alone is NOT impact.
- AXFR dump is proof; count unique internal hostnames into `state_update`.
- Internal-name leakage via SRV/TXT: list what became newly reachable vs prior scope knowledge.

## Tooling
- `state_update`: new Host records for discovered subdomains, takeover candidates as Vulnerability.
- `nuclei_parse` on takeover template runs.
- `gobuster_parse` after resolving+fuzzing web on live subdomains.
- `scope_check` BEFORE testing any domain — records may point at out-of-scope shared hosting.

## Pitfalls
- Wildcard DNS resolves everything — brute-force hits are noise unless filtered against the wildcard IP.
- Dangling CNAME ≠ takeover: provider must return its "no such app/bucket" page AND the resource must be claimable.
- `dig @<target>` only answers authoritatively if target is NS for the zone; recursion tests are a separate question.
- Cloud-hosted zones (Route53/Cloud DNS) rarely permit AXFR — don't burn cycles retrying variants.

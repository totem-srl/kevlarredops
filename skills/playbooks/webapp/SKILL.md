---
name: playbook-webapp
description: Web application penetration testing playbook — OWASP Testing Guide based methodology.
---

# Web Application Pentest Playbook

Based on OWASP Testing Guide v4.2.

## Scope
- Target URLs and domains
- Authentication credentials (if gray/white box)
- Out-of-scope pages/functionality
- Rate limiting constraints

## Phase Flow

### 1. Reconnaissance
- Technology stack: `whatweb`, `wappalyzer`, response headers
- CMS detection: WordPress (`wpscan`), Drupal, Joomla
- API discovery: `/api`, `/swagger`, `/graphql`, `/.well-known`
- Robots.txt, sitemap.xml
- JavaScript analysis for endpoints, API keys, secrets

### 2. Mapping
- Directory/file brute force: `gobuster dir -w raft-medium -x php,html,js,txt,bak`
- Virtual host discovery: `ffuf -H "Host: FUZZ.domain"`
- Parameter discovery: `arjun -u <url>`
- Authentication endpoints (login, register, reset, OAuth)
- API endpoint mapping

### 3. OWASP Top 10 Testing

**A01 — Broken Access Control**
- IDOR: change IDs in URLs/params, test horizontal access
- Privilege escalation: access admin functions as regular user
- Directory traversal: `../../../etc/passwd`
- Missing function-level access control

**A02 — Cryptographic Failures**
- SSL/TLS: `sslscan <target>`, `testssl.sh <target>`
- Sensitive data in responses, cookies, local storage
- Hardcoded secrets in JavaScript

**A03 — Injection**
- SQL injection: `sqlmap -u "<url>?param=1" --batch --level 3`
- Command injection: test with `;id`, `$(whoami)`, `` `id` ``
- SSTI: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- LDAP, XPath, NoSQL injection

**A04 — Insecure Design**
- Business logic flaws
- Race conditions
- Mass assignment

**A05 — Security Misconfiguration**
- Default credentials on admin panels
- Verbose error messages (stack traces)
- Unnecessary HTTP methods (PUT, DELETE)
- CORS misconfiguration
- Security headers: CSP, HSTS, X-Frame-Options

**A06 — Vulnerable Components**
- Check versions against CVE databases
- `npm audit`, `retire.js` for JavaScript
- Known CMS plugin vulnerabilities

**A07 — Authentication Failures**
- Brute force: `hydra http-post-form`
- Password policy bypass
- Session fixation, session prediction
- JWT attacks: none algorithm, weak secret, token reuse

**A08 — Software Integrity**
- CI/CD pipeline exposure
- Dependency confusion
- Unsigned updates

**A09 — Logging & Monitoring**
- Error-based information disclosure
- Log injection

**A10 — SSRF**
- `http://169.254.169.254/` (cloud metadata)
- Internal service access
- Protocol smuggling (gopher://, file://)

### 4. Additional Tests
- XSS: `dalfox`, manual payload testing (reflected, stored, DOM)
- CSRF: missing/weak tokens
- File upload: bypass extension filters, webshell upload
- WebSocket testing
- GraphQL introspection and injection

### 5. Reporting
- Each finding: description, reproduction steps, evidence (request/response), severity, remediation
- CVSS scoring per finding
- OWASP category mapping

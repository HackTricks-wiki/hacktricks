# Databases and Secret Material on Linux Hosts

{{#include ../../banners/hacktricks-training.md}}

Database and application credentials often sit beside the service they support. Map the process, local socket or port, configuration, and credential file before testing whether an account can read data or execute a privileged operation.

## Locate local data services and credentials

```bash
ss -lntup
ss -lnx
ps -eo user,pid,args | grep -E '[m]ysqld|[m]ariadbd|[p]ostgres|[r]edis-server|[m]ongod'
find /etc /opt /var/www /home -type f \( -name '*.env' -o -name '*config*' -o -name '.my.cnf' -o -name '.pgpass' \) -ls 2>/dev/null | head -100
```

Inspect readable application configs, deployment files, service environment files, and backups for connection strings or keys. A DB process's Unix socket can have different access rules from its TCP listener. Database permissions differ from OS permissions: a recovered DB password grants only the roles assigned to that DB account unless another path is demonstrated. In PostgreSQL, row-level security policies can hide records from one role while a role with policy-management rights can change that view; distinguish data access from policy administration. Use the service-specific guides for [MySQL/MariaDB](../../network-services-pentesting/pentesting-mysql.md), [PostgreSQL](../../network-services-pentesting/pentesting-postgresql.md), and [Redis](../../network-services-pentesting/6379-pentesting-redis.md).

## Review key and token stores

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

An SSH private key, agent socket, Kerberos cache, GPG keyring, or PKCS#12 bundle is useful only if the current user can access it and any required passphrase or policy permits use. Inspect ownership and permissions first. The [users and sessions](../user-information/user-and-session-triage.md), [Linux AD](../user-information/linux-active-directory.md), and [post-exploitation](../post-exploitation/README.md) pages explain the corresponding access paths. Git history, old backups, and shell history can also retain secrets after a live config has been cleaned.

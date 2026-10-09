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

A readable SQLite application database may contain user names and password hashes without any listening database service. Inspect its schema and file permissions before treating a hash as an offline audit lead. A recovered application password grants OS-account or local-admin-panel access only if reuse is separately confirmed; the hash format or matching user name is not proof of reuse.

For PostgreSQL, inspect `pg_policies` and `pg_class.relrowsecurity` to distinguish a filtered query from missing records. Changing or disabling a policy requires the appropriate table ownership or administrative privileges. A separately leaked maintenance account may have those privileges even when the application account does not. An unauthenticated Redis listener is another distinct finding: verify whether it binds only to loopback and whether protected mode or ACLs restrict the current connection before treating it as a secret source.

## Review key and token stores

```bash
find /home /root -maxdepth 4 -type f \( -name 'id_*' -o -name '*.p12' -o -name '*.pfx' -o -name '*.kdbx' -o -name '*.gpg' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home /root -maxdepth 4 -type d -name '.gnupg' -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

An SSH private key, agent socket, Kerberos cache, GPG keyring, or PKCS#12 bundle is useful only if the current user can access it and any required passphrase or policy permits use. Inspect ownership and permissions first. The [users and sessions](../user-information/user-and-session-triage.md), [Linux AD](../user-information/linux-active-directory.md), and [post-exploitation](../post-exploitation/README.md) pages explain the corresponding access paths. Git history, old backups, and shell history can also retain secrets after a live config has been cleaned.

For encrypted database backups, correlate the readable archive, accessible private-key material, and any passphrase requirement before drawing a conclusion. Where authorized, recovery of a protected key's passphrase and inspection of decrypted backup data are separate manual steps. A database `root` credential is not a Unix `root` credential; password reuse across those accounts requires separate, authorized validation. Filesystem trust boundaries in web applications can also expose the account that owns these materials; see the [Django file-cache review](../../network-services-pentesting/pentesting-web/django.md#cache-manipulation-to-rce).

Container root and host root are separate identities. A private SSH key readable only after becoming root inside a container may authenticate to a host account if the host accepts it, but the key filename or public-key comment does not prove that access. Likewise, a custom password generator found beside a timestamped password-change record is only a manual analysis lead: a time-seeded non-cryptographic generator may have a small candidate seed window, but timezone, clock precision, library behavior, and later password changes affect reconstruction. Validate candidate credentials only when authorized; do not treat generated candidates as confirmed passwords.

If a readable `.p12` or `.pfx` bundle has a password exposed in application configuration, inspect it with `openssl pkcs12 -info -in bundle.p12 -noout`. Where the bundle contains an exportable private key, `openssl pkcs12 -in bundle.p12 -nocerts -nodes -out extracted.key` writes that key without encryption. Protect the output file and remove it after analysis; use the recovered key only for the service or ciphertext it actually matches. A bundle alone does not imply that its private key is useful for a different application.
{{#include ../../banners/hacktricks-training.md}}

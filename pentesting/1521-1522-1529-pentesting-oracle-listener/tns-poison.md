# TNS Poison

## TNS Poison

If you encounter a newer version of the listener, there is not much room left except brute-forcing. However, all versions up to version 12c are vulnerable to an attack called ‘TNS Poison’. Though the latter version is vulnerable only in some special configurations. For example, one of the ways to fix this vulnerability is by disabling the dynamic configuration of the listener, which is impossible when using Oracle DataGuard, PL/SQL Gateway in connection with APEX and in some versions of SAP. In general, the issue is that, by default, the listener service supports remote configuration and, in addition, it allows to do it anonymously. This is where the heart of vulnerability lies.

[![Fig. 1. TNS Poison Vulnerability](https://hackmag.com/wp-content/uploads/2015/04/poison.png)](https://hackmag.com/wp-content/uploads/2015/04/poison.png)

Fig. 1. TNS Poison Vulnerability

This is a sample attack algorithm \(see Fig. 1\):

* Send the following TNS query: ‘CONNECT\_DATA=\(COMMAND=SERVICE\_REGISTER\_NSGR\)\)’.
* The vulnerable server will respond: ‘\(DESCRIPTION=\(TMP=\)\)’. This is what will be the answer from a patched server: ‘\(ERROR\_STACK=\(ERROR=1194\)\)’.
* Generate a configuration package with SID and IP of the new listener \(for future MITM\). The number of characters in the name of the current SID is of fundamental importance. You need to know it, since this is what a Well Formed package depends on.
* Next, send all these goodies to the listener.
* If everything is correct, then all new connections will be forwarded by the listener through your controlled IP.

It is important not to forget to enable the proxying of queries \(like IP\_forwarding in Linux\), otherwise, instead of a neat MITM attack, you will get a rough DoS, because the new clients will be unable to connect to the database. As a result, an attacker can embed their own commands within another user’s session. **You can check whether the server is vulnerable by using the following MSF module: ‘auxiliary/scanner/oracle/tnspoison\_checker’.**

All this page was extracted from here: [https://hackmag.com/uncategorized/looking-into-methods-to-penetrate-oracle-db/](https://hackmag.com/uncategorized/looking-into-methods-to-penetrate-oracle-db/)

**Other way to test:**

```text
./odat.py tnspoison -s <IP> -p <PORT> -d <SID> --test-module
```


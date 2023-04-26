# Web Tool - WFuzz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

A tool to FUZZ web applications anywhere.

> Wfuzz has been created to facilitate the task in web applications assessments and it is based on a simple concept: it replaces any reference to the FUZZ keyword by the value of a given payload.

## Installation

Installed in Kali

Github: [https://github.com/xmendez/wfuzz](https://github.com/xmendez/wfuzz)

```
pip install wfuzz
```

## Filtering options

```bash
--hs/ss "regex" #Hide/Show
#Simple example, match a string: "Invalid username"
#Regex example: "Invalid *"

--hc/sc CODE #Hide/Show by code in response
--hl/sl NUM #Hide/Show by number of lines in response
--hw/sw NUM #Hide/Show by number of words in response
--hh/sh NUM #Hide/Show by number of chars in response
--hc/sc NUM #Hide/Show by response code
```

## Output options

```bash
wfuzz -e printers #Prints the available output formats
-f /tmp/output,csv #Saves the output in that location in csv format
```

### Encoders options

```bash
wfuzz -e encoders #Prints the available encoders
#Examples: urlencode, md5, base64, hexlify, uri_hex, doble urlencode
```

In order to use an encoder, you have to indicate it in the **"-w"** or **"-z"** option.

Examples:

```bash
-z file,/path/to/file,md5 #Will use a list inside the file, and will transform each value into its md5 hash before sending it
-w /path/to/file,base64 #Will use a list, and transform to base64
-z list,each-element-here,hexlify #Inline list and to hex before sending values
```

## CheetSheet

### Login Form bruteforce

#### **POST, Single list, filter string (hide)**

```bash
wfuzz -c -w users.txt --hs "Login name" -d "name=FUZZ&password=FUZZ&autologin=1&enter=Sign+in" http://zipper.htb/zabbix/index.php
#Here we have filtered by line
```

#### **POST, 2 lists, filter code (show)**

```bash
wfuzz.py -c -z file,users.txt -z file,pass.txt --sc 200 -d "name=FUZZ&password=FUZ2Z&autologin=1&enter=Sign+in" http://zipper.htb/zabbix/index.php
#Here we have filtered by code
```

#### **GET, 2 lists, filter string (show), proxy, cookies**

```bash
wfuzz -c -w users.txt -w pass.txt --ss "Welcome " -p 127.0.0.1:8080:HTTP -b "PHPSESSIONID=1234567890abcdef;customcookie=hey" "http://example.com/index.php?username=FUZZ&password=FUZ2Z&action=sign+in"
```

### Bruteforce Directory/RESTful bruteforce

[Arjun parameters wordlist](https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/params.txt)

```
wfuzz -c -w /tmp/tmp/params.txt --hc 404 https://domain.com/api/FUZZ
```

### Path Parameters BF

```bash
wfuzz -c -w ~/git/Arjun/db/params.txt --hw 11 'http://example.com/path%3BFUZZ=FUZZ'
```

### Header Authentication

#### **Basic, 2 lists, filter string (show), proxy**

```bash
wfuzz -c -w users.txt -w pass.txt -p 127.0.0.1:8080:HTTP --ss "Welcome" --basic FUZZ:FUZ2Z "http://example.com/index.php"
```

#### **NTLM, 2 lists, filter string (show), proxy**

```bash
wfuzz -c -w users.txt -w pass.txt -p 127.0.0.1:8080:HTTP --ss "Welcome" --ntlm 'domain\FUZZ:FUZ2Z' "http://example.com/index.php"
```

### Cookie/Header bruteforce (vhost brute)

#### **Cookie, filter code (show), proxy**

```bash
wfuzz -c -w users.txt -p 127.0.0.1:8080:HTTP --ss "Welcome " -H "Cookie:id=1312321&user=FUZZ"  "http://example.com/index.php"
```

#### **User-Agent, filter code (hide), proxy**

```bash
wfuzz -c -w user-agents.txt -p 127.0.0.1:8080:HTTP --ss "Welcome " -H "User-Agent: FUZZ"  "http://example.com/index.php"
```

#### **Host**

```bash
wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-
top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u 
http://example.com -t 100
```

### HTTP Verbs (methods) bruteforce

#### **Using file**

```bash
wfuzz -c -w methods.txt -p 127.0.0.1:8080:HTTP --sc 200 -X FUZZ "http://example.com/index.php"
```

#### **Using inline list**

```bash
$ wfuzz -z list,GET-HEAD-POST-TRACE-OPTIONS -X FUZZ http://testphp.vulnweb.com/
```

### Directory & Files Bruteforce

```bash
#Filter by whitelisting codes
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --sc 200,202,204,301,302,307,403 http://example.com/uploads/FUZZ
```

## Tool to bypass Webs

[https://github.com/carlospolop/fuzzhttpbypass](https://github.com/carlospolop/fuzzhttpbypass)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

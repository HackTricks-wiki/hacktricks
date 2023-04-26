# XSS Tools

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## XSStrike

```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py

python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test" 
```

**Basic Usage(Get):**\
python3 xsstrike.py --headers -u "http://localhost/vulnerabilities/xss\_r/?name=asd"\
**Basic Usage(Post):**\
python xsstrike.py -u "http://example.com/search.php" --data "q=query"\
**Crawling(depth=2 default):**\
python xsstrike.py -u "http://example.com/page.php" --crawl -l 3\
**Find hidden parameters:**\
python xsstrike.py -u "http://example.com/page.php" --params\
**Extra:**\
\--headers #Set custom headers (like cookies). It is necessary to set every time\
\--skip-poc\
\--skip-dom #Skip DOM XSS scanning

## BruteXSS

```
git clone https://github.com/rajeshmajumdar/BruteXSS
```

Tool to find vulnerable (GET or POST) parameter to XSS using a list of payloads with a GUI.\
Custom headers (like cookies) can not be configured.

## XSSer

[https://github.com/epsylon/xsser](https://github.com/epsylon/xsser)\
Already installed in Kali.\
Complete tool to find XSS.

**Basic Usage(Get):**\
\
The tool doesnt send the payload:(

## XSSCrapy

```
git clone https://github.com/DanMcInerney/xsscrapy
```

Not recommended. A lot of unnecessary output, and it doesn\`t work properly.

## Dalfox

[https://github.com/hahwul/dalfox](https://github.com/hahwul/dalfox)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

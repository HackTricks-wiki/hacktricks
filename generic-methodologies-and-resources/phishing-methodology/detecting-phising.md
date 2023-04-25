# Detecting Phising

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introduction

To detect a phishing attempt it's important to **understand the phishing techniques that are being used nowadays**. On the parent page of this post, you can find this information, so if you aren't aware of which techniques are being used today I recommend you to go to the parent page and read at least that section.

This post is based on the idea that the **attackers will try to somehow mimic or use the victim's domain name**. If your domain is called `example.com` and you are phished using a completely different domain name for some reason like `youwonthelottery.com`, these techniques aren't going to uncover it.

## Domain name variations

It's kind of **easy** to **uncover** those **phishing** attempts that will use a **similar domain** name inside the email.\
It's enough to **generate a list of the most probable phishing names** that an attacker may use and **check** if it's **registered** or just check if there is any **IP** using it.

### Finding suspicious domains

For this purpose, you can use any of the following tools. Note that these tolls will also perform DNS requests automatically to check if the domain has any IP assigned to it:

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

In the world of computing, everything is stored in bits (zeros and ones) in memory behind the scenes.\
This applies to domains too. For example, _windows.com_ becomes _01110111..._ in the volatile memory of your computing device.\
However, what if one of these bits got automatically flipped due to a solar flare, cosmic rays, or a hardware error? That is one of the 0's becomes a 1 and vice versa.\
Applying this concept to DNS requests, it's possible that the **domain requested** that arrives at the DNS server **isn't the same as the domain initially requested.**

For example, a 1 bit modification in the domain microsoft.com can transform it into _windnws.com._\
**Attackers may register as many bit-flipping domains as possible related to the victim to redirect legitimate users to their infrastructure**.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

**All possible bit-flipping domain names should be also monitored.**

### Basic checks

Once you have a list of potential suspicious domain names you should **check** them (mainly the ports HTTP and HTTPS) to **see if they are using some login form similar** to someone of the victim's domain.\
You could also check port 3333 to see if it's open and running an instance of `gophish`.\
It's also interesting to know **how old each discovered suspicions domain is**, the younger it's the riskier it is.\
You can also get **screenshots** of the HTTP and/or HTTPS suspicious web page to see if it's suspicious and in that case **access it to take a deeper look**.

### Advanced checks

If you want to go one step further I would recommend you to **monitor those suspicious domains and search for more** once in a while (every day? it only takes a few seconds/minutes). You should also **check** the open **ports** of the related IPs and **search for instances of `gophish` or similar tools** (yes, attackers also make mistakes) and **monitor the HTTP and HTTPS web pages of the suspicious domains and subdomains** to see if they have copied any login form from the victim's web pages.\
In order to **automate this** I would recommend having a list of login forms of the victim's domains, spider the suspicious web pages and comparing each login form found inside the suspicious domains with each login form of the victim's domain using something like `ssdeep`.\
If you have located the login forms of the suspicious domains, you can try to **send junk credentials** and **check if it's redirecting you to the victim's domain**.

## Domain names using keywords

The parent page also mentions a domain name variation technique that consists of putting the **victim's domain name inside a bigger domain** (e.g. paypal-financial.com for paypal.com).

### Certificate Transparency

It's not possible to take the previous "Brute-Force" approach but it's actually **possible to uncover such phishing attempts** also thanks to certificate transparency. Every time a certificate is emitted by a CA, the details are made public. This means that by reading the certificate transparency or even monitoring it, it's **possible to find domains that are using a keyword inside its name** For example, if an attacker generates a certificate of [https://paypal-financial.com](https://paypal-financial.com), seeing the certificate it's possible to find the keyword "paypal" and know that suspicious email is being used.

The post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) suggests that you can use Censys to search for certificates affecting a specific keyword and filter by date (only "new" certificates) and by the CA issuer "Let's Encrypt":

![](<../../.gitbook/assets/image (390).png>)

However, you can do "the same" using the free web [**crt.sh**](https://crt.sh). You can **search for the keyword** and the **filter** the results **by date and CA** if you wish.

![](<../../.gitbook/assets/image (391).png>)

Using this last option you can even use the field Matching Identities to see if any identity from the real domain matches any of the suspicious domains (note that a suspicious domain can be a false positive).

**Another alternative** is the fantastic project called [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream provides a real-time stream of newly generated certificates which you can use to detect specified keywords in (near) real-time. In fact, there is a project called [**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher) that does just that.

### **New domains**

**One last alternative** is to gather a list of **newly registered domains** for some TLDs ([Whoxy](https://www.whoxy.com/newly-registered-domains/) provides such service) and **check the keywords in these domains**. However, long domains usually use one or more subdomains, therefore the keyword won't appear inside the FLD and you won't be able to find the phishing subdomain.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

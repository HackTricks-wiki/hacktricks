

<details>

<summary><strong><a href="https://www.twitch.tv/hacktricks_live/schedule">🎙️ HackTricks LIVE Twitch</a> Wednesdays 5.30pm (UTC) 🎙️ - <a href="https://www.youtube.com/@hacktricks_LIVE">🎥 Youtube 🎥</a></strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Payloads

## Ignored parts of an email

The symbols: **+, -** and **{}** in rare occasions can be used for tagging and ignored by most e-mail servers

* E.g. john.doe+intigriti@example.com → john.doe@example.com

**Comments between parentheses ()** at the beginning or the end will also be ignored

* E.g. john.doe(intigriti)@example.com → john.doe@example.com

## Whitelist bypass

* inti(;inti@inti.io;)@whitelisted.com
* inti@inti.io(@whitelisted.com)
* inti+(@whitelisted.com;)@inti.io

## IPs

You can also use IPs as domain named between square brackets:

* john.doe@\[127.0.0.1]
* john.doe@\[IPv6:2001:db8::1]

## Other vulns

![](<.gitbook/assets/image (296).png>)

# Third party SSO

## XSS

Some services like **github** or **salesforce allows** you to create an **email address with XSS payloads on it**. If you can **use this providers to login on other services** and this services **aren't sanitising** correctly the email, you could cause **XSS**.

## Account-Takeover

If a **SSO service** allows you to **create an account without verifying the given email address** (like **salesforce**) and then you can use that account to **login in a different service** that **trusts** salesforce, you could access any account.\
_Note that salesforce indicates if the given email was or not verified but so the application should take into account this info._

# Reply-To

You can send an email using _**From: company.com**_** ** and _**Replay-To: attacker.com**_ and if any **automatic reply** is sent due to the email was sent **from** an **internal address** the **attacker** may be able to **receive** that **response**.

# **References**

* [**https://drive.google.com/file/d/1iKL6wbp3yYwOmxEtAg1jEmuOf8RM8ty9/view**](https://drive.google.com/file/d/1iKL6wbp3yYwOmxEtAg1jEmuOf8RM8ty9/view)

# Hard Bounce Rate

Some applications like AWS have a **Hard Bounce Rate** (in AWS is 10%), that whenever is overloaded the email service is blocked.

A **hard bounce** is an **email** that couldn’t be delivered for some permanent reasons. Maybe the **email’s** a fake address, maybe the **email** domain isn’t a real domain, or maybe the **email** recipient’s server won’t accept **emails**) , that means from total of 1000 emails if 100 of them were fake or were invalid that caused all of them to bounce, **AWS SES** will block your service.

So, if you are able to **send mails (maybe invitations) from the web application to any email address, you could provoke this block by sending hundreds of invitations to nonexistent users and domains: Email service DoS.**


<details>

<summary><strong><a href="https://www.twitch.tv/hacktricks_live/schedule">🎙️ HackTricks LIVE Twitch</a> Wednesdays 5.30pm (UTC) 🎙️ - <a href="https://www.youtube.com/@hacktricks_LIVE">🎥 Youtube 🎥</a></strong></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>



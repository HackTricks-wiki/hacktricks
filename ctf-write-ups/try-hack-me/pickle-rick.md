# Pickle Rick

## Pickle Rick

<details>

<summary><a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ HackTricks LIVE Twitch</strong></a> <strong>Wednesdays 5.30pm (UTC) 🎙️ -</strong> <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](../../.gitbook/assets/picklerick.gif)

This machine was categorised as easy and it was pretty easy.

## Enumeration

I started **enumerating the machine using my tool** [**Legion**](https://github.com/carlospolop/legion):

![](<../../.gitbook/assets/image (79) (2).png>)

In as you can see 2 ports are open: 80 (**HTTP**) and 22 (**SSH**)

So, I launched legion to enumerate the HTTP service:

![](<../../.gitbook/assets/image (234).png>)

Note that in the image you can see that `robots.txt` contains the string `Wubbalubbadubdub`

After some seconds I reviewed what `disearch` has already discovered :

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

And as you may see in the last image a **login** page was discovered.

Checking the source code of the root page, a username is discovered: `R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

Therefore, you can login on the login page using the credentials `R1ckRul3s:Wubbalubbadubdub`

## User

Using those credentials you will access a portal where you can execute commands:

![](<../../.gitbook/assets/image (241).png>)

Some commands like cat aren't allowed but you can read the first ingredient (flag) using for example grep:

![](<../../.gitbook/assets/image (242).png>)

Then I used:

![](<../../.gitbook/assets/image (243) (1).png>)

To obtain a reverse shell:

![](<../../.gitbook/assets/image (239) (1).png>)

The **second ingredient** can be found in `/home/rick`

![](<../../.gitbook/assets/image (240).png>)

## Root

The user **www-data can execute anything as sudo**:

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ HackTricks LIVE Twitch</strong></a> <strong>Wednesdays 5.30pm (UTC) 🎙️ -</strong> <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

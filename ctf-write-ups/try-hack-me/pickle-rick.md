# Pickle Rick

## Pickle Rick

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

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

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

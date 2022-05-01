

<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>


# Class Methods

You can access the **methods** of a **class** using **\_\_dict\_\_.**

![](<../../.gitbook/assets/image (42).png>)

You can access the functions

![](<../../.gitbook/assets/image (45).png>)

# Object class

## **Attributes**

You can access the **attributes of an object** using **\_\_dict\_\_**. Example:

![](<../../.gitbook/assets/image (41).png>)

## Class

You can access the **class** of an object using **\_\_class\_\_**

![](<../../.gitbook/assets/image (43).png>)

You can access the **methods** of the **class** of an **object chainning** magic functions:

![](<../../.gitbook/assets/image (44).png>)

# Server Side Template Injection

Interesting functions to exploit this vulnerability

```
__init__.__globals__
__class__.__init__.__globals__
```

Inside the response search for the application (probably at the end?)

Then **access the environment content** of the application where you will hopefully find **some passwords** of interesting information:

```
__init__.__globals__[<name>].config
__init__.__globals__[<name>].__dict__
__init__.__globals__[<name>].__dict__.config
__class__.__init__.__globals__[<name>].config
__class__.__init__.__globals__[<name>].__dict__
__class__.__init__.__globals__[<name>].__dict__.config
```

# More Information

* [https://rushter.com/blog/python-class-internals/](https://rushter.com/blog/python-class-internals/)
* [https://docs.python.org/3/reference/datamodel.html](https://docs.python.org/3/reference/datamodel.html)
* [https://balsn.tw/ctf\_writeup/20190603-facebookctf/#events](https://balsn.tw/ctf\_writeup/20190603-facebookctf/#events)
* [https://medium.com/bugbountywriteup/solving-each-and-every-fb-ctf-challenge-part-1-4bce03e2ecb0](https://medium.com/bugbountywriteup/solving-each-and-every-fb-ctf-challenge-part-1-4bce03e2ecb0) (events)


<details>

<summary><strong>Support HackTricks and get benefits!</strong></summary>

Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

**Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**

**Share your hacking tricks submitting PRs to the** [**hacktricks github repo**](https://github.com/carlospolop/hacktricks)**.**

</details>



# SOME - Same Origin Method Execution

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Same Origin Method Execution

There will be occasions where you can execute some limited javascript in a page. For example, in the case where you can[ **control a callback value that will be executed**](./#javascript-function).

In those case, one of the best things that you could do is to **access the DOM to call whatever** sensitive action you can find in there (like clicking a button). However, usually you will find this vulnerability in **small endpoints without any interesting thing in the DOM**.

In those scenarios, this attack will be very useful, because its goal is to be able to **abuse the limited JS execution inside a DOM from a different page from the same domain** with much interesting actions.

Basically, the attack flow is the following:

* Find a **callback that you can abuse** (potentially limited to \[\w\\.\_]).
  * If it's not limited and you can execute any JS, you could just abuse this as a regular XSS
* Make the **victim open a page** controlled by the **attacker**
* The **page will open itself** in a **different window** (the new window will have the object **`opener`** referencing the initial one)
* The **initial page** will load the **page** where the **interesting DOM** is located.
* The **second page** will load the **vulnerable page abusing the callback** and using the **`opener`** object to **access and execute some action in the initial page** (which now contains the interesting DOM).

{% hint style="danger" %}
Note that even if the initial page access to a new URL after having created the second page, the **`opener` object of the second page is still a valid reference to the first page in the new DOM**.

Moreover, in order for the second page to be able to use the opener object **both pages must be in the same origin**. This is the reason why, in order to abuse this vulnerability, you need to find some sort of **XSS in the same origin**.
{% endhint %}

### Exploitation

* You can use this form to **generate a PoC** to exploit this type of vulnerability: [https://www.someattack.com/Playground/SOMEGenerator](https://www.someattack.com/Playground/SOMEGenerator)
* In order to find a DOM path to a HTML element with a click you can use this browser extension: [https://www.someattack.com/Playground/targeting\_tool](https://www.someattack.com/Playground/targeting\_tool)

### Example

* You can find a vulnerable example in [https://www.someattack.com/Playground/](https://www.someattack.com/Playground/)
  * Note that in this example the server is **generating javascript code** and **adding** it to the HTML based on the **content of the callback parameter:** `<script>opener.{callbacl_content}</script>` . Thats why in this example you don't need to indicate the use of `opener` explicitly.
* Also check this CTF writeup: [https://ctftime.org/writeup/36068](https://ctftime.org/writeup/36068)

## References

* [https://conference.hitb.org/hitbsecconf2017ams/sessions/everybody-wants-some-advance-same-origin-method-execution/](https://conference.hitb.org/hitbsecconf2017ams/sessions/everybody-wants-some-advance-same-origin-method-execution/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

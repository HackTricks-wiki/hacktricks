# iButton

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Intro

iButton is a generic name for an electronic identification key packed in a **coin-shaped metal container**. It is also called **Dallas Touch** Memory or contact memory. Even though it is often wrongly referred to as a “magnetic” key, there is **nothing magnetic** in it. In fact, a full-fledged **microchip** operating on a digital protocol is hidden inside.

<figure><img src="../../.gitbook/assets/image (19).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

Usually, iButton implies the physical form of the key and reader - a round coin with two contacts. For the frame surrounding it, there are lots of variations from the most common plastic holder with a hole to rings, pendants, etc.

<figure><img src="../../.gitbook/assets/image (23) (2).png" alt=""><figcaption></figcaption></figure>

When the key reaches the reader, the **contacts come to touch** and the key is powered to **transmit** its ID. Sometimes the key is **not read** immediately because the **contact PSD of an intercom is larger** than it should be. So the outer contours of the key and the reader couldn't touch. If that's the case, you'll have to press the key over one of the walls of the reader.

<figure><img src="../../.gitbook/assets/image (21) (2).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#1-wire-protocol" id="1-wire-protocol"></a>

Dallas keys exchange data using the 1-wire protocol. With only one contact for data transfer (!!) in both directions, from master to slave and vice versa. The 1-wire protocol works according to the Master-Slave model. In this topology, the Master always initiates communication and the Slave follows its instructions.

When the key (Slave) contacts the intercom (Master), the chip inside the key turns on, powered by the intercom, and the key is initialized. Following that the intercom requests the key ID. Next, we will look up this process in more detail.

Flipper can work both in Master and Slave modes. In the key reading mode, Flipper acts as a reader this is to say it works as a Master. And in the key emulation mode, the flipper pretends to be a key, it is in the Slave mode.

### Dallas, Cyfral & Metakom keys

For information about how these keys works check the page [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacks

iButtons can be attacked with Flipper Zero:

{% content-ref url="flipper-zero/fz-ibutton.md" %}
[fz-ibutton.md](flipper-zero/fz-ibutton.md)
{% endcontent-ref %}

## References

* [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

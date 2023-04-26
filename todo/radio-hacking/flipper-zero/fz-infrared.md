# FZ - Infrared

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

For more info about how Infrared works check:

{% content-ref url="../infrared.md" %}
[infrared.md](../infrared.md)
{% endcontent-ref %}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper uses a digital IR signal receiver TSOP, which **allows intercepting signals from IR remotes**. There are some **smartphones** like Xiaomi, which also have an IR port, but keep in mind that **most of them can only transmit** signals and are **unable to receive** them.

The Flipper infrared **receiver is quite sensitive**. You can even **catch the signal** while remaining **somewhere in between** the remote and the TV. Pointing the remote directly at Flipper's IR port is unnecessary. This comes in handy when someone is switching channels while standing near the TV, and both you and Flipper are some distance away.

As the **decoding of the infrared** signal happens on the **software** side, Flipper Zero potentially supports the **reception and transmission of any IR remote codes**. In the case of **unknown** protocols which could not be recognized - it **records and plays back** the raw signal exactly as received.

## Actions

### Universal Remotes

Flipper Zero can be used as a **universal remote to control any TV, air conditioner, or media center**. In this mode, Flipper **bruteforces** all **known codes** of all supported manufacturers **according to the dictionary from the SD card**. You don't need to choose a particular remote to turn of a restaurant TV.

It is enough to press the power button in the Universal Remote mode, and Flipper will **sequentially send "Power Off"** commands of all the TVs it knows: Sony, Samsung, Panasonic... and so on. When the TV receives its signal, it will react and turn off.

Such brute-force takes time. The larger the dictionary, the longer it will take to finish. It is impossible to find out which signal exactly the TV recognized since there is no feedback from the TV.

### Learn New Remote

It's possible to **capture an infrared signal** with Flipper Zero. If it **finds the signal in the database** Flipper will automatically **know which device this is** and will let you interact with it.\
If it doesn't, Flipper can **store** the **signal** and will allow you to **replay it**.

## References

* [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

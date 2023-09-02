# FZ - Sub-GHz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero can **receive and transmit radio frequencies in the range of 300-928 MHz** with its built-in module, which can read, save, and emulate remote controls. These controls are used for interaction with gates, barriers, radio locks, remote control switches, wireless doorbells, smart lights, and more. Flipper Zero can help you to learn if your security is compromised.

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero has a built-in sub-1 GHz module based on a [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) and a radio antenna (the maximum range is 50 meters). Both the CC1101 chip and the antenna are designed to operate at frequencies in the 300-348 MHz, 387-464 MHz, and 779-928 MHz bands.

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

{% hint style="info" %}
How to find which frequency is the remote using
{% endhint %}

When analysing, Flipper Zero is scanning signals strength (RSSI) at all the frequencies available in frequency configuration. Flipper Zero displays the frequency with the highest RSSI value, with signal strength higher than -90 [dBm](https://en.wikipedia.org/wiki/DBm).

To determine the remote's frequency, do the following:

1. Place the remote control very close to the left of Flipper Zero.
2. Go to **Main Menu** **→ Sub-GHz**.
3. Select **Frequency Analyzer**, then press and hold the button on the remote control you want to analyze.
4. Review the frequency value on the screen.

### Read

{% hint style="info" %}
Find info about the frequency used (also another way to find which frequency is used)
{% endhint %}

The **Read** option **listens on the configured frequency** on the indicated modulation: 433.92 AM by default. If **something is found** when reading, **info is given** in the screen. This info could be use to replicate the signal in the future.

While Read is in use, it's possible to press the **left button** and **configure it**.\
At this moment it has **4 modulations** (AM270, AM650, FM328 and FM476), and **several relevant frequencies** stored:

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

You can set **any that interests you**, however, if you are **not sure which frequency** could be the one used by the remote you have, **set Hopping to ON** (Off by default), and press the button several times until Flipper captures it and give you the info you need to set the frequency.

{% hint style="danger" %}
Switching between frequencies takes some time, therefore signals transmitted at the time of switching can be missed. For better signal reception, set a fixed frequency determined by Frequency Analyzer.
{% endhint %}

### **Read Raw**

{% hint style="info" %}
Steal (and replay) a signal in the configured frequency
{% endhint %}

The **Read Raw** option **records signals** send in the listening frequency. This can be used to **steal** a signal and **repeat** it.

By default **Read Raw is also in 433.92 in AM650**, but if with the Read option you found that the signal that interest you is in a **different frequency/modulation, you can also modify that** pressing left (while inside the Read Raw option).

### Brute-Force

If you know the protocol used for example by the garage door it's possible to g**enerate all the codes and send them with the Flipper Zero.** This is an example that support general common types of garages: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### Add Manually

{% hint style="info" %}
Add signals from a configured list of protocols
{% endhint %}

#### List of [supported protocols](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (works with the majority of static code systems) | 433.92 | Static  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | Static  |
| Nice Flo 24bit\_433                                             | 433.92 | Static  |
| CAME 12bit\_433                                                 | 433.92 | Static  |
| CAME 24bit\_433                                                 | 433.92 | Static  |
| Linear\_300                                                     | 300.00 | Static  |
| CAME TWEE                                                       | 433.92 | Static  |
| Gate TX\_433                                                    | 433.92 | Static  |
| DoorHan\_315                                                    | 315.00 | Dynamic |
| DoorHan\_433                                                    | 433.92 | Dynamic |
| LiftMaster\_315                                                 | 315.00 | Dynamic |
| LiftMaster\_390                                                 | 390.00 | Dynamic |
| Security+2.0\_310                                               | 310.00 | Dynamic |
| Security+2.0\_315                                               | 315.00 | Dynamic |
| Security+2.0\_390                                               | 390.00 | Dynamic |

### Supported Sub-GHz vendors

Check the list in [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Supported Frequencies by region

Check the list in [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

{% hint style="info" %}
Get dBms of the saved frequencies
{% endhint %}

## Reference

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

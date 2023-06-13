# macOS Serial Number

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Apple devices manufactured after 2010 generally have **12-character alphanumeric** serial numbers, with the **first three digits representing the manufacturing location**, the following **two** indicating the **year** and **week** of manufacture, the next **three** digits providing a **unique** **identifier**, and the **last** **four** digits representing the **model number**.

Serial number example: **C02L13ECF8J2**

### **3 - Manufacturing locations**

| Code           | Factory                                      |
| -------------- | -------------------------------------------- |
| FC             | Fountain Colorado, USA                       |
| F              | Fremont, California, USA                     |
| XA, XB, QP, G8 | USA                                          |
| RN             | Mexico                                       |
| CK             | Cork, Ireland                                |
| VM             | Foxconn, Pardubice, Czech Republic           |
| SG, E          | Singapore                                    |
| MB             | Malaysia                                     |
| PT, CY         | Korea                                        |
| EE, QT, UV     | Taiwan                                       |
| FK, F1, F2     | Foxconn – Zhengzhou, China                   |
| W8             | Shanghai China                               |
| DL, DM         | Foxconn – China                              |
| DN             | Foxconn, Chengdu, China                      |
| YM, 7J         | Hon Hai/Foxconn, China                       |
| 1C, 4H, WQ, F7 | China                                        |
| C0             | Tech Com – Quanta Computer Subsidiary, China |
| C3             | Foxxcon, Shenzhen, China                     |
| C7             | Pentragon, Changhai, China                   |
| RM             | Refurbished/remanufactured                   |

### 1 - Year of manufacturing

| Code | Release              |
| ---- | -------------------- |
| C    | 2010/2020 (1st half) |
| D    | 2010/2020 (2nd half) |
| F    | 2011/2021 (1st half) |
| G    | 2011/2021 (2nd half) |
| H    | 2012/... (1st half)  |
| J    | 2012 (2nd half)      |
| K    | 2013 (1st half)      |
| L    | 2013 (2nd half)      |
| M    | 2014 (1st half)      |
| N    | 2014 (2nd half)      |
| P    | 2015 (1st half)      |
| Q    | 2015 (2nd half)      |
| R    | 2016 (1st half)      |
| S    | 2016 (2nd half)      |
| T    | 2017 (1st half)      |
| V    | 2017 (2nd half)      |
| W    | 2018 (1st half)      |
| X    | 2018 (2nd half)      |
| Y    | 2019 (1st half)      |
| Z    | 2019 (2nd half)      |

### 1 - Week of manufacturing

The fifth character represent the week in which the device was manufactured. There are 28 possible characters in this spot: **the digits 1-9 are used to represent the first through ninth weeks**, and the **characters C through Y**, **excluding** the vowels A, E, I, O, and U, and the letter S, represent the **tenth through twenty-seventh weeks**. For devices manufactured in the **second half of the year, add 26** to the number represented by the fifth character of the serial number. For example, a product with a serial number whose fourth and fifth digits are “JH” was manufactured in the 40th week of 2012.

### 3 - Uniq Code

The next three digits are an identifier code which **serves to differentiate each Apple device of the same model** which is manufactured in the same location and during the same week of the same year, ensuring that each device has a different serial number.

### 4 - Serial number

The last four digits of the serial number represent the **product’s model**.

### Reference

{% embed url="https://beetstech.com/blog/decode-meaning-behind-apple-serial-number" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

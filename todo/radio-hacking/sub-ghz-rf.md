# Sub-GHz RF

<details>

<summary><a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ HackTricks LIVE Twitch</strong></a> <strong>Wednesdays 5.30pm (UTC) 🎙️ -</strong> <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Garage Doors

Garage door openers typically operate at frequencies in the 300-190 MHz range, with the most common frequencies being 300 MHz, 310 MHz, 315 MHz, and 390 MHz. This frequency range is commonly used for garage door openers because it is less crowded than other frequency bands and is less likely to experience interference from other devices.

## Car Doors

Most car key fobs operate on either **315 MHz or 433 MHz**. These are both radio frequencies, and they are used in a variety of different applications. The main difference between the two frequencies is that 433 MHz has a longer range than 315 MHz. This means that 433 MHz is better for applications that require a longer range, such as remote keyless entry.\
In Europe 433.92MHz is commonly used and in U.S. and Japan it's the 315MHz.

## Security

### Rolling Codes

Automatic garage door openers typically use a wireless remote control to open and close the garage door. The remote control **sends a radio frequency (RF) signal** to the garage door opener, which activates the motor to open or close the door.

It is possible for someone to use a device known as a code grabber to intercept the RF signal and record it for later use. This is known as a **replay attack**. To prevent this type of attack, many modern garage door openers use a more secure encryption method known as a **rolling code** system.

The **RF signal is typically transmitted using a rolling code**, which means that the code changes with each use. This makes it **difficult** for someone to **intercept** the signal and **use** it to gain **unauthorised** access to the garage.

In a rolling code system, the remote control and the garage door opener have a **shared algorithm** that **generates a new code** every time the remote is used. The garage door opener will only respond to the **correct code**, making it much more difficult for someone to gain unauthorised access to the garage just by capturing a code.

## Attack

To attack these signals with Flipper Zero check:

{% content-ref url="flipper-zero/fz-sub-ghz.md" %}
[fz-sub-ghz.md](flipper-zero/fz-sub-ghz.md)
{% endcontent-ref %}

## References

* [https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)

<details>

<summary><a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ HackTricks LIVE Twitch</strong></a> <strong>Wednesdays 5.30pm (UTC) 🎙️ -</strong> <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

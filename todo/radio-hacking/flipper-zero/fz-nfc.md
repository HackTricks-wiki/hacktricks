# FZ - NFC

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

For info about RFID and NFC check the following page:

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## Supported NFC cards <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
Apart from NFC cards Flipper Zero supports **other type of High-frequency cards** such as several **Mifare** Classic and Ultralight and **NTAG**.
{% endhint %}

New types of NFC cards will be added to the list of supported cards. Flipper Zero supports the following **NFC cards type A** (ISO 14443A):

* ﻿**Bank cards (EMV)** — only read UID, SAK, and ATQA without saving.
* ﻿**Unknown cards** — read (UID, SAK, ATQA) and emulate an UID.

For **NFC cards type B, type F, and type V**, Flipper Zero is able to read an UID without saving it.

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero can only read an UID, SAK, ATQA, and stored data on bank cards **without saving**.

Bank card reading screenFor bank cards, Flipper Zero can only read data **without saving and emulating it**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

When Flipper Zero is **unable to determine NFC card's type**, then only an **UID, SAK, and ATQA** can be **read and saved**.

Unknown card reading screenFor unknown NFC cards, Flipper Zero can emulate only an UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

For **NFC cards types B, F, and V**, Flipper Zero can only **read and display an UID** without saving it.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Actions

For an intro about NFC [**read this page**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Read

Flipper Zero can **read NFC cards**, however, it **doesn't understand all the protocols** that are based on ISO 14443. However, since **UID is a low-level attribute**, you might find yourself in a situation when **UID is already read, but the high-level data transfer protocol is still unknown**. You can read, emulate and manually input UID using Flipper for the primitive readers that use UID for authorization.

#### Reading the UID VS Reading the Data Inside <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper, reading 13.56 MHz tags can be divided into two parts:

* **Low-level read** — reads only the UID, SAK, and ATQA. Flipper tries to guess the high-level protocol based on this data read from the card. You can't be 100% certain with this, as it is just an assumption based on certain factors.
* **High-level read** — reads the data from the card's memory using a specific high-level protocol. That would be reading the data on a Mifare Ultralight, reading the sectors from a Mifare Classic, or reading the card's attributes from PayPass/Apple Pay.

### Read Specific

In case Flipper Zero isn't capable of finding the type of card from the low level data, in `Extra Actions` you can select `Read Specific Card Type` and **manually** **indicate the type of card you would like to read**.

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Apart from simply reading the UID, you can extract a lot more data from a bank card. It's possible to **get the full card number** (the 16 digits on the front of the card), **validity date**, and in some cases even the **owner's name** along with a list of the **most recent transactions**.\
However, you **can't read the CVV this way** (the 3 digits on the back of the card). Also **bank cards are protected from replay attacks**, so copying it with Flipper and then trying to emulate it to pay for something won't work.

## References

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

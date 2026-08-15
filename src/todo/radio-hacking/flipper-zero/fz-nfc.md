# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

For info about RFID and NFC check the following page:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Supported NFC cards <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Apart from NFC cards Flipper Zero supports **other type of High-frequency cards** such as several **Mifare** Classic and Ultralight and **NTAG**.

The capability list below describes the firmware documented by the original article and should not be treated as the current exhaustive support matrix. Flipper firmware has added protocols and changed NFC behavior over time; check the current official documentation for the installed firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bank cards (EMV)** — only read UID, SAK, and ATQA without saving.
- **Unknown cards** — read the UID, SAK, and ATQA and emulate a UID.

For **NFC card types B, F, and V**, the documented firmware could read a UID without saving it.

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

The documented firmware could read a UID, SAK, ATQA, and available application data from a bank card **without saving it**.

For these bank cards, the firmware displayed data without saving or emulating the card.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

When Flipper Zero is **unable to determine NFC card's type**, then only an **UID, SAK, and ATQA** can be **read and saved**.

For an unknown NFC card, this mode can emulate only its UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

In the firmware documented by the original article, NFC card types B, F, and V could only have an identifier read and displayed without saving it.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

For an intro about NFC [**read this page**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Read

Flipper Zero can read NFC cards but does not implement every higher-level protocol built on ISO 14443. It may therefore recover the low-level UID, SAK, and ATQA while leaving the application protocol unknown. For primitive access systems that authorize only by UID, the tool can read, manually enter, and emulate that identifier; cryptographically authenticated systems require more than a copied UID.<sup>[[1]](#references)</sup>

#### Reading the UID VS Reading the Data Inside <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

In Flipper, reading 13.56 MHz tags can be divided into two parts:<sup>[[1]](#references)</sup>

- **Low-level read** — reads only the UID, SAK, and ATQA. Flipper tries to guess the high-level protocol based on this data read from the card. You can't be 100% certain with this, as it is just an assumption based on certain factors.
- **High-level read** — reads the data from the card's memory using a specific high-level protocol. That would be reading the data on a Mifare Ultralight, reading the sectors from a Mifare Classic, or reading the card's attributes from PayPass/Apple Pay.

### Read Specific

In case Flipper Zero isn't capable of finding the type of card from the low level data, in `Extra Actions` you can select `Read Specific Card Type` and **manually** **indicate the type of card you would like to read**.

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Older Flipper firmware and compatible EMV cards could expose more than the UID, potentially including the PAN, expiration date, cardholder name, or transaction log when those records were made available by the card. Availability varies by card, application, and firmware. The magnetic-stripe CVV printed on the card is not exposed this way, and reading these records does not clone the cryptographic transaction capability needed to make a contactless payment.<sup>[[1]](#references)</sup>

## References

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero documentation - NFC](https://docs.flipper.net/zero/nfc)

{{#include ../../../banners/hacktricks-training.md}}

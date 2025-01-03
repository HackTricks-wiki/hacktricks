# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## Intro

For more info about how 125kHz tags work check:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

For more info about these types of tags [**read this intro**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz).

### Read

Tries to **read** the card info. Then it can **emulate** them.

> [!WARNING]
> Note that some intercoms try to protect themselves from key duplication by sending a write command prior to reading. If the write succeeds, that tag is considered fake. When Flipper emulates RFID there is no way for the reader to distinguish it from the original one, so no such problems occur.

### Add Manually

You can create **fake cards in Flipper Zero indicating the data** you manually and then emulate it.

#### IDs on cards

Some times, when you get a card you will find the ID (or part) of it written in the card visible.

- **EM Marin**

For example in this EM-Marin card in the physical card is possible to **read the last 3 of 5 bytes in clear**.\
The other 2 can be brute-forced if you cannot read them from the card.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

Same happens in this HID card where only 2 out of 3 bytes can be found printed in the card

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

After **copying** a card or **entering** the ID **manually** it's possible to **emulate** it with Flipper Zero or **write** it in a real card.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}




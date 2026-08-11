# iButton

{{#include ../../banners/hacktricks-training.md}}

## Intro

iButton is a generic name for an electronic identification key packed in a **coin-shaped metal container**. It is also called **Dallas Touch** Memory or contact memory. Even though it is often wrongly referred to as a “magnetic” key, there is **nothing magnetic** in it. In fact, a full-fledged **microchip** operating on a digital protocol is hidden inside.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

The name iButton describes the durable coin-shaped package and contact arrangement. Holders include plastic fobs, rings, and pendants.

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

When both contacts meet the reader, the device receives power and exchanges data. If the recessed contact geometry prevents the outer ground contacts from meeting, tilting the key against the reader wall can restore contact.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim keys use the 1-Wire protocol: one data contact carries bidirectional traffic and may also provide parasitic power, while the metal can is the return contact. The controller initiates transactions and the device responds.<sup>[[2]](#references)</sup>

When the key (Slave) contacts the intercom (Master), the chip inside the key turns on, powered by the intercom, and the key is initialized. Following that the intercom requests the key ID. Next, we will look up this process in more detail.

Flipper can act as the controller while reading a key and as the emulated device while presenting a stored identifier to a reader.<sup>[[1]](#references)</sup>

### Dallas, Cyfral & Metakom keys

For information about how these keys works check the page [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### Attacks

iButtons can be attacked with Flipper Zero:


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 1-Wire communication through software](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)

{{#include ../../banners/hacktricks-training.md}}

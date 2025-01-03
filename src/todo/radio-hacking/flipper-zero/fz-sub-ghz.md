# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero can **receive and transmit radio frequencies in the range of 300-928 MHz** with its built-in module, which can read, save, and emulate remote controls. These controls are used for interaction with gates, barriers, radio locks, remote control switches, wireless doorbells, smart lights, and more. Flipper Zero can help you to learn if your security is compromised.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero has a built-in sub-1 GHz module based on a [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) and a radio antenna (the maximum range is 50 meters). Both the CC1101 chip and the antenna are designed to operate at frequencies in the 300-348 MHz, 387-464 MHz, and 779-928 MHz bands.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!NOTE]
> How to find which frequency is the remote using

When analysing, Flipper Zero is scanning signals strength (RSSI) at all the frequencies available in frequency configuration. Flipper Zero displays the frequency with the highest RSSI value, with signal strength higher than -90 [dBm](https://en.wikipedia.org/wiki/DBm).

To determine the remote's frequency, do the following:

1. Place the remote control very close to the left of Flipper Zero.
2. Go to **Main Menu** **→ Sub-GHz**.
3. Select **Frequency Analyzer**, then press and hold the button on the remote control you want to analyze.
4. Review the frequency value on the screen.

### Read

> [!NOTE]
> Find info about the frequency used (also another way to find which frequency is used)

The **Read** option **listens on the configured frequency** on the indicated modulation: 433.92 AM by default. If **something is found** when reading, **info is given** in the screen. This info could be use to replicate the signal in the future.

While Read is in use, it's possible to press the **left button** and **configure it**.\
At this moment it has **4 modulations** (AM270, AM650, FM328 and FM476), and **several relevant frequencies** stored:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

You can set **any that interests you**, however, if you are **not sure which frequency** could be the one used by the remote you have, **set Hopping to ON** (Off by default), and press the button several times until Flipper captures it and give you the info you need to set the frequency.

> [!CAUTION]
> Switching between frequencies takes some time, therefore signals transmitted at the time of switching can be missed. For better signal reception, set a fixed frequency determined by Frequency Analyzer.

### **Read Raw**

> [!NOTE]
> Steal (and replay) a signal in the configured frequency

The **Read Raw** option **records signals** send in the listening frequency. This can be used to **steal** a signal and **repeat** it.

By default **Read Raw is also in 433.92 in AM650**, but if with the Read option you found that the signal that interest you is in a **different frequency/modulation, you can also modify that** pressing left (while inside the Read Raw option).

### Brute-Force

If you know the protocol used for example by the garage door it's possible to g**enerate all the codes and send them with the Flipper Zero.** This is an example that support general common types of garages: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!NOTE]
> Add signals from a configured list of protocols

#### List of [supported protocols](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (works with the majority of static code systems) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Supported Sub-GHz vendors

Check the list in [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Supported Frequencies by region

Check the list in [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!NOTE]
> Get dBms of the saved frequencies

## Reference

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}




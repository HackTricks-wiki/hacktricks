# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#introduction" id="introduction"></a>

Flipper Zero can **receive and transmit radio frequencies in the range of 300-928 MHz** with its built-in module, subject to the frequency restrictions for the configured region. It can read, save, and emulate compatible remote controls used with gates, barriers, radio locks, switches, wireless doorbells, smart lights, and other devices.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Hardware <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero has a built-in sub-1 GHz module based on a CC1101 transceiver and a radio antenna. Actual range depends on the frequency, antenna, environment, and transmitter; Flipper documents up to approximately 50 meters under favorable conditions. The hardware covers 300-348 MHz, 387-464 MHz, and 779-928 MHz, while firmware and regional rules further restrict transmission.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!TIP]
> How to find which frequency is the remote using

When analysing, Flipper Zero is scanning signals strength (RSSI) at all the frequencies available in frequency configuration. Flipper Zero displays the frequency with the highest RSSI value, with signal strength higher than -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

To determine the remote's frequency, do the following:

1. Place the remote control very close to the left of Flipper Zero.
2. Go to **Main Menu** **→ Sub-GHz**.
3. Select **Frequency Analyzer**, then press and hold the button on the remote control you want to analyze.
4. Review the frequency value on the screen.

### Read

> [!TIP]
> Find info about the frequency used (also another way to find which frequency is used)

The **Read** option listens on the configured frequency and modulation (433.92 MHz AM by default). When it recognizes a supported signal, the screen displays information that can be saved and replayed later.<sup>[[1]](#references)</sup>

While Read is in use, it's possible to press the **left button** and **configure it**.\
At this moment it has **4 modulations** (AM270, AM650, FM328 and FM476), and **several relevant frequencies** stored:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

You can select any permitted frequency. If you are unsure which frequency the remote uses, set **Hopping to ON** (off by default), then press the remote button several times until Flipper captures the signal and reports the frequency.

> [!CAUTION]
> Switching between frequencies takes some time, therefore signals transmitted at the time of switching can be missed. For better signal reception, set a fixed frequency determined by Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Steal (and replay) a signal in the configured frequency

The **Read Raw** option records signals sent on the selected frequency. This can be used to capture and replay a signal during authorized testing.<sup>[[1]](#references)</sup>

By default, **Read Raw also uses 433.92 MHz with AM650**. If the Read option found a signal on a different frequency or modulation, press Left inside Read Raw to change those settings.

### Brute-Force

If you know the protocol used by a device such as a garage door, it may be possible to **generate candidate codes and transmit them with Flipper Zero**. The `flipperzero-bruteforce` project supports several common static-code protocols.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Add signals from a configured list of protocols

#### List of supported protocols <a href="#id-3iglu" id="id-3iglu"></a>

The Add Manually menu exposes the protocol presets documented by Flipper Zero.<sup>[[4]](#references)</sup>

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

Check Flipper Zero's supported-vendors list.<sup>[[5]](#references)</sup>

### Supported Frequencies by region

Check the official regional-frequency list before transmitting.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Get dBms of the saved frequencies

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 data sheet](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Add a manually created remote](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Supported Sub-GHz vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regional Sub-GHz frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

{{#include ../../../banners/hacktricks-training.md}}

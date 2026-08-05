# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero inaweza **kupokea na kutuma masafa ya redio katika kiwango cha 300-928 MHz** kwa kutumia module yake iliyojengewa ndani, ambayo inaweza kusoma, kuhifadhi na kuiga remote controls. Controls hizi hutumika kwa mwingiliano na gates, barriers, radio locks, remote control switches, wireless doorbells, smart lights na vinginevyo. Flipper Zero inaweza kukusaidia kujua ikiwa usalama wako umecompromise.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Vifaa vya Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ina module ya sub-1 GHz iliyojengewa ndani, inayotegemea [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) na radio antenna (masafa ya juu zaidi ni mita 50). CC1101 chip pamoja na antenna zimetengenezwa kufanya kazi katika bands za 300-348 MHz, 387-464 MHz na 779-928 MHz.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Vitendo

### Frequency Analyser

> [!TIP]
> Jinsi ya kupata frequency inayotumiwa na remote

Wakati wa kufanya analysis, Flipper Zero inaskani nguvu ya signals (RSSI) katika frequencies zote zinazopatikana kwenye frequency configuration. Flipper Zero huonyesha frequency yenye thamani ya juu zaidi ya RSSI, ikiwa na signal strength iliyo juu kuliko -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Ili kubaini frequency ya remote, fanya yafuatayo:

1. Weka remote control karibu sana upande wa kushoto wa Flipper Zero.
2. Nenda kwenye **Main Menu** **→ Sub-GHz**.
3. Chagua **Frequency Analyzer**, kisha bonyeza na ushikilie kitufe kwenye remote control unayotaka kuichanganua.
4. Kagua thamani ya frequency kwenye screen.

### Read

> [!TIP]
> Pata taarifa kuhusu frequency iliyotumika (pia ni njia nyingine ya kupata frequency iliyotumika)

Chaguo la **Read** **husikiliza frequency iliyoconfigure** kwa modulation iliyoonyeshwa: 433.92 AM kwa default. Ikiwa **kitu kinapatikana** wakati wa kusoma, **taarifa huonyeshwa** kwenye screen. Taarifa hii inaweza kutumika kureplicate signal hiyo baadaye.<sup>[[1]](#references)</sup>

Wakati Read inatumika, inawezekana kubonyeza **left button** na **kuiconfigure**.\
Kwa sasa ina **modulations 4** (AM270, AM650, FM328 na FM476), pamoja na **frequencies kadhaa muhimu** zilizohifadhiwa:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Unaweza kuweka **ile yoyote inayokuvutia**, hata hivyo, ikiwa **huna uhakika ni frequency ipi** inayoweza kuwa inatumiwa na remote uliyo nayo, **weka Hopping kwenye ON** (Off kwa default), kisha bonyeza kitufe mara kadhaa hadi Flipper iicapture na kukupa taarifa unayohitaji ili kuweka frequency.

> [!CAUTION]
> Kubadilisha kati ya frequencies huchukua muda; kwa hiyo signals zinazotumwa wakati wa kubadilisha zinaweza kukosekana. Kwa mapokezi bora ya signal, weka frequency thabiti iliyobainishwa na Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Steal (na replay) signal katika frequency iliyoconfigure

Chaguo la **Read Raw** **hurekodi signals** zinazotumwa kwenye frequency inayosikilizwa. Hii inaweza kutumika **kuiba** signal na **kuirudia**.

Kwa default **Read Raw pia iko kwenye 433.92 katika AM650**, lakini ikiwa kwa kutumia chaguo la Read uligundua kuwa signal inayokuvutia iko kwenye **frequency/modulation tofauti, unaweza pia kuibadilisha** kwa kubonyeza left (ukiwa ndani ya chaguo la Read Raw).

### Brute-Force

Ikiwa unajua protocol inayotumiwa, kwa mfano, na garage door, inawezekana **kugenerate codes zote na kuzituma kwa Flipper Zero.** Huu ni mfano unaosaidia aina za kawaida za garages: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Ongeza signals kutoka kwenye list iliyoconfigure ya protocols

#### Orodha ya [supported protocols](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

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

Kagua listi kwenye [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Supported Frequencies by region

Kagua listi kwenye [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!TIP]
> Pata dBms za frequencies zilizohifadhiwa

## Marejeo

- [1] [Flipper Zero Sub-GHz documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}

# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero inaweza **kupokea na kutuma masafa ya redio katika kiwango cha 300-928 MHz** kwa kutumia module yake iliyojengewa ndani, ambayo inaweza kusoma, kuhifadhi na kuiga remote controls. Controls hizi hutumika kwa mwingiliano na mageti, barriers, locks za redio, switches za remote control, doorbells zisizotumia waya, smart lights na zaidi. Flipper Zero inaweza kukusaidia kujua ikiwa security yako imecompromised.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Vifaa vya Sub-GHz <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ina module ya sub-1 GHz iliyojengewa ndani inayotumia [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) na radio antenna (kiwango cha juu ni mita 50). CC1101 chip na antenna zimeundwa kufanya kazi katika bands za 300-348 MHz, 387-464 MHz na 779-928 MHz.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Vitendo

### Frequency Analyser

> [!TIP]
> Jinsi ya kupata frequency inayotumiwa na remote

Wakati wa kufanya analysis, Flipper Zero inaskani signal strength (RSSI) katika masafa yote yanayopatikana kwenye frequency configuration. Flipper Zero huonyesha frequency yenye thamani ya juu zaidi ya RSSI, ikiwa na signal strength iliyo juu kuliko -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Ili kubaini frequency ya remote, fanya yafuatayo:

1. Weka remote control karibu sana upande wa kushoto wa Flipper Zero.
2. Nenda kwenye **Main Menu** **→ Sub-GHz**.
3. Chagua **Frequency Analyzer**, kisha bonyeza na ushikilie kitufe kwenye remote control unayotaka kuichanganua.
4. Kagua thamani ya frequency kwenye screen.

### Read

> [!TIP]
> Pata maelezo kuhusu frequency inayotumiwa (pia ni njia nyingine ya kupata frequency inayotumiwa)

Chaguo la **Read** **husikiliza frequency iliyosanidiwa** kwa modulation iliyoonyeshwa: 433.92 AM kwa default. Ikiwa **kuna kitu kinapatikana** wakati wa kusoma, **maelezo huonyeshwa** kwenye screen. Maelezo haya yanaweza kutumiwa kuiga signal hiyo baadaye.<sup>[[1]](#references)</sup>

Wakati Read inatumika, inawezekana kubonyeza **kitufe cha kushoto** na **kuisanidi**.\
Kwa sasa ina **modulations 4** (AM270, AM650, FM328 na FM476), pamoja na **frequencies kadhaa muhimu** zilizohifadhiwa:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Unaweza kuweka **frequency yoyote inayokuvutia**; hata hivyo, ikiwa **huna uhakika ni frequency ipi** inayoweza kutumiwa na remote uliyonayo, **weka Hopping kuwa ON** (Off kwa default), kisha bonyeza kitufe mara kadhaa hadi Flipper iikamate na kukupa maelezo unayohitaji ili kuweka frequency.

> [!CAUTION]
> Kubadilisha kati ya frequencies huchukua muda; kwa hiyo signals zinazotumwa wakati wa mabadiliko zinaweza kukosekana. Kwa signal reception bora, weka frequency thabiti iliyobainishwa na Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Iba (na replay) signal katika frequency iliyosanidiwa

Chaguo la **Read Raw** **hurekodi signals** zinazotumwa kwenye frequency inayosikilizwa. Hii inaweza kutumiwa **kuiba** signal na **kuirudia**.<sup>[[1]](#references)</sup>

Kwa default, **Read Raw pia iko kwenye 433.92 katika AM650**, lakini ikiwa kwa kutumia chaguo la Read umegundua kuwa signal inayokuvutia iko kwenye **frequency/modulation tofauti, unaweza pia kuibadilisha** kwa kubonyeza kitufe cha kushoto (ukiwa ndani ya chaguo la Read Raw).

### Brute-Force

Ikiwa unajua protocol inayotumiwa, kwa mfano na garage door, inawezekana **kugenerate codes zote na kuzituma kwa Flipper Zero.** Huu ni mfano unaotumia aina za jumla za garage zinazotumika sana: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Ongeza signals kutoka kwenye orodha iliyosanidiwa ya protocols

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

### Vendors wa Sub-GHz wanaotumika

Kagua orodha kwenye [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Frequencies zinazotumika kulingana na region

Kagua orodha kwenye [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!TIP]
> Pata dBms za frequencies zilizohifadhiwa

## Marejeo

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}

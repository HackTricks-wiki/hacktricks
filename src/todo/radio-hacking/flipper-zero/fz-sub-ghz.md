# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#introduction" id="introduction"></a>

Flipper Zero inaweza **kupokea na kutuma masafa ya redio katika kiwango cha 300-928 MHz** kwa kutumia module yake iliyojengwa ndani, kulingana na vizuizi vya masafa kwa eneo lililosanidiwa. Inaweza kusoma, kuhifadhi na kuiga remote controls zinazooana zinazotumika kwenye mageti, vizuizi, locks za redio, switches, doorbells zisizotumia waya, taa smart na vifaa vingine.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Hardware ya Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero ina module iliyojengwa ndani ya sub-1 GHz inayotumia transceiver ya CC1101 na antenna ya redio. Masafa halisi hutegemea frequency, antenna, mazingira na transmitter; Flipper inaeleza kuwa masafa yanaweza kufikia takriban mita 50 katika hali nzuri. Hardware inashughulikia 300-348 MHz, 387-464 MHz na 779-928 MHz, huku firmware na kanuni za eneo zikiweka vizuizi zaidi kwenye transmission.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Vitendo

### Frequency Analyser

> [!TIP]
> Jinsi ya kutambua frequency inayotumiwa na remote

Wakati wa kuchanganua, Flipper Zero inachanganua signal strength (RSSI) katika frequencies zote zinazopatikana kwenye frequency configuration. Flipper Zero huonyesha frequency yenye thamani ya juu zaidi ya RSSI, ikiwa signal strength yake ni kubwa kuliko -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Ili kutambua frequency ya remote, fanya yafuatayo:

1. Weka remote control karibu sana na upande wa kushoto wa Flipper Zero.
2. Nenda kwenye **Main Menu** **→ Sub-GHz**.
3. Chagua **Frequency Analyzer**, kisha bonyeza na ushikilie kitufe kwenye remote control unayotaka kuchanganua.
4. Kagua thamani ya frequency kwenye skrini.

### Read

> [!TIP]
> Tafuta maelezo kuhusu frequency inayotumika (pia ni njia nyingine ya kutambua frequency inayotumika)

Chaguo la **Read** husikiliza kwenye frequency na modulation iliyosanidiwa (433.92 MHz AM kwa default). Linapotambua signal inayoungwa mkono, skrini huonyesha maelezo ambayo yanaweza kuhifadhiwa na kuchezwa tena baadaye.<sup>[[1]](#references)</sup>

Wakati Read inatumika, inawezekana kubonyeza **left button** na **kuisanidi**.\
Kwa sasa ina **modulations 4** (AM270, AM650, FM328 na FM476), pamoja na **frequencies kadhaa muhimu** zilizohifadhiwa:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Unaweza kuchagua frequency yoyote inayoruhusiwa. Ikiwa huna uhakika remote inatumia frequency gani, weka **Hopping to ON** (imezimwa kwa default), kisha bonyeza kitufe cha remote mara kadhaa hadi Flipper inaponasa signal na kuripoti frequency.

> [!CAUTION]
> Kubadilisha kati ya frequencies huchukua muda, kwa hiyo signals zinazotumwa wakati wa kubadilisha zinaweza kukosekana. Kwa upokeaji bora wa signal, weka frequency isiyobadilika iliyotambuliwa na Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Nakili (na ucheze tena) signal kwenye frequency iliyosanidiwa

Chaguo la **Read Raw** hurekodi signals zinazotumwa kwenye frequency iliyochaguliwa. Hii inaweza kutumika kunasa na kucheza tena signal wakati wa testing iliyoidhinishwa.<sup>[[1]](#references)</sup>

Kwa default, **Read Raw pia hutumia 433.92 MHz na AM650**. Ikiwa chaguo la Read liligundua signal kwenye frequency au modulation tofauti, bonyeza Left ukiwa ndani ya Read Raw ili kubadilisha mipangilio hiyo.

### Brute-Force

Ikiwa unajua protocol inayotumiwa na kifaa kama vile mlango wa garage, huenda ikawezekana **kutengeneza candidate codes na kuzituma kwa Flipper Zero**. Project ya `flipperzero-bruteforce` inaunga mkono protocols kadhaa za kawaida za static-code.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Ongeza signals kutoka kwenye orodha iliyosanidiwa ya protocols

#### Orodha ya protocols zinazoungwa mkono <a href="#id-3iglu" id="id-3iglu"></a>

Menu ya Add Manually huonyesha protocol presets zilizoandikwa kwenye nyaraka za Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (inafanya kazi na mifumo mingi ya static code) | 433.92 | Static  |
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

### Wauzaji wa Sub-GHz wanaoungwa mkono

Kagua supported-vendors list ya Flipper Zero.<sup>[[5]](#references)</sup>

### Frequencies zinazoungwa mkono kwa eneo

Kagua regional-frequency list rasmi kabla ya kutuma signals.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Pata dBms za frequencies zilizohifadhiwa

## References

- [1] [Sub-GHz - Nyaraka za Mtumiaji za Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Hati ya data ya Texas Instruments CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Ongeza remote iliyoundwa manually](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Wauzaji wa Sub-GHz wanaoungwa mkono](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Frequencies za Sub-GHz za kikanda](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}

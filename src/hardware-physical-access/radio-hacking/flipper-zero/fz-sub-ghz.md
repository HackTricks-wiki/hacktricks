# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#introduction" id="introduction"></a>

Flipper Zero inaweza **kupokea na kutuma masafa ya redio katika masafa ya 300-928 MHz** kwa kutumia moduli yake iliyojengewa ndani, kwa kuzingatia vizuizi vya masafa vya eneo lililowekwa. Inaweza kusoma, kuhifadhi na kuiga vidhibiti vya mbali vinavyooana vinavyotumiwa kwenye mageti, vizuizi, kufuli za redio, swichi, kengele za mlango zisizotumia waya, taa mahiri na vifaa vingine.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Vifaa vya Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero ina moduli ya sub-1 GHz iliyojengewa ndani, inayotumia transceiver ya CC1101 na antena ya redio. Masafa halisi hutegemea frequency, antena, mazingira na transmitter; Flipper huandika kuwa inaweza kufikia takriban mita 50 katika hali nzuri. Vifaa hivi hufunika masafa ya 300-348 MHz, 387-464 MHz na 779-928 MHz, huku firmware na kanuni za eneo zikiweka vizuizi zaidi kwenye utumaji.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Vitendo

### Frequency Analyser

> [!TIP]
> Jinsi ya kujua frequency inayotumiwa na remote

Wakati wa kuchanganua, Flipper Zero hukagua nguvu ya mawimbi (RSSI) kwenye frequency zote zinazopatikana katika mipangilio ya frequency. Flipper Zero huonyesha frequency yenye thamani ya juu zaidi ya RSSI, ikiwa na nguvu ya mawimbi iliyo juu ya -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Ili kubaini frequency ya remote, fanya yafuatayo:

1. Weka remote karibu sana na upande wa kushoto wa Flipper Zero.
2. Nenda kwenye **Main Menu** **→ Sub-GHz**.
3. Chagua **Frequency Analyzer**, kisha bonyeza na ushikilie kitufe cha remote unayotaka kuchanganua.
4. Angalia thamani ya frequency kwenye skrini.

### Read

> [!TIP]
> Tafuta maelezo kuhusu frequency inayotumiwa (pia ni njia nyingine ya kujua frequency inayotumiwa)

Chaguo la **Read** husikiliza frequency na modulation iliyowekwa (kwa chaguo-msingi ni 433.92 MHz AM). Linapotambua mawimbi yanayotumika, skrini huonyesha maelezo yanayoweza kuhifadhiwa na kutumika tena baadaye.<sup>[[1]](#references)</sup>

Wakati Read inatumika, unaweza kubonyeza **kitufe cha kushoto** na **kusanidi mipangilio**.\
Kwa sasa ina **modulation 4** (AM270, AM650, FM328 na FM476), pamoja na **frequency kadhaa muhimu** zilizohifadhiwa:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Unaweza kuchagua frequency yoyote inayoruhusiwa. Ikiwa huna uhakika remote inatumia frequency gani, weka **Hopping kuwa ON** (imezimwa kwa chaguo-msingi), kisha bonyeza kitufe cha remote mara kadhaa hadi Flipper inase mawimbi na kuripoti frequency.

> [!CAUTION]
> Kubadilisha frequency huchukua muda, kwa hivyo mawimbi yanayotumwa wakati wa mabadiliko yanaweza kukosekana. Ili kupokea mawimbi vizuri zaidi, weka frequency isiyobadilika uliyobaini kwa kutumia Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Nasa (na uchezeshe tena) mawimbi kwenye frequency iliyowekwa

Chaguo la **Read Raw** hurekodi mawimbi yanayotumwa kwenye frequency iliyochaguliwa. Hili linaweza kutumiwa kunasa na kuchezesha tena mawimbi wakati wa majaribio yaliyoidhinishwa.<sup>[[1]](#references)</sup>

Kwa chaguo-msingi, **Read Raw pia hutumia 433.92 MHz pamoja na AM650**. Ikiwa chaguo la Read liligundua mawimbi kwenye frequency au modulation tofauti, bonyeza Left ndani ya Read Raw ili kubadilisha mipangilio hiyo.

### Brute-Force

Ikiwa unajua protocol inayotumiwa na kifaa kama vile mlango wa gereji, huenda ikawezekana **kutengeneza misimbo inayowezekana na kuituma kwa kutumia Flipper Zero**. Mradi wa `flipperzero-bruteforce` unaunga mkono protocol kadhaa za kawaida zinazotumia misimbo isiyobadilika.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Ongeza mawimbi kutoka kwenye orodha ya protocol zilizowekwa

#### Orodha ya protocol zinazotumika <a href="#id-3iglu" id="id-3iglu"></a>

Menyu ya Add Manually huonyesha mipangilio ya awali ya protocol iliyoandikwa kwenye nyaraka za Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (hufanya kazi na mifumo mingi inayotumia misimbo isiyobadilika) | 433.92 | Static  |
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

### Wachuuzi wa Sub-GHz wanaotumika

Angalia orodha ya wachuuzi wanaotumika ya Flipper Zero.<sup>[[5]](#references)</sup>

### Frequency zinazotumika kulingana na eneo

Angalia orodha rasmi ya frequency za maeneo kabla ya kutuma mawimbi.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Pata thamani za dBm za frequency zilizohifadhiwa

## References

- [1] [Sub-GHz - Nyaraka za Mtumiaji za Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Karatasi ya data ya Texas Instruments CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Ongeza remote iliyoundwa mwenyewe](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Wachuuzi wa Sub-GHz wanaotumika](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Frequency za Sub-GHz kulingana na eneo](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}

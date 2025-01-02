# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero inaweza **kupokea na kutuma masafa ya redio katika anuwai ya 300-928 MHz** na moduli yake iliyojengwa, ambayo inaweza kusoma, kuhifadhi, na kuiga remote controls. Remote hizi zinatumika kwa mwingiliano na milango, vizuizi, funguo za redio, swichi za remote control, kengele za mlango zisizo na waya, mwanga wa smart, na zaidi. Flipper Zero inaweza kukusaidia kujifunza ikiwa usalama wako umeathirika.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero ina moduli ya sub-1 GHz iliyojengwa inayotegemea [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) na antenna ya redio (anuwai ya juu ni mita 50). Chip ya CC1101 na antenna zimeundwa kufanya kazi katika masafa ya 300-348 MHz, 387-464 MHz, na 779-928 MHz.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!NOTE]
> Jinsi ya kupata ni masafa gani remote inatumia

Wakati wa kuchambua, Flipper Zero inachanganua nguvu za ishara (RSSI) katika masafa yote yanayopatikana katika usanidi wa masafa. Flipper Zero inaonyesha masafa yenye thamani ya juu ya RSSI, ikiwa na nguvu ya ishara zaidi ya -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Ili kubaini masafa ya remote, fanya yafuatayo:

1. Weka remote control karibu sana na kushoto ya Flipper Zero.
2. Nenda kwenye **Main Menu** **→ Sub-GHz**.
3. Chagua **Frequency Analyzer**, kisha bonyeza na ushikilie kitufe kwenye remote control unayotaka kuchambua.
4. Kagua thamani ya masafa kwenye skrini.

### Read

> [!NOTE]
> Pata taarifa kuhusu masafa yanayotumika (pia njia nyingine ya kupata ni masafa gani yanayotumika)

Chaguo la **Read** **linasikiliza kwenye masafa yaliyosanidiwa** kwenye moduli iliyotajwa: 433.92 AM kwa chaguo-msingi. Ikiwa **kitu kinapatikana** wakati wa kusoma, **taarifa inatolewa** kwenye skrini. Taarifa hii inaweza kutumika kuiga ishara siku zijazo.

Wakati Read inatumika, inawezekana kubonyeza **kitufe cha kushoto** na **kuisakinisha**.\
Kwa sasa ina **modulations 4** (AM270, AM650, FM328 na FM476), na **masafa kadhaa muhimu** yaliyohifadhiwa:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Unaweza kuweka **yoyote inayokuvutia**, hata hivyo, ikiwa **hujui ni masafa gani** yanaweza kuwa yanayotumiwa na remote ulionayo, **weka Hopping kuwa ON** (Off kwa chaguo-msingi), na bonyeza kitufe mara kadhaa hadi Flipper ikiteka na kukupa taarifa unayohitaji kuweka masafa.

> [!CAUTION]
> Kubadilisha kati ya masafa kunachukua muda, kwa hivyo ishara zinazotumwa wakati wa kubadilisha zinaweza kupuuziliwa mbali. Kwa kupokea ishara bora, weka masafa thabiti yaliyopangwa na Frequency Analyzer.

### **Read Raw**

> [!NOTE]
> Pora (na rudia) ishara katika masafa yaliyosanidiwa

Chaguo la **Read Raw** **linarekodi ishara** zinazotumwa katika masafa ya kusikiliza. Hii inaweza kutumika **kuiba** ishara na **kurudia** hiyo.

Kwa chaguo-msingi **Read Raw pia iko katika 433.92 katika AM650**, lakini ikiwa na chaguo la Read umegundua kuwa ishara inayokuvutia iko katika **masafa/modulation tofauti, unaweza pia kubadilisha hiyo** kwa kubonyeza kushoto (wakati uko ndani ya chaguo la Read Raw).

### Brute-Force

Ikiwa unajua itifaki inayotumiwa kwa mfano na mlango wa garaji inawezekana **kuunda nambari zote na kuzituma na Flipper Zero.** Hii ni mfano unaounga mkono aina za kawaida za garaji: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!NOTE]
> Ongeza ishara kutoka orodha iliyosanidiwa ya itifaki

#### Orodha ya [itifaki zinazoungwa mkono](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (inafanya kazi na mfumo wa nambari za statiki nyingi) | 433.92 | Static  |
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

### Vendors wa Sub-GHz wanaoungwa mkono

Angalia orodha katika [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Masafa yanayoungwa mkono kwa eneo

Angalia orodha katika [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Test

> [!NOTE]
> Pata dBms za masafa yaliyohifadhiwa

## Reference

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}

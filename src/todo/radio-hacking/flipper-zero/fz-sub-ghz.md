# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero kan **ontvang en oordra radiofrekwensies in die reeks van 300-928 MHz** met sy ingeboude module, wat afstandbeheerder kan lees, stoor en emuleer. Hierdie beheerders word gebruik vir interaksie met hekke, hindernisse, radio slotte, afstandbeheer skakelaars, draadlose deurklokke, slim ligte, en meer. Flipper Zero kan jou help om te leer of jou sekuriteit gecompromitteer is.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardeware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero het 'n ingeboude sub-1 GHz module gebaseer op 'n [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) en 'n radio antenne (die maksimum reeks is 50 meter). Beide die CC1101 chip en die antenne is ontwerp om te werk by frekwensies in die 300-348 MHz, 387-464 MHz, en 779-928 MHz bande.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Frekwensie Analiseerder

> [!NOTE]
> Hoe om te vind watter frekwensie die afstandbeheerder gebruik

Wanneer geanaliseer word, skandeer Flipper Zero die seinsterkte (RSSI) by al die frekwensies beskikbaar in frekwensie konfigurasie. Flipper Zero vertoon die frekwensie met die hoogste RSSI waarde, met seinsterkte hoër as -90 [dBm](https://en.wikipedia.org/wiki/DBm).

Om die afstandbeheerder se frekwensie te bepaal, doen die volgende:

1. Plaas die afstandbeheerder baie naby die linkerkant van Flipper Zero.
2. Gaan na **Hoofmenu** **→ Sub-GHz**.
3. Kies **Frekwensie Analiseerder**, druk dan en hou die knoppie op die afstandbeheerder wat jy wil analiseer.
4. Hersien die frekwensie waarde op die skerm.

### Lees

> [!NOTE]
> Vind inligting oor die frekwensie wat gebruik word (ook 'n ander manier om te vind watter frekwensie gebruik word)

Die **Lees** opsie **luister op die geconfigureerde frekwensie** op die aangeduide modulering: 433.92 AM per standaard. As **iets gevind word** wanneer gelees word, **word inligting gegee** op die skerm. Hierdie inligting kan gebruik word om die sein in die toekoms te repliseer.

Terwyl Lees in gebruik is, is dit moontlik om die **linker knoppie** te druk en **dit te konfigureer**.\
Op hierdie oomblik het dit **4 moduleringe** (AM270, AM650, FM328 en FM476), en **verskeie relevante frekwensies** gestoor:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Jy kan **enige wat jou interesseer** stel, egter, as jy **nie seker is watter frekwensie** die een kan wees wat deur die afstandbeheerder gebruik word nie, **stel Hopping op AAN** (Af per standaard), en druk die knoppie verskeie kere totdat Flipper dit vasvang en jou die inligting gee wat jy nodig het om die frekwensie in te stel.

> [!CAUTION]
> Om tussen frekwensies te skakel neem 'n bietjie tyd, daarom kan seine wat tydens die skakeling oorgedra word gemis word. Vir beter seinontvangs, stel 'n vaste frekwensie vasgestel deur Frekwensie Analiseerder.

### **Lees Rau**

> [!NOTE]
> Steel (en herhaal) 'n sein in die geconfigureerde frekwensie

Die **Lees Rau** opsie **registreer seine** wat in die luister frekwensie gestuur word. Dit kan gebruik word om 'n sein te **steel** en dit te **herhaal**.

Per standaard is **Lees Rau ook in 433.92 in AM650**, maar as jy met die Lees opsie gevind het dat die sein wat jou interesseer in 'n **ander frekwensie/modulering is, kan jy dit ook wysig** deur links te druk (terwyl jy binne die Lees Rau opsie is).

### Brute-Force

As jy die protokol weet wat byvoorbeeld deur die motorhuisdeur gebruik word, is dit moontlik om **alle kodes te genereer en dit met die Flipper Zero te stuur.** Dit is 'n voorbeeld wat algemene algemene tipes motorhuise ondersteun: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Voeg Handmatig By

> [!NOTE]
> Voeg seine by 'n geconfigureerde lys van protokolle

#### Lys van [ondersteunde protokolle](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (werk met die meerderheid van statiese kode stelsels) | 433.92 | Staties  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Staties  |
| Nice Flo 24bit_433                                             | 433.92 | Staties  |
| CAME 12bit_433                                                 | 433.92 | Staties  |
| CAME 24bit_433                                                 | 433.92 | Staties  |
| Linear_300                                                     | 300.00 | Staties  |
| CAME TWEE                                                      | 433.92 | Staties  |
| Gate TX_433                                                    | 433.92 | Staties  |
| DoorHan_315                                                    | 315.00 | Dinamies  |
| DoorHan_433                                                    | 433.92 | Dinamies  |
| LiftMaster_315                                                 | 315.00 | Dinamies  |
| LiftMaster_390                                                 | 390.00 | Dinamies  |
| Security+2.0_310                                               | 310.00 | Dinamies  |
| Security+2.0_315                                               | 315.00 | Dinamies  |
| Security+2.0_390                                               | 390.00 | Dinamies  |

### Ondersteunde Sub-GHz verskaffers

Kyk die lys in [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Ondersteunde Frekwensies per streek

Kyk die lys in [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Toets

> [!NOTE]
> Kry dBms van die gestoor frekwensies

## Verwysing

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}

# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero kan **radiofrekwensies in die reeks van 300-928 MHz ontvang en uitstuur** met sy ingeboude module, wat afstandbeheerders kan lees, stoor en emuleer. Hierdie beheerders word gebruik vir interaksie met hekke, versperrings, radio-slotte, afstandbeheerde skakelaars, draadlose deurklokkies, slimligte en meer. Flipper Zero kan jou help om vas te stel of jou sekuriteit gekompromitteer is.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz-hardeware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero het 'n ingeboude sub-1 GHz-module gebaseer op 'n [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101-chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf) en 'n radioantenna (die maksimum reikwydte is 50 meter). Beide die CC1101-chip en die antenna is ontwerp om teen frekwensies in die 300-348 MHz-, 387-464 MHz- en 779-928 MHz-bande te werk.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Frequency Analyser

> [!TIP]
> Hoe om uit te vind watter frekwensie die afstandbeheerder gebruik

Tydens ontleding skandeer Flipper Zero die seinsterkte (RSSI) by al die frekwensies wat in die frekwensiekonfigurasie beskikbaar is. Flipper Zero vertoon die frekwensie met die hoogste RSSI-waarde, met 'n seinsterkte hoër as -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Om die afstandbeheerder se frekwensie te bepaal, doen die volgende:

1. Plaas die afstandbeheerder baie naby aan die linkerkant van Flipper Zero.
2. Gaan na **Main Menu** **→ Sub-GHz**.
3. Kies **Frequency Analyzer**, en druk en hou dan die knoppie op die afstandbeheerder wat jy wil ontleed.
4. Hersien die frekwensiewaarde op die skerm.

### Read

> [!TIP]
> Vind inligting oor die frekwensie wat gebruik word (ook 'n ander manier om uit te vind watter frekwensie gebruik word)

Die **Read**-opsie **luister op die gekonfigureerde frekwensie** met die aangeduide modulasie: 433.92 AM by verstek. As **iets gevind word** tydens lees, word **inligting verskaf** op die skerm. Hierdie inligting kan gebruik word om die sein in die toekoms te repliseer.<sup>[[1]](#references)</sup>

Terwyl Read gebruik word, is dit moontlik om die **linkerknoppie** te druk en dit te **konfigureer**.\
Op hierdie oomblik het dit **4 modulasies** (AM270, AM650, FM328 en FM476), en **verskeie relevante frekwensies** wat gestoor is:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Jy kan **enige een kies wat jou interesseer**, maar as jy **nie seker is watter frekwensie** die een kan wees wat deur jou afstandbeheerder gebruik word nie, **stel Hopping op ON** (by verstek Off), en druk die knoppie verskeie kere totdat Flipper dit vasvang en jou die inligting gee wat jy nodig het om die frekwensie te stel.

> [!CAUTION]
> Om tussen frekwensies te wissel neem tyd; seine wat tydens die wisseling uitgestuur word, kan dus gemis word. Vir beter seinontvangs, stel 'n vaste frekwensie wat deur Frequency Analyzer bepaal is.

### **Read Raw**

> [!TIP]
> Steel (en speel weer) 'n sein op die gekonfigureerde frekwensie

Die **Read Raw**-opsie **neem seine op** wat op die luisterfrekwensie gestuur word. Dit kan gebruik word om 'n sein te **steel** en dit te **herhaal**.<sup>[[1]](#references)</sup>

By verstek is **Read Raw** ook op 433.92 in AM650, maar as jy met die Read-opsie gevind het dat die sein wat jou interesseer op 'n **ander frekwensie/modulasie is, kan jy dit ook wysig** deur links te druk (terwyl jy binne die Read Raw-opsie is).

### Brute-Force

As jy die protokol ken wat byvoorbeeld deur die motorhuisdeur gebruik word, is dit moontlik om **al die kodes te genereer en dit met die Flipper Zero te stuur.** Dit is 'n voorbeeld wat algemene tipes motorhuise ondersteun: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> Voeg seine by uit 'n gekonfigureerde lys protokolle

#### Lys van [ondersteunde protokolle](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

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

### Ondersteunde Sub-GHz-verskaffers

Gaan die lys na by [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)

### Ondersteunde frekwensies volgens streek

Gaan die lys na by [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)

### Toets

> [!TIP]
> Kry dBm-waardes van die gestoorde frekwensies

## Verwysings

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}

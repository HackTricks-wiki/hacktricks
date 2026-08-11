# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#introduction" id="introduction"></a>

Flipper Zero kan **radiofrekwensies in die reeks van 300-928 MHz ontvang en uitstuur** met sy ingeboude module, onderhewig aan die frekwensiebeperkings vir die gekonfigureerde streek. Dit kan versoenbare afstandbeheerders wat met hekke, versperrings, radioslotte, skakelaars, draadlose deurklokkies, slimligte en ander toestelle gebruik word, lees, stoor en naboots.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Hardeware <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero het ’n ingeboude sub-1 GHz-module wat op ’n CC1101-transceiver en ’n radioantenna gebaseer is. Die werklike reikafstand hang van die frekwensie, antenna, omgewing en sender af; Flipper dokumenteer tot ongeveer 50 meter onder gunstige toestande. Die hardeware dek 300-348 MHz, 387-464 MHz en 779-928 MHz, terwyl firmware en streeksreëls die uitsending verder beperk.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Frequency Analyser

> [!TIP]
> Hoe om uit te vind watter frekwensie die afstandbeheerder gebruik

Wanneer dit analiseer, skandeer Flipper Zero die seinsterkte (RSSI) by al die frekwensies wat in die frekwensiekonfigurasie beskikbaar is. Flipper Zero vertoon die frekwensie met die hoogste RSSI-waarde, met ’n seinsterkte hoër as -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Om die afstandbeheerder se frekwensie te bepaal, doen die volgende:

1. Plaas die afstandbeheerder baie naby aan die linkerkant van Flipper Zero.
2. Gaan na **Main Menu** **→ Sub-GHz**.
3. Kies **Frequency Analyzer**, en druk en hou dan die knoppie op die afstandbeheerder wat jy wil analiseer.
4. Hersien die frekwensiewaarde op die skerm.

### Read

> [!TIP]
> Vind inligting oor die gebruikte frekwensie (ook ’n ander manier om uit te vind watter frekwensie gebruik word)

Die **Read**-opsie luister op die gekonfigureerde frekwensie en modulasie (433.92 MHz AM by verstek). Wanneer dit ’n ondersteunde sein herken, vertoon die skerm inligting wat later gestoor en herspeel kan word.<sup>[[1]](#references)</sup>

Terwyl Read gebruik word, is dit moontlik om die **linkerknoppie** te druk en dit te **configureer**.\
Op hierdie oomblik het dit **4 modulasies** (AM270, AM650, FM328 en FM476), en **verskeie relevante frekwensies** wat gestoor is:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Jy kan enige toegelate frekwensie kies. As jy onseker is watter frekwensie die afstandbeheerder gebruik, stel **Hopping op ON** (by verstek af), en druk dan die afstandbeheerder se knoppie verskeie kere totdat Flipper die sein vaslê en die frekwensie rapporteer.

> [!CAUTION]
> Om tussen frekwensies te wissel neem tyd; seine wat tydens die wisseling uitgesaai word, kan dus gemis word. Vir beter seinontvangs, stel ’n vaste frekwensie wat deur Frequency Analyzer bepaal is.

### **Read Raw**

> [!TIP]
> Steel (en herspeel) ’n sein op die gekonfigureerde frekwensie

Die **Read Raw**-opsie neem seine op wat op die gekose frekwensie gestuur word. Dit kan gebruik word om ’n sein tydens gemagtigde toetsing vas te lê en te herspeel.<sup>[[1]](#references)</sup>

By verstek gebruik **Read Raw ook 433.92 MHz met AM650**. As die Read-opsie ’n sein op ’n ander frekwensie of modulasie gevind het, druk Left binne Read Raw om daardie instellings te verander.

### Brute-Force

As jy die protokol ken wat deur ’n toestel soos ’n motorhuisdeur gebruik word, kan dit moontlik wees om **kandidaatkodes te genereer en dit met Flipper Zero uit te stuur**. Die `flipperzero-bruteforce`-projek ondersteun verskeie algemene static-code-protokolle.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Voeg seine uit ’n gekonfigureerde protokolys by

#### Lys van ondersteunde protokolle <a href="#id-3iglu" id="id-3iglu"></a>

Die Add Manually-kieslys stel die protokolvoorinstellings bloot wat deur Flipper Zero gedokumenteer word.<sup>[[4]](#references)</sup>

| Princeton_433 (werk met die meerderheid van static-code-stelsels) | 433.92 | Static  |
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

Gaan Flipper Zero se ondersteunde-verskafferslys na.<sup>[[5]](#references)</sup>

### Ondersteunde frekwensies volgens streek

Gaan die amptelike streeksfrekwensielys na voordat jy uitstuur.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Kry dBms van die gestoorde frekwensies

## References

- [1] [Sub-GHz - Flipper Zero-gebruikersdokumentasie](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101-datablad](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Voeg ’n handmatig geskepte afstandbeheerder by](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Ondersteunde Sub-GHz-verskaffers](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Streeksgebaseerde Sub-GHz-frekwensies](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}

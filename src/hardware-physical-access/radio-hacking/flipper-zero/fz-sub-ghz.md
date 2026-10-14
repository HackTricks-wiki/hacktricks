# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Inleiding <a href="#introduction" id="introduction"></a>

Flipper Zero kan **radiofrekwensies in die reeks van 300-928 MHz ontvang en uitstuur** met sy ingeboude module, onderhewig aan die frekwensiebeperkings vir die ingestelde streek. Dit kan versoenbare afstandbeheerders lees, stoor en naboots wat vir hekke, versperrings, radioslotte, skakelaars, draadlose deurklokkies, slimligte en ander toestelle gebruik word.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz-hardeware <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero het ’n ingeboude sub-1 GHz-module wat op ’n CC1101-ontvanger en ’n radioantenna gebaseer is. Die werklike bereik hang af van die frekwensie, antenna, omgewing en sender; Flipper dokumenteer ’n bereik van tot ongeveer 50 meter onder gunstige omstandighede. Die hardeware dek 300-348 MHz, 387-464 MHz en 779-928 MHz, terwyl firmware en streekreëls die uitstuur van seine verder beperk.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Aksies

### Frequency Analyser

> [!TIP]
> Hoe om uit te vind watter frekwensie die afstandbeheerder gebruik

Wanneer Flipper Zero ontleed, skandeer dit die seinsterkte (RSSI) op al die frekwensies wat in die frekwensiekonfigurasie beskikbaar is. Flipper Zero wys die frekwensie met die hoogste RSSI-waarde en ’n seinsterkte hoër as -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Doen die volgende om die afstandbeheerder se frekwensie te bepaal:

1. Plaas die afstandbeheerder baie naby aan Flipper Zero se linkerkant.
2. Gaan na **Main Menu** **→ Sub-GHz**.
3. Kies **Frequency Analyzer** en hou dan die knoppie op die afstandbeheerder wat jy wil ontleed, ingedruk.
4. Gaan die frekwensiewaarde op die skerm na.

### Read

> [!TIP]
> Vind inligting oor die gebruikte frekwensie (ook ’n ander manier om uit te vind watter frekwensie gebruik word)

Die **Read**-opsie luister op die ingestelde frekwensie en modulasie (by verstek 433.92 MHz AM). Wanneer dit ’n ondersteunde sein herken, wys die skerm inligting wat gestoor en later weer gespeel kan word.<sup>[[1]](#references)</sup>

Terwyl Read gebruik word, kan jy die **linkerknoppie** druk en dit **konfigureer**.\
Op die oomblik het dit **4 modulasies** (AM270, AM650, FM328 en FM476), en **verskeie relevante frekwensies** is gestoor:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Jy kan enige toegelate frekwensie kies. As jy nie seker is watter frekwensie die afstandbeheerder gebruik nie, stel **Hopping op ON** (by verstek afgeskakel) en druk dan die afstandbeheerder se knoppie verskeie kere totdat Flipper die sein vaslê en die frekwensie rapporteer.

> [!CAUTION]
> Om tussen frekwensies te wissel, neem tyd; seine wat tydens die wisseling uitgestuur word, kan dus gemis word. Stel ’n vaste frekwensie in wat met Frequency Analyzer bepaal is om seine beter te ontvang.

### **Read Raw**

> [!TIP]
> Steel (en speel weer) ’n sein op die ingestelde frekwensie

Die **Read Raw**-opsie neem seine op wat op die gekose frekwensie uitgestuur word. Dit kan gebruik word om ’n sein tydens gemagtigde toetsing vas te lê en weer te speel.<sup>[[1]](#references)</sup>

By verstek gebruik **Read Raw** ook 433.92 MHz met AM650. As die Read-opsie ’n sein op ’n ander frekwensie of met ’n ander modulasie gevind het, druk Left binne Read Raw om daardie instellings te verander.

### Brute-Force

As jy die protokol ken wat ’n toestel soos ’n motorhuisdeur gebruik, kan dit moontlik wees om **kandidaatkodes te genereer en dit met Flipper Zero uit te stuur**. Die `flipperzero-bruteforce`-projek ondersteun verskeie algemene statiese-kodeprotokolle.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Voeg seine by uit ’n gekonfigureerde lys protokolle

#### Lys van ondersteunde protokolle <a href="#id-3iglu" id="id-3iglu"></a>

Die Add Manually-kieslys wys die protokolvoorinstellings wat deur Flipper Zero gedokumenteer word.<sup>[[4]](#references)</sup>

| Princeton_433 (werk met die meeste statiese-kodestelsels) | 433.92 | Static  |
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

Gaan Flipper Zero se lys van ondersteunde verskaffers na.<sup>[[5]](#references)</sup>

### Ondersteunde frekwensies per streek

Gaan die amptelike lys van streekfrekwensies na voordat jy seine uitstuur.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Kry dBm-waardes van die gestoorde frekwensies

## References

- [1] [Sub-GHz - Flipper Zero-gebruikersdokumentasie](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101-datablad](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Voeg ’n handmatig geskepte afstandbeheerder by](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Ondersteunde Sub-GHz-verskaffers](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Streekfrekwensies vir Sub-GHz](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}

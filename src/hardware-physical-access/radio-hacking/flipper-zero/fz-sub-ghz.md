# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Uvod <a href="#introduction" id="introduction"></a>

Flipper Zero može **da prima i emituje radio-frekvencije u opsegu od 300 do 928 MHz** pomoću ugrađenog modula, uz ograničenja frekvencija koja važe za podešeni region. Može da čita, čuva i emulira kompatibilne daljinske upravljače za kapije, barijere, radio-brave, prekidače, bežična zvona, pametna svetla i druge uređaje.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardver <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero ima ugrađeni sub-1 GHz modul zasnovan na CC1101 primopredajniku i radio-anteni. Stvarni domet zavisi od frekvencije, antene, okruženja i predajnika; Flipper navodi domet do približno 50 metara u povoljnim uslovima. Hardver pokriva opsege 300–348 MHz, 387–464 MHz i 779–928 MHz, dok firmver i regionalna pravila dodatno ograničavaju emitovanje.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Akcije

### Analizator frekvencije

> [!TIP]
> Kako pronaći frekvenciju koju koristi daljinski upravljač

Tokom analize, Flipper Zero skenira jačinu signala (RSSI) na svim frekvencijama dostupnim u podešavanjima frekvencija. Flipper Zero prikazuje frekvenciju s najvišom vrednošću RSSI-ja, odnosno jačinom signala većom od -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Da biste utvrdili frekvenciju daljinskog upravljača, uradite sledeće:

1. Postavite daljinski upravljač sasvim blizu leve strane uređaja Flipper Zero.
2. Otvorite **Main Menu** **→ Sub-GHz**.
3. Izaberite **Frequency Analyzer**, pa pritisnite i držite dugme na daljinskom upravljaču koji želite da analizirate.
4. Proverite vrednost frekvencije na ekranu.

### Read

> [!TIP]
> Pronađite informacije o korišćenoj frekvenciji (još jedan način da saznate koja se frekvencija koristi)

Opcija **Read** sluša na podešenoj frekvenciji i koristi podešenu modulaciju (podrazumevano 433,92 MHz AM). Kada prepozna podržani signal, na ekranu prikazuje informacije koje možete da sačuvate i kasnije ponovo reprodukujete.<sup>[[1]](#references)</sup>

Tokom korišćenja opcije Read, možete da pritisnete **levo dugme** i **podesite je**.\
Trenutno su dostupne **4 modulacije** (AM270, AM650, FM328 i FM476) i **nekoliko relevantnih sačuvanih frekvencija**:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Možete da izaberete bilo koju dozvoljenu frekvenciju. Ako niste sigurni koju frekvenciju koristi daljinski upravljač, uključite opciju **Hopping** (podrazumevano je isključena), pa nekoliko puta pritisnite dugme na daljinskom upravljaču dok Flipper ne uhvati signal i prikaže frekvenciju.

> [!CAUTION]
> Prebacivanje između frekvencija traje neko vreme, pa se signali emitovani tokom prebacivanja mogu propustiti. Za bolji prijem signala podesite fiksnu frekvenciju koju ste utvrdili pomoću opcije Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Uhvatite (i ponovo reprodukujte) signal na podešenoj frekvenciji

Opcija **Read Raw** snima signale emitovane na izabranoj frekvenciji. Može da se koristi za hvatanje i ponovno reprodukovanje signala tokom ovlašćenog testiranja.<sup>[[1]](#references)</sup>

Podrazumevano, **Read Raw takođe koristi frekvenciju 433,92 MHz i modulaciju AM650**. Ako je opcija Read pronašla signal na drugoj frekvenciji ili s drugom modulacijom, pritisnite Left unutar opcije Read Raw da biste promenili podešavanja.

### Brute-Force

Ako znate koji protokol koristi uređaj, na primer garažna vrata, možda možete da **generišete moguće kodove i emitujete ih pomoću uređaja Flipper Zero**. Projekat `flipperzero-bruteforce` podržava nekoliko uobičajenih protokola sa statičkim kodom.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Dodajte signale iz podešene liste protokola

#### Lista podržanih protokola <a href="#id-3iglu" id="id-3iglu"></a>

Meni Add Manually prikazuje unapred podešene protokole dokumentovane za Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (radi sa većinom sistema sa statičkim kodom) | 433.92 | Static  |
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

### Podržani Sub-GHz proizvođači

Pogledajte listu podržanih proizvođača za Flipper Zero.<sup>[[5]](#references)</sup>

### Podržane frekvencije po regionima

Pre emitovanja proverite zvaničnu listu regionalnih frekvencija.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Prikažite dBm vrednosti sačuvanih frekvencija

## References

- [1] [Sub-GHz – korisnička dokumentacija za Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Tehnički list CC1101 kompanije Texas Instruments](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero – dodavanje ručno kreiranog daljinskog upravljača](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero – podržani Sub-GHz proizvođači](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero – regionalne Sub-GHz frekvencije](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
